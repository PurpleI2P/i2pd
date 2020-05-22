/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "Crypto.h"
#include "Log.h"
#include "TunnelBase.h"
#include "RouterContext.h"
#include "Destination.h"
#include "Datagram.h"

namespace i2p
{
namespace datagram
{
	DatagramDestination::DatagramDestination (std::shared_ptr<i2p::client::ClientDestination> owner, bool gzip):
		m_Owner (owner), m_Receiver (nullptr), m_RawReceiver (nullptr), m_Gzip (gzip)
	{
		auto identityLen = m_Owner->GetIdentity ()->GetFullLen ();
		m_From.resize (identityLen);
		m_Owner->GetIdentity ()->ToBuffer (m_From.data (), identityLen);
		m_Signature.resize (m_Owner->GetIdentity ()->GetSignatureLen ());
	}

	DatagramDestination::~DatagramDestination ()
	{
		m_Sessions.clear();
	}

	void DatagramDestination::SendDatagramTo(const uint8_t * payload, size_t len, const i2p::data::IdentHash & identity, uint16_t fromPort, uint16_t toPort)
	{
		if (m_Owner->GetIdentity ()->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
		{
			uint8_t hash[32];
			SHA256(payload, len, hash);
			m_Owner->Sign (hash, 32, m_Signature.data ());
		}
		else
			m_Owner->Sign (payload, len, m_Signature.data ());

		auto session = ObtainSession(identity);
		auto msg = CreateDataMessage ({{m_From.data (), m_From.size ()}, {m_Signature.data (), m_Signature.size ()}, {payload, len}},
			fromPort, toPort, false, !session->IsRatchets ()); // datagram
		session->SendMsg(msg);
	}

	void DatagramDestination::SendRawDatagramTo(const uint8_t * payload, size_t len, const i2p::data::IdentHash & identity, uint16_t fromPort, uint16_t toPort)
	{
		auto session = ObtainSession(identity);
		auto msg = CreateDataMessage ({{payload, len}}, fromPort, toPort, true, !session->IsRatchets ()); // raw
		session->SendMsg(msg);
	}

	void DatagramDestination::HandleDatagram (uint16_t fromPort, uint16_t toPort,uint8_t * const &buf, size_t len)
	{
		i2p::data::IdentityEx identity;
		size_t identityLen = identity.FromBuffer (buf, len);
		const uint8_t * signature = buf + identityLen;
		size_t headerLen = identityLen + identity.GetSignatureLen ();

		bool verified = false;
		if (identity.GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
		{
			uint8_t hash[32];
			SHA256(buf + headerLen, len - headerLen, hash);
			verified = identity.Verify (hash, 32, signature);
		}
		else
			verified = identity.Verify (buf + headerLen, len - headerLen, signature);

		if (verified)
		{
			auto h = identity.GetIdentHash();
			auto session = ObtainSession(h);
			session->Ack();
			auto r = FindReceiver(toPort);
			if(r)
				r(identity, fromPort, toPort, buf + headerLen, len -headerLen);
			else
				LogPrint (eLogWarning, "DatagramDestination: no receiver for port ", toPort);
		}
		else
			LogPrint (eLogWarning, "Datagram signature verification failed");
	}

	void DatagramDestination::HandleRawDatagram (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (m_RawReceiver)
			m_RawReceiver (fromPort, toPort, buf, len);
		else
			LogPrint (eLogWarning, "DatagramDestination: no receiver for raw datagram");
	}

	DatagramDestination::Receiver DatagramDestination::FindReceiver(uint16_t port)
	{
		std::lock_guard<std::mutex> lock(m_ReceiversMutex);
		Receiver r = m_Receiver;
		auto itr = m_ReceiversByPorts.find(port);
		if (itr != m_ReceiversByPorts.end())
			r = itr->second;
		return r;
	}

	void DatagramDestination::HandleDataMessagePayload (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len, bool isRaw)
	{
		// unzip it
		uint8_t uncompressed[MAX_DATAGRAM_SIZE];
		size_t uncompressedLen = m_Inflator.Inflate (buf, len, uncompressed, MAX_DATAGRAM_SIZE);
		if (uncompressedLen)
		{
			if (isRaw)
				HandleRawDatagram (fromPort, toPort, uncompressed, uncompressedLen);
			else
				HandleDatagram (fromPort, toPort, uncompressed, uncompressedLen);
		}
		else
			LogPrint (eLogWarning, "Datagram: decompression failed");
	}

	std::shared_ptr<I2NPMessage> DatagramDestination::CreateDataMessage (
		const std::vector<std::pair<const uint8_t *, size_t> >& payloads,
		uint16_t fromPort, uint16_t toPort, bool isRaw, bool checksum)
	{
		auto msg = NewI2NPMessage ();
		uint8_t * buf = msg->GetPayload ();
		buf += 4; // reserve for length
		size_t size = m_Gzip ? m_Deflator.Deflate (payloads, buf, msg->maxLen - msg->len) :
			i2p::data::GzipNoCompression (payloads, buf, msg->maxLen - msg->len);
		if (size)
		{
			htobe32buf (msg->GetPayload (), size); // length
			htobe16buf (buf + 4, fromPort); // source port
			htobe16buf (buf + 6, toPort); // destination port
			buf[9] = isRaw ? i2p::client::PROTOCOL_TYPE_RAW : i2p::client::PROTOCOL_TYPE_DATAGRAM; // raw or datagram protocol
			msg->len += size + 4;
			msg->FillI2NPMessageHeader (eI2NPData, 0, checksum);
		}
		else
			msg = nullptr;
		return msg;
	}

	void DatagramDestination::CleanUp ()
	{
		if (m_Sessions.empty ()) return;
		auto now = i2p::util::GetMillisecondsSinceEpoch();
		LogPrint(eLogDebug, "DatagramDestination: clean up sessions");
		std::unique_lock<std::mutex> lock(m_SessionsMutex);
		// for each session ...
		for (auto it = m_Sessions.begin (); it != m_Sessions.end (); )
		{
			// check if expired
			if (now - it->second->LastActivity() >= DATAGRAM_SESSION_MAX_IDLE)
			{
				LogPrint(eLogInfo, "DatagramDestination: expiring idle session with ", it->first.ToBase32());
				it->second->Stop ();
				it = m_Sessions.erase (it); // we are expired
			}
			else
				it++;
		}
	}

	std::shared_ptr<DatagramSession> DatagramDestination::ObtainSession(const i2p::data::IdentHash & identity)
	{
		std::shared_ptr<DatagramSession> session = nullptr;
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		auto itr = m_Sessions.find(identity);
		if (itr == m_Sessions.end()) {
			// not found, create new session
			session = std::make_shared<DatagramSession>(m_Owner, identity);
			session->Start ();
			m_Sessions[identity] = session;
		} else {
			session = itr->second;
		}
		return session;
	}

	std::shared_ptr<DatagramSession::Info> DatagramDestination::GetInfoForRemote(const i2p::data::IdentHash & remote)
	{
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		for ( auto & item : m_Sessions)
		{
			if(item.first == remote) return std::make_shared<DatagramSession::Info>(item.second->GetSessionInfo());
		}
		return nullptr;
	}

	DatagramSession::DatagramSession(std::shared_ptr<i2p::client::ClientDestination> localDestination,
		const i2p::data::IdentHash & remoteIdent) :
		m_LocalDestination(localDestination),
		m_RemoteIdent(remoteIdent),
		m_SendQueueTimer(localDestination->GetService()),
		m_RequestingLS(false)
	{
	}

	void DatagramSession::Start ()
	{
		m_LastUse = i2p::util::GetMillisecondsSinceEpoch ();
		ScheduleFlushSendQueue();
	}

	void DatagramSession::Stop ()
	{
		m_SendQueueTimer.cancel ();
	}

	void DatagramSession::SendMsg(std::shared_ptr<I2NPMessage> msg)
	{
		// we used this session
		m_LastUse = i2p::util::GetMillisecondsSinceEpoch();
		// schedule send
		auto self = shared_from_this();
		m_LocalDestination->GetService().post(std::bind(&DatagramSession::HandleSend, self, msg));
	}

	DatagramSession::Info DatagramSession::GetSessionInfo() const
	{
		if(!m_RoutingSession)
			return DatagramSession::Info(nullptr, nullptr, m_LastUse);

		auto routingPath = m_RoutingSession->GetSharedRoutingPath();
		if (!routingPath)
			return DatagramSession::Info(nullptr, nullptr, m_LastUse);
		auto lease = routingPath->remoteLease;
		auto tunnel = routingPath->outboundTunnel;
		if(lease)
		{
			if(tunnel)
				return DatagramSession::Info(lease->tunnelGateway, tunnel->GetEndpointIdentHash(), m_LastUse);
			else
				return DatagramSession::Info(lease->tunnelGateway, nullptr, m_LastUse);
		}
		else if(tunnel)
			return DatagramSession::Info(nullptr, tunnel->GetEndpointIdentHash(), m_LastUse);
		else
			return DatagramSession::Info(nullptr, nullptr, m_LastUse);
	}

	void DatagramSession::Ack()
	{
		m_LastUse = i2p::util::GetMillisecondsSinceEpoch();
		auto path = GetSharedRoutingPath();
		if(path)
			path->updateTime = i2p::util::GetSecondsSinceEpoch ();
		if (IsRatchets ())
			SendMsg (nullptr); // send empty message in case if we have some data to send
	}

	std::shared_ptr<i2p::garlic::GarlicRoutingPath> DatagramSession::GetSharedRoutingPath ()
	{
		if(!m_RoutingSession) {
			if(!m_RemoteLeaseSet) {
				m_RemoteLeaseSet = m_LocalDestination->FindLeaseSet(m_RemoteIdent);
			}
			if(!m_RemoteLeaseSet) {
				// no remote lease set
				if(!m_RequestingLS) {
					m_RequestingLS = true;
					m_LocalDestination->RequestDestination(m_RemoteIdent, std::bind(&DatagramSession::HandleLeaseSetUpdated, this, std::placeholders::_1));
				}
				return nullptr;
			}
			m_RoutingSession = m_LocalDestination->GetRoutingSession(m_RemoteLeaseSet, true);
		}
		auto path = m_RoutingSession->GetSharedRoutingPath();
		if(path) {
			if (m_CurrentOutboundTunnel && !m_CurrentOutboundTunnel->IsEstablished()) {
				// bad outbound tunnel, switch outbound tunnel
				m_CurrentOutboundTunnel = m_LocalDestination->GetTunnelPool()->GetNextOutboundTunnel(m_CurrentOutboundTunnel);
				path->outboundTunnel = m_CurrentOutboundTunnel;
			}
			if(m_CurrentRemoteLease && m_CurrentRemoteLease->ExpiresWithin(DATAGRAM_SESSION_LEASE_HANDOVER_WINDOW)) {
				// bad lease, switch to next one
				if(m_RemoteLeaseSet && m_RemoteLeaseSet->IsExpired())
					m_RemoteLeaseSet = m_LocalDestination->FindLeaseSet(m_RemoteIdent);
				if(m_RemoteLeaseSet) {
					auto ls = m_RemoteLeaseSet->GetNonExpiredLeasesExcluding([&](const i2p::data::Lease& l) -> bool {
							return l.tunnelID == m_CurrentRemoteLease->tunnelID;
					});
					auto sz = ls.size();
					if (sz) {
						auto idx = rand() % sz;
						m_CurrentRemoteLease = ls[idx];
					}
				} else {
					// no remote lease set?
					LogPrint(eLogWarning, "DatagramSession: no cached remote lease set for ", m_RemoteIdent.ToBase32());
				}
				path->remoteLease = m_CurrentRemoteLease;
			}
		} else {
			// no current path, make one
			path = std::make_shared<i2p::garlic::GarlicRoutingPath>();
			// switch outbound tunnel if bad
			if(m_CurrentOutboundTunnel == nullptr || ! m_CurrentOutboundTunnel->IsEstablished()) {
				m_CurrentOutboundTunnel = m_LocalDestination->GetTunnelPool()->GetNextOutboundTunnel(m_CurrentOutboundTunnel);
			}
			// switch lease if bad
			if(m_CurrentRemoteLease && m_CurrentRemoteLease->ExpiresWithin(DATAGRAM_SESSION_LEASE_HANDOVER_WINDOW)) {
				if(!m_RemoteLeaseSet) {
					m_RemoteLeaseSet = m_LocalDestination->FindLeaseSet(m_RemoteIdent);
				}
				if(m_RemoteLeaseSet) {
					// pick random next good lease
					auto ls = m_RemoteLeaseSet->GetNonExpiredLeasesExcluding([&] (const i2p::data::Lease & l) -> bool {
							if(m_CurrentRemoteLease)
								return l.tunnelGateway == m_CurrentRemoteLease->tunnelGateway;
							return false;
					});
					auto sz = ls.size();
					if(sz) {
						auto idx = rand() % sz;
						m_CurrentRemoteLease = ls[idx];
					}
				} else {
					// no remote lease set currently, bail
					LogPrint(eLogWarning, "DatagramSession: no remote lease set found for ", m_RemoteIdent.ToBase32());
					return nullptr;
				}
			} else if (!m_CurrentRemoteLease) {
				if(!m_RemoteLeaseSet) m_RemoteLeaseSet = m_LocalDestination->FindLeaseSet(m_RemoteIdent);
				if (m_RemoteLeaseSet)
				{
					auto ls = m_RemoteLeaseSet->GetNonExpiredLeases();
					auto sz = ls.size();
					if (sz) {
						auto idx = rand() % sz;
						m_CurrentRemoteLease = ls[idx];
					}
				}
			}
			path->outboundTunnel = m_CurrentOutboundTunnel;
			path->remoteLease = m_CurrentRemoteLease;
			m_RoutingSession->SetSharedRoutingPath(path);
		}
		return path;

	}

	void DatagramSession::HandleLeaseSetUpdated(std::shared_ptr<i2p::data::LeaseSet> ls)
	{
		m_RequestingLS = false;
		if(!ls) return;
		// only update lease set if found and newer than previous lease set
		uint64_t oldExpire = 0;
		if(m_RemoteLeaseSet) oldExpire = m_RemoteLeaseSet->GetExpirationTime();
		if(ls && ls->GetExpirationTime() > oldExpire) m_RemoteLeaseSet = ls;
	}

	void DatagramSession::HandleSend(std::shared_ptr<I2NPMessage> msg)
	{
		if (msg || m_SendQueue.empty ())
			m_SendQueue.push_back(msg);
		// flush queue right away if full
		if(m_SendQueue.size() >= DATAGRAM_SEND_QUEUE_MAX_SIZE) FlushSendQueue();
	}

	void DatagramSession::FlushSendQueue ()
	{
		std::vector<i2p::tunnel::TunnelMessageBlock> send;
		auto routingPath = GetSharedRoutingPath();
		// if we don't have a routing path we will drop all queued messages
		if(routingPath && routingPath->outboundTunnel && routingPath->remoteLease)
		{
			for (const auto & msg : m_SendQueue)
			{
				auto m = m_RoutingSession->WrapSingleMessage(msg);
				if (m)
					send.push_back(i2p::tunnel::TunnelMessageBlock{i2p::tunnel::eDeliveryTypeTunnel,routingPath->remoteLease->tunnelGateway, routingPath->remoteLease->tunnelID, m});
			}
			routingPath->outboundTunnel->SendTunnelDataMsg(send);
		}
		m_SendQueue.clear();
		ScheduleFlushSendQueue();
	}

	void DatagramSession::ScheduleFlushSendQueue()
	{
		boost::posix_time::milliseconds dlt(10);
		m_SendQueueTimer.expires_from_now(dlt);
		auto self = shared_from_this();
		m_SendQueueTimer.async_wait([self](const boost::system::error_code & ec) { if(ec) return; self->FlushSendQueue(); });
	}
}
}
