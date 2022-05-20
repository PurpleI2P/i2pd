/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "I2PEndian.h"
#include <random>
#include <thread>
#include <algorithm>
#include <vector>
#include "Crypto.h"
#include "RouterContext.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "Config.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "util.h"
#include "ECIESX25519AEADRatchetSession.h"

namespace i2p
{
namespace tunnel
{
	Tunnel::Tunnel (std::shared_ptr<const TunnelConfig> config):
		TunnelBase (config->GetTunnelID (), config->GetNextTunnelID (), config->GetNextIdentHash ()),
		m_Config (config), m_IsShortBuildMessage (false), m_Pool (nullptr),
		m_State (eTunnelStatePending), m_FarEndTransports (i2p::data::RouterInfo::eAllTransports),
		m_IsRecreated (false), m_Latency (0)
	{
	}

	Tunnel::~Tunnel ()
	{
	}

	void Tunnel::Build (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		auto numHops = m_Config->GetNumHops ();
		const int numRecords = numHops <= STANDARD_NUM_RECORDS ? STANDARD_NUM_RECORDS : MAX_NUM_RECORDS;
		auto msg = numRecords <= STANDARD_NUM_RECORDS ? NewI2NPShortMessage () : NewI2NPMessage ();
		*msg->GetPayload () = numRecords;
		const size_t recordSize = m_Config->IsShort () ? SHORT_TUNNEL_BUILD_RECORD_SIZE : TUNNEL_BUILD_RECORD_SIZE;
		msg->len += numRecords*recordSize + 1;
		// shuffle records
		std::vector<int> recordIndicies;
		for (int i = 0; i < numRecords; i++) recordIndicies.push_back(i);
		std::shuffle (recordIndicies.begin(), recordIndicies.end(), std::mt19937(std::random_device()()));

		// create real records
		uint8_t * records = msg->GetPayload () + 1;
		TunnelHopConfig * hop = m_Config->GetFirstHop ();
		int i = 0;
		while (hop)
		{
			uint32_t msgID;
			if (hop->next) // we set replyMsgID for last hop only
				RAND_bytes ((uint8_t *)&msgID, 4);
			else
				msgID = replyMsgID;
			hop->recordIndex = recordIndicies[i]; i++;
			hop->CreateBuildRequestRecord (records, msgID);
			hop = hop->next;
		}
		// fill up fake records with random data
		for (int i = numHops; i < numRecords; i++)
		{
			int idx = recordIndicies[i];
			RAND_bytes (records + idx*recordSize, recordSize);
		}

		// decrypt real records
		hop = m_Config->GetLastHop ()->prev;
		while (hop)
		{
			// decrypt records after current hop
			TunnelHopConfig * hop1 = hop->next;
			while (hop1)
			{
				hop->DecryptRecord (records, hop1->recordIndex);
				hop1 = hop1->next;
			}
			hop = hop->prev;
		}
		msg->FillI2NPMessageHeader (m_Config->IsShort () ? eI2NPShortTunnelBuild : eI2NPVariableTunnelBuild);

		// send message
		if (outboundTunnel)
		{
			if (m_Config->IsShort ())
			{
				auto ident = m_Config->GetFirstHop () ? m_Config->GetFirstHop ()->ident : nullptr;
				if (ident && ident->GetIdentHash () != outboundTunnel->GetNextIdentHash ()) // don't encrypt if IBGW = OBEP
				{
					auto msg1 = i2p::garlic::WrapECIESX25519MessageForRouter (msg, ident->GetEncryptionPublicKey ());
					if (msg1) msg = msg1;
				}
			}
			outboundTunnel->SendTunnelDataMsg (GetNextIdentHash (), 0, msg);
		}
		else
		{
			if (m_Config->IsShort () && m_Config->GetLastHop () &&
				m_Config->GetLastHop ()->ident->GetIdentHash () != m_Config->GetLastHop ()->nextIdent)
			{
				// add garlic key/tag for reply
				uint8_t key[32];
				uint64_t tag = m_Config->GetLastHop ()->GetGarlicKey (key);
				if (m_Pool && m_Pool->GetLocalDestination ())
					m_Pool->GetLocalDestination ()->SubmitECIESx25519Key (key, tag);
				else
					i2p::context.AddECIESx25519Key (key, tag);
			}
			i2p::transport::transports.SendMessage (GetNextIdentHash (), msg);
		}
	}

	bool Tunnel::HandleTunnelBuildResponse (uint8_t * msg, size_t len)
	{
		LogPrint (eLogDebug, "Tunnel: TunnelBuildResponse ", (int)msg[0], " records.");

		TunnelHopConfig * hop = m_Config->GetLastHop ();
		while (hop)
		{
			// decrypt current hop
			if (hop->recordIndex >= 0 && hop->recordIndex < msg[0])
			{
				if (!hop->DecryptBuildResponseRecord (msg + 1))
					return false;
			}
			else
			{
				LogPrint (eLogWarning, "Tunnel: Hop index ", hop->recordIndex, " is out of range");
				return false;
			}

			// decrypt records before current hop
			TunnelHopConfig * hop1 = hop->prev;
			while (hop1)
			{
				auto idx = hop1->recordIndex;
				if (idx >= 0 && idx < msg[0])
					hop->DecryptRecord (msg + 1, idx);
				else
					LogPrint (eLogWarning, "Tunnel: Hop index ", idx, " is out of range");
				hop1 = hop1->prev;
			}
			hop = hop->prev;
		}

		bool established = true;
		size_t numHops = 0;
		hop = m_Config->GetFirstHop ();
		while (hop)
		{
			uint8_t ret = hop->GetRetCode (msg + 1);
			LogPrint (eLogDebug, "Tunnel: Build response ret code=", (int)ret);
			auto profile = i2p::data::netdb.FindRouterProfile (hop->ident->GetIdentHash ());
			if (profile)
				profile->TunnelBuildResponse (ret);
			if (ret)
				// if any of participants declined the tunnel is not established
				established = false;
			hop = hop->next;
			numHops++;
		}
		if (established)
		{
			// create tunnel decryptions from layer and iv keys in reverse order
			m_Hops.resize (numHops);
			hop = m_Config->GetLastHop ();
			int i = 0;
			while (hop)
			{
				m_Hops[i].ident = hop->ident;
				m_Hops[i].decryption.SetKeys (hop->layerKey, hop->ivKey);
				hop = hop->prev;
				i++;
			}
			m_IsShortBuildMessage = m_Config->IsShort ();
			m_FarEndTransports = m_Config->GetFarEndTransports ();
			m_Config = nullptr;
		}
		if (established) m_State = eTunnelStateEstablished;
		return established;
	}

	bool Tunnel::LatencyFitsRange(uint64_t lower, uint64_t upper) const
	{
		auto latency = GetMeanLatency();
		return latency >= lower && latency <= upper;
	}

	void Tunnel::EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out)
	{
		const uint8_t * inPayload = in->GetPayload () + 4;
		uint8_t * outPayload = out->GetPayload () + 4;
		for (auto& it: m_Hops)
		{
			it.decryption.Decrypt (inPayload, outPayload);
			inPayload = outPayload;
		}
	}

	void Tunnel::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		LogPrint (eLogWarning, "Tunnel: Can't send I2NP messages without delivery instructions");
	}

	std::vector<std::shared_ptr<const i2p::data::IdentityEx> > Tunnel::GetPeers () const
	{
		auto peers = GetInvertedPeers ();
		std::reverse (peers.begin (), peers.end ());
		return peers;
	}

	std::vector<std::shared_ptr<const i2p::data::IdentityEx> > Tunnel::GetInvertedPeers () const
	{
		// hops are in inverted order
		std::vector<std::shared_ptr<const i2p::data::IdentityEx> > ret;
		for (const auto& it: m_Hops)
			ret.push_back (it.ident);
		return ret;
	}

	void Tunnel::SetState(TunnelState state)
	{
		m_State = state;
	}

	void Tunnel::VisitTunnelHops(TunnelHopVisitor v)
	{
		// hops are in inverted order, we must return in direct order
		for (auto it = m_Hops.rbegin (); it != m_Hops.rend (); it++)
			v((*it).ident);
	}

	void InboundTunnel::HandleTunnelDataMsg (std::shared_ptr<I2NPMessage>&& msg)
	{
		if (IsFailed ()) SetState (eTunnelStateEstablished); // incoming messages means a tunnel is alive
		EncryptTunnelMsg (msg, msg);
		msg->from = shared_from_this ();
		m_Endpoint.HandleDecryptedTunnelDataMsg (msg);
	}

	ZeroHopsInboundTunnel::ZeroHopsInboundTunnel ():
		InboundTunnel (std::make_shared<ZeroHopsTunnelConfig> ()),
		m_NumReceivedBytes (0)
	{
	}

	void ZeroHopsInboundTunnel::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		if (msg)
		{
			m_NumReceivedBytes += msg->GetLength ();
			msg->from = shared_from_this ();
			HandleI2NPMessage (msg);
		}
	}

	void OutboundTunnel::SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, std::shared_ptr<i2p::I2NPMessage> msg)
	{
		TunnelMessageBlock block;
		if (gwHash)
		{
			block.hash = gwHash;
			if (gwTunnel)
			{
				block.deliveryType = eDeliveryTypeTunnel;
				block.tunnelID = gwTunnel;
			}
			else
				block.deliveryType = eDeliveryTypeRouter;
		}
		else
			block.deliveryType = eDeliveryTypeLocal;
		block.data = msg;

		SendTunnelDataMsg ({block});
	}

	void OutboundTunnel::SendTunnelDataMsg (const std::vector<TunnelMessageBlock>& msgs)
	{
		std::unique_lock<std::mutex> l(m_SendMutex);
		for (auto& it : msgs)
			m_Gateway.PutTunnelDataMsg (it);
		m_Gateway.SendBuffer ();
	}

	void OutboundTunnel::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		LogPrint (eLogError, "Tunnel: Incoming message for outbound tunnel ", GetTunnelID ());
	}

	ZeroHopsOutboundTunnel::ZeroHopsOutboundTunnel ():
		OutboundTunnel (std::make_shared<ZeroHopsTunnelConfig> ()),
		m_NumSentBytes (0)
	{
	}

	void ZeroHopsOutboundTunnel::SendTunnelDataMsg (const std::vector<TunnelMessageBlock>& msgs)
	{
		for (auto& msg : msgs)
		{
			if (!msg.data) continue;
			m_NumSentBytes += msg.data->GetLength ();
			switch (msg.deliveryType)
			{
				case eDeliveryTypeLocal:
					HandleI2NPMessage (msg.data);
				break;
				case eDeliveryTypeTunnel:
					i2p::transport::transports.SendMessage (msg.hash, i2p::CreateTunnelGatewayMsg (msg.tunnelID, msg.data));
				break;
				case eDeliveryTypeRouter:
					i2p::transport::transports.SendMessage (msg.hash, msg.data);
				break;
				default:
					LogPrint (eLogError, "Tunnel: Unknown delivery type ", (int)msg.deliveryType);
			}
		}
	}

	Tunnels tunnels;

	Tunnels::Tunnels (): m_IsRunning (false), m_Thread (nullptr),
		m_NumSuccesiveTunnelCreations (0), m_NumFailedTunnelCreations (0)
	{
	}

	Tunnels::~Tunnels ()
	{
	}

	std::shared_ptr<TunnelBase> Tunnels::GetTunnel (uint32_t tunnelID)
	{
		auto it = m_Tunnels.find(tunnelID);
		if (it != m_Tunnels.end ())
			return it->second;
		return nullptr;
	}

	std::shared_ptr<InboundTunnel> Tunnels::GetPendingInboundTunnel (uint32_t replyMsgID)
	{
		return GetPendingTunnel (replyMsgID, m_PendingInboundTunnels);
	}

	std::shared_ptr<OutboundTunnel> Tunnels::GetPendingOutboundTunnel (uint32_t replyMsgID)
	{
		return GetPendingTunnel (replyMsgID, m_PendingOutboundTunnels);
	}

	template<class TTunnel>
	std::shared_ptr<TTunnel> Tunnels::GetPendingTunnel (uint32_t replyMsgID, const std::map<uint32_t, std::shared_ptr<TTunnel> >& pendingTunnels)
	{
		auto it = pendingTunnels.find(replyMsgID);
		if (it != pendingTunnels.end () && it->second->GetState () == eTunnelStatePending)
		{
			it->second->SetState (eTunnelStateBuildReplyReceived);
			return it->second;
		}
		return nullptr;
	}

	std::shared_ptr<InboundTunnel> Tunnels::GetNextInboundTunnel ()
	{
		std::shared_ptr<InboundTunnel> tunnel;
		size_t minReceived = 0;
		for (const auto& it : m_InboundTunnels)
		{
			if (!it->IsEstablished ()) continue;
			if (!tunnel || it->GetNumReceivedBytes () < minReceived)
			{
				tunnel = it;
				minReceived = it->GetNumReceivedBytes ();
			}
		}
		return tunnel;
	}

	std::shared_ptr<OutboundTunnel> Tunnels::GetNextOutboundTunnel ()
	{
		if (m_OutboundTunnels.empty ()) return nullptr;
		uint32_t ind = rand () % m_OutboundTunnels.size (), i = 0;
		std::shared_ptr<OutboundTunnel> tunnel;
		for (const auto& it: m_OutboundTunnels)
		{
			if (it->IsEstablished ())
			{
				tunnel = it;
				i++;
			}
			if (i > ind && tunnel) break;
		}
		return tunnel;
	}

	std::shared_ptr<TunnelPool> Tunnels::CreateTunnelPool (int numInboundHops, int numOutboundHops,
		int numInboundTunnels, int numOutboundTunnels, int inboundVariance, int outboundVariance)
	{
		auto pool = std::make_shared<TunnelPool> (numInboundHops, numOutboundHops, numInboundTunnels, numOutboundTunnels, inboundVariance, outboundVariance);
		std::unique_lock<std::mutex> l(m_PoolsMutex);
		m_Pools.push_back (pool);
		return pool;
	}

	void Tunnels::DeleteTunnelPool (std::shared_ptr<TunnelPool> pool)
	{
		if (pool)
		{
			StopTunnelPool (pool);
			{
				std::unique_lock<std::mutex> l(m_PoolsMutex);
				m_Pools.remove (pool);
			}
		}
	}

	void Tunnels::StopTunnelPool (std::shared_ptr<TunnelPool> pool)
	{
		if (pool)
		{
			pool->SetActive (false);
			pool->DetachTunnels ();
		}
	}

	void Tunnels::AddTransitTunnel (std::shared_ptr<TransitTunnel> tunnel)
	{
		if (m_Tunnels.emplace (tunnel->GetTunnelID (), tunnel).second)
			m_TransitTunnels.push_back (tunnel);
		else
			LogPrint (eLogError, "Tunnel: Tunnel with id ", tunnel->GetTunnelID (), " already exists");
	}

	void Tunnels::Start ()
	{
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&Tunnels::Run, this));
	}

	void Tunnels::Stop ()
	{
		m_IsRunning = false;
		m_Queue.WakeUp ();
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = 0;
		}
	}

	void Tunnels::Run ()
	{
		i2p::util::SetThreadName("Tunnels");
		std::this_thread::sleep_for (std::chrono::seconds(1)); // wait for other parts are ready

		uint64_t lastTs = 0, lastPoolsTs = 0, lastMemoryPoolTs = 0;
		while (m_IsRunning)
		{
			try
			{
				auto msg = m_Queue.GetNextWithTimeout (1000); // 1 sec
				if (msg)
				{
					uint32_t prevTunnelID = 0, tunnelID = 0;
					std::shared_ptr<TunnelBase> prevTunnel;
					do
					{
						std::shared_ptr<TunnelBase> tunnel;
						uint8_t typeID = msg->GetTypeID ();
						switch (typeID)
						{
							case eI2NPTunnelData:
							case eI2NPTunnelGateway:
							{
								tunnelID = bufbe32toh (msg->GetPayload ());
								if (tunnelID == prevTunnelID)
									tunnel = prevTunnel;
								else if (prevTunnel)
									prevTunnel->FlushTunnelDataMsgs ();

								if (!tunnel)
									tunnel = GetTunnel (tunnelID);
								if (tunnel)
								{
									if (typeID == eI2NPTunnelData)
										tunnel->HandleTunnelDataMsg (std::move (msg));
									else // tunnel gateway assumed
										HandleTunnelGatewayMsg (tunnel, msg);
								}
								else
									LogPrint (eLogWarning, "Tunnel: Tunnel not found, tunnelID=", tunnelID, " previousTunnelID=", prevTunnelID, " type=", (int)typeID);

								break;
							}
							case eI2NPVariableTunnelBuild:
							case eI2NPVariableTunnelBuildReply:
							case eI2NPShortTunnelBuild:
							case eI2NPShortTunnelBuildReply:
							case eI2NPTunnelBuild:
							case eI2NPTunnelBuildReply:
								HandleI2NPMessage (msg->GetBuffer (), msg->GetLength ());
							break;
							default:
								LogPrint (eLogWarning, "Tunnel: Unexpected message type ", (int) typeID);
						}

						msg = m_Queue.Get ();
						if (msg)
						{
							prevTunnelID = tunnelID;
							prevTunnel = tunnel;
						}
						else if (tunnel)
							tunnel->FlushTunnelDataMsgs ();
					}
					while (msg);
				}

				if (i2p::transport::transports.IsOnline())
				{
					uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
					if (ts - lastTs >= 15) // manage tunnels every 15 seconds
					{
						ManageTunnels ();
						lastTs = ts;
					}
					if (ts - lastPoolsTs >= 5) // manage pools every 5 seconds
					{
						ManageTunnelPools (ts);
						lastPoolsTs = ts;
					}
					if (ts - lastMemoryPoolTs >= 120) // manage memory pool every 2 minutes
					{
						m_I2NPTunnelEndpointMessagesMemoryPool.CleanUpMt ();
						m_I2NPTunnelMessagesMemoryPool.CleanUpMt ();
						lastMemoryPoolTs = ts;
					}
				}
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Tunnel: Runtime exception: ", ex.what ());
			}
		}
	}

	void Tunnels::HandleTunnelGatewayMsg (std::shared_ptr<TunnelBase> tunnel, std::shared_ptr<I2NPMessage> msg)
	{
		if (!tunnel)
		{
			LogPrint (eLogError, "Tunnel: Missing tunnel for gateway");
			return;
		}
		const uint8_t * payload = msg->GetPayload ();
		uint16_t len = bufbe16toh(payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET);
		// we make payload as new I2NP message to send
		msg->offset += I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE;
		if (msg->offset + len > msg->len)
		{
			LogPrint (eLogError, "Tunnel: Gateway payload ", (int)len, " exceeds message length ", (int)msg->len);
			return;
		}
		msg->len = msg->offset + len;
		auto typeID = msg->GetTypeID ();
		LogPrint (eLogDebug, "Tunnel: Gateway of ", (int) len, " bytes for tunnel ", tunnel->GetTunnelID (), ", msg type ", (int)typeID);

		if (IsRouterInfoMsg (msg) || typeID == eI2NPDatabaseSearchReply)
			// transit DatabaseStore my contain new/updated RI
			// or DatabaseSearchReply with new routers
			i2p::data::netdb.PostI2NPMsg (CopyI2NPMessage (msg));
		tunnel->SendTunnelDataMsg (msg);
	}

	void Tunnels::ManageTunnels ()
	{
		ManagePendingTunnels ();
		ManageInboundTunnels ();
		ManageOutboundTunnels ();
		ManageTransitTunnels ();
	}

	void Tunnels::ManagePendingTunnels ()
	{
		ManagePendingTunnels (m_PendingInboundTunnels);
		ManagePendingTunnels (m_PendingOutboundTunnels);
	}

	template<class PendingTunnels>
	void Tunnels::ManagePendingTunnels (PendingTunnels& pendingTunnels)
	{
		// check pending tunnel. delete failed or timeout
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		for (auto it = pendingTunnels.begin (); it != pendingTunnels.end ();)
		{
			auto tunnel = it->second;
			switch (tunnel->GetState ())
			{
				case eTunnelStatePending:
					if (ts > tunnel->GetCreationTime () + TUNNEL_CREATION_TIMEOUT)
					{
						LogPrint (eLogDebug, "Tunnel: Pending build request ", it->first, " timeout, deleted");
						// update stats
						auto config = tunnel->GetTunnelConfig ();
						if (config)
						{
							auto hop = config->GetFirstHop ();
							while (hop)
							{
								if (hop->ident)
								{
									auto profile = i2p::data::netdb.FindRouterProfile (hop->ident->GetIdentHash ());
									if (profile)
										profile->TunnelNonReplied ();
								}
								hop = hop->next;
							}
						}
						// delete
						it = pendingTunnels.erase (it);
						m_NumFailedTunnelCreations++;
					}
					else
						++it;
				break;
				case eTunnelStateBuildFailed:
					LogPrint (eLogDebug, "Tunnel: Pending build request ", it->first, " failed, deleted");
					it = pendingTunnels.erase (it);
					m_NumFailedTunnelCreations++;
				break;
				case eTunnelStateBuildReplyReceived:
					// intermediate state, will be either established of build failed
					++it;
				break;
				default:
					// success
					it = pendingTunnels.erase (it);
					m_NumSuccesiveTunnelCreations++;
			}
		}
	}

	void Tunnels::ManageOutboundTunnels ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		{
			for (auto it = m_OutboundTunnels.begin (); it != m_OutboundTunnels.end ();)
			{
				auto tunnel = *it;
				if (ts > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
				{
					LogPrint (eLogDebug, "Tunnel: Tunnel with id ", tunnel->GetTunnelID (), " expired");
					auto pool = tunnel->GetTunnelPool ();
					if (pool)
						pool->TunnelExpired (tunnel);
					// we don't have outbound tunnels in m_Tunnels
					it = m_OutboundTunnels.erase (it);
				}
				else
				{
					if (tunnel->IsEstablished ())
					{
						if (!tunnel->IsRecreated () && ts + TUNNEL_RECREATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
						{
							auto pool = tunnel->GetTunnelPool ();
							// let it die if the tunnel pool has been reconfigured and this is old
							if (pool && tunnel->GetNumHops() == pool->GetNumOutboundHops())
							{
								tunnel->SetRecreated (true);
								pool->RecreateOutboundTunnel (tunnel);
							}
						}
						if (ts + TUNNEL_EXPIRATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
							tunnel->SetState (eTunnelStateExpiring);
					}
					++it;
				}
			}
		}

		if (m_OutboundTunnels.size () < 3)
		{
			// trying to create one more oubound tunnel
			auto inboundTunnel = GetNextInboundTunnel ();
			auto router = i2p::transport::transports.RoutesRestricted() ?
				i2p::transport::transports.GetRestrictedPeer() :
				i2p::data::netdb.GetRandomRouter (i2p::context.GetSharedRouterInfo (), false); // reachable by us
			if (!inboundTunnel || !router) return;
			LogPrint (eLogDebug, "Tunnel: Creating one hop outbound tunnel");
			CreateTunnel<OutboundTunnel> (
				std::make_shared<TunnelConfig> (std::vector<std::shared_ptr<const i2p::data::IdentityEx> > { router->GetRouterIdentity () },
					inboundTunnel->GetNextTunnelID (), inboundTunnel->GetNextIdentHash (), false), nullptr
			);
		}
	}

	void Tunnels::ManageInboundTunnels ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		{
			for (auto it = m_InboundTunnels.begin (); it != m_InboundTunnels.end ();)
			{
				auto tunnel = *it;
				if (ts > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
				{
					LogPrint (eLogDebug, "Tunnel: Tunnel with id ", tunnel->GetTunnelID (), " expired");
					auto pool = tunnel->GetTunnelPool ();
					if (pool)
						pool->TunnelExpired (tunnel);
					m_Tunnels.erase (tunnel->GetTunnelID ());
					it = m_InboundTunnels.erase (it);
				}
				else
				{
					if (tunnel->IsEstablished ())
					{
						if (!tunnel->IsRecreated () && ts + TUNNEL_RECREATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
						{
							auto pool = tunnel->GetTunnelPool ();
							// let it die if the tunnel pool was reconfigured and has different number of hops
							if (pool && tunnel->GetNumHops() == pool->GetNumInboundHops())
							{
								tunnel->SetRecreated (true);
								pool->RecreateInboundTunnel (tunnel);
							}
						}

						if (ts + TUNNEL_EXPIRATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
							tunnel->SetState (eTunnelStateExpiring);
						else // we don't need to cleanup expiring tunnels
							tunnel->Cleanup ();
					}
					it++;
				}
			}
		}

		if (m_InboundTunnels.empty ())
		{
			LogPrint (eLogDebug, "Tunnel: Creating zero hops inbound tunnel");
			CreateZeroHopsInboundTunnel (nullptr);
			CreateZeroHopsOutboundTunnel (nullptr);
			if (!m_ExploratoryPool)
			{
				int ibLen; i2p::config::GetOption("exploratory.inbound.length", ibLen);
				int obLen; i2p::config::GetOption("exploratory.outbound.length", obLen);
				int ibNum; i2p::config::GetOption("exploratory.inbound.quantity", ibNum);
				int obNum; i2p::config::GetOption("exploratory.outbound.quantity", obNum);
				m_ExploratoryPool = CreateTunnelPool (ibLen, obLen, ibNum, obNum, 0, 0);
				m_ExploratoryPool->SetLocalDestination (i2p::context.GetSharedDestination ());
			}
			return;
		}

		if (m_OutboundTunnels.empty () || m_InboundTunnels.size () < 3)
		{
			// trying to create one more inbound tunnel
			auto router = i2p::transport::transports.RoutesRestricted() ?
				i2p::transport::transports.GetRestrictedPeer() :
				// should be reachable by us because we send build request directly
				i2p::data::netdb.GetRandomRouter (i2p::context.GetSharedRouterInfo (), false);
			if (!router) {
				LogPrint (eLogWarning, "Tunnel: Can't find any router, skip creating tunnel");
				return;
			}
			LogPrint (eLogDebug, "Tunnel: Creating one hop inbound tunnel");
			CreateTunnel<InboundTunnel> (
				std::make_shared<TunnelConfig> (std::vector<std::shared_ptr<const i2p::data::IdentityEx> > { router->GetRouterIdentity () }, false), nullptr
			);
		}
	}

	void Tunnels::ManageTransitTunnels ()
	{
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		for (auto it = m_TransitTunnels.begin (); it != m_TransitTunnels.end ();)
		{
			auto tunnel = *it;
			if (ts > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
			{
				LogPrint (eLogDebug, "Tunnel: Transit tunnel with id ", tunnel->GetTunnelID (), " expired");
				m_Tunnels.erase (tunnel->GetTunnelID ());
				it = m_TransitTunnels.erase (it);
			}
			else
			{
				tunnel->Cleanup ();
				it++;
			}
		}
	}

	void Tunnels::ManageTunnelPools (uint64_t ts)
	{
		std::unique_lock<std::mutex> l(m_PoolsMutex);
		for (auto& pool : m_Pools)
		{
			if (pool && pool->IsActive ())
				pool->ManageTunnels (ts);
		}
	}

	void Tunnels::PostTunnelData (std::shared_ptr<I2NPMessage> msg)
	{
		if (msg) m_Queue.Put (msg);
	}

	void Tunnels::PostTunnelData (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		m_Queue.Put (msgs);
	}

	template<class TTunnel>
	std::shared_ptr<TTunnel> Tunnels::CreateTunnel (std::shared_ptr<TunnelConfig> config,
		std::shared_ptr<TunnelPool> pool, std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		auto newTunnel = std::make_shared<TTunnel> (config);
		newTunnel->SetTunnelPool (pool);
		uint32_t replyMsgID;
		RAND_bytes ((uint8_t *)&replyMsgID, 4);
		AddPendingTunnel (replyMsgID, newTunnel);
		newTunnel->Build (replyMsgID, outboundTunnel);
		return newTunnel;
	}

	std::shared_ptr<InboundTunnel> Tunnels::CreateInboundTunnel (std::shared_ptr<TunnelConfig> config,
		std::shared_ptr<TunnelPool> pool, std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		if (config)
			return CreateTunnel<InboundTunnel>(config, pool, outboundTunnel);
		else
			return CreateZeroHopsInboundTunnel (pool);
	}

	std::shared_ptr<OutboundTunnel> Tunnels::CreateOutboundTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<TunnelPool> pool)
	{
		if (config)
			return CreateTunnel<OutboundTunnel>(config, pool);
		else
			return CreateZeroHopsOutboundTunnel (pool);
	}

	void Tunnels::AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<InboundTunnel> tunnel)
	{
		m_PendingInboundTunnels[replyMsgID] = tunnel;
	}

	void Tunnels::AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> tunnel)
	{
		m_PendingOutboundTunnels[replyMsgID] = tunnel;
	}

	void Tunnels::AddOutboundTunnel (std::shared_ptr<OutboundTunnel> newTunnel)
	{
		// we don't need to insert it to m_Tunnels
		m_OutboundTunnels.push_back (newTunnel);
		auto pool = newTunnel->GetTunnelPool ();
		if (pool && pool->IsActive ())
			pool->TunnelCreated (newTunnel);
		else
			newTunnel->SetTunnelPool (nullptr);
	}

	void Tunnels::AddInboundTunnel (std::shared_ptr<InboundTunnel> newTunnel)
	{
		if (m_Tunnels.emplace (newTunnel->GetTunnelID (), newTunnel).second)
		{
			m_InboundTunnels.push_back (newTunnel);
			auto pool = newTunnel->GetTunnelPool ();
			if (!pool)
			{
				// build symmetric outbound tunnel
				CreateTunnel<OutboundTunnel> (std::make_shared<TunnelConfig>(newTunnel->GetInvertedPeers (),
						newTunnel->GetNextTunnelID (), newTunnel->GetNextIdentHash (), false), nullptr,
					GetNextOutboundTunnel ());
			}
			else
			{
				if (pool->IsActive ())
					pool->TunnelCreated (newTunnel);
				else
					newTunnel->SetTunnelPool (nullptr);
			}
		}
		else
			LogPrint (eLogError, "Tunnel: Tunnel with id ", newTunnel->GetTunnelID (), " already exists");
	}


	std::shared_ptr<ZeroHopsInboundTunnel> Tunnels::CreateZeroHopsInboundTunnel (std::shared_ptr<TunnelPool> pool)
	{
		auto inboundTunnel = std::make_shared<ZeroHopsInboundTunnel> ();
		inboundTunnel->SetTunnelPool (pool);
		inboundTunnel->SetState (eTunnelStateEstablished);
		m_InboundTunnels.push_back (inboundTunnel);
		m_Tunnels[inboundTunnel->GetTunnelID ()] = inboundTunnel;
		return inboundTunnel;
	}

	std::shared_ptr<ZeroHopsOutboundTunnel> Tunnels::CreateZeroHopsOutboundTunnel (std::shared_ptr<TunnelPool> pool)
	{
		auto outboundTunnel = std::make_shared<ZeroHopsOutboundTunnel> ();
		outboundTunnel->SetTunnelPool (pool);
		outboundTunnel->SetState (eTunnelStateEstablished);
		m_OutboundTunnels.push_back (outboundTunnel);
		// we don't insert into m_Tunnels
		return outboundTunnel;
	}

	std::shared_ptr<I2NPMessage> Tunnels::NewI2NPTunnelMessage (bool endpoint)
	{
		if (endpoint)
		{
			// should fit two tunnel message + tunnel gateway header, enough for one garlic encrypted streaming packet
			auto msg = m_I2NPTunnelEndpointMessagesMemoryPool.AcquireSharedMt ();
			msg->Align (6);
			msg->offset += TUNNEL_GATEWAY_HEADER_SIZE; // reserve room for TunnelGateway header
			return msg;
		}
		else
		{
			auto msg = m_I2NPTunnelMessagesMemoryPool.AcquireSharedMt ();
			msg->Align (12);
			return msg;
		}
	}

	int Tunnels::GetTransitTunnelsExpirationTimeout ()
	{
		int timeout = 0;
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		// TODO: possible race condition with I2PControl
		for (const auto& it : m_TransitTunnels)
		{
			int t = it->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT - ts;
			if (t > timeout) timeout = t;
		}
		return timeout;
	}

	size_t Tunnels::CountTransitTunnels() const
	{
		// TODO: locking
		return m_TransitTunnels.size();
	}

	size_t Tunnels::CountInboundTunnels() const
	{
		// TODO: locking
		return m_InboundTunnels.size();
	}

	size_t Tunnels::CountOutboundTunnels() const
	{
		// TODO: locking
		return m_OutboundTunnels.size();
	}
}
}
