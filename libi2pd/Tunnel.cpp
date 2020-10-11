/*
* Copyright (c) 2013-2020, The PurpleI2P Project
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

namespace i2p
{
namespace tunnel
{
	Tunnel::Tunnel (std::shared_ptr<const TunnelConfig> config):
		TunnelBase (config->GetTunnelID (), config->GetNextTunnelID (), config->GetNextIdentHash ()),
		m_Config (config), m_Pool (nullptr), m_State (eTunnelStatePending), m_IsRecreated (false),
		m_Latency (0)
	{
	}

	Tunnel::~Tunnel ()
	{
	}

	void Tunnel::Build (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		auto numHops = m_Config->GetNumHops ();
		int numRecords = numHops <= STANDARD_NUM_RECORDS ? STANDARD_NUM_RECORDS : numHops;
		auto msg = NewI2NPShortMessage ();
		*msg->GetPayload () = numRecords;
		msg->len += numRecords*TUNNEL_BUILD_RECORD_SIZE + 1;
		// shuffle records
		std::vector<int> recordIndicies;
		for (int i = 0; i < numRecords; i++) recordIndicies.push_back(i);
		std::shuffle (recordIndicies.begin(), recordIndicies.end(), std::mt19937(std::random_device()()));

		// create real records
		uint8_t * records = msg->GetPayload () + 1;
		TunnelHopConfig * hop = m_Config->GetFirstHop ();
		int i = 0;
		BN_CTX * ctx = BN_CTX_new ();
		while (hop)
		{
			uint32_t msgID;
			if (hop->next) // we set replyMsgID for last hop only
				RAND_bytes ((uint8_t *)&msgID, 4);
			else
				msgID = replyMsgID;
			int idx = recordIndicies[i];
			hop->CreateBuildRequestRecord (records + idx*TUNNEL_BUILD_RECORD_SIZE, msgID, ctx);
			hop->recordIndex = idx;
			i++;
			hop = hop->next;
		}
		BN_CTX_free (ctx);
		// fill up fake records with random data
		for (int i = numHops; i < numRecords; i++)
		{
			int idx = recordIndicies[i];
			RAND_bytes (records + idx*TUNNEL_BUILD_RECORD_SIZE, TUNNEL_BUILD_RECORD_SIZE);
		}

		// decrypt real records
		i2p::crypto::CBCDecryption decryption;
		hop = m_Config->GetLastHop ()->prev;
		while (hop)
		{
			decryption.SetKey (hop->replyKey);
			// decrypt records after current hop
			TunnelHopConfig * hop1 = hop->next;
			while (hop1)
			{
				decryption.SetIV (hop->replyIV);
				uint8_t * record = records + hop1->recordIndex*TUNNEL_BUILD_RECORD_SIZE;
				decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
				hop1 = hop1->next;
			}
			hop = hop->prev;
		}
		msg->FillI2NPMessageHeader (eI2NPVariableTunnelBuild);

		// send message
		if (outboundTunnel)
			outboundTunnel->SendTunnelDataMsg (GetNextIdentHash (), 0, msg);
		else
			i2p::transport::transports.SendMessage (GetNextIdentHash (), msg);
	}

	bool Tunnel::HandleTunnelBuildResponse (uint8_t * msg, size_t len)
	{
		LogPrint (eLogDebug, "Tunnel: TunnelBuildResponse ", (int)msg[0], " records.");

		i2p::crypto::CBCDecryption decryption;
		TunnelHopConfig * hop = m_Config->GetLastHop ();
		while (hop)
		{
			decryption.SetKey (hop->replyKey);
			// decrypt records before and including current hop
			TunnelHopConfig * hop1 = hop;
			while (hop1)
			{
				auto idx = hop1->recordIndex;
				if (idx >= 0 && idx < msg[0])
				{
					uint8_t * record = msg + 1 + idx*TUNNEL_BUILD_RECORD_SIZE;
					decryption.SetIV (hop->replyIV);
					decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
				}
				else
					LogPrint (eLogWarning, "Tunnel: hop index ", idx, " is out of range");
				hop1 = hop1->prev;
			}
			hop = hop->prev;
		}

		bool established = true;
		hop = m_Config->GetFirstHop ();
		while (hop)
		{
			const uint8_t * record = msg + 1 + hop->recordIndex*TUNNEL_BUILD_RECORD_SIZE;
			uint8_t ret = record[BUILD_RESPONSE_RECORD_RET_OFFSET];
			LogPrint (eLogDebug, "Tunnel: Build response ret code=", (int)ret);
			auto profile = i2p::data::netdb.FindRouterProfile (hop->ident->GetIdentHash ());
			if (profile)
				profile->TunnelBuildResponse (ret);
			if (ret)
				// if any of participants declined the tunnel is not established
				established = false;
			hop = hop->next;
		}
		if (established)
		{
			// create tunnel decryptions from layer and iv keys in reverse order
			hop = m_Config->GetLastHop ();
			while (hop)
			{
				auto tunnelHop = new TunnelHop;
				tunnelHop->ident = hop->ident;
				tunnelHop->decryption.SetKeys (hop->layerKey, hop->ivKey);
				m_Hops.push_back (std::unique_ptr<TunnelHop>(tunnelHop));
				hop = hop->prev;
			}
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
			it->decryption.Decrypt (inPayload, outPayload);
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
		for (auto& it: m_Hops)
			ret.push_back (it->ident);
		return ret;
	}

	void Tunnel::SetState(TunnelState state)
	{
		m_State = state;
	}


	void Tunnel::PrintHops (std::stringstream& s) const
	{
		// hops are in inverted order, we must print in direct order
		for (auto it = m_Hops.rbegin (); it != m_Hops.rend (); it++)
		{
			s << " &#8658; ";
			s << i2p::data::GetIdentHashAbbreviation ((*it)->ident->GetIdentHash ());
		}
	}

	void InboundTunnel::HandleTunnelDataMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		if (IsFailed ()) SetState (eTunnelStateEstablished); // incoming messages means a tunnel is alive
		auto newMsg = CreateEmptyTunnelDataMsg ();
		EncryptTunnelMsg (msg, newMsg);
		newMsg->from = shared_from_this ();
		m_Endpoint.HandleDecryptedTunnelDataMsg (newMsg);
	}

	void InboundTunnel::Print (std::stringstream& s) const
	{
		PrintHops (s);
		s << " &#8658; " << GetTunnelID () << ":me";
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

	void ZeroHopsInboundTunnel::Print (std::stringstream& s) const
	{
		s << " &#8658; " << GetTunnelID () << ":me";
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

	void OutboundTunnel::HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg)
	{
		LogPrint (eLogError, "Tunnel: incoming message for outbound tunnel ", GetTunnelID ());
	}

	void OutboundTunnel::Print (std::stringstream& s) const
	{
		s << GetTunnelID () << ":me";
		PrintHops (s);
		s << " &#8658; ";
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
			switch (msg.deliveryType)
			{
				case eDeliveryTypeLocal:
					i2p::HandleI2NPMessage (msg.data);
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

	void ZeroHopsOutboundTunnel::Print (std::stringstream& s) const
	{
		s << GetTunnelID () << ":me &#8658; ";
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

	std::shared_ptr<TunnelPool> Tunnels::CreateTunnelPool (int numInboundHops,
		int numOutboundHops, int numInboundTunnels, int numOutboundTunnels)
	{
		auto pool = std::make_shared<TunnelPool> (numInboundHops, numOutboundHops, numInboundTunnels, numOutboundTunnels);
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
			LogPrint (eLogError, "Tunnel: tunnel with id ", tunnel->GetTunnelID (), " already exists");
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
		std::this_thread::sleep_for (std::chrono::seconds(1)); // wait for other parts are ready

		uint64_t lastTs = 0;
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
										tunnel->HandleTunnelDataMsg (msg);
									else // tunnel gateway assumed
										HandleTunnelGatewayMsg (tunnel, msg);
								}
								else
									LogPrint (eLogWarning, "Tunnel: tunnel not found, tunnelID=", tunnelID, " previousTunnelID=", prevTunnelID, " type=", (int)typeID);

								break;
							}
							case eI2NPVariableTunnelBuild:
							case eI2NPVariableTunnelBuildReply:
							case eI2NPTunnelBuild:
							case eI2NPTunnelBuildReply:
								HandleI2NPMessage (msg->GetBuffer (), msg->GetLength ());
							break;
							default:
								LogPrint (eLogWarning, "Tunnel: unexpected message type ", (int) typeID);
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

				uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
				if (ts - lastTs >= 15) // manage tunnels every 15 seconds
				{
					ManageTunnels ();
					lastTs = ts;
				}
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Tunnel: runtime exception: ", ex.what ());
			}
		}
	}

	void Tunnels::HandleTunnelGatewayMsg (std::shared_ptr<TunnelBase> tunnel, std::shared_ptr<I2NPMessage> msg)
	{
		if (!tunnel)
		{
			LogPrint (eLogError, "Tunnel: missing tunnel for gateway");
			return;
		}
		const uint8_t * payload = msg->GetPayload ();
		uint16_t len = bufbe16toh(payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET);
		// we make payload as new I2NP message to send
		msg->offset += I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE;
		if (msg->offset + len > msg->len)
		{
			LogPrint (eLogError, "Tunnel: gateway payload ", (int)len, " exceeds message length ", (int)msg->len);
			return;
		}
		msg->len = msg->offset + len;
		auto typeID = msg->GetTypeID ();
		LogPrint (eLogDebug, "Tunnel: gateway of ", (int) len, " bytes for tunnel ", tunnel->GetTunnelID (), ", msg type ", (int)typeID);

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
		ManageTunnelPools ();
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
						LogPrint (eLogDebug, "Tunnel: pending build request ", it->first, " timeout, deleted");
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
					LogPrint (eLogDebug, "Tunnel: pending build request ", it->first, " failed, deleted");
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
					LogPrint (eLogDebug, "Tunnel: tunnel with id ", tunnel->GetTunnelID (), " expired");
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
								tunnel->SetIsRecreated ();
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
				i2p::data::netdb.GetRandomRouter ();
			if (!inboundTunnel || !router) return;
			LogPrint (eLogDebug, "Tunnel: creating one hop outbound tunnel");
			CreateTunnel<OutboundTunnel> (
				std::make_shared<TunnelConfig> (std::vector<std::shared_ptr<const i2p::data::IdentityEx> > { router->GetRouterIdentity () },
					inboundTunnel->GetNextTunnelID (), inboundTunnel->GetNextIdentHash ())
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
					LogPrint (eLogDebug, "Tunnel: tunnel with id ", tunnel->GetTunnelID (), " expired");
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
								tunnel->SetIsRecreated ();
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
			CreateZeroHopsInboundTunnel ();
			CreateZeroHopsOutboundTunnel ();
			if (!m_ExploratoryPool)
			{
				int ibLen; i2p::config::GetOption("exploratory.inbound.length", ibLen);
				int obLen; i2p::config::GetOption("exploratory.outbound.length", obLen);
				int ibNum; i2p::config::GetOption("exploratory.inbound.quantity", ibNum);
				int obNum; i2p::config::GetOption("exploratory.outbound.quantity", obNum);
				m_ExploratoryPool = CreateTunnelPool (ibLen, obLen, ibNum, obNum);
				m_ExploratoryPool->SetLocalDestination (i2p::context.GetSharedDestination ());
			}
			return;
		}

		if (m_OutboundTunnels.empty () || m_InboundTunnels.size () < 3)
		{
			// trying to create one more inbound tunnel
			auto router = i2p::transport::transports.RoutesRestricted() ?
				i2p::transport::transports.GetRestrictedPeer() :
				i2p::data::netdb.GetRandomRouter ();
			if (!router) {
				LogPrint (eLogWarning, "Tunnel: can't find any router, skip creating tunnel");
				return;
			}
			LogPrint (eLogDebug, "Tunnel: creating one hop inbound tunnel");
			CreateTunnel<InboundTunnel> (
				std::make_shared<TunnelConfig> (std::vector<std::shared_ptr<const i2p::data::IdentityEx> > { router->GetRouterIdentity () })
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

	void Tunnels::ManageTunnelPools ()
	{
		std::unique_lock<std::mutex> l(m_PoolsMutex);
		for (auto& pool : m_Pools)
		{
			if (pool && pool->IsActive ())
			{
				pool->CreateTunnels ();
				pool->TestTunnels ();
			}
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
	std::shared_ptr<TTunnel> Tunnels::CreateTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		auto newTunnel = std::make_shared<TTunnel> (config);
		uint32_t replyMsgID;
		RAND_bytes ((uint8_t *)&replyMsgID, 4);
		AddPendingTunnel (replyMsgID, newTunnel);
		newTunnel->Build (replyMsgID, outboundTunnel);
		return newTunnel;
	}

	std::shared_ptr<InboundTunnel> Tunnels::CreateInboundTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		if (config)
			return CreateTunnel<InboundTunnel>(config, outboundTunnel);
		else
			return CreateZeroHopsInboundTunnel ();
	}

	std::shared_ptr<OutboundTunnel> Tunnels::CreateOutboundTunnel (std::shared_ptr<TunnelConfig> config)
	{
		if (config)
			return CreateTunnel<OutboundTunnel>(config);
		else
			return CreateZeroHopsOutboundTunnel ();
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
						newTunnel->GetNextTunnelID (), newTunnel->GetNextIdentHash ()),
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
			LogPrint (eLogError, "Tunnel: tunnel with id ", newTunnel->GetTunnelID (), " already exists");
	}


	std::shared_ptr<ZeroHopsInboundTunnel> Tunnels::CreateZeroHopsInboundTunnel ()
	{
		auto inboundTunnel = std::make_shared<ZeroHopsInboundTunnel> ();
		inboundTunnel->SetState (eTunnelStateEstablished);
		m_InboundTunnels.push_back (inboundTunnel);
		m_Tunnels[inboundTunnel->GetTunnelID ()] = inboundTunnel;
		return inboundTunnel;
	}

	std::shared_ptr<ZeroHopsOutboundTunnel> Tunnels::CreateZeroHopsOutboundTunnel ()
	{
		auto outboundTunnel = std::make_shared<ZeroHopsOutboundTunnel> ();
		outboundTunnel->SetState (eTunnelStateEstablished);
		m_OutboundTunnels.push_back (outboundTunnel);
		// we don't insert into m_Tunnels
		return outboundTunnel;
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
