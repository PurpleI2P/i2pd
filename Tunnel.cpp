#include <string.h>
#include "I2PEndian.h"
#include <thread>
#include <algorithm>
#include <vector> 
#include <openssl/rand.h>
#include "RouterContext.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "NetDb.h"
#include "Tunnel.h"

namespace i2p
{	
namespace tunnel
{		
	
	Tunnel::Tunnel (std::shared_ptr<const TunnelConfig> config): 
		TunnelBase (config->GetTunnelID (), config->GetNextTunnelID (), config->GetNextIdentHash ()),
		m_Config (config), m_Pool (nullptr), m_State (eTunnelStatePending), m_IsRecreated (false)
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
		std::random_shuffle (recordIndicies.begin(), recordIndicies.end());

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
			int idx = recordIndicies[i];
			hop->CreateBuildRequestRecord (records + idx*TUNNEL_BUILD_RECORD_SIZE, msgID); 
			hop->recordIndex = idx; 
			i++;
			hop = hop->next;
		}	
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

	void Tunnel::PrintHops (std::stringstream& s) const
	{
		for (auto& it: m_Hops)
		{	
			s << " ⇒ ";
			s << i2p::data::GetIdentHashAbbreviation (it->ident->GetIdentHash ());
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
		s << " ⇒ " << GetTunnelID () << ":me";
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
		
		std::unique_lock<std::mutex> l(m_SendMutex);
		m_Gateway.SendTunnelDataMsg (block);
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
		s << " ⇒ ";
	}	
		
	Tunnels tunnels;
	
	Tunnels::Tunnels (): m_IsRunning (false), m_Thread (nullptr),
		m_NumSuccesiveTunnelCreations (0), m_NumFailedTunnelCreations (0)
	{
	}
	
	Tunnels::~Tunnels ()	
	{
		for (auto& it : m_TransitTunnels)
			delete it.second;
		m_TransitTunnels.clear ();
	}	
	
	std::shared_ptr<InboundTunnel> Tunnels::GetInboundTunnel (uint32_t tunnelID)
	{
		auto it = m_InboundTunnels.find(tunnelID);
		if (it != m_InboundTunnels.end ())
			return it->second;
		return nullptr;
	}	
	
	TransitTunnel * Tunnels::GetTransitTunnel (uint32_t tunnelID)
	{
		auto it = m_TransitTunnels.find(tunnelID);
		if (it != m_TransitTunnels.end ())
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
		for (auto it : m_InboundTunnels)
		{
			if (!it.second->IsEstablished ()) continue;
			if (!tunnel || it.second->GetNumReceivedBytes () < minReceived)
			{
				tunnel = it.second;
				minReceived = it.second->GetNumReceivedBytes ();
			}
		}			
		return tunnel;
	}
	
	std::shared_ptr<OutboundTunnel> Tunnels::GetNextOutboundTunnel ()
	{
		if (!m_OutboundTunnels.size ()) return nullptr;
		uint32_t ind = rand () % m_OutboundTunnels.size (), i = 0;
		std::shared_ptr<OutboundTunnel> tunnel;
		for (auto it: m_OutboundTunnels)
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
		
	void Tunnels::AddTransitTunnel (TransitTunnel * tunnel)
	{
		std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
		if (!m_TransitTunnels.insert (std::make_pair (tunnel->GetTunnelID (), tunnel)).second)
		{	
			LogPrint (eLogError, "Tunnel: transit tunnel with id ", tunnel->GetTunnelID (), " already exists");
			delete tunnel;
		}
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
					TunnelBase * prevTunnel = nullptr; 
					do
					{
						TunnelBase * tunnel = nullptr;
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
						
								if (!tunnel && typeID == eI2NPTunnelData)
									tunnel = GetInboundTunnel (tunnelID).get ();
								if (!tunnel)
									tunnel = GetTransitTunnel (tunnelID);
								if (tunnel)
								{
									if (typeID == eI2NPTunnelData)
										tunnel->HandleTunnelDataMsg (msg);
									else // tunnel gateway assumed
										HandleTunnelGatewayMsg (tunnel, msg);
								}
								else		
									LogPrint (eLogWarning, "Tunnel: tunnel with id ", tunnelID, " not found");
								break;
							}	
							case eI2NPVariableTunnelBuild:		
							case eI2NPVariableTunnelBuildReply:
							case eI2NPTunnelBuild:
							case eI2NPTunnelBuildReply:	
								HandleI2NPMessage (msg->GetBuffer (), msg->GetLength ());
							break;	
							default:
								LogPrint (eLogError, "Tunnel: unexpected messsage type ", (int) typeID);
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

	void Tunnels::HandleTunnelGatewayMsg (TunnelBase * tunnel, std::shared_ptr<I2NPMessage> msg)
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
		msg->len = msg->offset + len;
		auto typeID = msg->GetTypeID ();
		LogPrint (eLogDebug, "Tunnel: gateway of ", (int) len, " bytes for tunnel ", tunnel->GetTunnelID (), ", msg type ", (int)typeID);
			
		if (IsRouterInfoMsg (msg) || typeID == eI2NPDatabaseSearchReply)
			// transit DatabaseStore my contain new/updated RI 
			// or DatabaseSearchReply with new routers
			i2p::data::netdb.PostI2NPMsg (msg);	
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
						LogPrint (eLogWarning, "Tunnel: pending build request ", it->first, " timeout, deleted");
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
						it++;
				break;
				case eTunnelStateBuildFailed:
					LogPrint (eLogError, "Tunnel: pending build request ", it->first, " failed, deleted");
					it = pendingTunnels.erase (it);
					m_NumFailedTunnelCreations++;
				break;
				case eTunnelStateBuildReplyReceived:
					// intermediate state, will be either established of build failed
					it++;
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
					it = m_OutboundTunnels.erase (it);
				}	
				else 
				{
					if (tunnel->IsEstablished ())
					{	
						if (!tunnel->IsRecreated () && ts + TUNNEL_RECREATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
						{
							tunnel->SetIsRecreated ();	
							auto pool = tunnel->GetTunnelPool ();
							if (pool)
								pool->RecreateOutboundTunnel (tunnel);
						}
						if (ts + TUNNEL_EXPIRATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
							tunnel->SetState (eTunnelStateExpiring);
					}	
					it++;
				}
			}
		}	
	
		if (m_OutboundTunnels.size () < 5) 
		{
			// trying to create one more oubound tunnel
			auto inboundTunnel = GetNextInboundTunnel ();
			auto router = i2p::data::netdb.GetRandomRouter ();
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
				auto tunnel = it->second;
				if (ts > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
				{
					LogPrint (eLogDebug, "Tunnel: tunnel with id ", tunnel->GetTunnelID (), " expired");
					auto pool = tunnel->GetTunnelPool ();
					if (pool)
						pool->TunnelExpired (tunnel);
					it = m_InboundTunnels.erase (it);
				}	
				else 
				{
					if (tunnel->IsEstablished ())
					{	
						if (!tunnel->IsRecreated () && ts + TUNNEL_RECREATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
						{
							tunnel->SetIsRecreated ();	
							auto pool = tunnel->GetTunnelPool ();
							if (pool)
								pool->RecreateInboundTunnel (tunnel);
						}
	
						if (ts + TUNNEL_EXPIRATION_THRESHOLD > tunnel->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
							tunnel->SetState (eTunnelStateExpiring);
					}	
					it++;
				}
			}
		}	

		if (m_InboundTunnels.empty ())
		{
			LogPrint (eLogDebug, "Tunnel: Creating zero hops inbound tunnel");
			CreateZeroHopsInboundTunnel ();
			if (!m_ExploratoryPool)
			{
				m_ExploratoryPool = CreateTunnelPool (2, 2, 5, 5); // 2-hop exploratory, 5 tunnels
				m_ExploratoryPool->SetLocalDestination (i2p::context.GetSharedDestination ());
			}
			return;
		}
		
		if (m_OutboundTunnels.empty () || m_InboundTunnels.size () < 5) 
		{
			// trying to create one more inbound tunnel		
			auto router = i2p::data::netdb.GetRandomRouter ();
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
			if (ts > it->second->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
			{
				auto tmp = it->second;
				LogPrint (eLogDebug, "Tunnel: Transit tunnel with id ", tmp->GetTunnelID (), " expired");
				{
					std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
					it = m_TransitTunnels.erase (it);
				}	
				delete tmp;
			}	
			else 
				it++;
		}
	}	

	void Tunnels::ManageTunnelPools ()
	{
		std::unique_lock<std::mutex> l(m_PoolsMutex);
		for (auto it: m_Pools)
		{	
			auto pool = it;
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
		m_OutboundTunnels.push_back (newTunnel);
		auto pool = newTunnel->GetTunnelPool ();
		if (pool && pool->IsActive ())
			pool->TunnelCreated (newTunnel);
		else
			newTunnel->SetTunnelPool (nullptr);
	}	

	void Tunnels::AddInboundTunnel (std::shared_ptr<InboundTunnel> newTunnel)
	{
		m_InboundTunnels[newTunnel->GetTunnelID ()] = newTunnel;
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

	
	void Tunnels::CreateZeroHopsInboundTunnel ()
	{
		CreateTunnel<InboundTunnel> (
			std::make_shared<TunnelConfig> (std::vector<std::shared_ptr<const i2p::data::IdentityEx> >
			    { 
					i2p::context.GetIdentity ()
				}));
	}	

	int Tunnels::GetTransitTunnelsExpirationTimeout ()
	{
		int timeout = 0;
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
		for (auto it: m_TransitTunnels)
		{
			int t = it.second->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT - ts;
			if (t > timeout) timeout = t;
		}	
		return timeout;
	}	
}
}

