#include "I2PEndian.h"
#include <thread>
#include <algorithm>
#include <vector> 
#include <cryptopp/sha.h>
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
	
	Tunnel::Tunnel (TunnelConfig * config): 
		m_Config (config), m_Pool (nullptr), m_State (eTunnelStatePending)
	{
	}	

	Tunnel::~Tunnel ()
	{
		delete m_Config;
	}	

	void Tunnel::Build (uint32_t replyMsgID, OutboundTunnel * outboundTunnel)
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		auto numHops = m_Config->GetNumHops ();
		int numRecords = numHops <= STANDARD_NUM_RECORDS ? STANDARD_NUM_RECORDS : numHops; 
		I2NPMessage * msg = NewI2NPMessage ();
		*msg->GetPayload () = numRecords;
		msg->len += numRecords*sizeof (I2NPBuildRequestRecordElGamalEncrypted) + 1;		

		// shuffle records
		std::vector<int> recordIndicies;
		for (int i = 0; i < numRecords; i++) recordIndicies.push_back(i);
		std::random_shuffle (recordIndicies.begin(), recordIndicies.end());

		// create real records
		I2NPBuildRequestRecordElGamalEncrypted * records = (I2NPBuildRequestRecordElGamalEncrypted *)(msg->GetPayload () + 1); 
		TunnelHopConfig * hop = m_Config->GetFirstHop ();
		int i = 0;
		while (hop)
		{
			int idx = recordIndicies[i];
			EncryptBuildRequestRecord (*hop->router,
				CreateBuildRequestRecord (hop->router->GetIdentHash (), 
				    hop->tunnelID,
					hop->nextRouter->GetIdentHash (), 
					hop->nextTunnelID,
					hop->layerKey, hop->ivKey,                  
					hop->replyKey, hop->replyIV,
					hop->next ? rnd.GenerateWord32 () : replyMsgID, // we set replyMsgID for last hop only
				    hop->isGateway, hop->isEndpoint), 
		    	records[idx]);
			hop->recordIndex = idx; 
			i++;
			hop = hop->next;
		}	
		// fill up fake records with random data	
		for (int i = numHops; i < numRecords; i++)
		{
			int idx = recordIndicies[i];
			rnd.GenerateBlock ((uint8_t *)(records + idx), sizeof (records[idx])); 
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
				decryption.Decrypt((uint8_t *)&records[hop1->recordIndex], 
					sizeof (I2NPBuildRequestRecordElGamalEncrypted), 
				    (uint8_t *)&records[hop1->recordIndex]);
				hop1 = hop1->next;
			}	
			hop = hop->prev;
		}	
		FillI2NPMessageHeader (msg, eI2NPVariableTunnelBuild);

		// send message
		if (outboundTunnel)
			outboundTunnel->SendTunnelDataMsg (GetNextIdentHash (), 0, msg);	
		else
			i2p::transports.SendMessage (GetNextIdentHash (), msg);
	}	
		
	bool Tunnel::HandleTunnelBuildResponse (uint8_t * msg, size_t len)
	{
		LogPrint ("TunnelBuildResponse ", (int)msg[0], " records.");
		
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
					uint8_t * record = msg + 1 + idx*sizeof (I2NPBuildResponseRecord);
					decryption.SetIV (hop->replyIV);
					decryption.Decrypt(record, sizeof (I2NPBuildResponseRecord), record);
				}	
				else
					LogPrint ("Tunnel hop index ", idx, " is out of range");
				hop1 = hop1->prev;
			}	
			hop = hop->prev;
		}

		bool established = true;
		hop = m_Config->GetFirstHop ();
		while (hop)
		{			
			I2NPBuildResponseRecord * record = (I2NPBuildResponseRecord *)(msg + 1 + hop->recordIndex*sizeof (I2NPBuildResponseRecord));
			LogPrint ("Ret code=", (int)record->ret);
			if (record->ret) 
				// if any of participants declined the tunnel is not established
				established = false; 
			hop = hop->next;
		}
		if (established) 
		{
			// change reply keys to layer keys
			hop = m_Config->GetFirstHop ();
			while (hop)
			{
				hop->decryption.SetKeys (hop->layerKey, hop->ivKey);
				hop = hop->next;
			}	
		}	
		if (established) m_State = eTunnelStateEstablished;
		return established;
	}	

	void Tunnel::EncryptTunnelMsg (I2NPMessage * tunnelMsg)
	{
		uint8_t * payload = tunnelMsg->GetPayload () + 4;
		TunnelHopConfig * hop = m_Config->GetLastHop (); 
		while (hop)
		{	
			hop->decryption.Decrypt (payload);
			hop = hop->prev;
		}
	}	
	
	void InboundTunnel::HandleTunnelDataMsg (I2NPMessage * msg)
	{
		if (IsFailed ()) SetState (eTunnelStateEstablished); // incoming messages means a tunnel is alive			
		msg->from = this;
		EncryptTunnelMsg (msg);
		m_Endpoint.HandleDecryptedTunnelDataMsg (msg);	
	}	

	void OutboundTunnel::SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg)
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
		
	void OutboundTunnel::SendTunnelDataMsg (std::vector<TunnelMessageBlock> msgs)
	{
		std::unique_lock<std::mutex> l(m_SendMutex);
		for (auto& it : msgs)
			m_Gateway.PutTunnelDataMsg (it);
		m_Gateway.SendBuffer ();
	}	
	
	Tunnels tunnels;
	
	Tunnels::Tunnels (): m_IsRunning (false), m_IsTunnelCreated (false), 
		m_NextReplyMsgID (555), m_Thread (nullptr), m_ExploratoryPool (nullptr)
	{
	}
	
	Tunnels::~Tunnels ()	
	{
		for (auto& it : m_OutboundTunnels)
			delete it;
		m_OutboundTunnels.clear ();

		for (auto& it : m_InboundTunnels)
			delete it.second;
		m_InboundTunnels.clear ();
		
		for (auto& it : m_TransitTunnels)
			delete it.second;
		m_TransitTunnels.clear ();

		/*for (auto& it : m_PendingTunnels)
			delete it.second;
		m_PendingTunnels.clear ();*/

		for (auto& it: m_Pools)
			delete it.second;
		m_Pools.clear ();
	}	
	
	InboundTunnel * Tunnels::GetInboundTunnel (uint32_t tunnelID)
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
		
	Tunnel * Tunnels::GetPendingTunnel (uint32_t replyMsgID)
	{
		auto it = m_PendingTunnels.find(replyMsgID);
		if (it != m_PendingTunnels.end ())
			return it->second;
		return nullptr;
	}	

	InboundTunnel * Tunnels::GetNextInboundTunnel ()
	{
		InboundTunnel * tunnel  = nullptr; 
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
	
	OutboundTunnel * Tunnels::GetNextOutboundTunnel ()
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t ind = rnd.GenerateWord32 (0, m_OutboundTunnels.size () - 1), i = 0;
		OutboundTunnel * tunnel = nullptr;
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

	TunnelPool * Tunnels::CreateTunnelPool (i2p::data::LocalDestination& localDestination, int numHops)
	{
		auto pool = new TunnelPool (localDestination, numHops);
		m_Pools[pool->GetIdentHash ()] = pool;
		return pool;
	}	

	void Tunnels::DeleteTunnelPool (TunnelPool * pool)
	{
		if (pool)
		{
			m_Pools.erase (pool->GetIdentHash ());
			delete pool;
		}
	}	
	
	void Tunnels::AddTransitTunnel (TransitTunnel * tunnel)
	{
		m_TransitTunnels[tunnel->GetTunnelID ()] = tunnel;
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
				I2NPMessage * msg = m_Queue.GetNextWithTimeout (1000); // 1 sec
				while (msg)
				{
					uint32_t  tunnelID = be32toh (*(uint32_t *)msg->GetPayload ()); 
					InboundTunnel * tunnel = GetInboundTunnel (tunnelID);
					if (tunnel)
						tunnel->HandleTunnelDataMsg (msg);
					else
					{	
						TransitTunnel * transitTunnel = GetTransitTunnel (tunnelID);
						if (transitTunnel)
							transitTunnel->HandleTunnelDataMsg (msg);
						else	
						{	
							LogPrint ("Tunnel ", tunnelID, " not found");
							i2p::DeleteI2NPMessage (msg);
						}	
					}	
					msg = m_Queue.Get ();
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
				LogPrint ("Tunnels: ", ex.what ());
			}	
		}	
	}	

	void Tunnels::ManageTunnels ()
	{
		// check pending tunnel. delete non-successive
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		for (auto it = m_PendingTunnels.begin (); it != m_PendingTunnels.end ();)
		{	
			if (it->second->GetState () == eTunnelStatePending) 
			{
				if (ts > it->second->GetCreationTime () + TUNNEL_CREATION_TIMEOUT)
				{
					LogPrint ("Pending tunnel build request ", it->first, " was not successive. Deleted");
					delete it->second;
					it = m_PendingTunnels.erase (it);
				}
				else
					it++;
			}
			else
				it = m_PendingTunnels.erase (it);
		}	
		
		ManageInboundTunnels ();
		ManageOutboundTunnels ();
		ManageTransitTunnels ();
		ManageTunnelPools ();
	}	

	void Tunnels::ManageOutboundTunnels ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (auto it = m_OutboundTunnels.begin (); it != m_OutboundTunnels.end ();)
			{
				if (ts > (*it)->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
				{
					LogPrint ("Tunnel ", (*it)->GetTunnelID (), " expired");
					auto pool = (*it)->GetTunnelPool ();
					if (pool)
						pool->TunnelExpired (*it);
					delete *it;
					it = m_OutboundTunnels.erase (it);
				}	
				else 
				{
					if ((*it)->IsEstablished () && ts + TUNNEL_EXPIRATION_THRESHOLD > (*it)->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
						(*it)->SetState (eTunnelStateExpiring);
					it++;
				}
			}
		}	
	
		if (m_OutboundTunnels.size () < 5) 
		{
			// trying to create one more oubound tunnel
			InboundTunnel * inboundTunnel = GetNextInboundTunnel ();
			if (!inboundTunnel) return;
			LogPrint ("Creating one hop outbound tunnel...");
			CreateTunnel<OutboundTunnel> (
			  	new TunnelConfig (std::vector<const i2p::data::RouterInfo *> 
				    { 
						i2p::data::netdb.GetRandomRouter ()
					},		
		     		inboundTunnel->GetTunnelConfig ()));
		}
	}
	
	void Tunnels::ManageInboundTunnels ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (auto it = m_InboundTunnels.begin (); it != m_InboundTunnels.end ();)
			{
				if (ts > it->second->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
				{
					LogPrint ("Tunnel ", it->second->GetTunnelID (), " expired");
					auto pool = it->second->GetTunnelPool ();
					if (pool)
						pool->TunnelExpired (it->second);
					delete it->second;
					it = m_InboundTunnels.erase (it);
				}	
				else 
				{
					if (it->second->IsEstablished () && ts + TUNNEL_EXPIRATION_THRESHOLD > it->second->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
						it->second->SetState (eTunnelStateExpiring);
					it++;
				}
			}
		}	

		if (m_InboundTunnels.empty ())
		{
			LogPrint ("Creating zero hops inbound tunnel...");
			CreateZeroHopsInboundTunnel ();
			if (!m_ExploratoryPool)
				m_ExploratoryPool = CreateTunnelPool (i2p::context, 2); // 2-hop exploratory
			return;
		}
		
		if (m_OutboundTunnels.empty () || m_InboundTunnels.size () < 5) 
		{
			// trying to create one more inbound tunnel			
			LogPrint ("Creating one hop inbound tunnel...");
			CreateTunnel<InboundTunnel> (
				new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
				    {              
						i2p::data::netdb.GetRandomRouter ()
					}));
		}
	}	

	void Tunnels::ManageTransitTunnels ()
	{
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		for (auto it = m_TransitTunnels.begin (); it != m_TransitTunnels.end ();)
		{
			if (ts > it->second->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
			{
				LogPrint ("Transit tunnel ", it->second->GetTunnelID (), " expired");
				auto tmp = it->second;
				it = m_TransitTunnels.erase (it);
				delete tmp;
			}	
			else 
				it++;
		}
	}	

	void Tunnels::ManageTunnelPools ()
	{
		for (auto& it: m_Pools)
		{	
			it.second->CreateTunnels ();
			it.second->TestTunnels ();
		}
	}	
	
	void Tunnels::PostTunnelData (I2NPMessage * msg)
	{
		if (msg) m_Queue.Put (msg);		
	}	

	template<class TTunnel>
	TTunnel * Tunnels::CreateTunnel (TunnelConfig * config, OutboundTunnel * outboundTunnel)
	{
		TTunnel * newTunnel = new TTunnel (config);
		m_PendingTunnels[m_NextReplyMsgID] = newTunnel; 
		newTunnel->Build (m_NextReplyMsgID, outboundTunnel);
		m_NextReplyMsgID++; // TODO: should be atomic
		return newTunnel;
	}	

	void Tunnels::AddOutboundTunnel (OutboundTunnel * newTunnel)
	{
		std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
		m_OutboundTunnels.push_back (newTunnel);
		auto pool = newTunnel->GetTunnelPool ();
		if (pool)
			pool->TunnelCreated (newTunnel);
	}	

	void Tunnels::AddInboundTunnel (InboundTunnel * newTunnel)
	{
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		m_InboundTunnels[newTunnel->GetTunnelID ()] = newTunnel;
		auto pool = newTunnel->GetTunnelPool ();
		if (!pool)
		{		
			// build symmetric outbound tunnel
			CreateTunnel<OutboundTunnel> (newTunnel->GetTunnelConfig ()->Invert (), GetNextOutboundTunnel ());		
		}
		else
			pool->TunnelCreated (newTunnel);
	}	

	
	void Tunnels::CreateZeroHopsInboundTunnel ()
	{
		CreateTunnel<InboundTunnel> (
			new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
			    { 
					&i2p::context.GetRouterInfo ()
				}));
	}	
}
}
