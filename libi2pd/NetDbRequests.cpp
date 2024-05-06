/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "NetDbRequests.h"
#include "ECIESX25519AEADRatchetSession.h"

namespace i2p
{
namespace data
{
	RequestedDestination::RequestedDestination (const IdentHash& destination, bool isExploratory, bool direct):
		m_Destination (destination), m_IsExploratory (isExploratory), m_IsDirect (direct), m_IsActive (true),
		m_CreationTime (i2p::util::GetSecondsSinceEpoch ()), m_LastRequestTime (0) 
	{
	}
		
	RequestedDestination::~RequestedDestination () 
	{ 
		if (m_RequestComplete) m_RequestComplete (nullptr); 
	}
		
	std::shared_ptr<I2NPMessage> RequestedDestination::CreateRequestMessage (std::shared_ptr<const RouterInfo> router,
		std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel)
	{
		std::lock_guard<std::mutex> l (m_ExcludedPeersMutex);
		std::shared_ptr<I2NPMessage> msg;
		if(replyTunnel)
			msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination,
				replyTunnel->GetNextIdentHash (), replyTunnel->GetNextTunnelID (), m_IsExploratory,
				&m_ExcludedPeers);
		else
			msg = i2p::CreateRouterInfoDatabaseLookupMsg(m_Destination, i2p::context.GetIdentHash(), 0, m_IsExploratory, &m_ExcludedPeers);
		if(router)
			m_ExcludedPeers.insert (router->GetIdentHash ());
		m_LastRequestTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}

	std::shared_ptr<I2NPMessage> RequestedDestination::CreateRequestMessage (const IdentHash& floodfill)
	{
		std::lock_guard<std::mutex> l (m_ExcludedPeersMutex);
		auto msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination,
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_LastRequestTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}

	bool RequestedDestination::IsExcluded (const IdentHash& ident) const 
	{ 
		std::lock_guard<std::mutex> l (m_ExcludedPeersMutex);
		return m_ExcludedPeers.count (ident); 
	}
		
	void RequestedDestination::ClearExcludedPeers ()
	{
		std::lock_guard<std::mutex> l (m_ExcludedPeersMutex);
		m_ExcludedPeers.clear ();
	}

	std::set<IdentHash> RequestedDestination::GetExcludedPeers () const 
	{ 
		std::lock_guard<std::mutex> l (m_ExcludedPeersMutex);
		return m_ExcludedPeers; 
	}

	size_t RequestedDestination::GetNumExcludedPeers () const 
	{ 
		std::lock_guard<std::mutex> l (m_ExcludedPeersMutex);
		return m_ExcludedPeers.size (); 
	}
		
	void RequestedDestination::Success (std::shared_ptr<RouterInfo> r)
	{
		if (m_IsActive)
		{	
			m_IsActive = false;
			if (m_RequestComplete)
			{
				m_RequestComplete (r);
				m_RequestComplete = nullptr;
			}
		}	
	}

	void RequestedDestination::Fail ()
	{
		if (m_IsActive)
		{	
			m_IsActive = false;
			if (m_RequestComplete)
			{
				m_RequestComplete (nullptr);
				m_RequestComplete = nullptr;
			}
		}	
	}

	void NetDbRequests::Start ()
	{
		m_LastPoolCleanUpTime = i2p::util::GetSecondsSinceEpoch ();
	}

	void NetDbRequests::Stop ()
	{
		m_RequestedDestinations.clear ();
		m_RequestedDestinationsPool.CleanUpMt ();
	}


	std::shared_ptr<RequestedDestination> NetDbRequests::CreateRequest (const IdentHash& destination, 
		bool isExploratory, bool direct, RequestedDestination::RequestComplete requestComplete)
	{
		// request RouterInfo directly
		auto dest = m_RequestedDestinationsPool.AcquireSharedMt (destination, isExploratory, direct);
		dest->SetRequestComplete (requestComplete);
		{
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex); 
			auto ret = m_RequestedDestinations.emplace (destination, dest);
			if (!ret.second) // not inserted
			{	
				dest->SetRequestComplete (nullptr); // don't call requestComplete in destructor	
				dest = ret.first->second; // existing one
				if (requestComplete && dest->IsActive ())
				{	
					auto prev = dest->GetRequestComplete ();  
					if (prev) // if already set 	
						dest->SetRequestComplete (
							[requestComplete, prev](std::shared_ptr<RouterInfo> r)
							{
								prev (r); // call previous
								requestComplete (r); // then new
							});
					else
						dest->SetRequestComplete (requestComplete);
				}
				return nullptr;
			}	
		}
		return dest;
	}

	void NetDbRequests::RequestComplete (const IdentHash& ident, std::shared_ptr<RouterInfo> r)
	{
		std::shared_ptr<RequestedDestination> request;
		{
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
			auto it = m_RequestedDestinations.find (ident);
			if (it != m_RequestedDestinations.end ())
			{
				request = it->second;
				if (request->IsExploratory ())
					m_RequestedDestinations.erase (it);
				// otherwise cache for a while
			}
		}
		if (request)
		{
			if (r)
				request->Success (r);
			else
				request->Fail ();
		}
	}

	std::shared_ptr<RequestedDestination> NetDbRequests::FindRequest (const IdentHash& ident) const
	{
		std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
		auto it = m_RequestedDestinations.find (ident);
		if (it != m_RequestedDestinations.end ())
			return it->second;
		return nullptr;
	}

	void NetDbRequests::ManageRequests ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		if (ts > m_LastPoolCleanUpTime + REQUESTED_DESTINATIONS_POOL_CLEANUP_INTERVAL)
		{
			m_RequestedDestinationsPool.CleanUpMt ();
			m_LastPoolCleanUpTime = ts;
		}	
		std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
		for (auto it = m_RequestedDestinations.begin (); it != m_RequestedDestinations.end ();)
		{
			auto& dest = it->second;
			if (dest->IsActive () || ts < dest->GetCreationTime () + REQUEST_CACHE_TIME)
			{	
				if (!dest->IsExploratory ())
				{	
					// regular request
					bool done = false;
					if (ts < dest->GetCreationTime () + MAX_REQUEST_TIME)
					{
						if (ts > dest->GetLastRequestTime () + MIN_REQUEST_TIME) // try next floodfill if no response after min interval
							done = !SendNextRequest (dest);
					}
					else // request is expired
						done = true;
					if (done)
						dest->Fail ();
					it++;
				}	
				else
				{	
					// exploratory
					if (ts >= dest->GetCreationTime () + MAX_EXPLORATORY_REQUEST_TIME)
					{
						dest->Fail ();
						it = m_RequestedDestinations.erase (it); // delete expired exploratory request right a way
					}	
					else
						it++;
				}	
			}	
			else
				it = m_RequestedDestinations.erase (it);
		}
	}

	bool NetDbRequests::SendNextRequest (std::shared_ptr<RequestedDestination> dest)
	{
		if (!dest || !dest->IsActive ()) return false;
		bool ret = true;
		auto count = dest->GetNumExcludedPeers ();
		if (!dest->IsExploratory () && count < MAX_NUM_REQUEST_ATTEMPTS)
		{
			auto nextFloodfill = netdb.GetClosestFloodfill (dest->GetDestination (), dest->GetExcludedPeers ());
			if (nextFloodfill)
			{	
				bool direct = dest->IsDirect ();
				if (direct && !nextFloodfill->IsReachableFrom (i2p::context.GetRouterInfo ()) &&
					!i2p::transport::transports.IsConnected (nextFloodfill->GetIdentHash ()))
					direct = false; // floodfill can't be reached directly
				if (direct)
				{
					if (CheckLogLevel (eLogDebug))
						LogPrint (eLogDebug, "NetDbReq: Try ", dest->GetDestination ().ToBase64 (), " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 (), " directly");
					auto msg = dest->CreateRequestMessage (nextFloodfill->GetIdentHash ());
					auto s = shared_from_this ();
					msg->onDrop = [s, dest]() { if (dest->IsActive ()) s->SendNextRequest (dest); }; 
					i2p::transport::transports.SendMessage (nextFloodfill->GetIdentHash (), msg);
				}	
				else
				{	
					auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
					if (pool)
					{	
						auto outbound = pool->GetNextOutboundTunnel ();
						auto inbound = pool->GetNextInboundTunnel ();
						if (nextFloodfill && outbound && inbound)
						{
							if (CheckLogLevel (eLogDebug))
								LogPrint (eLogDebug, "NetDbReq: Try ", dest->GetDestination ().ToBase64 (), " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 (), " through tunnels");
							auto msg = dest->CreateRequestMessage (nextFloodfill, inbound); 
							auto s = shared_from_this ();
							msg->onDrop = [s, dest]() { if (dest->IsActive ()) s->SendNextRequest (dest); };
							outbound->SendTunnelDataMsgTo (nextFloodfill->GetIdentHash (), 0,
								i2p::garlic::WrapECIESX25519MessageForRouter (msg, nextFloodfill->GetIdentity ()->GetEncryptionPublicKey ()));
						}	
						else
						{
							ret = false;
							if (!inbound) LogPrint (eLogWarning, "NetDbReq: No inbound tunnels");
							if (!outbound) LogPrint (eLogWarning, "NetDbReq: No outbound tunnels");
						}
					}	
					else
					{
						ret = false;
						LogPrint (eLogWarning, "NetDbReq: Exploratory pool is not ready");
					}	
				}		
			}
			else
			{
				ret = false;
				if (!nextFloodfill) LogPrint (eLogWarning, "NetDbReq: No more floodfills");
			}	
		}
		else
		{
			if (!dest->IsExploratory ())
				LogPrint (eLogWarning, "NetDbReq: ", dest->GetDestination ().ToBase64 (), " not found after 7 attempts");
			ret = false;
		}
		return ret;
	}	
}
}
