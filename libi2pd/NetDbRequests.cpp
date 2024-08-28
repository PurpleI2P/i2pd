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
#include "ECIESX25519AEADRatchetSession.h"
#include "RouterContext.h"
#include "Timestamp.h"
#include "NetDbRequests.h"

namespace i2p
{
namespace data
{
	RequestedDestination::RequestedDestination (const IdentHash& destination, bool isExploratory, bool direct):
		m_Destination (destination), m_IsExploratory (isExploratory), m_IsDirect (direct), m_IsActive (true),
		m_CreationTime (i2p::util::GetSecondsSinceEpoch ()), m_LastRequestTime (0), m_NumAttempts (0)
	{
		if (i2p::context.IsFloodfill ())
			m_ExcludedPeers.insert (i2p::context.GetIdentHash ()); // exclude self if floodfill
	}
		
	RequestedDestination::~RequestedDestination () 
	{ 
		InvokeRequestComplete (nullptr);
	}
		
	std::shared_ptr<I2NPMessage> RequestedDestination::CreateRequestMessage (std::shared_ptr<const RouterInfo> router,
		std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel)
	{
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
		m_NumAttempts++;
		return msg;
	}

	std::shared_ptr<I2NPMessage> RequestedDestination::CreateRequestMessage (const IdentHash& floodfill)
	{
		auto msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination,
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_NumAttempts++;
		m_LastRequestTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}

	bool RequestedDestination::IsExcluded (const IdentHash& ident) const 
	{ 
		return m_ExcludedPeers.count (ident); 
	}
		
	void RequestedDestination::ClearExcludedPeers ()
	{
		m_ExcludedPeers.clear ();
	}

	void RequestedDestination::InvokeRequestComplete (std::shared_ptr<RouterInfo> r)
	{
		if (!m_RequestComplete.empty ())
		{	
			for (auto it: m_RequestComplete)
				if (it != nullptr) it (r);
			m_RequestComplete.clear ();
		}	
	}	
		
	void RequestedDestination::Success (std::shared_ptr<RouterInfo> r)
	{
		if (m_IsActive)
		{	
			m_IsActive = false;
			InvokeRequestComplete (r);
		}	
	}

	void RequestedDestination::Fail ()
	{
		if (m_IsActive)
		{	
			m_IsActive = false;
			InvokeRequestComplete (nullptr);
		}	
	}

	NetDbRequests::NetDbRequests ():
		RunnableServiceWithWork ("NetDbReq"),
		m_ManageRequestsTimer (GetIOService ()), m_ExploratoryTimer (GetIOService ()),
		m_CleanupTimer (GetIOService ()), m_DiscoveredRoutersTimer (GetIOService ()),
		m_Rng(i2p::util::GetMonotonicMicroseconds () % 1000000LL) 
	{
	}
		
	NetDbRequests::~NetDbRequests ()
	{
		Stop ();
	}	
		
	void NetDbRequests::Start ()
	{
		if (!IsRunning ())
		{	
			StartIOService ();
			ScheduleManageRequests ();
			ScheduleCleanup ();
			if (!i2p::context.IsHidden ())
				ScheduleExploratory (EXPLORATORY_REQUEST_INTERVAL);
		}	
	}

	void NetDbRequests::Stop ()
	{
		if (IsRunning ())
		{	
			m_ManageRequestsTimer.cancel ();
			m_ExploratoryTimer.cancel ();
			m_CleanupTimer.cancel ();
			StopIOService ();
		
			m_RequestedDestinations.clear ();
			m_RequestedDestinationsPool.CleanUpMt ();
		}	
	}

	void NetDbRequests::ScheduleCleanup ()
	{
		m_CleanupTimer.expires_from_now (boost::posix_time::seconds(REQUESTED_DESTINATIONS_POOL_CLEANUP_INTERVAL));
		m_CleanupTimer.async_wait (std::bind (&NetDbRequests::HandleCleanupTimer,
			this, std::placeholders::_1));
	}	
		
	void NetDbRequests::HandleCleanupTimer (const boost::system::error_code& ecode)
	{		
		if (ecode != boost::asio::error::operation_aborted)
		{
			m_RequestedDestinationsPool.CleanUpMt ();
			ScheduleCleanup ();
		}	
	}
		
	std::shared_ptr<RequestedDestination> NetDbRequests::CreateRequest (const IdentHash& destination, 
		bool isExploratory, bool direct, RequestedDestination::RequestComplete requestComplete)
	{
		// request RouterInfo directly
		auto dest = m_RequestedDestinationsPool.AcquireSharedMt (destination, isExploratory, direct);
		if (requestComplete)
			dest->AddRequestComplete (requestComplete);
		
		auto ret = m_RequestedDestinations.emplace (destination, dest);
		if (!ret.second) // not inserted
		{	
			dest->ResetRequestComplete (); // don't call requestComplete in destructor	
			dest = ret.first->second; // existing one
			if (requestComplete)
			{	
				if (dest->IsActive ())
					dest->AddRequestComplete (requestComplete);
				else
					requestComplete (nullptr);
			}	
			return nullptr;
		}	
		return dest;
	}

	void NetDbRequests::RequestComplete (const IdentHash& ident, std::shared_ptr<RouterInfo> r)
	{
		GetIOService ().post ([this, ident, r]()
			{                      
				std::shared_ptr<RequestedDestination> request;
				auto it = m_RequestedDestinations.find (ident);
				if (it != m_RequestedDestinations.end ())
				{
					request = it->second;
					if (request->IsExploratory ())
						m_RequestedDestinations.erase (it);
					// otherwise cache for a while
				}
				if (request)
				{
					if (r)
						request->Success (r);
					else
						request->Fail ();
				}
			});
	}

	std::shared_ptr<RequestedDestination> NetDbRequests::FindRequest (const IdentHash& ident) const
	{
		auto it = m_RequestedDestinations.find (ident);
		if (it != m_RequestedDestinations.end ())
			return it->second;
		return nullptr;
	}

	void NetDbRequests::ManageRequests ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
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
		auto count = dest->GetNumAttempts ();
		if (!dest->IsExploratory () && count < MAX_NUM_REQUEST_ATTEMPTS)
		{
			auto nextFloodfill = netdb.GetClosestFloodfill (dest->GetDestination (), dest->GetExcludedPeers ());
			if (nextFloodfill)
			{	
				bool direct = dest->IsDirect ();
				if (direct && !nextFloodfill->IsReachableFrom (i2p::context.GetRouterInfo ()) &&
					!i2p::transport::transports.IsConnected (nextFloodfill->GetIdentHash ()))
					direct = false; // floodfill can't be reached directly
				auto s = shared_from_this ();
				auto onDrop = [s, dest]()
					{
						if (dest->IsActive ())
						{
							s->GetIOService ().post ([s, dest]()
								{
									if (dest->IsActive ()) s->SendNextRequest (dest);
								});
						}	
					};		
				if (direct)
				{
					if (CheckLogLevel (eLogDebug))
						LogPrint (eLogDebug, "NetDbReq: Try ", dest->GetDestination ().ToBase64 (), " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 (), " directly");
					auto msg = dest->CreateRequestMessage (nextFloodfill->GetIdentHash ());
					msg->onDrop = onDrop; 
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
							msg->onDrop = onDrop;
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
				LogPrint (eLogWarning, "NetDbReq: No more floodfills for ", dest->GetDestination ().ToBase64 (), " after ", count, "attempts");
			}	
		}
		else
		{
			if (!dest->IsExploratory ())
				LogPrint (eLogWarning, "NetDbReq: ", dest->GetDestination ().ToBase64 (), " not found after ", MAX_NUM_REQUEST_ATTEMPTS," attempts");
			ret = false;
		}
		return ret;
	}	

	void NetDbRequests::ScheduleManageRequests ()
	{
		m_ManageRequestsTimer.expires_from_now (boost::posix_time::seconds(MANAGE_REQUESTS_INTERVAL));
		m_ManageRequestsTimer.async_wait (std::bind (&NetDbRequests::HandleManageRequestsTimer,
			this, std::placeholders::_1));
	}
		
	void NetDbRequests::HandleManageRequestsTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (i2p::tunnel::tunnels.GetExploratoryPool ()) // expolratory pool is ready?
				ManageRequests ();
			ScheduleManageRequests ();
		}	
	}	

	void NetDbRequests::PostDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		GetIOService ().post ([this, msg]()
			{
				HandleDatabaseSearchReplyMsg (msg);
			});	
	}	

	void NetDbRequests::HandleDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		const uint8_t * buf = msg->GetPayload ();
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (buf, 32, key, 48);
		key[l] = 0;
		size_t num = buf[32]; // num
		LogPrint (eLogDebug, "NetDbReq: DatabaseSearchReply for ", key, " num=", num);
		IdentHash ident (buf);
		bool isExploratory = false;
		auto dest = FindRequest (ident);
		if (dest && dest->IsActive ())
		{
			isExploratory = dest->IsExploratory ();
			if (!isExploratory && (num > 0 || dest->GetNumAttempts () < 3)) // before 3-rd attempt might be just bad luck
			{	
				// try to send next requests
				if (!SendNextRequest (dest))
					RequestComplete (ident, nullptr);
			}	
			else
				// no more requests for destination possible. delete it
				RequestComplete (ident, nullptr);
		}
		else /*if (!m_FloodfillBootstrap)*/
		{	
			LogPrint (eLogInfo, "NetDbReq: Unsolicited or late database search reply for ", key);
			return;
		}	

		// try responses
		if (num > NETDB_MAX_NUM_SEARCH_REPLY_PEER_HASHES)
		{
			LogPrint (eLogWarning, "NetDbReq: Too many peer hashes ", num, " in database search reply, Reduced to ", NETDB_MAX_NUM_SEARCH_REPLY_PEER_HASHES);
			num = NETDB_MAX_NUM_SEARCH_REPLY_PEER_HASHES;
		}	
		if (isExploratory && !m_DiscoveredRouterHashes.empty ())
		{
			// request outstanding routers
			for (auto it: m_DiscoveredRouterHashes)
				RequestRouter (it);
			m_DiscoveredRouterHashes.clear ();
			m_DiscoveredRoutersTimer.cancel ();
		}	
		for (size_t i = 0; i < num; i++)
		{
			IdentHash router (buf + 33 + i*32);
			if (CheckLogLevel (eLogDebug))
				LogPrint (eLogDebug, "NetDbReq: ", i, ": ", router.ToBase64 ());

			if (isExploratory)
				// postpone request
				m_DiscoveredRouterHashes.push_back (router);
			else	
				// send request right a way
				RequestRouter (router);
		}
		if (isExploratory && !m_DiscoveredRouterHashes.empty ())
			ScheduleDiscoveredRoutersRequest (); 	
	}	

	void NetDbRequests::RequestRouter (const IdentHash& router)
	{		
		auto r = netdb.FindRouter (router);
		if (!r || i2p::util::GetMillisecondsSinceEpoch () > r->GetTimestamp () + 3600*1000LL)
		{
			// router with ident not found or too old (1 hour)
			LogPrint (eLogDebug, "NetDbReq: Found new/outdated router. Requesting RouterInfo...");
			if (!IsRouterBanned (router))
				RequestDestination (router, nullptr, true);
			else
				LogPrint (eLogDebug, "NetDbReq: Router ", router.ToBase64 (), " is banned. Skipped");
		}
		else
			LogPrint (eLogDebug, "NetDbReq: [:|||:]");
	}	
		
	void NetDbRequests::PostRequestDestination (const IdentHash& destination, 
		const RequestedDestination::RequestComplete& requestComplete, bool direct)
	{
		GetIOService ().post ([this, destination, requestComplete, direct]()
			{
				RequestDestination (destination, requestComplete, direct);
			});	
	}
		
	void NetDbRequests::RequestDestination (const IdentHash& destination, const RequestedDestination::RequestComplete& requestComplete, bool direct)
	{
		auto dest = CreateRequest (destination, false, direct, requestComplete); // non-exploratory
		if (dest)
		{	
			if (!SendNextRequest (dest))
				RequestComplete (destination, nullptr);
		}	
		else
			LogPrint (eLogWarning, "NetDbReq: Destination ", destination.ToBase64(), " is requested already or cached");
	}	

	void NetDbRequests::Explore (int numDestinations)
	{
		// new requests
		auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
		auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
		auto inbound = exploratoryPool ? exploratoryPool->GetNextInboundTunnel () : nullptr;
		bool throughTunnels = outbound && inbound;

		uint8_t randomHash[32];
		std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
		LogPrint (eLogInfo, "NetDbReq: Exploring new ", numDestinations, " routers ...");
		for (int i = 0; i < numDestinations; i++)
		{
			RAND_bytes (randomHash, 32);
			auto dest = CreateRequest (randomHash, true, !throughTunnels); // exploratory
			if (!dest)
			{
				LogPrint (eLogWarning, "NetDbReq: Exploratory destination is requested already");
				return;
			}
			auto floodfill = netdb.GetClosestFloodfill (randomHash, dest->GetExcludedPeers ());
			if (floodfill)
			{
				if (i2p::transport::transports.IsConnected (floodfill->GetIdentHash ()))
					throughTunnels = false;
				if (throughTunnels)
				{
					msgs.push_back (i2p::tunnel::TunnelMessageBlock
						{
							i2p::tunnel::eDeliveryTypeRouter,
							floodfill->GetIdentHash (), 0,
							CreateDatabaseStoreMsg () // tell floodfill about us
						});
					msgs.push_back (i2p::tunnel::TunnelMessageBlock
						{
							i2p::tunnel::eDeliveryTypeRouter,
							floodfill->GetIdentHash (), 0,
							dest->CreateRequestMessage (floodfill, inbound) // explore
						});
				}
				else
					i2p::transport::transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));
			}
			else
				RequestComplete (randomHash, nullptr);
		}
		if (throughTunnels && msgs.size () > 0)
			outbound->SendTunnelDataMsgs (msgs);
	}	

	void NetDbRequests::ScheduleExploratory (uint64_t interval)
	{
		m_ExploratoryTimer.expires_from_now (boost::posix_time::seconds(interval));
		m_ExploratoryTimer.async_wait (std::bind (&NetDbRequests::HandleExploratoryTimer,
			this, std::placeholders::_1));
	}
		
	void NetDbRequests::HandleExploratoryTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto numRouters = netdb.GetNumRouters ();
			auto nextExploratoryInterval = numRouters < 2500 ? (EXPLORATORY_REQUEST_INTERVAL + m_Rng () % EXPLORATORY_REQUEST_INTERVAL)/2 :
				EXPLORATORY_REQUEST_INTERVAL + m_Rng () % EXPLORATORY_REQUEST_INTERVAL_VARIANCE;
			if (numRouters)
			{	
				if (i2p::transport::transports.IsOnline () && i2p::transport::transports.IsRunning ()) 
				{	
					// explore only if online
					numRouters = 800/numRouters;
					if (numRouters < 1) numRouters = 1;
					if (numRouters > 9) numRouters = 9;
					Explore (numRouters);
				}	
			}	
			else
				LogPrint (eLogError, "NetDbReq: No known routers, reseed seems to be totally failed");
			ScheduleExploratory (nextExploratoryInterval);
		}	
	}	

	void NetDbRequests::ScheduleDiscoveredRoutersRequest ()
	{
		m_DiscoveredRoutersTimer.expires_from_now (boost::posix_time::milliseconds(
			DISCOVERED_REQUEST_INTERVAL + m_Rng () % DISCOVERED_REQUEST_INTERVAL_VARIANCE));
		m_DiscoveredRoutersTimer.async_wait (std::bind (&NetDbRequests::HandleDiscoveredRoutersTimer,
			this, std::placeholders::_1));
	}	

	void NetDbRequests::HandleDiscoveredRoutersTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (!m_DiscoveredRouterHashes.empty ())
			{
				RequestRouter (m_DiscoveredRouterHashes.front ());
				m_DiscoveredRouterHashes.pop_front ();
				if (!m_DiscoveredRouterHashes.empty ()) // more hashes to request
					ScheduleDiscoveredRoutersRequest ();
			}	
		}	
	}	
}
}
