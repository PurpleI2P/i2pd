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
		m_Destination (destination), m_IsExploratory (isExploratory), m_IsDirect (direct), 
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
		auto msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination,
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_LastRequestTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}

	void RequestedDestination::ClearExcludedPeers ()
	{
		m_ExcludedPeers.clear ();
	}

	void RequestedDestination::Success (std::shared_ptr<RouterInfo> r)
	{
		if (m_RequestComplete)
		{
			m_RequestComplete (r);
			m_RequestComplete = nullptr;
		}
	}

	void RequestedDestination::Fail ()
	{
		if (m_RequestComplete)
		{
			m_RequestComplete (nullptr);
			m_RequestComplete = nullptr;
		}
	}

	void NetDbRequests::Start ()
	{
	}

	void NetDbRequests::Stop ()
	{
		m_RequestedDestinations.clear ();
	}


	std::shared_ptr<RequestedDestination> NetDbRequests::CreateRequest (const IdentHash& destination, 
		bool isExploratory, bool direct, RequestedDestination::RequestComplete requestComplete)
	{
		// request RouterInfo directly
		auto dest = std::make_shared<RequestedDestination> (destination, isExploratory, direct);
		dest->SetRequestComplete (requestComplete);
		{
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex); 
			auto ret = m_RequestedDestinations.emplace (destination, dest);
			if (!ret.second) // not inserted
			{	
				dest->SetRequestComplete (nullptr); // don't call requestComplete in destructor	
				if (requestComplete)
				{	
					auto prev = ret.first->second->GetRequestComplete ();  
					if (prev) // if already set 	
						ret.first->second->SetRequestComplete (
							[requestComplete, prev](std::shared_ptr<RouterInfo> r)
							{
								prev (r); // call previous
								requestComplete (r); // then new
							});
					else
						ret.first->second->SetRequestComplete (requestComplete);
				}
				if (i2p::util::GetSecondsSinceEpoch () > ret.first->second->GetLastRequestTime () + MIN_REQUEST_TIME)
					if (!SendNextRequest (ret.first->second)) // try next floodfill
						m_RequestedDestinations.erase (ret.first); // delete request if failed
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
				m_RequestedDestinations.erase (it);
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
		std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
		for (auto it = m_RequestedDestinations.begin (); it != m_RequestedDestinations.end ();)
		{
			auto& dest = it->second;
			bool done = false;
			if (ts < dest->GetCreationTime () + MAX_REQUEST_TIME) // request becomes worthless
			{
				if (ts > dest->GetLastRequestTime () + MIN_REQUEST_TIME) // try next floodfill if no response after min interval
					done = !SendNextRequest (dest);
			}
			else // delete obsolete request
				done = true;

			if (done)
				it = m_RequestedDestinations.erase (it);
			else
				++it;
		}
	}

	bool NetDbRequests::SendNextRequest (std::shared_ptr<RequestedDestination> dest)
	{
		if (!dest) return false;
		bool ret = true;
		auto count = dest->GetExcludedPeers ().size ();
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
					LogPrint (eLogDebug, "NetDbReq: Try ", dest->GetDestination ().ToBase64 (), " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 (), " directly");
					auto msg = dest->CreateRequestMessage (nextFloodfill->GetIdentHash ());
					msg->onDrop = [this, dest]() { this->SendNextRequest (dest); }; 
					i2p::transport::transports.SendMessage (nextFloodfill->GetIdentHash (), msg);
				}	
				else
				{	
					auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
					auto outbound = pool->GetNextOutboundTunnel ();
					auto inbound = pool->GetNextInboundTunnel ();
					if (nextFloodfill && outbound && inbound)
					{
						LogPrint (eLogDebug, "NetDbReq: Try ", dest->GetDestination ().ToBase64 (), " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 (), " through tunnels");
						auto msg = dest->CreateRequestMessage (nextFloodfill, inbound); 
						msg->onDrop = [this, dest]() { this->SendNextRequest (dest); };
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
