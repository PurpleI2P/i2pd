#include "Log.h"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "NetDb.h"
#include "NetDbRequests.h"

namespace i2p
{
namespace data
{
	std::shared_ptr<I2NPMessage> RequestedDestination::CreateRequestMessage (std::shared_ptr<const RouterInfo> router,
		std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel)
	{
		I2NPMessage * msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination, 
			replyTunnel->GetNextIdentHash (), replyTunnel->GetNextTunnelID (), m_IsExploratory, 
		    &m_ExcludedPeers);
		m_ExcludedPeers.insert (router->GetIdentHash ());
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
		return ToSharedI2NPMessage (msg);
	}	

	std::shared_ptr<I2NPMessage> RequestedDestination::CreateRequestMessage (const IdentHash& floodfill)
	{
		I2NPMessage * msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination, 
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
		return ToSharedI2NPMessage (msg);
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


	std::shared_ptr<RequestedDestination> NetDbRequests::CreateRequest (const IdentHash& destination, bool isExploratory, RequestedDestination::RequestComplete requestComplete)
	{
		// request RouterInfo directly
		auto dest = std::make_shared<RequestedDestination> (destination, isExploratory); 
		dest->SetRequestComplete (requestComplete);
		{
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
			if (!m_RequestedDestinations.insert (std::make_pair (destination, 
				std::shared_ptr<RequestedDestination> (dest))).second) // not inserted
				return nullptr; 
		}
		return dest;
	}	

	void NetDbRequests::RequestComplete (const IdentHash& ident, std::shared_ptr<RouterInfo> r)
	{
		auto it = m_RequestedDestinations.find (ident);
		if (it != m_RequestedDestinations.end ())
		{	
			if (r)
				it->second->Success (r);
			else
				it->second->Fail ();
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
			m_RequestedDestinations.erase (it);
		}	
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
		std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);	
		for (auto it = m_RequestedDestinations.begin (); it != m_RequestedDestinations.end ();)
		{
			auto& dest = it->second;
			bool done = false;
			if (ts < dest->GetCreationTime () + 60) // request is worthless after 1 minute
			{
				if (ts > dest->GetCreationTime () + 5) // no response for 5 seconds
				{
					auto count = dest->GetExcludedPeers ().size ();
					if (!dest->IsExploratory () && count < 7)
					{
						auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
						auto outbound = pool->GetNextOutboundTunnel ();
						auto inbound = pool->GetNextInboundTunnel ();	
						auto nextFloodfill = netdb.GetClosestFloodfill (dest->GetDestination (), dest->GetExcludedPeers ());
						if (nextFloodfill && outbound && inbound)
							outbound->SendTunnelDataMsg (nextFloodfill->GetIdentHash (), 0,
								dest->CreateRequestMessage (nextFloodfill, inbound));
						else
						{
							done = true;
							if (!inbound) LogPrint (eLogWarning, "No inbound tunnels");	
							if (!outbound) LogPrint (eLogWarning, "No outbound tunnels");
							if (!nextFloodfill) LogPrint (eLogWarning, "No more floodfills");	
						}
					}	
					else
					{
						if (!dest->IsExploratory ())
							LogPrint (eLogWarning, dest->GetDestination ().ToBase64 (), " not found after 7 attempts");	
						done = true;
					}	 
				}	
			}	
			else // delete obsolete request
				done = true;

			if (done)
				it = m_RequestedDestinations.erase (it);
			else
				it++;
		}	
	}
}
}

