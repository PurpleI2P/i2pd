#include <boost/filesystem.hpp>
#include "Log.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "NetDb.h"

namespace i2p
{
namespace data
{		
	
	NetDb netdb;

	NetDb::NetDb ()
	{
		Load ("netDb");
	}
	
	NetDb::~NetDb ()
	{
		for (auto l:m_LeaseSets)
			delete l.second;
		for (auto r:m_RouterInfos)
			delete r.second;
	}	
	
	void NetDb::AddRouterInfo (uint8_t * buf, int len)
	{
		RouterInfo * r = new RouterInfo (buf, len);
		m_RouterInfos[std::string ((const char *)r->GetIdentHash (), 32)] = r;
	}	

	void NetDb::AddLeaseSet (uint8_t * buf, int len)
	{
		LeaseSet * l = new LeaseSet (buf, len);
		m_LeaseSets[std::string ((const char *)l->GetIdentHash (), 32)] = l;
	}	

	RouterInfo * NetDb::FindRouter (const uint8_t * ident)
	{
		auto it = m_RouterInfos.find (std::string ((const char *)ident, 32));
		if (it != m_RouterInfos.end ())
			return it->second;
		else
			return nullptr;
	}
	
	void NetDb::Load (const char * directory)
	{
		boost::filesystem::path p (directory);
		if (boost::filesystem::exists (p))
		{
			int numRouters = 0;
			boost::filesystem::directory_iterator end;
			for (boost::filesystem::directory_iterator it (p); it != end; ++it)
			{
				if (boost::filesystem::is_directory (it->status()))
				{
					for (boost::filesystem::directory_iterator it1 (it->path ()); it1 != end; ++it1)
					{
						RouterInfo * r = new RouterInfo (it1->path ().c_str ());
						m_RouterInfos[std::string ((const char *)r->GetIdentHash (), 32)] = r;
						numRouters++;
					}	
				}	
			}	
			LogPrint (numRouters, " routers loaded");
		}
		else
			LogPrint (directory, " doesn't exist");
	}	

	void NetDb::RequestDestination (const uint8_t * destination, const uint8_t * router)
	{
		i2p::tunnel::OutboundTunnel * outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		if (outbound)
		{
			i2p::tunnel::InboundTunnel * inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
			if (inbound)
			{
				I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (destination, inbound->GetGatewayIdentHash (), 
					inbound->GetGetwayTunnelID ());
				outbound->SendTunnelDataMsg (router, 0, msg);
				i2p::DeleteI2NPMessage (msg);
			}	
			else
				LogPrint ("No inbound tunnels found");	
		}
		else
			LogPrint ("No outbound tunnels found");
	}	
	
	const RouterInfo * NetDb::GetNextFloodfill () const
	{
		for (auto it: m_RouterInfos)
			if (it.second->IsFloodfill () && it.second->IsNTCP ())
				return it.second;
		return 0;
	}	
}
}
