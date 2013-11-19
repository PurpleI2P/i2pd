#include <boost/filesystem.hpp>
#include "Log.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "NetDb.h"

namespace i2p
{
namespace data
{		
	
	NetDb netdb;

	NetDb::NetDb (): m_IsRunning (false), m_Thread (0)
	{
		Load ("netDb");
	}
	
	NetDb::~NetDb ()
	{
		Stop ();
		for (auto l:m_LeaseSets)
			delete l.second;
		for (auto r:m_RouterInfos)
			delete r.second;
	}	

	void NetDb::Start ()
	{
		m_Thread = new std::thread (std::bind (&NetDb::Run, this));
	}
	
	void NetDb::Stop ()
	{
		if (m_Thread)
		{	
			m_IsRunning = false;
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
	}	
	
	void NetDb::Run ()
	{
		m_IsRunning = true;
		while (m_IsRunning)
		{	
			sleep (10);
			Explore ();
		}	
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
				I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (destination, inbound->GetNextIdentHash (), 
					inbound->GetNextTunnelID ());
				outbound->SendTunnelDataMsg (router, 0, msg);
			}	
			else
				LogPrint ("No inbound tunnels found");	
		}
		else
			LogPrint ("No outbound tunnels found");
	}	

	void NetDb::HandleDatabaseSearchReply (const uint8_t * key, const uint8_t * router)	
	{
		if (!memcmp (m_Exploratory, key, 32))
		{
			if (m_RouterInfos.find (std::string ((const char *)router, 32)) == m_RouterInfos.end ())
				LogPrint ("Found new router");
			else
				LogPrint ("Bayan");
		}
		else
			RequestDestination (key, router);
	}	

	void NetDb::Explore ()
	{
		i2p::tunnel::OutboundTunnel * outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		i2p::tunnel::InboundTunnel * inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
		if (outbound && inbound)
		{
			const RouterInfo * floodFill = GetRandomNTCPRouter (true);
			if (floodFill)
			{
				LogPrint ("Exploring new routers ...");
				CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
				rnd.GenerateBlock (m_Exploratory, 32);
				I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (m_Exploratory, inbound->GetNextIdentHash (), 
					inbound->GetNextTunnelID (), true);
				outbound->SendTunnelDataMsg (floodFill->GetIdentHash (), 0, msg);
			}	
		}
	}	

	const RouterInfo * NetDb::GetRandomNTCPRouter (bool floodfillOnly) const
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t ind = rnd.GenerateWord32 (0, m_RouterInfos.size () - 1), i = 0;
		RouterInfo * last = nullptr;
		for (auto it: m_RouterInfos)
		{	
			if (it.second->IsNTCP () && (!floodfillOnly || it.second->IsFloodfill ()))
				last = it.second;
			if (i >= ind) break;
			else i++;
		}	
		return last;
	}	

	const RouterInfo * NetDb::GetRandomRouter () const
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t ind = rnd.GenerateWord32 (0, m_RouterInfos.size () - 1), i = 0;
		for (auto it: m_RouterInfos)
		{	
			if (i >= ind) return it.second;
			else i++;
		}	
		return nullptr;
	}	
}
}
