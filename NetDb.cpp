#include <fstream>
#include <boost/filesystem.hpp>
#include "base64.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "NetDb.h"

namespace i2p
{
namespace data
{		
	
	NetDb netdb;

	NetDb::NetDb (): m_IsRunning (false), m_Thread (0), m_LastFloodfill (0)
	{
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
		Load ("netDb");
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
		uint32_t lastTs = 0;
		m_IsRunning = true;
		while (m_IsRunning)
		{	
			I2NPMessage * msg = m_Queue.GetNextWithTimeout (10000); // 10 sec
			if (msg)
			{	
				while (msg)
				{
					if (msg->GetHeader ()->typeID == eI2NPDatabaseStore)
					{	
						i2p::HandleDatabaseStoreMsg (msg->GetPayload (), msg->GetLength ()); // TODO
						i2p::DeleteI2NPMessage (msg);
					}
					else if (msg->GetHeader ()->typeID == eI2NPDatabaseSearchReply)
						HandleDatabaseSearchReplyMsg (msg);
					else // WTF?
					{
						LogPrint ("NetDb: unexpected message type ", msg->GetHeader ()->typeID);
						i2p::HandleI2NPMessage (msg);
					}	
					msg = m_Queue.Get ();
				}	
			}
			else // if no new DatabaseStore coming, explore it
				Explore ();

			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			if (ts - lastTs >= 60) // save routers every minute
			{
				if (lastTs)
					SaveUpdated ("netDb");
				lastTs = ts;
			}	
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

	void NetDb::SaveUpdated (const char * directory)
	{	
		int count = 0;
		for (auto it: m_RouterInfos)
			if (it.second->IsUpdated ())
			{
				std::ofstream r (std::string (directory) + "/routerInfo-" + 
					it.second->GetIdentHashBase64 () + ".dat");
				r.write ((char *)it.second->GetBuffer (), it.second->GetBufferLen ());
				it.second->SetUpdated (false);
				count++;
			}
		if (count > 0)
			LogPrint (count," new routers saved");
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
			{	
				LogPrint ("Found new router. Requesting RouterInfo ...");
				if (m_LastFloodfill)
					RequestDestination (router, m_LastFloodfill->GetIdentHash ());
			}	
			else
				LogPrint ("Bayan");
		}
	//	else
	//		RequestDestination (key, router);
	}	

	void NetDb::HandleDatabaseSearchReplyMsg (I2NPMessage * msg)
	{
		uint8_t * buf = msg->GetPayload ();
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (buf, 32, key, 48);
		key[l] = 0;
		int num = buf[32]; // num
		LogPrint ("DatabaseSearchReply for ", key, " num=", num);
		if (num > 0)
		{
			if (!memcmp (m_Exploratory, buf, 32) && m_LastFloodfill)
			{
				i2p::tunnel::OutboundTunnel * outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
				i2p::tunnel::InboundTunnel * inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
				for (int i = 0; i < num; i++)
				{
					uint8_t * router = buf + 33 + i*32;
					char peerHash[48];
					int l1 = i2p::data::ByteStreamToBase64 (router, 32, peerHash, 48);
					peerHash[l1] = 0;
					LogPrint (i,": ", peerHash);

					if (outbound && inbound)
					{
						I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (router, inbound->GetNextIdentHash (), 
							inbound->GetNextTunnelID ());
						outbound->GetTunnelGateway ().PutTunnelDataMsg (m_LastFloodfill->GetIdentHash (), 0, msg);
					}	
				}
				if (outbound)
					outbound->GetTunnelGateway ().SendBuffer ();
			}	
		}	
		i2p::DeleteI2NPMessage (msg);
	}	
	
	void NetDb::Explore ()
	{
		i2p::tunnel::OutboundTunnel * outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		i2p::tunnel::InboundTunnel * inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
		if (outbound && inbound)
		{
			m_LastFloodfill = GetRandomNTCPRouter (true);
			if (m_LastFloodfill)
			{
				LogPrint ("Exploring new routers ...");
				CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
				rnd.GenerateBlock (m_Exploratory, 32);
				I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (m_Exploratory, inbound->GetNextIdentHash (), 
					inbound->GetNextTunnelID (), true);
				outbound->SendTunnelDataMsg (m_LastFloodfill->GetIdentHash (), 0, msg);
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

	void NetDb::PostI2NPMsg (I2NPMessage * msg)
	{
		if (msg) m_Queue.Put (msg);	
	}	
}
}
