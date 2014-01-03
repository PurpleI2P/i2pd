#include <endian.h>
#include <fstream>
#include <boost/filesystem.hpp>
#include <cryptopp/gzip.h>
#include "base64.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "Garlic.h"
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
			try
			{	
				I2NPMessage * msg = m_Queue.GetNextWithTimeout (10000); // 10 sec
				if (msg)
				{	
					while (msg)
					{
						if (msg->GetHeader ()->typeID == eI2NPDatabaseStore)
						{	
							HandleDatabaseStoreMsg (msg->GetPayload (), msg->GetLength ()); // TODO
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
			catch (std::exception& ex)
			{
				LogPrint ("NetDb: ", ex.what ());
			}	
		}	
	}	
	
	void NetDb::AddRouterInfo (uint8_t * buf, int len)
	{
		RouterInfo * r = new RouterInfo (buf, len);
		auto it = m_RouterInfos.find(r->GetIdentHash ());
		if (it != m_RouterInfos.end ())
		{
			if (r->GetTimestamp () > it->second->GetTimestamp ())
			{
				LogPrint ("RouterInfo updated");
				*m_RouterInfos[r->GetIdentHash ()] = *r; // we can't replace point because it's used by tunnels
			}	
			else
				delete r;
		}	
		else	
		{	
			LogPrint ("New RouterInfo added");
			m_RouterInfos[r->GetIdentHash ()] = r;
		}	
	}	

	void NetDb::AddLeaseSet (uint8_t * buf, int len)
	{
		LeaseSet * l = new LeaseSet (buf, len);
		m_LeaseSets[l->GetIdentHash ()] = l;
	}	

	RouterInfo * NetDb::FindRouter (const IdentHash& ident) const
	{
		auto it = m_RouterInfos.find (ident);
		if (it != m_RouterInfos.end ())
			return it->second;
		else
			return nullptr;
	}

	LeaseSet * NetDb::FindLeaseSet (const IdentHash& destination) const
	{
		auto it = m_LeaseSets.find (destination);
		if (it != m_LeaseSets.end ())
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
						m_RouterInfos[r->GetIdentHash ()] = r;
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
		auto GetFilePath = [](const char * directory, const RouterInfo * routerInfo)
		{
			return std::string (directory) + "/r" +
				routerInfo->GetIdentHashBase64 ()[0] + "/routerInfo-" + 
				routerInfo->GetIdentHashBase64 () + ".dat";
		};	
			
		int count = 0, deletedCount = 0;
		for (auto it: m_RouterInfos)
		{	
			if (it.second->IsUpdated ())
			{
				std::ofstream r (GetFilePath(directory, it.second));
				r.write ((char *)it.second->GetBuffer (), it.second->GetBufferLen ());
				it.second->SetUpdated (false);
				count++;
			}
			else if (it.second->IsUnreachable ())
			{
				if (boost::filesystem::exists (GetFilePath (directory, it.second)))
				{    
				    boost::filesystem::remove (GetFilePath (directory, it.second));
					deletedCount++;
				}	
			}	
		}	
		if (count > 0)
			LogPrint (count," new/updated routers saved");
		if (deletedCount > 0)
			LogPrint (deletedCount," routers deleted");
	}

	void NetDb::RequestDestination (const char * b32)
	{
		uint8_t destination[32];
		Base32ToByteStream (b32, strlen(b32), destination, 32);
		RequestDestination (destination, true);
	}	

	void NetDb::RequestDestination (const IdentHash& destination, bool isLeaseSet)
	{
		auto floodfill= GetRandomNTCPRouter (true);
		if (floodfill)
			RequestDestination (destination, floodfill, isLeaseSet);
		else
			LogPrint ("No floodfill routers found");
	}	
	
	void NetDb::RequestDestination (const IdentHash& destination, const RouterInfo * floodfill, bool isLeaseSet)
	{
		if (!floodfill) return;
		i2p::tunnel::OutboundTunnel * outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		if (outbound)
		{
			i2p::tunnel::InboundTunnel * inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
			if (inbound)
			{
				I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (destination, inbound->GetNextIdentHash (), 
					inbound->GetNextTunnelID ());
				if (isLeaseSet) // wrap lookup message into garlic
					msg = i2p::garlic::routing.WrapSingleMessage (floodfill, msg);
				outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, msg);
			}	
			else
				LogPrint ("No inbound tunnels found");	
		}
		else
			LogPrint ("No outbound tunnels found");
	}	
	
	void NetDb::HandleDatabaseStoreMsg (uint8_t * buf, size_t len)
	{		
		I2NPDatabaseStoreMsg * msg = (I2NPDatabaseStoreMsg *)buf;
		size_t offset = sizeof (I2NPDatabaseStoreMsg);
		if (msg->replyToken)
			offset += 36;
		if (msg->type)
		{
			LogPrint ("LeaseSet");
			AddLeaseSet (buf + offset, len - offset);
		}	
		else
		{
			LogPrint ("RouterInfo");
			size_t size = be16toh (*(uint16_t *)(buf + offset));
			if (size > 2048)
			{
				LogPrint ("Invalid RouterInfo length ", (int)size);
				return;
			}	
			offset += 2;
			CryptoPP::Gunzip decompressor;
			decompressor.Put (buf + offset, size);
			decompressor.MessageEnd();
			uint8_t uncompressed[2048];
			int uncomressedSize = decompressor.MaxRetrievable ();
			decompressor.Get (uncompressed, uncomressedSize);
			AddRouterInfo (uncompressed, uncomressedSize);
		}	
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
			bool isExploratory = !memcmp (m_Exploratory, buf, 32) && m_LastFloodfill;			
			i2p::tunnel::OutboundTunnel * outbound = isExploratory ? m_LastOutboundTunnel : i2p::tunnel::tunnels.GetNextOutboundTunnel ();
			i2p::tunnel::InboundTunnel * inbound = isExploratory ? m_LastInboundTunnel : i2p::tunnel::tunnels.GetNextInboundTunnel ();
			
			for (int i = 0; i < num; i++)
			{
				uint8_t * router = buf + 33 + i*32;
				char peerHash[48];
				int l1 = i2p::data::ByteStreamToBase64 (router, 32, peerHash, 48);
				peerHash[l1] = 0;
				LogPrint (i,": ", peerHash);

				if (isExploratory)
				{	
					if (m_RouterInfos.find (IdentHash(router)) == m_RouterInfos.end ())
					{	
						LogPrint ("Found new router. Requesting RouterInfo ...");
						if (outbound && inbound)
						{
							I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (router, inbound->GetNextIdentHash (), 
								inbound->GetNextTunnelID ());
							outbound->GetTunnelGateway ().PutTunnelDataMsg (m_LastFloodfill->GetIdentHash (), 0, msg);
						}	
					}
					else
						LogPrint ("Bayan");
				}	
				else
				{	
					// reply to our destination. Try other floodfills
					if (outbound && inbound)
					{
						// do we have that floodfill router in our database?
						if (!FindRouter (router))
						{	
							// request router
							LogPrint ("Found new floodfill. Request it");
							msg = i2p::CreateDatabaseLookupMsg (router, inbound->GetNextIdentHash (), 
								inbound->GetNextTunnelID ());
							outbound->GetTunnelGateway ().PutTunnelDataMsg (
								GetRandomNTCPRouter (true)->GetIdentHash (), 0, msg);
							// request destination
							I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (buf, inbound->GetNextIdentHash (), 
							inbound->GetNextTunnelID ());
							outbound->GetTunnelGateway ().PutTunnelDataMsg (router, 0, msg);
						}	
					}	
				}	
			}
				
			if (outbound)
				outbound->GetTunnelGateway ().SendBuffer ();	
		}	
		i2p::DeleteI2NPMessage (msg);
	}	
	
	void NetDb::Explore ()
	{
		m_LastOutboundTunnel = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		m_LastInboundTunnel = i2p::tunnel::tunnels.GetNextInboundTunnel ();
		if (m_LastOutboundTunnel && m_LastInboundTunnel)
		{
			m_LastFloodfill = GetRandomNTCPRouter (true);
			if (m_LastFloodfill)
			{
				LogPrint ("Exploring new routers ...");
				CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
				rnd.GenerateBlock (m_Exploratory, 32);
				
				m_LastOutboundTunnel->GetTunnelGateway ().PutTunnelDataMsg (m_LastFloodfill->GetIdentHash (), 0,
					CreateDatabaseStoreMsg ()); // tell floodfill about us                                         
				m_LastOutboundTunnel->GetTunnelGateway ().PutTunnelDataMsg (m_LastFloodfill->GetIdentHash (), 0, 
					i2p::CreateDatabaseLookupMsg (m_Exploratory, m_LastInboundTunnel->GetNextIdentHash (), 
					m_LastInboundTunnel->GetNextTunnelID (), true)); // explore
				m_LastOutboundTunnel->GetTunnelGateway ().SendBuffer ();
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
			if (it.second->IsNTCP () && !it.second->IsUnreachable () && 
				(!floodfillOnly || it.second->IsFloodfill ()))
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
