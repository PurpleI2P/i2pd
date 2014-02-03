#include "I2PEndian.h"
#include <fstream>
#include <vector>
#include <boost/asio.hpp>
#include <cryptopp/gzip.h>
#include "base64.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "Transports.h"
#include "RouterContext.h"
#include "Garlic.h"
#include "NetDb.h"
#include "Reseed.h"
#include "util.h"

namespace i2p
{
namespace data
{		
	I2NPMessage * RequestedDestination::CreateRequestMessage (const RouterInfo * router,
		const i2p::tunnel::InboundTunnel * replyTunnel)
	{
		I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (m_Destination, 
			replyTunnel->GetNextIdentHash (), replyTunnel->GetNextTunnelID (), m_IsExploratory, &m_ExcludedPeers);
		if (m_IsLeaseSet) // wrap lookup message into garlic
			msg = i2p::garlic::routing.WrapSingleMessage (router, msg);
		m_ExcludedPeers.insert (router->GetIdentHash ());
		m_LastRouter = router;
		m_LastReplyTunnel = replyTunnel;
		return msg;
	}	

	I2NPMessage * RequestedDestination::CreateRequestMessage (const IdentHash& floodfill)
	{
		I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (m_Destination, 
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_LastRouter = nullptr;
		m_LastReplyTunnel = nullptr;
		return msg;
	}	

#ifndef _WIN32		
	const char NetDb::m_NetDbPath[] = "/netDb";
#else
	const char NetDb::m_NetDbPath[] = "\\netDb";
#endif			
	NetDb netdb;

	NetDb::NetDb (): m_IsRunning (false), m_ReseedRetries (0), m_Thread (0)
	{
	}
	
	NetDb::~NetDb ()
	{
		Stop ();
		for (auto l:m_LeaseSets)
			delete l.second;
		for (auto r:m_RouterInfos)
			delete r.second;
		for (auto r:m_RequestedDestinations)
			delete r.second;
	}	

	void NetDb::Start ()
	{	
		Load (m_NetDbPath);
		while (m_RouterInfos.size () < 100 && m_ReseedRetries < 10)
		{
			Reseeder reseeder;
			reseeder.reseedNow();
			m_ReseedRetries++;
			Load (m_NetDbPath);
		}	
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
							i2p::HandleI2NPMessage (msg, false);
						}	
						msg = m_Queue.Get ();
					}	
				}
				else // if no new DatabaseStore coming, explore it
					Explore ();

				uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
				if (ts - lastTs >= 60) // save routers every minute
				{
					if (lastTs)
						SaveUpdated (m_NetDbPath);
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
		DeleteRequestedDestination (r->GetIdentHash ());
		auto it = m_RouterInfos.find(r->GetIdentHash ());
		if (it != m_RouterInfos.end ())
		{
			if (r->GetTimestamp () > it->second->GetTimestamp ())
			{
				LogPrint ("RouterInfo updated");
				*(it->second) = *r; // we can't replace pointer because it's used by tunnels
			}				
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
		DeleteRequestedDestination (l->GetIdentHash ());
		auto it = m_LeaseSets.find(l->GetIdentHash ());
		if (it != m_LeaseSets.end ())
		{
			LogPrint ("LeaseSet updated");
			*(it->second) = *l; // we can't replace pointer because it's used by streams
			delete l;
		}
		else
		{	
			LogPrint ("New LeaseSet added");
			m_LeaseSets[l->GetIdentHash ()] = l;
		}	
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

	// TODO: Move to reseed and/or scheduled tasks. (In java version, scheduler fix this as well as sort RIs.)
	bool NetDb::CreateNetDb(boost::filesystem::path directory)
	{
		LogPrint (directory.string(), " doesn't exist, trying to create it.");
		if (!boost::filesystem::create_directory (directory))
		{
			LogPrint("Failed to create directory ", directory.string());
			return false;
		}

		// list of chars might appear in base64 string
		const char * chars = GetBase64SubstitutionTable (); // 64 bytes
		boost::filesystem::path suffix;
		for (int i = 0; i < 64; i++)
		{
#ifndef _WIN32
			suffix = std::string ("/r") + chars[i];
#else
			suffix = std::string ("\\r") + chars[i];
#endif
			if (!boost::filesystem::create_directory( boost::filesystem::path (directory / suffix) )) return false;
		}
		return true;
	}

	void NetDb::Load (const char * directory)
	{
		boost::filesystem::path p (i2p::util::filesystem::GetDataDir());
		p /= (directory);
		if (!boost::filesystem::exists (p))
		{
			// seems netDb doesn't exist yet
			if (!CreateNetDb(p)) return;
		}
		// make sure we cleanup netDb from previous attempts
		for (auto r: m_RouterInfos)
			delete r.second;
		m_RouterInfos.clear ();	

		// load routers now
		int numRouters = 0;
		boost::filesystem::directory_iterator end;
		for (boost::filesystem::directory_iterator it (p); it != end; ++it)
		{
			if (boost::filesystem::is_directory (it->status()))
			{
				for (boost::filesystem::directory_iterator it1 (it->path ()); it1 != end; ++it1)
				{
#if BOOST_VERSION > 10500
					RouterInfo * r = new RouterInfo (it1->path().string().c_str ());
#else
					RouterInfo * r = new RouterInfo(it1->path().c_str());
#endif
					m_RouterInfos[r->GetIdentHash ()] = r;
					numRouters++;
				}	
			}	
		}
		LogPrint (numRouters, " routers loaded");
	}	

	void NetDb::SaveUpdated (const char * directory)
	{	
		auto GetFilePath = [](const char * directory, const RouterInfo * routerInfo)
		{
#ifndef _WIN32
			return std::string (directory) + "/r" +
				routerInfo->GetIdentHashBase64 ()[0] + "/routerInfo-" +
#else
			return std::string (directory) + "\\r" +
				routerInfo->GetIdentHashBase64 ()[0] + "\\routerInfo-" +
#endif
				routerInfo->GetIdentHashBase64 () + ".dat";
		};	

		boost::filesystem::path p (i2p::util::filesystem::GetDataDir());
		p /= (directory);
#if BOOST_VERSION > 10500		
		const char * fullDirectory = p.string().c_str ();
#else
		const char * fullDirectory = p.c_str ();
#endif		
		int count = 0, deletedCount = 0;
		auto total = m_RouterInfos.size ();
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it: m_RouterInfos)
		{	
			if (it.second->IsUpdated ())
			{
				std::ofstream r (GetFilePath(fullDirectory, it.second), std::ofstream::binary);
				r.write ((char *)it.second->GetBuffer (), it.second->GetBufferLen ());
				it.second->SetUpdated (false);
				count++;
			}
			else 
			{
				// RouterInfo expires in 72 hours if more than 300
				if (total > 300 && ts > it.second->GetTimestamp () + 3*24*3600*1000LL) // 3 days
				{	
					total--;
					it.second->SetUnreachable (true);
				}	
				
				if (it.second->IsUnreachable ())
				{	
					if (boost::filesystem::exists (GetFilePath (fullDirectory, it.second)))
					{    
						boost::filesystem::remove (GetFilePath (fullDirectory, it.second));
						deletedCount++;
					}	
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
		if (isLeaseSet) // we request LeaseSet through tunnels
		{	
			i2p::tunnel::OutboundTunnel * outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
			if (outbound)
			{
				i2p::tunnel::InboundTunnel * inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
				if (inbound)
				{
					RequestedDestination * dest = CreateRequestedDestination (destination, isLeaseSet);
					auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
					if (floodfill)
					{	
						std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
						// DatabaseLookup message
						dest->SetLastOutboundTunnel (outbound);
						msgs.push_back (i2p::tunnel::TunnelMessageBlock 
							{ 
								i2p::tunnel::eDeliveryTypeRouter,
								floodfill->GetIdentHash (), 0,
								dest->CreateRequestMessage (floodfill, inbound)
							});	
				
						outbound->SendTunnelDataMsg (msgs);	
					}	
					else
						LogPrint ("No more floodfills found");
				}	
				else
					LogPrint ("No inbound tunnels found");	
			}
			else
				LogPrint ("No outbound tunnels found");
		}	
		else // RouterInfo is requested directly
		{
			RequestedDestination * dest = CreateRequestedDestination (destination, false);
			auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
			if (floodfill)
			{
				dest->SetLastOutboundTunnel (nullptr);
				i2p::transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));
			}	
		}	
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
			size_t uncomressedSize = decompressor.MaxRetrievable ();
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
		auto it = m_RequestedDestinations.find (IdentHash (buf));
		if (it != m_RequestedDestinations.end ())
		{	
			RequestedDestination * dest = it->second;
			if (num > 0)
			{	
				i2p::tunnel::OutboundTunnel * outbound = dest->GetLastOutboundTunnel ();
				const i2p::tunnel::InboundTunnel * inbound = dest->GetLastReplyTunnel ();
				std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
				
				for (int i = 0; i < num; i++)
				{
					uint8_t * router = buf + 33 + i*32;
					char peerHash[48];
					int l1 = i2p::data::ByteStreamToBase64 (router, 32, peerHash, 48);
					peerHash[l1] = 0;
					LogPrint (i,": ", peerHash);

					if (dest->IsExploratory ())
					{	
						if (!FindRouter (router)) // router with ident not found
						{	
							LogPrint ("Found new router. Requesting RouterInfo ...");
							if (outbound && inbound)
							{
								RequestedDestination * d1 = CreateRequestedDestination (router, false, false);
								d1->SetLastOutboundTunnel (outbound);
								auto msg = d1->CreateRequestMessage (dest->GetLastRouter (), dest->GetLastReplyTunnel ());
								msgs.push_back (i2p::tunnel::TunnelMessageBlock 
									{ 
										i2p::tunnel::eDeliveryTypeRouter,
										dest->GetLastRouter ()->GetIdentHash (), 0, msg
									});
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
							auto r = FindRouter (router); 
							// do we have that floodfill router in our database?
							if (r)
							{
								if (!dest->IsExcluded (r->GetIdentHash ()) && dest->GetNumExcludedPeers () < 30) // TODO: fix TunnelGateway first
								{	
									// request destination
									auto msg = dest->CreateRequestMessage (r, dest->GetLastReplyTunnel ());
									msgs.push_back (i2p::tunnel::TunnelMessageBlock 
										{ 
											i2p::tunnel::eDeliveryTypeRouter,
											r->GetIdentHash (), 0, msg
										});
								}	
							}
							else
							{	
								// request router
								LogPrint ("Found new floodfill. Request it");
								RequestedDestination * d2 = CreateRequestedDestination (router, false, false);
								d2->SetLastOutboundTunnel (outbound);
								I2NPMessage * msg = d2->CreateRequestMessage (dest->GetLastRouter (), inbound);
								msgs.push_back (i2p::tunnel::TunnelMessageBlock 
									{ 
										i2p::tunnel::eDeliveryTypeRouter,
										dest->GetLastRouter ()->GetIdentHash (), 0, msg
									});
							}	
						}
						else // we should send directly
						{
							if (!dest->IsLeaseSet ()) // if not LeaseSet
								i2p::transports.SendMessage (router, dest->CreateRequestMessage (router));
							else
								LogPrint ("Can't request LeaseSet");
						}	
					}	
				}
				
				if (outbound && msgs.size () > 0)
					outbound->SendTunnelDataMsg (msgs);	
			}
			else
			{
				// no more requests for detination possible. delete it
				delete it->second;
				m_RequestedDestinations.erase (it);
			}	
		}
		else
			LogPrint ("Requested destination for ", key, " not found");
		i2p::DeleteI2NPMessage (msg);
	}	
	
	void NetDb::Explore ()
	{
		auto outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		auto inbound = i2p::tunnel::tunnels.GetNextInboundTunnel ();
		if (outbound && inbound)
		{
			auto floodfill = GetRandomRouter (outbound->GetEndpointRouter (), true);
			if (floodfill)
			{
				LogPrint ("Exploring new routers ...");
				CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
				uint8_t randomHash[32];
				rnd.GenerateBlock (randomHash, 32);
				RequestedDestination * dest = CreateRequestedDestination (IdentHash (randomHash), false, true);
				dest->SetLastOutboundTunnel (outbound);

				std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
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
				outbound->SendTunnelDataMsg (msgs);	
			}	
		}
	}	

	RequestedDestination * NetDb::CreateRequestedDestination (const IdentHash& dest,
		bool isLeaseSet, bool isExploratory)
	{
		auto it = m_RequestedDestinations.find (dest);
		if (it == m_RequestedDestinations.end ()) // not exist yet
		{
			RequestedDestination * d = new RequestedDestination (dest, isLeaseSet, isExploratory);
			m_RequestedDestinations[dest] = d;
			return d;
		}	
		else
			return it->second;
	}
	
	void NetDb::DeleteRequestedDestination (const IdentHash& dest)
	{
		auto it = m_RequestedDestinations.find (dest);
		if (it != m_RequestedDestinations.end ())
		{	
			delete it->second;
			m_RequestedDestinations.erase (it);
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

	const RouterInfo * NetDb::GetRandomRouter (const RouterInfo * compatibleWith, bool floodfillOnly) const
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t ind = rnd.GenerateWord32 (0, m_RouterInfos.size () - 1);	
		for (int j = 0; j < 2; j++)
		{	
			uint32_t i = 0;
			for (auto it: m_RouterInfos)
			{	
				if (i >= ind)
				{	
					if (!it.second->IsUnreachable () && 
					 (!compatibleWith || it.second->IsCompatible (*compatibleWith)) &&
					 (!floodfillOnly || it.second->IsFloodfill ()))
						return it.second;
				}	
				else 
					i++;
			}
			// we couldn't find anything, try second pass
			ind = 0;
		}	
		return nullptr; // seem we have too few routers
	}	

	void NetDb::PostI2NPMsg (I2NPMessage * msg)
	{
		if (msg) m_Queue.Put (msg);	
	}	

	const RouterInfo * NetDb::GetClosestFloodfill (const IdentHash& destination, 
		const std::set<IdentHash>& excluded) const
	{
		RouterInfo * r = nullptr;
		XORMetric minMetric;
		RoutingKey destKey = CreateRoutingKey (destination);
		minMetric.SetMax ();
		for (auto it: m_RouterInfos)
		{	
			if (it.second->IsFloodfill () &&! it.second->IsUnreachable () && !excluded.count (it.first))
			{	
				XORMetric m = destKey ^ it.second->GetRoutingKey ();
				if (m < minMetric)
				{
					minMetric = m;
					r = it.second;
				}
			}	
		}	
		return r;
	}	

}
}
