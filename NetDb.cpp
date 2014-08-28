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
			replyTunnel->GetNextIdentHash (), replyTunnel->GetNextTunnelID (), m_IsExploratory, &m_ExcludedPeers, m_IsLeaseSet);
		if (m_IsLeaseSet) // wrap lookup message into garlic
			msg = i2p::garlic::routing.WrapSingleMessage (*router, msg);
		m_ExcludedPeers.insert (router->GetIdentHash ());
		m_LastRouter = router;
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}	

	I2NPMessage * RequestedDestination::CreateRequestMessage (const IdentHash& floodfill)
	{
		I2NPMessage * msg = i2p::CreateDatabaseLookupMsg (m_Destination, 
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_LastRouter = nullptr;
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}	

	void RequestedDestination::ClearExcludedPeers ()
	{
		m_ExcludedPeers.clear ();
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
		uint32_t lastSave = 0, lastPublish = 0, lastKeyspaceRotation = 0;
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
						switch (msg->GetHeader ()->typeID) 
						{
							case eI2NPDatabaseStore:	
								LogPrint ("DatabaseStore");
								HandleDatabaseStoreMsg (msg->GetPayload (), be16toh (msg->GetHeader ()->size)); // TODO
								i2p::DeleteI2NPMessage (msg);
							break;
							case eI2NPDatabaseSearchReply:
								LogPrint ("DatabaseSearchReply");
								HandleDatabaseSearchReplyMsg (msg);
							break;
							case eI2NPDatabaseLookup:
								LogPrint ("DatabaseLookup");
								HandleDatabaseLookupMsg (msg);
							break;	
							default: // WTF?
								LogPrint ("NetDb: unexpected message type ", msg->GetHeader ()->typeID);
								i2p::HandleI2NPMessage (msg);
						}	
						msg = m_Queue.Get ();
					}	
				}
				else // if no new DatabaseStore coming, explore it
				{
					auto numRouters = m_RouterInfos.size ();
					Explore (numRouters < 1500 ? 5 : 1);
				}	

				uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
				if (ts - lastSave >= 60) // save routers, manage leasesets and validate subscriptions every minute
				{
					if (lastSave)
					{
						SaveUpdated (m_NetDbPath);
						ManageLeaseSets ();
						ValidateSubscriptions ();
					}	
					lastSave = ts;
				}	
				if (ts - lastPublish >= 600) // publish every 10 minutes
				{
					Publish ();
					lastPublish = ts;
				}	
				if (ts % 86400 < 60 && ts - lastKeyspaceRotation >= 60)  // wihhin 1 minutes since midnight (86400 = 24*3600)
				{
					KeyspaceRotation ();
					lastKeyspaceRotation = ts;
				} 
			}
			catch (std::exception& ex)
			{
				LogPrint ("NetDb: ", ex.what ());
			}	
		}	
	}	
	
	void NetDb::AddRouterInfo (const IdentHash& ident, uint8_t * buf, int len)
	{	
		DeleteRequestedDestination (ident);
		auto it = m_RouterInfos.find(ident);
		if (it != m_RouterInfos.end ())
		{
			auto ts = it->second->GetTimestamp ();
			it->second->Update (buf, len);
			if (it->second->GetTimestamp () > ts)
				LogPrint ("RouterInfo updated");
		}	
		else	
		{	
			LogPrint ("New RouterInfo added");
			RouterInfo * r = new RouterInfo (buf, len);
			m_RouterInfos[r->GetIdentHash ()] = r;
			if (r->IsFloodfill ())
				m_Floodfills.push_back (r);
		}	
	}	

	void NetDb::AddLeaseSet (const IdentHash& ident, uint8_t * buf, int len)
	{
		bool unsolicited = !DeleteRequestedDestination (ident);
		auto it = m_LeaseSets.find(ident);
		if (it != m_LeaseSets.end ())
		{
			it->second->Update (buf, len); 
			LogPrint ("LeaseSet updated");
		}
		else
		{	
			LogPrint ("New LeaseSet added");
			m_LeaseSets[ident] = new LeaseSet (buf, len, unsolicited);
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
		m_Floodfills.clear ();	

		// load routers now
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();	
		int numRouters = 0;
		boost::filesystem::directory_iterator end;
		for (boost::filesystem::directory_iterator it (p); it != end; ++it)
		{
			if (boost::filesystem::is_directory (it->status()))
			{
				for (boost::filesystem::directory_iterator it1 (it->path ()); it1 != end; ++it1)
				{
#if BOOST_VERSION > 10500
					const std::string& fullPath = it1->path().string();
#else
					const std::string& fullPath = it1->path();
#endif
					RouterInfo * r = new RouterInfo(fullPath);
					if (!r->IsUnreachable () && (!r->UsesIntroducer () || ts < r->GetTimestamp () + 3600*1000LL)) // 1 hour
					{	
						r->DeleteBuffer ();
						m_RouterInfos[r->GetIdentHash ()] = r;
						if (r->IsFloodfill ())
							m_Floodfills.push_back (r);
						numRouters++;
					}	
					else
					{	
						if (boost::filesystem::exists (fullPath))  
							boost::filesystem::remove (fullPath);
						delete r;
					}	
				}	
			}	
		}
		LogPrint (numRouters, " routers loaded");
		LogPrint (m_Floodfills.size (), " floodfills loaded");	
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
				it.second->SaveToFile (GetFilePath(fullDirectory, it.second));
				it.second->SetUpdated (false);
				it.second->DeleteBuffer ();
				count++;
			}
			else 
			{
				// RouterInfo expires after 1 hour if uses introducer
				if ((it.second->UsesIntroducer () && ts > it.second->GetTimestamp () + 3600*1000LL) // 1 hour
				// RouterInfo expires in 72 hours if more than 300
					|| (total > 300 && ts > it.second->GetTimestamp () + 3*24*3600*1000LL)) // 3 days
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

	void NetDb::RequestDestination (const IdentHash& destination, bool isLeaseSet, i2p::tunnel::TunnelPool * pool)
	{
		if (isLeaseSet) // we request LeaseSet through tunnels
		{	
			i2p::tunnel::OutboundTunnel * outbound = pool ? pool->GetNextOutboundTunnel () : i2p::tunnel::tunnels.GetNextOutboundTunnel ();
			if (outbound)
			{
				i2p::tunnel::InboundTunnel * inbound = pool ? pool->GetNextInboundTunnel () :i2p::tunnel::tunnels.GetNextInboundTunnel ();
				if (inbound)
				{
					RequestedDestination * dest = CreateRequestedDestination (destination, isLeaseSet, pool);
					std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
					// request 3 closests floodfills
					for (int i = 0; i < 3; i++)
					{	
						auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
						if (floodfill)
						{		
							// DatabaseLookup message
							msgs.push_back (i2p::tunnel::TunnelMessageBlock 
								{ 
									i2p::tunnel::eDeliveryTypeRouter,
									floodfill->GetIdentHash (), 0,
									dest->CreateRequestMessage (floodfill, inbound)
								});	
						}	
					}
					if (msgs.size () > 0)
					{	
						dest->ClearExcludedPeers (); 
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
			RequestedDestination * dest = CreateRequestedDestination (destination, false, pool);
			auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
			if (floodfill)
				i2p::transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));
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
			AddLeaseSet (msg->key, buf + offset, len - offset);
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
			AddRouterInfo (msg->key, uncompressed, uncomressedSize);
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
			bool deleteDest = true;
			if (num > 0)
			{	
				auto pool = dest ? dest->GetTunnelPool () : nullptr;
				auto outbound = pool ? pool->GetNextOutboundTunnel () : i2p::tunnel::tunnels.GetNextOutboundTunnel ();
				auto inbound = pool ? pool->GetNextInboundTunnel () : i2p::tunnel::tunnels.GetNextInboundTunnel ();
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
						auto r = FindRouter (router); 
						if (!r || i2p::util::GetMillisecondsSinceEpoch () > r->GetTimestamp () + 3600*1000LL) 
						{	
							// router with ident not found or too old (1 hour)
							LogPrint ("Found new/outdated router. Requesting RouterInfo ...");
							if (outbound && inbound && dest->GetLastRouter ())
							{
								RequestedDestination * d1 = CreateRequestedDestination (router, false, false, pool);
								auto msg = d1->CreateRequestMessage (dest->GetLastRouter (), inbound);
								msgs.push_back (i2p::tunnel::TunnelMessageBlock 
									{ 
										i2p::tunnel::eDeliveryTypeRouter,
										dest->GetLastRouter ()->GetIdentHash (), 0, msg
									});
							}	
							else
								RequestDestination (router, false, pool);
						}
						else
							LogPrint ("Bayan");
					}	
					else
					{	
						// reply to our destination. Try other floodfills
						if (outbound && inbound && dest->GetLastRouter ())
						{
							auto r = FindRouter (router); 
							// do we have that floodfill router in our database?
							if (r) 
							{
								// we do
								if (!dest->IsExcluded (r->GetIdentHash ()) && dest->GetNumExcludedPeers () < 30) // TODO: fix TunnelGateway first
								{	
									LogPrint ("Try ", key, " at floodfill ", peerHash); 
									if (!dest->IsLeaseSet ())
									{	
										// tell floodfill about us 
										msgs.push_back (i2p::tunnel::TunnelMessageBlock 
											{ 
												i2p::tunnel::eDeliveryTypeRouter,
												r->GetIdentHash (), 0,
												CreateDatabaseStoreMsg () 
											});  
									}	
									// request destination
									auto msg = dest->CreateRequestMessage (r, inbound);
									msgs.push_back (i2p::tunnel::TunnelMessageBlock 
										{ 
											i2p::tunnel::eDeliveryTypeRouter,
											r->GetIdentHash (), 0, msg
										});
									deleteDest = false;
								}	
							}
							else
							{	
								// request router
								LogPrint ("Found new floodfill. Request it");
								RequestedDestination * d2 = CreateRequestedDestination (router, false, false, pool);
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
							{
								if (!dest->IsExcluded (router) && dest->GetNumExcludedPeers () < 30) 
								{	
									LogPrint ("Try ", key, " at floodfill ", peerHash, " directly"); 
									i2p::transports.SendMessage (router, dest->CreateRequestMessage (router));
									deleteDest = false;
								}	
							}	
							else
								LogPrint ("Can't request LeaseSet");
						}	
					}						
				}
				
				if (outbound && msgs.size () > 0)
					outbound->SendTunnelDataMsg (msgs);	
				if (deleteDest)
				{
					// no more requests for tha destinationation. delete it
					delete it->second;
					m_RequestedDestinations.erase (it);
				}	
			}
			else
			{
				// no more requests for detination possible. delete it
				delete it->second;
				m_RequestedDestinations.erase (it);
			}	
		}
		else
		{	
			LogPrint ("Requested destination for ", key, " not found");
			// it might contain new routers
			for (int i = 0; i < num; i++)
			{
				IdentHash router (buf + 33 + i*32);
				if (!FindRouter (router))
				{	
					LogPrint ("New router ", router.ToBase64 (), " found. Request it");
					RequestDestination (router);
				}	
			}	
		}	
		i2p::DeleteI2NPMessage (msg);
	}	
	
	void NetDb::HandleDatabaseLookupMsg (I2NPMessage * msg)
	{
		uint8_t * buf = msg->GetPayload ();
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (buf, 32, key, 48);
		key[l] = 0;
		LogPrint ("DatabaseLookup for ", key, " recieved");
		uint8_t flag = buf[64];
		uint8_t * excluded = buf + 65;		
		uint32_t replyTunnelID = 0;
		if (flag & 0x01) //reply to tunnel
		{
			replyTunnelID = be32toh (*(uint32_t *)(buf + 64));
			excluded += 4;
		}
		uint16_t numExcluded = be16toh (*(uint16_t *)excluded);	
		excluded += 2;
		if (numExcluded > 512)
		{
			LogPrint ("Number of excluded peers", numExcluded, " exceeds 512");
			numExcluded = 0; // TODO:
		} 

		I2NPMessage * replyMsg = nullptr;

		{
			auto router = FindRouter (buf);
			if (router)
			{
				LogPrint ("Requested RouterInfo ", key, " found");
				router->LoadBuffer ();
				if (router->GetBuffer ()) 
					replyMsg = CreateDatabaseStoreMsg (router);
			}
		}
		if (!replyMsg)
		{
			auto leaseSet = FindLeaseSet (buf);
			if (leaseSet && leaseSet->IsUnsolicited ()) // we don't send back our LeaseSets
			{
				LogPrint ("Requested LeaseSet ", key, " found");
				replyMsg = CreateDatabaseStoreMsg (leaseSet);
			}
		}
		if (!replyMsg)
		{
			LogPrint ("Requested ", key, " not found. ", numExcluded, " excluded");
			std::set<IdentHash> excludedRouters;
			for (int i = 0; i < numExcluded; i++)
			{
				// TODO: check for all zeroes (exploratory)
				excludedRouters.insert (excluded);
				excluded += 32;
			}	
			replyMsg = CreateDatabaseSearchReply (buf, GetClosestFloodfill (buf, excludedRouters));
		}
		else
			excluded += numExcluded*32; // we don't care about exluded	

		if (replyMsg)
		{	
			if (replyTunnelID)
			{
				// encryption might be used though tunnel only
				if (flag & 0x02) // encrypted reply requested
				{
					uint8_t * sessionKey = excluded;
					uint8_t numTags = sessionKey[32];
					if (numTags > 0) 
					{
						uint8_t * sessionTag = sessionKey + 33; // take first tag
						i2p::garlic::GarlicRoutingSession garlic (sessionKey, sessionTag);
						replyMsg = garlic.WrapSingleMessage (replyMsg, nullptr);
					}
				}	
				auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
				if (outbound)
					outbound->SendTunnelDataMsg (buf+32, replyTunnelID, replyMsg);
				else
					i2p::transports.SendMessage (buf+32, i2p::CreateTunnelGatewayMsg (replyTunnelID, replyMsg));
			}
			else
				i2p::transports.SendMessage (buf+32, replyMsg);
		}
		i2p::DeleteI2NPMessage (msg);
	}	

	void NetDb::Explore (int numDestinations)
	{	
		// clean up previous exploratories
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();	
		for (auto it = m_RequestedDestinations.begin (); it != m_RequestedDestinations.end ();)
		{
			if (it->second->IsExploratory () || ts > it->second->GetCreationTime () + 60) // no response for 1 minute
			{
				delete it->second;
				it = m_RequestedDestinations.erase (it);
			}
			else
				it++;
		}	
		// new requests
		auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
		auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		auto inbound = exploratoryPool ? exploratoryPool->GetNextInboundTunnel () : i2p::tunnel::tunnels.GetNextInboundTunnel ();
		bool throughTunnels = outbound && inbound;
		
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint8_t randomHash[32];
		std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
		std::set<const RouterInfo *> floodfills;
		LogPrint ("Exploring new ", numDestinations, " routers ...");
		for (int i = 0; i < numDestinations; i++)
		{	
			rnd.GenerateBlock (randomHash, 32);
			RequestedDestination * dest = CreateRequestedDestination (IdentHash (randomHash), false, true, exploratoryPool);
			auto floodfill = GetClosestFloodfill (randomHash, dest->GetExcludedPeers ());
			if (floodfill && !floodfills.count (floodfill)) // request floodfill only once
			{	
				floodfills.insert (floodfill);
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
					i2p::transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));
			}	
			else
				DeleteRequestedDestination (dest);
		}	
		if (throughTunnels && msgs.size () > 0)
			outbound->SendTunnelDataMsg (msgs);		
	}	

	void NetDb::Publish ()
	{
		std::set<IdentHash> excluded; // TODO: fill up later
		for (int i = 0; i < 3; i++)
		{	
			auto floodfill = GetClosestFloodfill (i2p::context.GetRouterInfo ().GetIdentHash (), excluded);
			if (floodfill)
			{
				LogPrint ("Publishing our RouterInfo to ", floodfill->GetIdentHashAbbreviation ());
				transports.SendMessage (floodfill->GetIdentHash (), CreateDatabaseStoreMsg ());	
				excluded.insert (floodfill->GetIdentHash ());
			}
		}	
	}	
	
	RequestedDestination * NetDb::CreateRequestedDestination (const IdentHash& dest,
		bool isLeaseSet, bool isExploratory, i2p::tunnel::TunnelPool * pool)
	{
		auto it = m_RequestedDestinations.find (dest);
		if (it == m_RequestedDestinations.end ()) // not exist yet
		{
			RequestedDestination * d = new RequestedDestination (dest, isLeaseSet, isExploratory, pool);
			m_RequestedDestinations[dest] = d;
			return d;
		}	
		else
			return it->second;
	}
	
	bool NetDb::DeleteRequestedDestination (const IdentHash& dest)
	{
		auto it = m_RequestedDestinations.find (dest);
		if (it != m_RequestedDestinations.end ())
		{	
			delete it->second;
			m_RequestedDestinations.erase (it);
			return true;
		}	
		return false;
	}	

	void NetDb::DeleteRequestedDestination (RequestedDestination * dest)
	{
		if (dest)
		{
			m_RequestedDestinations.erase (dest->GetDestination ());
			delete dest;
		}	
	}	

	const RouterInfo * NetDb::GetRandomRouter (const RouterInfo * compatibleWith) const
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
					if (!it.second->IsUnreachable () && !it.second->IsHidden () && 
					 (!compatibleWith || it.second->IsCompatible (*compatibleWith)))
						return it.second;
				}	
				else 
					i++;
			}
			// we couldn't find anything, try second pass
			ind = 0;
		}	
		return nullptr; // seems we have too few routers
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
		for (auto it: m_Floodfills)
		{	
			if (!it->IsUnreachable () && !excluded.count (it->GetIdentHash ()))
			{	
				XORMetric m = destKey ^ it->GetRoutingKey ();
				if (m < minMetric)
				{
					minMetric = m;
					r = it;
				}
			}	
		}	
		return r;
	}	

	void NetDb::Subscribe (const IdentHash& ident, i2p::tunnel::TunnelPool * pool)
	{
		LeaseSet * leaseSet = FindLeaseSet (ident);
		if (!leaseSet)
		{
			LogPrint ("LeaseSet requested");	
			RequestDestination (ident, true, pool);
		}
		else
			leaseSet->SetUnsolicited (false);
		m_Subscriptions.insert (ident);
	}
		
	void NetDb::Unsubscribe (const IdentHash& ident)
	{
		m_Subscriptions.erase (ident);
	}

	void NetDb::ValidateSubscriptions ()
	{
		for (auto it : m_Subscriptions)
		{
			LeaseSet * leaseSet = FindLeaseSet (it);
			if (!leaseSet || leaseSet->HasExpiredLeases ())
			{
				LogPrint ("LeaseSet re-requested");	
				RequestDestination (it, true);
			}			
		}
	}

	void NetDb::KeyspaceRotation ()
	{
		for (auto it: m_RouterInfos)
			it.second->UpdateRoutingKey ();
		LogPrint ("Keyspace rotation complete");	
		Publish ();
	}

	void NetDb::ManageLeaseSets ()
	{
		for (auto it = m_LeaseSets.begin (); it != m_LeaseSets.end ();)
		{
			if (it->second->IsUnsolicited () && !it->second->HasNonExpiredLeases ()) // all leases expired
			{
				LogPrint ("LeaseSet ", it->second->GetIdentHash ().ToBase64 (), " expired");
				delete it->second;
				it = m_LeaseSets.erase (it);
			}	
			else 
				it++;
		}
	}

	void NetDb::PublishLeaseSet (const LeaseSet * leaseSet, i2p::tunnel::TunnelPool * pool)
	{
		if (!leaseSet || !pool) return;
		auto outbound = pool->GetNextOutboundTunnel ();
		if (!outbound)
		{
			LogPrint ("Can't publish LeaseSet. No outbound tunnels");
			return;
		}
		std::set<IdentHash> excluded; 
		auto floodfill = GetClosestFloodfill (leaseSet->GetIdentHash (), excluded);	
		if (!floodfill)
		{
			LogPrint ("Can't publish LeaseSet. No floodfills found");
			return;
		}	
		uint32_t replyToken = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
		auto msg = i2p::garlic::routing.WrapSingleMessage (*floodfill, i2p::CreateDatabaseStoreMsg (leaseSet, replyToken));	
		outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, msg);		
	}
}
}
