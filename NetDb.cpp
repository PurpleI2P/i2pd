#include <string.h>
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
#include "util.h"

using namespace i2p::transport;

namespace i2p
{
namespace data
{		
	I2NPMessage * RequestedDestination::CreateRequestMessage (std::shared_ptr<const RouterInfo> router,
		std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel)
	{
		I2NPMessage * msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination, 
			replyTunnel->GetNextIdentHash (), replyTunnel->GetNextTunnelID (), m_IsExploratory, 
		    &m_ExcludedPeers);
		m_ExcludedPeers.insert (router->GetIdentHash ());
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
		return msg;
	}	

	I2NPMessage * RequestedDestination::CreateRequestMessage (const IdentHash& floodfill)
	{
		I2NPMessage * msg = i2p::CreateRouterInfoDatabaseLookupMsg (m_Destination, 
			i2p::context.GetRouterInfo ().GetIdentHash () , 0, false, &m_ExcludedPeers);
		m_ExcludedPeers.insert (floodfill);
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
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

#ifndef _WIN32		
	const char NetDb::m_NetDbPath[] = "/netDb";
#else
	const char NetDb::m_NetDbPath[] = "\\netDb";
#endif			
	NetDb netdb;

	NetDb::NetDb (): m_IsRunning (false), m_Thread (nullptr), m_Reseeder (nullptr)
	{
	}
	
	NetDb::~NetDb ()
	{
		Stop ();	
		delete m_Reseeder;
	}	

	void NetDb::Start ()
	{	
		Load (m_NetDbPath);
		if (m_RouterInfos.size () < 50) // reseed if # of router less than 50
		{	
			// try SU3 first
			Reseed ();

			// deprecated
			if (m_Reseeder)
			{
				// if still not enough download .dat files
				int reseedRetries = 0;
				while (m_RouterInfos.size () < 50 && reseedRetries < 10)
				{
					m_Reseeder->reseedNow();
					reseedRetries++;
					Load (m_NetDbPath);
				}
			}
		}	
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&NetDb::Run, this));
	}
	
	void NetDb::Stop ()
	{
		if (m_Thread)
		{	
			m_IsRunning = false;
			m_Queue.WakeUp ();
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}
		m_LeaseSets.clear();
		m_RequestedDestinations.clear ();
	}	
	
	void NetDb::Run ()
	{
		uint32_t lastSave = 0, lastPublish = 0, lastExploratory = 0, lastManageRequest = 0;
		while (m_IsRunning)
		{	
			try
			{	
				I2NPMessage * msg = m_Queue.GetNextWithTimeout (15000); // 15 sec
				if (msg)
				{	
					int numMsgs = 0;	
					while (msg)
					{
						switch (msg->GetTypeID ()) 
						{
							case eI2NPDatabaseStore:	
								LogPrint ("DatabaseStore");
								HandleDatabaseStoreMsg (msg);
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
								LogPrint ("NetDb: unexpected message type ", msg->GetTypeID ());
								i2p::HandleI2NPMessage (msg);
						}	
						if (numMsgs > 100) break;
						msg = m_Queue.Get ();
						numMsgs++;
					}	
				}			
				if (!m_IsRunning) break;

				uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
				if (ts - lastManageRequest >= 15) // manage requests every 15 seconds
				{
					ManageRequests ();
					lastManageRequest = ts;
				}	
				if (ts - lastSave >= 60) // save routers, manage leasesets and validate subscriptions every minute
				{
					if (lastSave)
					{
						SaveUpdated (m_NetDbPath);
						ManageLeaseSets ();
					}	
					lastSave = ts;
				}	
				if (ts - lastPublish >= 2400) // publish every 40 minutes
				{
					Publish ();
					lastPublish = ts;
				}	
				if (ts - lastExploratory >= 30) // exploratory every 30 seconds
				{	
					auto numRouters = m_RouterInfos.size ();
					if (numRouters < 2500 || ts - lastExploratory >= 90)
					{	
						numRouters = 800/numRouters;
						if (numRouters < 1) numRouters = 1;
						if (numRouters > 9) numRouters = 9;	
						ManageRequests ();					
						Explore (numRouters);
						lastExploratory = ts;
					}	
				}	
			}
			catch (std::exception& ex)
			{
				LogPrint ("NetDb: ", ex.what ());
			}	
		}	
	}	
	
	void NetDb::AddRouterInfo (const uint8_t * buf, int len)
	{
		IdentityEx identity;
		if (identity.FromBuffer (buf, len))
			AddRouterInfo (identity.GetIdentHash (), buf, len);	
	}

	void NetDb::AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len)
	{	
		auto r = FindRouter (ident);
		if (r)
		{
			auto ts = r->GetTimestamp ();
			r->Update (buf, len);
			if (r->GetTimestamp () > ts)
				LogPrint ("RouterInfo updated");
		}	
		else	
		{	
			LogPrint ("New RouterInfo added");
			r = std::make_shared<RouterInfo> (buf, len);
			{
				std::unique_lock<std::mutex> l(m_RouterInfosMutex);
				m_RouterInfos[r->GetIdentHash ()] = r;
			}
			if (r->IsFloodfill ())
			{
				std::unique_lock<std::mutex> l(m_FloodfillsMutex);
				m_Floodfills.push_back (r);
			}	
		}	
		// take care about requested destination
		auto it = m_RequestedDestinations.find (ident);
		if (it != m_RequestedDestinations.end ())
		{	
			it->second->Success (r);
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
			m_RequestedDestinations.erase (it);
		}	
	}	

	void NetDb::AddLeaseSet (const IdentHash& ident, const uint8_t * buf, int len,
		std::shared_ptr<i2p::tunnel::InboundTunnel> from)
	{
		if (!from) // unsolicited LS must be received directly
		{	
			auto it = m_LeaseSets.find(ident);
			if (it != m_LeaseSets.end ())
			{
				it->second->Update (buf, len); 
				LogPrint ("LeaseSet updated");
			}
			else
			{	
				LogPrint ("New LeaseSet added");
				m_LeaseSets[ident] = std::make_shared<LeaseSet> (buf, len);
			}	
		}	
	}	

	std::shared_ptr<RouterInfo> NetDb::FindRouter (const IdentHash& ident) const
	{
		std::unique_lock<std::mutex> l(m_RouterInfosMutex);
		auto it = m_RouterInfos.find (ident);
		if (it != m_RouterInfos.end ())
			return it->second;
		else
			return nullptr;
	}

	std::shared_ptr<LeaseSet> NetDb::FindLeaseSet (const IdentHash& destination) const
	{
		auto it = m_LeaseSets.find (destination);
		if (it != m_LeaseSets.end ())
			return it->second;
		else
			return nullptr;
	}

	void NetDb::SetUnreachable (const IdentHash& ident, bool unreachable)
	{
		auto it = m_RouterInfos.find (ident);
		if (it != m_RouterInfos.end ())
			return it->second->SetUnreachable (unreachable);
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

	void NetDb::Reseed ()
	{
		if (!m_Reseeder)
		{		
			m_Reseeder = new Reseeder ();
			m_Reseeder->LoadCertificates (); // we need certificates for SU3 verification
		}
		int reseedRetries = 0;	
		while (reseedRetries < 10 && !m_Reseeder->ReseedNowSU3 ())
			reseedRetries++;
		if (reseedRetries >= 10)
			LogPrint (eLogWarning, "Failed to reseed after 10 attempts");
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
					auto r = std::make_shared<RouterInfo>(fullPath);
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
				it.second->SaveToFile (GetFilePath(fullDirectory, it.second.get ()));
				it.second->SetUpdated (false);
				it.second->SetUnreachable (false);
				it.second->DeleteBuffer ();
				count++;
			}
			else 
			{
				// RouterInfo expires after 1 hour if uses introducer
				if (it.second->UsesIntroducer () && ts > it.second->GetTimestamp () + 3600*1000LL) // 1 hour
					it.second->SetUnreachable (true);
				else if (total > 25 && ts > (i2p::context.GetStartupTime () + 600)*1000LL) // routers don't expire if less than 25 or uptime is less than 10 minutes
				{
					if (i2p::context.IsFloodfill ())
					{
						if (ts > it.second->GetTimestamp () + 3600*1000LL) // 1 hours
							it.second->SetUnreachable (true);
					}
					else if (total > 300)
					{
						if (ts > it.second->GetTimestamp () + 30*3600*1000LL) // 30 hours
							it.second->SetUnreachable (true);
					}
					else if (total > 120)
					{
						if (ts > it.second->GetTimestamp () + 72*3600*1000LL) // 72 hours
							it.second->SetUnreachable (true);
					}
				}
				
				if (it.second->IsUnreachable ())
				{	
					total--;
					// delete RI file
					if (boost::filesystem::exists (GetFilePath (fullDirectory, it.second.get ())))
					{    
						boost::filesystem::remove (GetFilePath (fullDirectory, it.second.get ()));
						deletedCount++;
					}	
					// delete from floodfills list
					if (it.second->IsFloodfill ())
					{
						std::unique_lock<std::mutex> l(m_FloodfillsMutex);
						m_Floodfills.remove (it.second);
					}
				}
			}	
		}	
		if (count > 0)
			LogPrint (count," new/updated routers saved");
		if (deletedCount > 0)
		{
			LogPrint (deletedCount," routers deleted");
			// clean up RouterInfos table
			std::unique_lock<std::mutex> l(m_RouterInfosMutex);
			for (auto it = m_RouterInfos.begin (); it != m_RouterInfos.end ();)
			{
				if (it->second->IsUnreachable ())
					it = m_RouterInfos.erase (it);
				else
					it++;
			}
		}
	}

	void NetDb::RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete)
	{
		// request RouterInfo directly
		auto dest = new RequestedDestination (destination, false); // non-exploratory
		dest->SetRequestComplete (requestComplete);
		{
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
			if (!m_RequestedDestinations.insert (std::make_pair (destination, 
				std::unique_ptr<RequestedDestination> (dest))).second) // not inserted
			{	
				LogPrint (eLogWarning, "Destination ", destination.ToBase64(), " is requested already");
				return; 
			}	
		}
				
		auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
		if (floodfill)
			transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));	
		else
		{
			LogPrint (eLogError, "No floodfills found");
			dest->Fail ();
			std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
			m_RequestedDestinations.erase (destination);
		}	
	}	
	
	void NetDb::HandleDatabaseStoreMsg (I2NPMessage * m)
	{	
		const uint8_t * buf = m->GetPayload ();
		size_t len = m->GetSize ();		
		uint32_t replyToken = bufbe32toh (buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
		size_t offset = DATABASE_STORE_HEADER_SIZE;
		if (replyToken)
		{
			auto deliveryStatus = CreateDeliveryStatusMsg (replyToken);			
			uint32_t tunnelID = bufbe32toh (buf + offset);
			offset += 4;
			if (!tunnelID) // send response directly
				transports.SendMessage (buf + offset, deliveryStatus);
			else
			{
				auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = pool ? pool->GetNextOutboundTunnel () : nullptr;
				if (outbound)
					outbound->SendTunnelDataMsg (buf + offset, tunnelID, deliveryStatus);
				else
				{
					LogPrint (eLogError, "No outbound tunnels for DatabaseStore reply found");
					DeleteI2NPMessage (deliveryStatus);
				}
			}		
			offset += 32;

			if (context.IsFloodfill ())
			{
				// flood it
				std::set<IdentHash> excluded;
				for (int i = 0; i < 3; i++)
				{
					auto floodfill = GetClosestFloodfill (buf + DATABASE_STORE_KEY_OFFSET, excluded);
					if (floodfill)
					{
						excluded.insert (floodfill->GetIdentHash ());	
						auto floodMsg = NewI2NPShortMessage ();
						uint8_t * payload = floodMsg->GetPayload ();		
						memcpy (payload, buf, 33); // key + type
						htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0); // zero reply token
						memcpy (payload + DATABASE_STORE_HEADER_SIZE, buf + offset, len - offset);
						floodMsg->len += DATABASE_STORE_HEADER_SIZE + len -offset;
						FillI2NPMessageHeader (floodMsg, eI2NPDatabaseStore);
						transports.SendMessage (floodfill->GetIdentHash (), floodMsg);
					}	
				}	
			}	
		}
		
		if (buf[DATABASE_STORE_TYPE_OFFSET]) // type
		{
			LogPrint ("LeaseSet");
			AddLeaseSet (buf + DATABASE_STORE_KEY_OFFSET, buf + offset, len - offset, m->from);
		}	
		else
		{
			LogPrint ("RouterInfo");
			size_t size = bufbe16toh (buf + offset);
			offset += 2;
			if (size > 2048 || size > len - offset)
			{
				LogPrint ("Invalid RouterInfo length ", (int)size);
				i2p::DeleteI2NPMessage (m);
				return;
			}	
			try
			{	
				CryptoPP::Gunzip decompressor;
				decompressor.Put (buf + offset, size);
				decompressor.MessageEnd();
				uint8_t uncompressed[2048];
				size_t uncomressedSize = decompressor.MaxRetrievable ();
				decompressor.Get (uncompressed, uncomressedSize);
				AddRouterInfo (buf + DATABASE_STORE_KEY_OFFSET, uncompressed, uncomressedSize);
			}
			catch (CryptoPP::Exception& ex)
			{
				LogPrint (eLogError, "DatabaseStore: ", ex.what ());
			}
		}	
		i2p::DeleteI2NPMessage (m);
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
			auto& dest = it->second;
			bool deleteDest = true;
			if (num > 0)
			{	
				auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = pool ? pool->GetNextOutboundTunnel () : nullptr;
				auto inbound = pool ? pool->GetNextInboundTunnel () : nullptr;
				if (!dest->IsExploratory ())
				{
					// reply to our destination. Try other floodfills
					if (outbound && inbound )
					{
						std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
						auto count = dest->GetExcludedPeers ().size ();
						if (count < 7)
						{	
							auto nextFloodfill = GetClosestFloodfill (dest->GetDestination (), dest->GetExcludedPeers ());
							if (nextFloodfill)
							{	
								// tell floodfill about us 
								msgs.push_back (i2p::tunnel::TunnelMessageBlock 
									{ 
										i2p::tunnel::eDeliveryTypeRouter,
										nextFloodfill->GetIdentHash (), 0,
										CreateDatabaseStoreMsg () 
									});  
								
								// request destination
								LogPrint ("Try ", key, " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 ()); 
								auto msg = dest->CreateRequestMessage (nextFloodfill, inbound);
								msgs.push_back (i2p::tunnel::TunnelMessageBlock 
									{ 
										i2p::tunnel::eDeliveryTypeRouter,
										nextFloodfill->GetIdentHash (), 0, msg
									});
								deleteDest = false;
							}	
						}
						else
							LogPrint (key, " was not found on 7 floodfills");

						if (msgs.size () > 0)
							outbound->SendTunnelDataMsg (msgs);	
					}	
				}	

				if (deleteDest)
				{
					// no more requests for the destinationation. delete it
					it->second->Fail ();
					m_RequestedDestinations.erase (it);
				}	
			}
			else
			{
				// no more requests for detination possible. delete it
				it->second->Fail ();
				m_RequestedDestinations.erase (it);
			}	
		}
		else	
			LogPrint ("Requested destination for ", key, " not found");

		// try responses
		for (int i = 0; i < num; i++)
		{
			uint8_t * router = buf + 33 + i*32;
			char peerHash[48];
			int l1 = i2p::data::ByteStreamToBase64 (router, 32, peerHash, 48);
			peerHash[l1] = 0;
			LogPrint (i,": ", peerHash);

			auto r = FindRouter (router); 
			if (!r || i2p::util::GetMillisecondsSinceEpoch () > r->GetTimestamp () + 3600*1000LL) 
			{	
				// router with ident not found or too old (1 hour)
				LogPrint ("Found new/outdated router. Requesting RouterInfo ...");
				RequestDestination (router);
			}
			else
				LogPrint ("Bayan");	
		}	
		
		i2p::DeleteI2NPMessage (msg);
	}	
	
	void NetDb::HandleDatabaseLookupMsg (I2NPMessage * msg)
	{
		uint8_t * buf = msg->GetPayload ();
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (buf, 32, key, 48);
		key[l] = 0;
		uint8_t flag = buf[64];
		LogPrint ("DatabaseLookup for ", key, " recieved flags=", (int)flag);
		uint8_t lookupType = flag & DATABASE_LOOKUP_TYPE_FLAGS_MASK;
		uint8_t * excluded = buf + 65;		
		uint32_t replyTunnelID = 0;
		if (flag & DATABASE_LOOKUP_DELIVERY_FLAG) //reply to tunnel
		{
			replyTunnelID = bufbe32toh (buf + 64);
			excluded += 4;
		}
		uint16_t numExcluded = bufbe16toh (excluded);	
		excluded += 2;
		if (numExcluded > 512)
		{
			LogPrint ("Number of excluded peers", numExcluded, " exceeds 512");
			numExcluded = 0; // TODO:
		} 
		
		I2NPMessage * replyMsg = nullptr;
		if (lookupType == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP)
		{
			LogPrint ("Exploratory close to  ", key, " ", numExcluded, " excluded");
			std::set<IdentHash> excludedRouters;
			for (int i = 0; i < numExcluded; i++)
			{
				excludedRouters.insert (excluded);
				excluded += 32;
			}	
			std::vector<IdentHash> routers;
			for (int i = 0; i < 3; i++)
			{
				auto r = GetClosestNonFloodfill (buf, excludedRouters);
				if (r)
				{	
					routers.push_back (r->GetIdentHash ());
					excludedRouters.insert (r->GetIdentHash ());
				}	
			}	
			replyMsg = CreateDatabaseSearchReply (buf, routers);
		}	
		else
		{	
			auto router = FindRouter (buf);
			if (router)
			{
				LogPrint ("Requested RouterInfo ", key, " found");
				router->LoadBuffer ();
				if (router->GetBuffer ()) 
					replyMsg = CreateDatabaseStoreMsg (router.get ());
			}
		
			if (!replyMsg)
			{
				auto leaseSet = FindLeaseSet (buf);
				if (leaseSet) // we don't send back our LeaseSets
				{
					LogPrint ("Requested LeaseSet ", key, " found");
					replyMsg = CreateDatabaseStoreMsg (leaseSet.get ());
				}
			}
			if (!replyMsg)
			{
				LogPrint ("Requested ", key, " not found. ", numExcluded, " excluded");
				std::set<IdentHash> excludedRouters;
				for (int i = 0; i < numExcluded; i++)
				{
					excludedRouters.insert (excluded);
					excluded += 32;
				}	
				std::vector<IdentHash> routers;
				for (int i = 0; i < 3; i++)
				{
					auto floodfill = GetClosestFloodfill (buf, excludedRouters);
					if (floodfill)
					{	
						routers.push_back (floodfill->GetIdentHash ());
						excludedRouters.insert (floodfill->GetIdentHash ());
					}	
				}	
				replyMsg = CreateDatabaseSearchReply (buf, routers);
			}
		}
		
		if (replyMsg)
		{	
			if (replyTunnelID)
			{
				// encryption might be used though tunnel only
				if (flag & DATABASE_LOOKUP_ENCYPTION_FLAG) // encrypted reply requested
				{
					uint8_t * sessionKey = excluded;
					uint8_t numTags = sessionKey[32];
					if (numTags > 0) 
					{
						uint8_t * sessionTag = sessionKey + 33; // take first tag
						i2p::garlic::GarlicRoutingSession garlic (sessionKey, sessionTag);
						replyMsg = garlic.WrapSingleMessage (replyMsg);
					}
				}	
				auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
				if (outbound)
					outbound->SendTunnelDataMsg (buf+32, replyTunnelID, replyMsg);
				else
					transports.SendMessage (buf+32, i2p::CreateTunnelGatewayMsg (replyTunnelID, replyMsg));
			}
			else
				transports.SendMessage (buf+32, replyMsg);
		}
		i2p::DeleteI2NPMessage (msg);
	}	

	void NetDb::Explore (int numDestinations)
	{	
		// new requests
		auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
		auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
		auto inbound = exploratoryPool ? exploratoryPool->GetNextInboundTunnel () : nullptr;
		bool throughTunnels = outbound && inbound;
		
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint8_t randomHash[32];
		std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
		std::set<const RouterInfo *> floodfills;
		LogPrint ("Exploring new ", numDestinations, " routers ...");
		for (int i = 0; i < numDestinations; i++)
		{	
			rnd.GenerateBlock (randomHash, 32);
			auto dest = new RequestedDestination (randomHash, true); // exploratory
			{
				std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
				if (!m_RequestedDestinations.insert (std::make_pair (randomHash, 
					std::unique_ptr<RequestedDestination> (dest))).second) // not inserted
				{	
					LogPrint (eLogWarning, "Exploratory destination is requested already");
					return; 
				}	
			}	
			auto floodfill = GetClosestFloodfill (randomHash, dest->GetExcludedPeers ());
			if (floodfill && !floodfills.count (floodfill.get ())) // request floodfill only once
			{	
				floodfills.insert (floodfill.get ());
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
			{
				std::unique_lock<std::mutex> l(m_RequestedDestinationsMutex);
				m_RequestedDestinations.erase (dest->GetDestination ());
			}	
		}	
		if (throughTunnels && msgs.size () > 0)
			outbound->SendTunnelDataMsg (msgs);		
	}	

	void NetDb::Publish ()
	{
		std::set<IdentHash> excluded; // TODO: fill up later
		for (int i = 0; i < 2; i++)
		{	
			auto floodfill = GetClosestFloodfill (i2p::context.GetRouterInfo ().GetIdentHash (), excluded);
			if (floodfill)
			{
				uint32_t replyToken = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
				LogPrint ("Publishing our RouterInfo to ", floodfill->GetIdentHashAbbreviation (), ". reply token=", replyToken);
				transports.SendMessage (floodfill->GetIdentHash (), CreateDatabaseStoreMsg ((RouterInfo *)nullptr, replyToken));	
				excluded.insert (floodfill->GetIdentHash ());
			}
		}	
	}		

	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter () const
	{
		return GetRandomRouter (
			[](std::shared_ptr<const RouterInfo> router)->bool 
			{ 
				return !router->IsHidden (); 
			});
	}	
	
	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith) const
	{
		return GetRandomRouter (
			[compatibleWith](std::shared_ptr<const RouterInfo> router)->bool 
			{ 
				return !router->IsHidden () && router != compatibleWith && 
					router->IsCompatible (*compatibleWith); 
			});
	}	

	std::shared_ptr<const RouterInfo> NetDb::GetRandomPeerTestRouter () const
	{
		return GetRandomRouter (
			[](std::shared_ptr<const RouterInfo> router)->bool 
			{ 
				return !router->IsHidden () && router->IsPeerTesting (); 
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomIntroducer () const
	{
		return GetRandomRouter (
			[](std::shared_ptr<const RouterInfo> router)->bool 
			{ 
				return !router->IsHidden () && router->IsIntroducer (); 
			});
	}	
	
	std::shared_ptr<const RouterInfo> NetDb::GetHighBandwidthRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith) const
	{
		return GetRandomRouter (
			[compatibleWith](std::shared_ptr<const RouterInfo> router)->bool 
			{ 
				return !router->IsHidden () && router != compatibleWith &&
					router->IsCompatible (*compatibleWith) && (router->GetCaps () & RouterInfo::eHighBandwidth); 
			});
	}	
	
	template<typename Filter>
	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (Filter filter) const
	{
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t ind = rnd.GenerateWord32 (0, m_RouterInfos.size () - 1);	
		for (int j = 0; j < 2; j++)
		{	
			uint32_t i = 0;
			std::unique_lock<std::mutex> l(m_RouterInfosMutex);
			for (auto it: m_RouterInfos)
			{	
				if (i >= ind)
				{	
					if (!it.second->IsUnreachable () && filter (it.second))
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

	std::shared_ptr<const RouterInfo> NetDb::GetClosestFloodfill (const IdentHash& destination, 
		const std::set<IdentHash>& excluded) const
	{
		std::shared_ptr<const RouterInfo> r;
		XORMetric minMetric;
		IdentHash destKey = CreateRoutingKey (destination);
		minMetric.SetMax ();
		std::unique_lock<std::mutex> l(m_FloodfillsMutex);
		for (auto it: m_Floodfills)
		{	
			if (!it->IsUnreachable () && !excluded.count (it->GetIdentHash ()))
			{	
				XORMetric m = destKey ^ it->GetIdentHash ();
				if (m < minMetric)
				{
					minMetric = m;
					r = it;
				}
			}	
		}	
		return r;
	}	

	std::shared_ptr<const RouterInfo> NetDb::GetClosestNonFloodfill (const IdentHash& destination, 
		const std::set<IdentHash>& excluded) const
	{
		std::shared_ptr<const RouterInfo> r;
		XORMetric minMetric;
		IdentHash destKey = CreateRoutingKey (destination);
		minMetric.SetMax ();
		// must be called from NetDb thread only
		for (auto it: m_RouterInfos)
		{	
			if (!it.second->IsFloodfill () && !excluded.count (it.first))
			{	
				XORMetric m = destKey ^ it.first;
				if (m < minMetric)
				{
					minMetric = m;
					r = it.second;
				}
			}	
		}	
		return r;
	}	
	
	void NetDb::ManageLeaseSets ()
	{
		for (auto it = m_LeaseSets.begin (); it != m_LeaseSets.end ();)
		{
			if (!it->second->HasNonExpiredLeases ()) // all leases expired
			{
				LogPrint ("LeaseSet ", it->second->GetIdentHash ().ToBase64 (), " expired");
				it = m_LeaseSets.erase (it);
			}	
			else 
				it++;
		}
	}

	void NetDb::ManageRequests ()
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
						auto nextFloodfill = GetClosestFloodfill (dest->GetDestination (), dest->GetExcludedPeers ());
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
