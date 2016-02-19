#include <string.h>
#include "I2PEndian.h"
#include <fstream>
#include <vector>
#include <boost/asio.hpp>
#include <openssl/rand.h>
#include <zlib.h>
#include "Base.h"
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
	const char NetDb::m_NetDbPath[] = "netDb";
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
		m_Families.LoadCertificates ();	
		Load ();
		if (m_RouterInfos.size () < 25) // reseed if # of router less than 50
			Reseed ();

		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&NetDb::Run, this));
	}
	
	void NetDb::Stop ()
	{
		if (m_IsRunning)
		{	
			for (auto it: m_RouterInfos)
				it.second->SaveProfile ();
			DeleteObsoleteProfiles ();
			m_RouterInfos.clear ();
			m_Floodfills.clear ();
			if (m_Thread)
			{	
				m_IsRunning = false;
				m_Queue.WakeUp ();
				m_Thread->join (); 
				delete m_Thread;
				m_Thread = 0;
			}
			m_LeaseSets.clear();
			m_Requests.Stop ();
		}	
	}	
	
	void NetDb::Run ()
	{
		uint32_t lastSave = 0, lastPublish = 0, lastExploratory = 0, lastManageRequest = 0;
		while (m_IsRunning)
		{	
			try
			{	
				auto msg = m_Queue.GetNextWithTimeout (15000); // 15 sec
				if (msg)
				{	
					int numMsgs = 0;	
					while (msg)
					{
						LogPrint(eLogDebug, "NetDb: got request with type ", (int) msg->GetTypeID ());
						switch (msg->GetTypeID ()) 
						{
							case eI2NPDatabaseStore:	
								HandleDatabaseStoreMsg (msg);
							break;
							case eI2NPDatabaseSearchReply:
								HandleDatabaseSearchReplyMsg (msg);
							break;
							case eI2NPDatabaseLookup:
								HandleDatabaseLookupMsg (msg);
							break;	
							default: // WTF?
								LogPrint (eLogError, "NetDb: unexpected message type ", (int) msg->GetTypeID ());
								//i2p::HandleI2NPMessage (msg);
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
					m_Requests.ManageRequests ();
					lastManageRequest = ts;
				}	
				if (ts - lastSave >= 60) // save routers, manage leasesets and validate subscriptions every minute
				{
					if (lastSave)
					{
						SaveUpdated ();
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
					if (numRouters == 0)
					{
						LogPrint(eLogError, "NetDb: no known routers, reseed seems to be totally failed");
						break;
					}
					if (numRouters < 2500 || ts - lastExploratory >= 90)
					{	
						numRouters = 800/numRouters;
						if (numRouters < 1) numRouters = 1;
						if (numRouters > 9) numRouters = 9;	
						m_Requests.ManageRequests ();					
						Explore (numRouters);
						lastExploratory = ts;
					}	
				}	
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "NetDb: runtime exception: ", ex.what ());
			}	
		}	
	}	
	
	bool NetDb::AddRouterInfo (const uint8_t * buf, int len)
	{
		IdentityEx identity;
		if (identity.FromBuffer (buf, len))
			return AddRouterInfo (identity.GetIdentHash (), buf, len);	
		return false;
	}

	bool NetDb::AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len)
	{	
		bool updated = true;	
		auto r = FindRouter (ident);
		if (r)
		{
			if (r->IsNewer (buf, len))
			{
				r->Update (buf, len);
				LogPrint (eLogInfo, "NetDb: RouterInfo updated: ", ident.ToBase64());
			}
			else
			{
				LogPrint (eLogDebug, "NetDb: RouterInfo is older: ", ident.ToBase64());
				updated = false;
			}
		}	
		else	
		{	
			r = std::make_shared<RouterInfo> (buf, len);
			if (!r->IsUnreachable ())
			{
				LogPrint (eLogInfo, "NetDb: RouterInfo added: ", ident.ToBase64());
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
			else
				updated = false;
		}	
		// take care about requested destination
		m_Requests.RequestComplete (ident, r);
		return updated;
	}	

	bool NetDb::AddLeaseSet (const IdentHash& ident, const uint8_t * buf, int len,
		std::shared_ptr<i2p::tunnel::InboundTunnel> from)
	{
		bool updated = false;
		if (!from) // unsolicited LS must be received directly
		{	
			auto it = m_LeaseSets.find(ident);
			if (it != m_LeaseSets.end ())
			{
				if (it->second->IsNewer (buf, len))
				{
					it->second->Update (buf, len); 
					if (it->second->IsValid ())
					{
						LogPrint (eLogInfo, "NetDb: LeaseSet updated: ", ident.ToBase64());
						updated = true;	
					}
					else
					{
						LogPrint (eLogWarning, "NetDb: LeaseSet update failed: ", ident.ToBase64());
						m_LeaseSets.erase (it);
					}	
				}
				else
					LogPrint (eLogDebug, "NetDb: LeaseSet is older: ", ident.ToBase64());
			}
			else
			{	
				auto leaseSet = std::make_shared<LeaseSet> (buf, len, false); // we don't need leases in netdb 
				if (leaseSet->IsValid ())
				{
					LogPrint (eLogInfo, "NetDb: LeaseSet added: ", ident.ToBase64());
					m_LeaseSets[ident] = leaseSet;
					updated = true;
				}
				else
					LogPrint (eLogError, "NetDb: new LeaseSet validation failed: ", ident.ToBase64());
			}	
		}	
		return updated;
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

	std::shared_ptr<RouterProfile> NetDb::FindRouterProfile (const IdentHash& ident) const
	{
		auto router = FindRouter (ident);
		return router ? router->GetProfile () : nullptr;
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
		LogPrint (eLogInfo, "NetDb: storage directory doesn't exist, trying to create it.");
		if (!boost::filesystem::create_directory (directory))
		{
			LogPrint (eLogError, "NetDb: failed to create directory ", directory);
			return false;
		}

		// list of chars might appear in base64 string
		const char * chars = GetBase64SubstitutionTable (); // 64 bytes
		for (int i = 0; i < 64; i++)
		{
			auto p = directory / (std::string ("r") + chars[i]);
			if (!boost::filesystem::exists (p) && !boost::filesystem::create_directory (p)) 
			{
				LogPrint (eLogError, "NetDb: failed to create directory ", p);
				return false;
			}
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
			LogPrint (eLogWarning, "NetDb: failed to reseed after 10 attempts");
	}

	void NetDb::Load ()
	{
		boost::filesystem::path p(i2p::util::filesystem::GetDataDir() / m_NetDbPath);
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
					if (r->GetRouterIdentity () && !r->IsUnreachable () && 
					    (!r->UsesIntroducer () || ts < r->GetTimestamp () + 3600*1000LL)) // 1 hour
					{	
						r->DeleteBuffer ();
						r->ClearProperties (); // properties are not used for regular routers
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
		LogPrint (eLogInfo, "NetDb: ", numRouters, " routers loaded (", m_Floodfills.size (), " floodfils)");
	}	

	void NetDb::SaveUpdated ()
	{	
		auto GetFilePath = [](const boost::filesystem::path& directory, const RouterInfo * routerInfo)
		{
			std::string s(routerInfo->GetIdentHashBase64());
			return directory / (std::string("r") + s[0]) / ("routerInfo-" + s + ".dat");
		};	

		boost::filesystem::path fullDirectory (i2p::util::filesystem::GetDataDir() / m_NetDbPath);
		int count = 0, deletedCount = 0;
		auto total = m_RouterInfos.size ();
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it: m_RouterInfos)
		{	
			if (it.second->IsUpdated ())
			{
				std::string f = GetFilePath(fullDirectory, it.second.get()).string();
				it.second->SaveToFile (f);
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
				else if (total > 75 && ts > (i2p::context.GetStartupTime () + 600)*1000LL) // routers don't expire if less than 25 or uptime is less than 10 minutes
				{
					if (i2p::context.IsFloodfill ())
					{
						if (ts > it.second->GetTimestamp () + 3600*1000LL) // 1 hours
						{	
							it.second->SetUnreachable (true);
							total--;
						}	
					}
					else if (total > 2500)
					{
						if (ts > it.second->GetTimestamp () + 12*3600*1000LL) // 12 hours
						{	
							it.second->SetUnreachable (true);
							total--;
						}	
					}	
					else if (total > 300)
					{
						if (ts > it.second->GetTimestamp () + 30*3600*1000LL) // 30 hours
						{	
							it.second->SetUnreachable (true);
							total--;
						}	
					}
					else if (total > 120)
					{
						if (ts > it.second->GetTimestamp () + 72*3600*1000LL) // 72 hours
						{	
							it.second->SetUnreachable (true);
							total--;
						}	
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
			LogPrint (eLogInfo, "NetDb: ", count, " new/updated routers saved");
		if (deletedCount > 0)
		{
			LogPrint (eLogDebug, "NetDb: ", deletedCount, " routers deleted");
			// clean up RouterInfos table
			std::unique_lock<std::mutex> l(m_RouterInfosMutex);
			for (auto it = m_RouterInfos.begin (); it != m_RouterInfos.end ();)
			{
				if (it->second->IsUnreachable ())
				{	
					it->second->SaveProfile ();
					it = m_RouterInfos.erase (it);
				}	
				else
					it++;
			}
		}
	}

	void NetDb::RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete)
	{
		auto dest = m_Requests.CreateRequest (destination, false, requestComplete); // non-exploratory
		if (!dest)
		{
			LogPrint (eLogWarning, "NetDb: destination ", destination.ToBase64(), " is requested already");
			return;			
		}

		auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
		if (floodfill)
			transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));	
		else
		{
			LogPrint (eLogError, "NetDb: ", destination.ToBase64(), " destination requested, but no floodfills found");
			m_Requests.RequestComplete (destination, nullptr);
		}	
	}	
	
	void NetDb::HandleDatabaseStoreMsg (std::shared_ptr<const I2NPMessage> m)
	{	
		const uint8_t * buf = m->GetPayload ();
		size_t len = m->GetSize ();		
		IdentHash ident (buf + DATABASE_STORE_KEY_OFFSET);
		if (ident.IsZero ())
		{
			LogPrint (eLogError, "NetDb: database store with zero ident, dropped");
			return;
		}	
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
					LogPrint (eLogError, "NetDb: no outbound tunnels for DatabaseStore reply found");
			}		
			offset += 32;
		}
		size_t payloadOffset = offset;		

		bool updated = false;
		if (buf[DATABASE_STORE_TYPE_OFFSET]) // type
		{
			LogPrint (eLogDebug, "NetDb: store request: LeaseSet");
			updated = AddLeaseSet (ident, buf + offset, len - offset, m->from);
		}	
		else
		{
			LogPrint (eLogDebug, "NetDb: store request: RouterInfo");
			size_t size = bufbe16toh (buf + offset);
			offset += 2;
			if (size > 2048 || size > len - offset)
			{
				LogPrint (eLogError, "NetDb: invalid RouterInfo length ", (int)size);
				return;
			}	
			uint8_t uncompressed[2048];
			size_t uncompressedSize = m_Inflator.Inflate (buf + offset, size, uncompressed, 2048);
			if (uncompressedSize)
				updated = AddRouterInfo (ident, uncompressed, uncompressedSize);
		}	

		if (replyToken && context.IsFloodfill () && updated)
		{
			// flood updated
			auto floodMsg = NewI2NPShortMessage ();
			uint8_t * payload = floodMsg->GetPayload ();		
			memcpy (payload, buf, 33); // key + type
			htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0); // zero reply token
			auto msgLen = len - payloadOffset;
			floodMsg->len += DATABASE_STORE_HEADER_SIZE + msgLen;
			if (floodMsg->len < floodMsg->maxLen)
			{	
				memcpy (payload + DATABASE_STORE_HEADER_SIZE, buf + payloadOffset, msgLen);
				floodMsg->FillI2NPMessageHeader (eI2NPDatabaseStore); 
				std::set<IdentHash> excluded;
				for (int i = 0; i < 3; i++)
				{
					auto floodfill = GetClosestFloodfill (ident, excluded);
					if (floodfill)
						transports.SendMessage (floodfill->GetIdentHash (), floodMsg);
					else
						break;
				}	
			}	
			else
				LogPrint (eLogError, "Database store message is too long ", floodMsg->len);
		}	
	}	

	void NetDb::HandleDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		const uint8_t * buf = msg->GetPayload ();
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (buf, 32, key, 48);
		key[l] = 0;
		int num = buf[32]; // num
		LogPrint (eLogDebug, "NetDb: DatabaseSearchReply for ", key, " num=", num);
		IdentHash ident (buf);
		auto dest = m_Requests.FindRequest (ident); 
		if (dest)
		{	
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
								LogPrint (eLogDebug, "NetDb: Try ", key, " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 ());
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
							LogPrint (eLogWarning, "NetDb: ", key, " was not found on ", count, " floodfills");

						if (msgs.size () > 0)
							outbound->SendTunnelDataMsg (msgs);	
					}	
				}	

				if (deleteDest)
					// no more requests for the destinationation. delete it
					m_Requests.RequestComplete (ident, nullptr);
			}
			else
				// no more requests for detination possible. delete it
				m_Requests.RequestComplete (ident, nullptr);
		}
		else	
			LogPrint (eLogWarning, "NetDb: requested destination for ", key, " not found");

		// try responses
		for (int i = 0; i < num; i++)
		{
			const uint8_t * router = buf + 33 + i*32;
			char peerHash[48];
			int l1 = i2p::data::ByteStreamToBase64 (router, 32, peerHash, 48);
			peerHash[l1] = 0;
			LogPrint (eLogDebug, "NetDb: ", i, ": ", peerHash);

			auto r = FindRouter (router); 
			if (!r || i2p::util::GetMillisecondsSinceEpoch () > r->GetTimestamp () + 3600*1000LL) 
			{	
				// router with ident not found or too old (1 hour)
				LogPrint (eLogDebug, "NetDb: found new/outdated router. Requesting RouterInfo ...");
				RequestDestination (router);
			}
			else
				LogPrint (eLogDebug, "NetDb: [:|||:]");
		}	
	}	
	
	void NetDb::HandleDatabaseLookupMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		const uint8_t * buf = msg->GetPayload ();
		IdentHash ident (buf);
		if (ident.IsZero ())
		{
			LogPrint (eLogError, "NetDb: DatabaseLookup for zero ident. Ignored");
			return;
		}	
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (buf, 32, key, 48);
		key[l] = 0;
		uint8_t flag = buf[64];
		LogPrint (eLogDebug, "NetDb: DatabaseLookup for ", key, " recieved flags=", (int)flag);
		uint8_t lookupType = flag & DATABASE_LOOKUP_TYPE_FLAGS_MASK;
		const uint8_t * excluded = buf + 65;		
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
			LogPrint (eLogWarning, "NetDb: number of excluded peers", numExcluded, " exceeds 512");
			numExcluded = 0; // TODO:
		} 
		
		std::shared_ptr<I2NPMessage> replyMsg;
		if (lookupType == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP)
		{
			LogPrint (eLogInfo, "NetDb: exploratory close to  ", key, " ", numExcluded, " excluded");
			std::set<IdentHash> excludedRouters;
			for (int i = 0; i < numExcluded; i++)
			{
				excludedRouters.insert (excluded);
				excluded += 32;
			}	
			std::vector<IdentHash> routers;
			for (int i = 0; i < 3; i++)
			{
				auto r = GetClosestNonFloodfill (ident, excludedRouters);
				if (r)
				{	
					routers.push_back (r->GetIdentHash ());
					excludedRouters.insert (r->GetIdentHash ());
				}	
			}	
			replyMsg = CreateDatabaseSearchReply (ident, routers);
		}	
		else
		{	
			if (lookupType == DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP  ||
			    lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP)
			{	
				auto router = FindRouter (ident);
				if (router)
				{
					LogPrint (eLogDebug, "NetDb: requested RouterInfo ", key, " found");
					router->LoadBuffer ();
					if (router->GetBuffer ()) 
						replyMsg = CreateDatabaseStoreMsg (router);
				}
			}
			
			if (!replyMsg && (lookupType == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP  ||
			    lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP))
			{
				auto leaseSet = FindLeaseSet (ident);
				if (leaseSet && !leaseSet->IsExpired ()) // we don't send back our LeaseSets
				{
					LogPrint (eLogDebug, "NetDb: requested LeaseSet ", key, " found");
					replyMsg = CreateDatabaseStoreMsg (leaseSet);
				}
			}
			
			if (!replyMsg)
			{
				LogPrint (eLogWarning, "NetDb: Requested ", key, " not found. ", numExcluded, " excluded");
				std::set<IdentHash> excludedRouters;	
				for (int i = 0; i < numExcluded; i++)
				{
					excludedRouters.insert (excluded);
					excluded += 32;
				}
				replyMsg = CreateDatabaseSearchReply (ident, GetClosestFloodfills (ident, 3, excludedRouters));
			}
		}
		
		if (replyMsg)
		{	
			if (replyTunnelID)
			{
				// encryption might be used though tunnel only
				if (flag & DATABASE_LOOKUP_ENCYPTION_FLAG) // encrypted reply requested
				{
					const uint8_t * sessionKey = excluded;
					uint8_t numTags = sessionKey[32];
					if (numTags > 0) 
					{
						const uint8_t * sessionTag = sessionKey + 33; // take first tag
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
	}	

	void NetDb::Explore (int numDestinations)
	{	
		// new requests
		auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
		auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
		auto inbound = exploratoryPool ? exploratoryPool->GetNextInboundTunnel () : nullptr;
		bool throughTunnels = outbound && inbound;
		
		uint8_t randomHash[32];
		std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
		std::set<const RouterInfo *> floodfills;
		LogPrint (eLogInfo, "NetDb: exploring new ", numDestinations, " routers ...");
		for (int i = 0; i < numDestinations; i++)
		{	
			RAND_bytes (randomHash, 32);
			auto dest = m_Requests.CreateRequest (randomHash, true); // exploratory
			if (!dest)
			{	
				LogPrint (eLogWarning, "NetDb: exploratory destination is requested already");
				return; 	
			}	
			auto floodfill = GetClosestFloodfill (randomHash, dest->GetExcludedPeers ());
			if (floodfill && !floodfills.count (floodfill.get ())) // request floodfill only once
			{	
				floodfills.insert (floodfill.get ());
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
				m_Requests.RequestComplete (randomHash, nullptr);
		}	
		if (throughTunnels && msgs.size () > 0)
			outbound->SendTunnelDataMsg (msgs);		
	}	

	void NetDb::Publish ()
	{
		i2p::context.UpdateStats (); // for floodfill
		std::set<IdentHash> excluded; // TODO: fill up later
		for (int i = 0; i < 2; i++)
		{	
			auto floodfill = GetClosestFloodfill (i2p::context.GetRouterInfo ().GetIdentHash (), excluded);
			if (floodfill)
			{
				uint32_t replyToken;
				RAND_bytes ((uint8_t *)&replyToken, 4);
				LogPrint (eLogInfo, "NetDb: Publishing our RouterInfo to ", i2p::data::GetIdentHashAbbreviation(floodfill->GetIdentHash ()), ". reply token=", replyToken);
				transports.SendMessage (floodfill->GetIdentHash (), CreateDatabaseStoreMsg (i2p::context.GetSharedRouterInfo (), replyToken));	
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
					router->IsCompatible (*compatibleWith) && 
					(router->GetCaps () & RouterInfo::eHighBandwidth);
			});
	}	
	
	template<typename Filter>
	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (Filter filter) const
	{
		if (!m_RouterInfos.size ()) return 0;
		uint32_t ind = rand () % m_RouterInfos.size ();	
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
	
	void NetDb::PostI2NPMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		if (msg) m_Queue.Put (msg);	
	}	

	std::shared_ptr<const RouterInfo> NetDb::GetClosestFloodfill (const IdentHash& destination, 
		const std::set<IdentHash>& excluded, bool closeThanUsOnly) const
	{
		std::shared_ptr<const RouterInfo> r;
		XORMetric minMetric;
		IdentHash destKey = CreateRoutingKey (destination);
		if (closeThanUsOnly)
			minMetric = destKey ^ i2p::context.GetIdentHash ();
		else	
			minMetric.SetMax ();
		std::unique_lock<std::mutex> l(m_FloodfillsMutex);
		for (auto it: m_Floodfills)
		{	
			if (!it->IsUnreachable ())
			{	
				XORMetric m = destKey ^ it->GetIdentHash ();
				if (m < minMetric && !excluded.count (it->GetIdentHash ()))
				{
					minMetric = m;
					r = it;
				}
			}	
		}	
		return r;
	}	

	std::vector<IdentHash> NetDb::GetClosestFloodfills (const IdentHash& destination, size_t num,
		std::set<IdentHash>& excluded) const
	{
		struct Sorted
		{
			std::shared_ptr<const RouterInfo> r;
			XORMetric metric;
			bool operator< (const Sorted& other) const { return metric < other.metric; };
		};

		std::set<Sorted> sorted;
		IdentHash destKey = CreateRoutingKey (destination);
		{
			std::unique_lock<std::mutex> l(m_FloodfillsMutex);
			for (auto it: m_Floodfills)
			{
				if (!it->IsUnreachable ())
				{	
					XORMetric m = destKey ^ it->GetIdentHash ();
					if (sorted.size () < num)
						sorted.insert ({it, m});
					else if (m < sorted.rbegin ()->metric)
					{
						sorted.insert ({it, m});
						sorted.erase (std::prev (sorted.end ()));
					}
				}
			}
		}

		std::vector<IdentHash> res;	
		size_t i = 0;			
		for (auto it: sorted)
		{
			if (i < num)
			{
				auto& ident = it.r->GetIdentHash ();
				if (!excluded.count (ident))
				{	
					res.push_back (ident);
					i++;
				}
			}
			else
				break;
		}	
		return res;
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
			if (!it.second->IsFloodfill ())
			{	
				XORMetric m = destKey ^ it.first;
				if (m < minMetric && !excluded.count (it.first))
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
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it = m_LeaseSets.begin (); it != m_LeaseSets.end ();)
		{
			if (ts > it->second->GetExpirationTime ()) 
			{
				LogPrint (eLogWarning, "NetDb: LeaseSet ", it->second->GetIdentHash ().ToBase64 (), " expired");
				it = m_LeaseSets.erase (it);
			}	
			else 
				it++;
		}
	}
}
}
