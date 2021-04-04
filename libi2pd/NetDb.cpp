/*
* Copyright (c) 2013-2021, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <fstream>
#include <vector>
#include <boost/asio.hpp>
#include <stdexcept>

#include "I2PEndian.h"
#include "Base.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "Transports.h"
#include "NTCP2.h"
#include "RouterContext.h"
#include "Garlic.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "Config.h"
#include "NetDb.hpp"
#include "util.h"

using namespace i2p::transport;

namespace i2p
{
namespace data
{
	NetDb netdb;

	NetDb::NetDb (): m_IsRunning (false), m_Thread (nullptr), m_Reseeder (nullptr), m_Storage("netDb", "r", "routerInfo-", "dat"), m_PersistProfiles (true), m_HiddenMode(false)
	{
	}

	NetDb::~NetDb ()
	{
		Stop ();
		delete m_Reseeder;
	}

	void NetDb::Start ()
	{
		m_Storage.SetPlace(i2p::fs::GetDataDir());
		m_Storage.Init(i2p::data::GetBase64SubstitutionTable(), 64);
		InitProfilesStorage ();
		m_Families.LoadCertificates ();
		Load ();

		uint16_t threshold; i2p::config::GetOption("reseed.threshold", threshold);
		if (m_RouterInfos.size () < threshold) // reseed if # of router less than threshold
			Reseed ();
		else if (!GetRandomRouter (i2p::context.GetSharedRouterInfo (), false))
			Reseed (); // we don't have a router we can connect to. Trying to reseed
		
		i2p::config::GetOption("persist.profiles", m_PersistProfiles);

		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&NetDb::Run, this));
	}

	void NetDb::Stop ()
	{
		if (m_IsRunning)
		{
			if (m_PersistProfiles)
				for (auto& it: m_RouterInfos)
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
		i2p::util::SetThreadName("NetDB");

		uint32_t lastSave = 0, lastPublish = 0, lastExploratory = 0, lastManageRequest = 0, lastDestinationCleanup = 0;
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
							case eI2NPDeliveryStatus:
								HandleDeliveryStatusMsg (msg);
							break;
							case eI2NPDummyMsg:
								// plain RouterInfo from NTCP2 with flags for now
								HandleNTCP2RouterInfoMsg (msg);
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
				if (!i2p::transport::transports.IsOnline ()) continue; // don't manage netdb when offline
			
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
				if (ts - lastDestinationCleanup >= i2p::garlic::INCOMING_TAGS_EXPIRATION_TIMEOUT)
				{
					i2p::context.CleanupDestination ();
					lastDestinationCleanup = ts;
				}

				// publish 
				if (!m_HiddenMode && i2p::transport::transports.IsOnline ()) 
				{
					bool publish = false;
					if (m_PublishReplyToken)
					{
						if (ts - lastPublish >= NETDB_PUBLISH_CONFIRMATION_TIMEOUT) publish = true;
					}
					else if (i2p::context.GetLastUpdateTime () > lastPublish || 
						ts - lastPublish >= NETDB_PUBLISH_INTERVAL) publish = true;
					if (publish) // update timestamp and publish
					{
						i2p::context.UpdateTimestamp (ts);
						Publish ();
						lastPublish = ts;
					}
				}
				if (ts - lastExploratory >= 30) // exploratory every 30 seconds
				{
					auto numRouters = m_RouterInfos.size ();
					if (!numRouters)
						throw std::runtime_error("No known routers, reseed seems to be totally failed");
					else // we have peers now
						m_FloodfillBootstrap = nullptr;
					if (numRouters < 2500 || ts - lastExploratory >= 90)
					{
						numRouters = 800/numRouters;
						if (numRouters < 1) numRouters = 1;
						if (numRouters > 9) numRouters = 9;
						m_Requests.ManageRequests ();
						if(!m_HiddenMode)
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

	void NetDb::SetHidden(bool hide)
	{
		// TODO: remove reachable addresses from router info
		m_HiddenMode = hide;
	}

	bool NetDb::AddRouterInfo (const uint8_t * buf, int len)
	{
		bool updated;
		AddRouterInfo (buf, len, updated);
		return updated;
	}

	std::shared_ptr<const RouterInfo> NetDb::AddRouterInfo (const uint8_t * buf, int len, bool& updated)
	{
		IdentityEx identity;
		if (identity.FromBuffer (buf, len))
			return AddRouterInfo (identity.GetIdentHash (), buf, len, updated);
		updated = false;
		return nullptr;
	}

	bool NetDb::AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len)
	{
		bool updated;
		AddRouterInfo (ident, buf, len, updated);
		return updated;
	}

	std::shared_ptr<const RouterInfo> NetDb::AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len, bool& updated)
	{
		updated = true;
		auto r = FindRouter (ident);
		if (r)
		{
			if (r->IsNewer (buf, len))
			{
				bool wasFloodfill = r->IsFloodfill ();
				r->Update (buf, len);
				LogPrint (eLogInfo, "NetDb: RouterInfo updated: ", ident.ToBase64());
				if (wasFloodfill != r->IsFloodfill ()) // if floodfill status updated
				{
					LogPrint (eLogDebug, "NetDb: RouterInfo floodfill status updated: ", ident.ToBase64());
					std::unique_lock<std::mutex> l(m_FloodfillsMutex);
					if (wasFloodfill)
						m_Floodfills.remove (r);
					else if (r->IsEligibleFloodfill ())
						m_Floodfills.push_back (r);
				}
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
			if (!r->IsUnreachable () && r->HasValidAddresses ())
			{
				bool inserted = false;
				{
					std::unique_lock<std::mutex> l(m_RouterInfosMutex);
					inserted = m_RouterInfos.insert ({r->GetIdentHash (), r}).second;
				}
				if (inserted)
				{
					LogPrint (eLogInfo, "NetDb: RouterInfo added: ", ident.ToBase64());
					if (r->IsFloodfill () && r->IsEligibleFloodfill ()) 
					{
						std::unique_lock<std::mutex> l(m_FloodfillsMutex);
						m_Floodfills.push_back (r);
					}
				}
				else
				{
					LogPrint (eLogWarning, "NetDb: Duplicated RouterInfo ", ident.ToBase64());
					updated = false;
				}
			}
			else
				updated = false;
		}
		// take care about requested destination
		m_Requests.RequestComplete (ident, r);
		return r;
	}

	bool NetDb::AddLeaseSet (const IdentHash& ident, const uint8_t * buf, int len)
	{
		std::unique_lock<std::mutex> lock(m_LeaseSetsMutex);
		bool updated = false;
		auto it = m_LeaseSets.find(ident);
		if (it != m_LeaseSets.end () && it->second->GetStoreType () == i2p::data::NETDB_STORE_TYPE_LEASESET)
		{
			// we update only is existing LeaseSet is not LeaseSet2
			uint64_t expires;
			if(LeaseSetBufferValidate(buf, len, expires))
			{
				if(it->second->GetExpirationTime() < expires)
				{
					it->second->Update (buf, len, false); // signature is verified already
					LogPrint (eLogInfo, "NetDb: LeaseSet updated: ", ident.ToBase32());
					updated = true;
				}
				else
					LogPrint(eLogDebug, "NetDb: LeaseSet is older: ", ident.ToBase32());
			}
			else
				LogPrint(eLogError, "NetDb: LeaseSet is invalid: ", ident.ToBase32());
		}
		else
		{
			auto leaseSet = std::make_shared<LeaseSet> (buf, len, false); // we don't need leases in netdb
			if (leaseSet->IsValid ())
			{
				LogPrint (eLogInfo, "NetDb: LeaseSet added: ", ident.ToBase32());
				m_LeaseSets[ident] = leaseSet;
				updated = true;
			}
			else
				LogPrint (eLogError, "NetDb: new LeaseSet validation failed: ", ident.ToBase32());
		}
		return updated;
	}

	bool NetDb::AddLeaseSet2 (const IdentHash& ident, const uint8_t * buf, int len, uint8_t storeType)
	{
		std::unique_lock<std::mutex> lock(m_LeaseSetsMutex);
		auto leaseSet = std::make_shared<LeaseSet2> (storeType, buf, len, false); // we don't need leases in netdb
		if (leaseSet->IsValid ())
		{
			auto it = m_LeaseSets.find(ident);
			if (it == m_LeaseSets.end () || it->second->GetStoreType () != storeType ||
				leaseSet->GetPublishedTimestamp () > it->second->GetPublishedTimestamp ())
			{
				if (leaseSet->IsPublic () && !leaseSet->IsExpired ())
				{
					// TODO: implement actual update
					LogPrint (eLogInfo, "NetDb: LeaseSet2 updated: ", ident.ToBase32());
					m_LeaseSets[ident] = leaseSet;
					return true;
				}
				else
				{
					LogPrint (eLogWarning, "NetDb: Unpublished or expired LeaseSet2 received: ", ident.ToBase32());
					m_LeaseSets.erase (ident);
				}
			}
		}
		else
			LogPrint (eLogError, "NetDb: new LeaseSet2 validation failed: ", ident.ToBase32());
		return false;
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
		std::unique_lock<std::mutex> lock(m_LeaseSetsMutex);
		auto it = m_LeaseSets.find (destination);
		if (it != m_LeaseSets.end ())
			return it->second;
		else
			return nullptr;
	}

	std::shared_ptr<RouterProfile> NetDb::FindRouterProfile (const IdentHash& ident) const
	{
		if (!m_PersistProfiles)
			return nullptr;

		auto router = FindRouter (ident);
		return router ? router->GetProfile () : nullptr;
	}

	void NetDb::SetUnreachable (const IdentHash& ident, bool unreachable)
	{
		auto it = m_RouterInfos.find (ident);
		if (it != m_RouterInfos.end ())
			return it->second->SetUnreachable (unreachable);
	}

	void NetDb::Reseed ()
	{
		if (!m_Reseeder)
		{
			m_Reseeder = new Reseeder ();
			m_Reseeder->LoadCertificates (); // we need certificates for SU3 verification
		}

		// try reseeding from floodfill first if specified
		std::string riPath;
		if(i2p::config::GetOption("reseed.floodfill", riPath)) {
			auto ri = std::make_shared<RouterInfo>(riPath);
			if (ri->IsFloodfill()) {
				const uint8_t * riData = ri->GetBuffer();
				int riLen = ri->GetBufferLen();
				if(!i2p::data::netdb.AddRouterInfo(riData, riLen)) {
					// bad router info
					LogPrint(eLogError, "NetDb: bad router info");
					return;
				}
				m_FloodfillBootstrap = ri;
				ReseedFromFloodfill(*ri);
				// don't try reseed servers if trying to bootstrap from floodfill
				return;
			}
		}

		m_Reseeder->Bootstrap ();
	}

	void NetDb::ReseedFromFloodfill(const RouterInfo & ri, int numRouters, int numFloodfills)
	{
		LogPrint(eLogInfo, "NetDB: reseeding from floodfill ", ri.GetIdentHashBase64());
		std::vector<std::shared_ptr<i2p::I2NPMessage> > requests;

		i2p::data::IdentHash ourIdent = i2p::context.GetIdentHash();
		i2p::data::IdentHash ih = ri.GetIdentHash();
		i2p::data::IdentHash randomIdent;

		// make floodfill lookups
		while(numFloodfills > 0) {
			randomIdent.Randomize();
			auto msg = i2p::CreateRouterInfoDatabaseLookupMsg(randomIdent, ourIdent, 0, false);
			requests.push_back(msg);
			numFloodfills --;
		}

		// make regular router lookups
		while(numRouters > 0) {
			randomIdent.Randomize();
			auto msg = i2p::CreateRouterInfoDatabaseLookupMsg(randomIdent, ourIdent, 0, true);
			requests.push_back(msg);
			numRouters --;
		}

		// send them off
		i2p::transport::transports.SendMessages(ih, requests);
	}

	bool NetDb::LoadRouterInfo (const std::string & path)
	{
		auto r = std::make_shared<RouterInfo>(path);
		if (r->GetRouterIdentity () && !r->IsUnreachable () &&
				(!r->HasUnreachableCap () || m_LastLoad < r->GetTimestamp () + NETDB_INTRODUCEE_EXPIRATION_TIMEOUT*1000LL)) // 1 hour
		{
			r->DeleteBuffer ();
			r->ClearProperties (); // properties are not used for regular routers
			m_RouterInfos[r->GetIdentHash ()] = r;
			if (r->IsFloodfill () && r->IsReachable ()) // floodfill must be reachable
				m_Floodfills.push_back (r);
		}
		else
		{
			LogPrint(eLogWarning, "NetDb: RI from ", path, " is invalid. Delete");
			i2p::fs::Remove(path);
		}
		return true;
	}

	void NetDb::VisitLeaseSets(LeaseSetVisitor v)
	{
		std::unique_lock<std::mutex> lock(m_LeaseSetsMutex);
		for ( auto & entry : m_LeaseSets)
			v(entry.first, entry.second);
	}

	void NetDb::VisitStoredRouterInfos(RouterInfoVisitor v)
	{
		m_Storage.Iterate([v] (const std::string & filename)
		{
			auto ri = std::make_shared<i2p::data::RouterInfo>(filename);
				v(ri);
		});
	}

	void NetDb::VisitRouterInfos(RouterInfoVisitor v)
	{
		std::unique_lock<std::mutex> lock(m_RouterInfosMutex);
		for ( const auto & item : m_RouterInfos )
			v(item.second);
	}

	size_t NetDb::VisitRandomRouterInfos(RouterInfoFilter filter, RouterInfoVisitor v, size_t n)
	{
		std::vector<std::shared_ptr<const RouterInfo> > found;
		const size_t max_iters_per_cyle = 3;
		size_t iters = max_iters_per_cyle;
		while(n > 0)
		{
			std::unique_lock<std::mutex> lock(m_RouterInfosMutex);
			uint32_t idx = rand () % m_RouterInfos.size ();
			uint32_t i = 0;
			for (const auto & it : m_RouterInfos) {
				if(i >= idx) // are we at the random start point?
				{
					// yes, check if we want this one
					if(filter(it.second))
					{
						// we have a match
						--n;
						found.push_back(it.second);
						// reset max iterations per cycle
						iters = max_iters_per_cyle;
						break;
					}
				}
				else // not there yet
					++i;
			}
			// we have enough
			if(n == 0) break;
			--iters;
			// have we tried enough this cycle ?
			if(!iters) {
				// yes let's try the next cycle
				--n;
				iters = max_iters_per_cyle;
			}
		}
		// visit the ones we found
		size_t visited = 0;
		for(const auto & ri : found ) {
			v(ri);
			++visited;
		}
		return visited;
	}

	void NetDb::Load ()
	{
		// make sure we cleanup netDb from previous attempts
		m_RouterInfos.clear ();
		m_Floodfills.clear ();

		m_LastLoad = i2p::util::GetSecondsSinceEpoch();
		std::vector<std::string> files;
		m_Storage.Traverse(files);
		for (const auto& path : files)
			LoadRouterInfo(path);

		LogPrint (eLogInfo, "NetDb: ", m_RouterInfos.size(), " routers loaded (", m_Floodfills.size (), " floodfils)");
	}

	void NetDb::SaveUpdated ()
	{
		int updatedCount = 0, deletedCount = 0;
		auto total = m_RouterInfos.size ();
		uint64_t expirationTimeout = NETDB_MAX_EXPIRATION_TIMEOUT*1000LL;
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
		auto uptime = i2p::context.GetUptime ();
		// routers don't expire if less than 90 or uptime is less than 1 hour
		bool checkForExpiration = total > NETDB_MIN_ROUTERS && uptime > 600; // 10 minutes
		if (checkForExpiration && uptime > 3600) // 1 hour
			expirationTimeout = i2p::context.IsFloodfill () ? NETDB_FLOODFILL_EXPIRATION_TIMEOUT*1000LL :
				NETDB_MIN_EXPIRATION_TIMEOUT*1000LL + (NETDB_MAX_EXPIRATION_TIMEOUT - NETDB_MIN_EXPIRATION_TIMEOUT)*1000LL*NETDB_MIN_ROUTERS/total;

		for (auto& it: m_RouterInfos)
		{
			std::string ident = it.second->GetIdentHashBase64();
			std::string path  = m_Storage.Path(ident);
			if (it.second->IsUpdated ())
			{
				it.second->SaveToFile (path);
				it.second->SetUpdated (false);
				it.second->SetUnreachable (false);
				it.second->DeleteBuffer ();
				updatedCount++;
				continue;
			}
			// make router reachable back if too few routers
			if (it.second->IsUnreachable () && total - deletedCount < NETDB_MIN_ROUTERS)	
				it.second->SetUnreachable (false); 
			// find & mark expired routers
			if (it.second->HasUnreachableCap ())
			{
				if (ts > it.second->GetTimestamp () + NETDB_INTRODUCEE_EXPIRATION_TIMEOUT*1000LL)
				// RouterInfo expires after 1 hour if uses introducer
					it.second->SetUnreachable (true);
			}
			else if (checkForExpiration && ts > it.second->GetTimestamp () + expirationTimeout)
					it.second->SetUnreachable (true);

			if (it.second->IsUnreachable ())
			{
				// delete RI file
				m_Storage.Remove(ident);
				deletedCount++;
				if (total - deletedCount < NETDB_MIN_ROUTERS) checkForExpiration = false;	
			}
		} // m_RouterInfos iteration

		if (updatedCount > 0)
			LogPrint (eLogInfo, "NetDb: saved ", updatedCount, " new/updated routers");
		if (deletedCount > 0)
		{
			LogPrint (eLogInfo, "NetDb: deleting ", deletedCount, " unreachable routers");
			// clean up RouterInfos table
			{
				std::unique_lock<std::mutex> l(m_RouterInfosMutex);
				for (auto it = m_RouterInfos.begin (); it != m_RouterInfos.end ();)
				{
					if (it->second->IsUnreachable ())
					{
						if (m_PersistProfiles) it->second->SaveProfile ();
						it = m_RouterInfos.erase (it);
						continue;
					}
					++it;
				}
			}
			// clean up expired floodfills or not floodfills anymore
			{
				std::unique_lock<std::mutex> l(m_FloodfillsMutex);
				for (auto it = m_Floodfills.begin (); it != m_Floodfills.end ();)
					if ((*it)->IsUnreachable () || !(*it)->IsFloodfill ())
						it = m_Floodfills.erase (it);
					else
						++it;
			}
		}
	}

	void NetDb::RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete, bool direct)
	{
		auto dest = m_Requests.CreateRequest (destination, false, requestComplete); // non-exploratory
		if (!dest)
		{
			LogPrint (eLogWarning, "NetDb: destination ", destination.ToBase64(), " is requested already");
			return;
		}

		auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
		if (floodfill)
		{
			if (direct && !floodfill->IsReachableFrom (i2p::context.GetRouterInfo ()) &&
			    !i2p::transport::transports.IsConnected (floodfill->GetIdentHash ())) 
				direct = false; // floodfill can't be reached directly
			if (direct)
				transports.SendMessage (floodfill->GetIdentHash (), dest->CreateRequestMessage (floodfill->GetIdentHash ()));
			else
			{
				auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = pool ? pool->GetNextOutboundTunnel () : nullptr;
				auto inbound = pool ? pool->GetNextInboundTunnel () : nullptr;
				if (outbound &&	inbound)
					outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, dest->CreateRequestMessage (floodfill, inbound));
				else
				{
					LogPrint (eLogError, "NetDb: ", destination.ToBase64(), " destination requested, but no tunnels found");
					m_Requests.RequestComplete (destination, nullptr);	
				}		
			}		
		}	
		else
		{
			LogPrint (eLogError, "NetDb: ", destination.ToBase64(), " destination requested, but no floodfills found");
			m_Requests.RequestComplete (destination, nullptr);
		}
	}

	void NetDb::RequestDestinationFrom (const IdentHash& destination, const IdentHash & from, bool exploritory, RequestedDestination::RequestComplete requestComplete)
	{

		auto dest = m_Requests.CreateRequest (destination, exploritory, requestComplete); // non-exploratory
		if (!dest)
		{
			LogPrint (eLogWarning, "NetDb: destination ", destination.ToBase64(), " is requested already");
			return;
		}
		LogPrint(eLogInfo, "NetDb: destination ", destination.ToBase64(), " being requested directly from ", from.ToBase64());
		// direct
		transports.SendMessage (from, dest->CreateRequestMessage (nullptr, nullptr));
	}

	void NetDb::HandleNTCP2RouterInfoMsg (std::shared_ptr<const I2NPMessage> m)
	{
		uint8_t flood = m->GetPayload ()[0] & NTCP2_ROUTER_INFO_FLAG_REQUEST_FLOOD;
		bool updated;
		auto ri = AddRouterInfo (m->GetPayload () + 1, m->GetPayloadLength () - 1, updated); // without flags
		if (flood && updated && context.IsFloodfill () && ri)
		{
			auto floodMsg = CreateDatabaseStoreMsg (ri, 0); // replyToken = 0
			Flood (ri->GetIdentHash (), floodMsg);
		}
	}

	void NetDb::HandleDatabaseStoreMsg (std::shared_ptr<const I2NPMessage> m)
	{
		const uint8_t * buf = m->GetPayload ();
		size_t len = m->GetSize ();
		IdentHash ident (buf + DATABASE_STORE_KEY_OFFSET);
		if (ident.IsZero ())
		{
			LogPrint (eLogDebug, "NetDb: database store with zero ident, dropped");
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
					LogPrint (eLogWarning, "NetDb: no outbound tunnels for DatabaseStore reply found");
			}
			offset += 32;
		}
		// we must send reply back before this check
		if (ident == i2p::context.GetIdentHash ())
		{
			LogPrint (eLogDebug, "NetDb: database store with own RouterInfo received, dropped");
			return;
		}
		size_t payloadOffset = offset;

		bool updated = false;
		uint8_t storeType = buf[DATABASE_STORE_TYPE_OFFSET];
		if (storeType) // LeaseSet or LeaseSet2
		{
			if (!m->from) // unsolicited LS must be received directly
			{
				if (storeType == NETDB_STORE_TYPE_LEASESET) // 1
				{
					LogPrint (eLogDebug, "NetDb: store request: LeaseSet for ", ident.ToBase32());
					updated = AddLeaseSet (ident, buf + offset, len - offset);
				}
				else // all others are considered as LeaseSet2
				{
					LogPrint (eLogDebug, "NetDb: store request: LeaseSet2 of type ", storeType, " for ", ident.ToBase32());
					updated = AddLeaseSet2 (ident, buf + offset, len - offset, storeType);
				}
			}
		}
		else // RouterInfo
		{
			LogPrint (eLogDebug, "NetDb: store request: RouterInfo");
			size_t size = bufbe16toh (buf + offset);
			offset += 2;
			if (size > MAX_RI_BUFFER_SIZE || size > len - offset)
			{
				LogPrint (eLogError, "NetDb: invalid RouterInfo length ", (int)size);
				return;
			}
			uint8_t uncompressed[MAX_RI_BUFFER_SIZE];
			size_t uncompressedSize = m_Inflator.Inflate (buf + offset, size, uncompressed, MAX_RI_BUFFER_SIZE);
			if (uncompressedSize && uncompressedSize < MAX_RI_BUFFER_SIZE)
				updated = AddRouterInfo (ident, uncompressed, uncompressedSize);
			else
			{
				LogPrint (eLogInfo, "NetDb: decompression failed ", uncompressedSize);
				return;
			}
		}

		if (replyToken && context.IsFloodfill () && updated)
		{
			// flood updated
			auto floodMsg = NewI2NPShortMessage ();
			uint8_t * payload = floodMsg->GetPayload ();
			memcpy (payload, buf, 33); // key + type
			htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0); // zero reply token
			size_t msgLen = len - payloadOffset;
			floodMsg->len += DATABASE_STORE_HEADER_SIZE + msgLen;
			if (floodMsg->len < floodMsg->maxLen)
			{
				memcpy (payload + DATABASE_STORE_HEADER_SIZE, buf + payloadOffset, msgLen);
				floodMsg->FillI2NPMessageHeader (eI2NPDatabaseStore);
				Flood (ident, floodMsg);
			}
			else
				LogPrint (eLogError, "NetDb: Database store message is too long ", floodMsg->len);
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
					if (outbound && inbound)
					{
						auto count = dest->GetExcludedPeers ().size ();
						if (count < 7)
						{
							auto nextFloodfill = GetClosestFloodfill (dest->GetDestination (), dest->GetExcludedPeers ());
							if (nextFloodfill)
							{
								// request destination
								LogPrint (eLogDebug, "NetDb: Try ", key, " at ", count, " floodfill ", nextFloodfill->GetIdentHash ().ToBase64 ());
								outbound->SendTunnelDataMsg (nextFloodfill->GetIdentHash (), 0,
									dest->CreateRequestMessage (nextFloodfill, inbound));
								deleteDest = false;
							}
						}
						else
							LogPrint (eLogWarning, "NetDb: ", key, " was not found on ", count, " floodfills");
					}
				}

				if (deleteDest)
					// no more requests for the destinationation. delete it
					m_Requests.RequestComplete (ident, nullptr);
			}
			else
				// no more requests for destination possible. delete it
				m_Requests.RequestComplete (ident, nullptr);
		}
		else if(!m_FloodfillBootstrap)
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
				if(m_FloodfillBootstrap)
					RequestDestinationFrom(router, m_FloodfillBootstrap->GetIdentHash(), true);
				else
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

		IdentHash replyIdent(buf + 32);
		uint8_t flag = buf[64];


		LogPrint (eLogDebug, "NetDb: DatabaseLookup for ", key, " received flags=", (int)flag);
		uint8_t lookupType = flag & DATABASE_LOOKUP_TYPE_FLAGS_MASK;
		const uint8_t * excluded = buf + 65;
		uint32_t replyTunnelID = 0;
		if (flag & DATABASE_LOOKUP_DELIVERY_FLAG) //reply to tunnel
		{
			replyTunnelID = bufbe32toh (excluded);
			excluded += 4;
		}
		uint16_t numExcluded = bufbe16toh (excluded);
		excluded += 2;
		if (numExcluded > 512)
		{
			LogPrint (eLogWarning, "NetDb: number of excluded peers", numExcluded, " exceeds 512");
			return;
		}

		std::shared_ptr<I2NPMessage> replyMsg;
		if (lookupType == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP)
		{
			LogPrint (eLogInfo, "NetDb: exploratory close to ", key, " ", numExcluded, " excluded");
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
			if (lookupType == DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP ||
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

			if (!replyMsg && (lookupType == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP ||
				lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP))
			{
				auto leaseSet = FindLeaseSet (ident);
				if (!leaseSet)
				{
					// no lease set found
					LogPrint(eLogDebug, "NetDb: requested LeaseSet not found for ", ident.ToBase32());
				}
				else if (!leaseSet->IsExpired ()) // we don't send back our LeaseSets
				{
					LogPrint (eLogDebug, "NetDb: requested LeaseSet ", key, " found");
					replyMsg = CreateDatabaseStoreMsg (ident, leaseSet);
				}
			}

			if (!replyMsg)
			{
				std::set<IdentHash> excludedRouters;
				const uint8_t * exclude_ident = excluded;
				for (int i = 0; i < numExcluded; i++)
				{
					excludedRouters.insert (exclude_ident);
					exclude_ident += 32;
				}
				auto closestFloodfills = GetClosestFloodfills (ident, 3, excludedRouters, true);
				if (closestFloodfills.empty ())
					LogPrint (eLogWarning, "NetDb: Requested ", key, " not found, ", numExcluded, " peers excluded");
				replyMsg = CreateDatabaseSearchReply (ident, closestFloodfills);
		}
		}
		excluded += numExcluded * 32;
		if (replyMsg)
		{
			if (replyTunnelID)
			{
				// encryption might be used though tunnel only
				if (flag & (DATABASE_LOOKUP_ENCRYPTION_FLAG | DATABASE_LOOKUP_ECIES_FLAG)) // encrypted reply requested
				{
					const uint8_t * sessionKey = excluded;
					const uint8_t numTags = excluded[32];
					if (numTags)
					{
						if (flag & DATABASE_LOOKUP_ECIES_FLAG)
						{
							uint64_t tag;
							memcpy (&tag, excluded + 33, 8);
							replyMsg = i2p::garlic::WrapECIESX25519AEADRatchetMessage (replyMsg, sessionKey, tag);
						}
						else
						{
							const i2p::garlic::SessionTag sessionTag(excluded + 33); // take first tag
							i2p::garlic::ElGamalAESSession garlic (sessionKey, sessionTag);
							replyMsg = garlic.WrapSingleMessage (replyMsg);
						}
						if (!replyMsg)
							LogPrint (eLogError, "NetDb: failed to wrap message");
					}
					else
						LogPrint(eLogWarning, "NetDb: encrypted reply requested but no tags provided");
				}
				auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
				if (outbound)
					outbound->SendTunnelDataMsg (replyIdent, replyTunnelID, replyMsg);
				else
					transports.SendMessage (replyIdent, i2p::CreateTunnelGatewayMsg (replyTunnelID, replyMsg));
			}
			else
				transports.SendMessage (replyIdent, replyMsg);
		}
	}

	void NetDb::HandleDeliveryStatusMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		if (m_PublishReplyToken == bufbe32toh (msg->GetPayload () + DELIVERY_STATUS_MSGID_OFFSET))
		{
			LogPrint (eLogInfo, "NetDb: Publishing confirmed. reply token=", m_PublishReplyToken);
			m_PublishExcluded.clear ();
			m_PublishReplyToken = 0;
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
			if (floodfill)
			{
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

		if (m_PublishExcluded.size () > NETDB_MAX_PUBLISH_EXCLUDED_FLOODFILLS)
		{
			LogPrint (eLogError, "NetDb: Couldn't publish our RouterInfo to ", NETDB_MAX_PUBLISH_EXCLUDED_FLOODFILLS, " closest routers. Try again");
			m_PublishExcluded.clear ();
		}
		
		auto floodfill = GetClosestFloodfill (i2p::context.GetIdentHash (), m_PublishExcluded);
		if (floodfill)
		{
			uint32_t replyToken;
			RAND_bytes ((uint8_t *)&replyToken, 4);
			LogPrint (eLogInfo, "NetDb: Publishing our RouterInfo to ", i2p::data::GetIdentHashAbbreviation(floodfill->GetIdentHash ()), ". reply token=", replyToken);
			m_PublishExcluded.insert (floodfill->GetIdentHash ());
			m_PublishReplyToken = replyToken;
			if (floodfill->IsReachableFrom (i2p::context.GetRouterInfo ()) || // are we able to connect?
			    i2p::transport::transports.IsConnected (floodfill->GetIdentHash ()))  // already connected ?    
				// send directly
				transports.SendMessage (floodfill->GetIdentHash (), CreateDatabaseStoreMsg (i2p::context.GetSharedRouterInfo (), replyToken));
			else
			{
				// otherwise through exploratory	
				auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
				auto inbound = exploratoryPool ? exploratoryPool->GetNextInboundTunnel () : nullptr;	
				if (inbound && outbound)
					outbound->SendTunnelDataMsg (floodfill->GetIdentHash (), 0, 
						CreateDatabaseStoreMsg (i2p::context.GetSharedRouterInfo (), replyToken, inbound));	
			}		
		}
	}

	void NetDb::Flood (const IdentHash& ident, std::shared_ptr<I2NPMessage> floodMsg)
	{
		std::set<IdentHash> excluded;
		excluded.insert (i2p::context.GetIdentHash ()); // don't flood to itself
		excluded.insert (ident); // don't flood back
		for (int i = 0; i < 3; i++)
		{
			auto floodfill = GetClosestFloodfill (ident, excluded);
			if (floodfill)
			{
				auto h = floodfill->GetIdentHash();
				LogPrint(eLogDebug, "NetDb: Flood lease set for ", ident.ToBase32(), " to ", h.ToBase64());
				transports.SendMessage (h, CopyI2NPMessage(floodMsg));
				excluded.insert (h);
			}
			else
				break;
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

	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith, bool reverse) const
	{
		return GetRandomRouter (
			[compatibleWith, reverse](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router != compatibleWith &&
					(reverse ? compatibleWith->IsReachableFrom (*router) :
						router->IsReachableFrom (*compatibleWith));
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomPeerTestRouter (bool v4) const
	{
		return GetRandomRouter (
			[v4](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router->IsPeerTesting (v4);
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomSSUV6Router () const
	{
		return GetRandomRouter (
			[](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router->IsSSUV6 ();
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomIntroducer () const
	{
		return GetRandomRouter (
			[](std::shared_ptr<const RouterInfo> router)->bool
			{
				return router->IsIntroducer (true) && !router->IsHidden () && !router->IsFloodfill (); // floodfills don't send relay tag
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetHighBandwidthRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith, bool reverse) const
	{
		return GetRandomRouter (
			[compatibleWith, reverse](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router != compatibleWith &&
					(reverse ? compatibleWith->IsReachableFrom (*router) :
						router->IsReachableFrom (*compatibleWith)) &&
					(router->GetCaps () & RouterInfo::eHighBandwidth) &&
					router->GetVersion () >= NETDB_MIN_HIGHBANDWIDTH_VERSION;
			});
	}

	template<typename Filter>
	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (Filter filter) const
	{
		if (m_RouterInfos.empty())
			return 0;
		uint32_t ind = rand () % m_RouterInfos.size ();
		for (int j = 0; j < 2; j++)
		{
			uint32_t i = 0;
			std::unique_lock<std::mutex> l(m_RouterInfosMutex);
			for (const auto& it: m_RouterInfos)
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
		for (const auto& it: m_Floodfills)
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
		std::set<IdentHash>& excluded, bool closeThanUsOnly) const
	{
		struct Sorted
		{
			std::shared_ptr<const RouterInfo> r;
			XORMetric metric;
			bool operator< (const Sorted& other) const { return metric < other.metric; };
		};

		std::set<Sorted> sorted;
		IdentHash destKey = CreateRoutingKey (destination);
		XORMetric ourMetric;
		if (closeThanUsOnly) ourMetric = destKey ^ i2p::context.GetIdentHash ();
		{
			std::unique_lock<std::mutex> l(m_FloodfillsMutex);
			for (const auto& it: m_Floodfills)
			{
				if (!it->IsUnreachable ())
				{
					XORMetric m = destKey ^ it->GetIdentHash ();
					if (closeThanUsOnly && ourMetric < m) continue;
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
		for (const auto& it: sorted)
		{
			if (i < num)
			{
				const auto& ident = it.r->GetIdentHash ();
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

	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouterInFamily(const std::string & fam) const {
		return GetRandomRouter(
			[fam](std::shared_ptr<const RouterInfo> router)->bool
		{
			return router->IsFamily(fam);
		});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetClosestNonFloodfill (const IdentHash& destination,
		const std::set<IdentHash>& excluded) const
	{
		std::shared_ptr<const RouterInfo> r;
		XORMetric minMetric;
		IdentHash destKey = CreateRoutingKey (destination);
		minMetric.SetMax ();
		// must be called from NetDb thread only
		for (const auto& it: m_RouterInfos)
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
			if (!it->second->IsValid () || ts > it->second->GetExpirationTime () - LEASE_ENDDATE_THRESHOLD)
			{
				LogPrint (eLogInfo, "NetDb: LeaseSet ", it->first.ToBase64 (), " expired or invalid");
				it = m_LeaseSets.erase (it);
			}
			else
				++it;
		}
	}
}
}
