/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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

	NetDb::NetDb (): m_IsRunning (false), m_Thread (nullptr), m_Reseeder (nullptr), m_Storage("netDb", "r", "routerInfo-", "dat"), m_PersistProfiles (true)
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
		if (m_RouterInfos.size () < threshold || m_Floodfills.GetSize () < NETDB_MIN_FLOODFILLS) // reseed if # of router less than threshold or too few floodfiils
		{
			Reseed ();
		}
		else if (!GetRandomRouter (i2p::context.GetSharedRouterInfo (), false, false))
			Reseed (); // we don't have a router we can connect to. Trying to reseed

		auto it = m_RouterInfos.find (i2p::context.GetIdentHash ());
		if (it != m_RouterInfos.end ())
		{
			// remove own router
			m_Floodfills.Remove (it->second->GetIdentHash ());
			m_RouterInfos.erase (it);
		}
		// insert own router
		m_RouterInfos.emplace (i2p::context.GetIdentHash (), i2p::context.GetSharedRouterInfo ());
		if (i2p::context.IsFloodfill ())
			m_Floodfills.Insert (i2p::context.GetSharedRouterInfo ());

		i2p::config::GetOption("persist.profiles", m_PersistProfiles);

		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&NetDb::Run, this));
	}

	void NetDb::Stop ()
	{
		if (m_IsRunning)
		{
			if (m_PersistProfiles)
				SaveProfiles ();
			DeleteObsoleteProfiles ();
			m_RouterInfos.clear ();
			m_Floodfills.Clear ();
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

		uint64_t lastManage = 0, lastExploratory = 0, lastManageRequest = 0;
		uint64_t lastProfilesCleanup = i2p::util::GetSecondsSinceEpoch ();
		int16_t profilesCleanupVariance = 0;

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
						LogPrint(eLogDebug, "NetDb: Got request with type ", (int) msg->GetTypeID ());
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
							case eI2NPDummyMsg:
								// plain RouterInfo from NTCP2 with flags for now
								HandleNTCP2RouterInfoMsg (msg);
							break;
							default: // WTF?
								LogPrint (eLogError, "NetDb: Unexpected message type ", (int) msg->GetTypeID ());
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
				if (ts - lastManageRequest >= MANAGE_REQUESTS_INTERVAL || ts + MANAGE_REQUESTS_INTERVAL < lastManageRequest) // manage requests every 15 seconds
				{
					m_Requests.ManageRequests ();
					lastManageRequest = ts;
				}

				if (ts - lastManage >= 60 || ts + 60 < lastManage) // manage routers and leasesets every minute
				{
					if (lastManage)
					{
						ManageRouterInfos ();
						ManageLeaseSets ();
					}
					lastManage = ts;
				}

				if (ts - lastProfilesCleanup >= (uint64_t)(i2p::data::PEER_PROFILE_AUTOCLEAN_TIMEOUT + profilesCleanupVariance) ||
				    ts + i2p::data::PEER_PROFILE_AUTOCLEAN_TIMEOUT < lastProfilesCleanup)
				{
					m_RouterProfilesPool.CleanUpMt ();
					if (m_PersistProfiles) PersistProfiles ();
					DeleteObsoleteProfiles ();
					lastProfilesCleanup = ts;
					profilesCleanupVariance = (rand () % (2 * i2p::data::PEER_PROFILE_AUTOCLEAN_VARIANCE) - i2p::data::PEER_PROFILE_AUTOCLEAN_VARIANCE);
				}

				if (ts - lastExploratory >= 30 || ts + 30 < lastExploratory) // exploratory every 30 seconds
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
						if(!i2p::context.IsHidden ())
							Explore (numRouters);
						lastExploratory = ts;
					}
				}
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "NetDb: Runtime exception: ", ex.what ());
			}
		}
	}

	std::shared_ptr<const RouterInfo> NetDb::AddRouterInfo (const uint8_t * buf, int len)
	{
		bool updated;
		return AddRouterInfo (buf, len, updated);
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
		if (!AddRouterInfo (ident, buf, len, updated)) 
			updated = false;
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
				{
					std::lock_guard<std::mutex> l(m_RouterInfosMutex);
					if (!r->Update (buf, len))
					{
						updated = false;
						m_Requests.RequestComplete (ident, r);
						return r;
					}
					if (r->IsUnreachable () ||
					    i2p::util::GetMillisecondsSinceEpoch () + NETDB_EXPIRATION_TIMEOUT_THRESHOLD*1000LL < r->GetTimestamp ())
					{
						// delete router as invalid or from future after update
						m_RouterInfos.erase (ident);
						if (wasFloodfill)
						{
							std::lock_guard<std::mutex> l(m_FloodfillsMutex);
							m_Floodfills.Remove (r->GetIdentHash ());
						}
						m_Requests.RequestComplete (ident, nullptr);
						return nullptr;
					}
				}
				if (CheckLogLevel (eLogInfo))
					LogPrint (eLogInfo, "NetDb: RouterInfo updated: ", ident.ToBase64());
				if (wasFloodfill != r->IsFloodfill ()) // if floodfill status updated
				{
					if (CheckLogLevel (eLogDebug))
						LogPrint (eLogDebug, "NetDb: RouterInfo floodfill status updated: ", ident.ToBase64());
					std::lock_guard<std::mutex> l(m_FloodfillsMutex);
					if (wasFloodfill)
						m_Floodfills.Remove (r->GetIdentHash ());
					else if (r->IsEligibleFloodfill ())
					{
						if (m_Floodfills.GetSize () < NETDB_NUM_FLOODFILLS_THRESHOLD || r->GetProfile ()->IsReal ())
							m_Floodfills.Insert (r);
						else
							r->ResetFlooldFill ();
					}
				}
			}
			else
			{
				if (CheckLogLevel (eLogDebug))
					LogPrint (eLogDebug, "NetDb: RouterInfo is older: ", ident.ToBase64());
				updated = false;
			}
		}
		else
		{
			r = std::make_shared<RouterInfo> (buf, len);
			if (!r->IsUnreachable () && r->HasValidAddresses () && (!r->IsFloodfill () || !r->GetProfile ()->IsUnreachable ()) &&
			    i2p::util::GetMillisecondsSinceEpoch () + NETDB_EXPIRATION_TIMEOUT_THRESHOLD*1000LL > r->GetTimestamp ())
			{
				bool inserted = false;
				{
					std::lock_guard<std::mutex> l(m_RouterInfosMutex);
					inserted = m_RouterInfos.insert ({r->GetIdentHash (), r}).second;
				}
				if (inserted)
				{
					if (CheckLogLevel (eLogInfo))
						LogPrint (eLogInfo, "NetDb: RouterInfo added: ", ident.ToBase64());
					if (r->IsFloodfill () && r->IsEligibleFloodfill ())
					{
						if (m_Floodfills.GetSize () < NETDB_NUM_FLOODFILLS_THRESHOLD ||
						 r->GetProfile ()->IsReal ()) // don't insert floodfill until it's known real if we have enough
						{
							std::lock_guard<std::mutex> l(m_FloodfillsMutex);
							m_Floodfills.Insert (r);
						}
						else
							r->ResetFlooldFill ();
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
		std::lock_guard<std::mutex> lock(m_LeaseSetsMutex);
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
					if (CheckLogLevel (eLogInfo))
						LogPrint (eLogInfo, "NetDb: LeaseSet updated: ", ident.ToBase32());
					updated = true;
				}
				else if (CheckLogLevel (eLogDebug))
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
				if (CheckLogLevel (eLogInfo))
					LogPrint (eLogInfo, "NetDb: LeaseSet added: ", ident.ToBase32());
				m_LeaseSets[ident] = leaseSet;
				updated = true;
			}
			else
				LogPrint (eLogError, "NetDb: New LeaseSet validation failed: ", ident.ToBase32());
		}
		return updated;
	}

	bool NetDb::AddLeaseSet2 (const IdentHash& ident, const uint8_t * buf, int len, uint8_t storeType)
	{
		auto leaseSet = std::make_shared<LeaseSet2> (storeType, buf, len, false); // we don't need leases in netdb
		if (leaseSet->IsValid ())
		{
			std::lock_guard<std::mutex> lock(m_LeaseSetsMutex);
			auto it = m_LeaseSets.find(ident);
			if (it == m_LeaseSets.end () || it->second->GetStoreType () != storeType ||
				leaseSet->GetPublishedTimestamp () > it->second->GetPublishedTimestamp ())
			{
				if (leaseSet->IsPublic () && !leaseSet->IsExpired () &&
				     i2p::util::GetSecondsSinceEpoch () + NETDB_EXPIRATION_TIMEOUT_THRESHOLD > leaseSet->GetPublishedTimestamp ())
				{
					// TODO: implement actual update
					if (CheckLogLevel (eLogInfo))
						LogPrint (eLogInfo, "NetDb: LeaseSet2 updated: ", ident.ToBase32());
					m_LeaseSets[ident] = leaseSet;
					return true;
				}
				else
				{
					LogPrint (eLogWarning, "NetDb: Unpublished or expired or future LeaseSet2 received: ", ident.ToBase32());
					m_LeaseSets.erase (ident);
				}
			}
		}
		else
			LogPrint (eLogError, "NetDb: New LeaseSet2 validation failed: ", ident.ToBase32());
		return false;
	}

	std::shared_ptr<RouterInfo> NetDb::FindRouter (const IdentHash& ident) const
	{
		std::lock_guard<std::mutex> l(m_RouterInfosMutex);
		auto it = m_RouterInfos.find (ident);
		if (it != m_RouterInfos.end ())
			return it->second;
		else
			return nullptr;
	}

	std::shared_ptr<LeaseSet> NetDb::FindLeaseSet (const IdentHash& destination) const
	{
		std::lock_guard<std::mutex> lock(m_LeaseSetsMutex);
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
		auto r = FindRouter (ident);
		if (r)
		{
			r->SetUnreachable (unreachable);
			auto profile = r->GetProfile ();
			if (profile)
				profile->Unreachable (unreachable);
		}
	}

	void NetDb::ExcludeReachableTransports (const IdentHash& ident, RouterInfo::CompatibleTransports transports)
	{
		auto r = FindRouter (ident);
		if (r)
		{
			std::lock_guard<std::mutex> l(m_RouterInfosMutex);
			r->ExcludeReachableTransports (transports);
		}
	}

	void NetDb::Reseed ()
	{
		if (!m_Reseeder)
		{
			m_Reseeder = new Reseeder ();
			m_Reseeder->LoadCertificates (); // we need certificates for SU3 verification
		}

		// try reseeding from floodfill first if specified
		std::string riPath; i2p::config::GetOption("reseed.floodfill", riPath);
		if (!riPath.empty())
		{
			auto ri = std::make_shared<RouterInfo>(riPath);
			if (ri->IsFloodfill())
			{
				const uint8_t * riData = ri->GetBuffer();
				int riLen = ri->GetBufferLen();
				if (!i2p::data::netdb.AddRouterInfo(riData, riLen))
				{
					// bad router info
					LogPrint(eLogError, "NetDb: Bad router info");
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
		LogPrint(eLogInfo, "NetDB: Reseeding from floodfill ", ri.GetIdentHashBase64());
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

	bool NetDb::LoadRouterInfo (const std::string& path, uint64_t ts)
	{
		auto r = std::make_shared<RouterInfo>(path);
		if (r->GetRouterIdentity () && !r->IsUnreachable () && r->HasValidAddresses () &&
			ts < r->GetTimestamp () + 24*60*60*NETDB_MAX_OFFLINE_EXPIRATION_TIMEOUT*1000LL) // too old
		{
			r->DeleteBuffer ();
			if (m_RouterInfos.emplace (r->GetIdentHash (), r).second)
			{
				if (r->IsFloodfill () && r->IsEligibleFloodfill ())
					m_Floodfills.Insert (r);
			}
		}
		else
		{
			LogPrint(eLogWarning, "NetDb: RI from ", path, " is invalid or too old. Delete");
			i2p::fs::Remove(path);
		}
		return true;
	}

	void NetDb::VisitLeaseSets(LeaseSetVisitor v)
	{
		std::lock_guard<std::mutex> lock(m_LeaseSetsMutex);
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
		std::lock_guard<std::mutex> lock(m_RouterInfosMutex);
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
			std::lock_guard<std::mutex> lock(m_RouterInfosMutex);
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
		m_Floodfills.Clear ();

		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
		std::vector<std::string> files;
		m_Storage.Traverse(files);
		for (const auto& path : files)
			LoadRouterInfo (path, ts);

		LogPrint (eLogInfo, "NetDb: ", m_RouterInfos.size(), " routers loaded (", m_Floodfills.GetSize (), " floodfils)");
	}

	void NetDb::SaveUpdated ()
	{
		int updatedCount = 0, deletedCount = 0, deletedFloodfillsCount = 0;
		auto total = m_RouterInfos.size ();
		auto totalFloodfills = m_Floodfills.GetSize ();
		uint64_t expirationTimeout = NETDB_MAX_EXPIRATION_TIMEOUT*1000LL;
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
		auto uptime = i2p::context.GetUptime ();
		double minTunnelCreationSuccessRate;
		i2p::config::GetOption("limits.zombies", minTunnelCreationSuccessRate);
		bool isLowRate = i2p::tunnel::tunnels.GetPreciseTunnelCreationSuccessRate () < minTunnelCreationSuccessRate;
		// routers don't expire if less than 90 or uptime is less than 1 hour
		bool checkForExpiration = total > NETDB_MIN_ROUTERS && uptime > 600; // 10 minutes
		if (checkForExpiration && uptime > 3600) // 1 hour
			expirationTimeout = i2p::context.IsFloodfill () ? NETDB_FLOODFILL_EXPIRATION_TIMEOUT*1000LL :
				NETDB_MIN_EXPIRATION_TIMEOUT*1000LL + (NETDB_MAX_EXPIRATION_TIMEOUT - NETDB_MIN_EXPIRATION_TIMEOUT)*1000LL*NETDB_MIN_ROUTERS/total;

		auto own = i2p::context.GetSharedRouterInfo ();
		for (auto& it: m_RouterInfos)
		{
			if (!it.second || it.second == own) continue; // skip own
			std::string ident = it.second->GetIdentHashBase64();
			if (it.second->IsUpdated ())
			{
				if (it.second->GetBuffer ())
				{
					// we have something to save
					it.second->SaveToFile (m_Storage.Path(ident));
					it.second->SetUnreachable (false);
					std::lock_guard<std::mutex> l(m_RouterInfosMutex); // possible collision between DeleteBuffer and Update
					it.second->DeleteBuffer ();
				}
				it.second->SetUpdated (false);
				updatedCount++;
				continue;
			}
			if (it.second->GetProfile ()->IsUnreachable ())
				it.second->SetUnreachable (true);
			// make router reachable back if too few routers or floodfills
			if (it.second->IsUnreachable () && (total - deletedCount < NETDB_MIN_ROUTERS || isLowRate ||
				(it.second->IsFloodfill () && totalFloodfills - deletedFloodfillsCount < NETDB_MIN_FLOODFILLS)))
				it.second->SetUnreachable (false);
			if (!it.second->IsUnreachable ())
			{
				// find & mark expired routers
				if (!it.second->GetCompatibleTransports (true)) // non reachable by any transport
					it.second->SetUnreachable (true);
				else if (ts + NETDB_EXPIRATION_TIMEOUT_THRESHOLD*1000LL < it.second->GetTimestamp ())
				{
					LogPrint (eLogWarning, "NetDb: RouterInfo is from future for ", (it.second->GetTimestamp () - ts)/1000LL, " seconds");
					it.second->SetUnreachable (true);
				}
				else if (checkForExpiration) 
				{	
					if (ts > it.second->GetTimestamp () + expirationTimeout)
						it.second->SetUnreachable (true);
					else if ((ts > it.second->GetTimestamp () + expirationTimeout/2) && // more than half of expiration
						total > NETDB_NUM_ROUTERS_THRESHOLD && !it.second->IsHighBandwidth() &&  // low bandwidth
						!it.second->IsFloodfill() && (!i2p::context.IsFloodfill () || // non floodfill 
					    (CreateRoutingKey (it.second->GetIdentHash ()) ^ i2p::context.GetIdentHash ()).metric[0] >= 0x02)) // different first 7 bits 
							it.second->SetUnreachable (true);
				}	
			}
			// make router reachable back if connected now
			if (it.second->IsUnreachable () && i2p::transport::transports.IsConnected (it.second->GetIdentHash ()))
				it.second->SetUnreachable (false);
			
			if (it.second->IsUnreachable ())
			{
				if (it.second->IsFloodfill ()) deletedFloodfillsCount++;
				// delete RI file
				m_Storage.Remove(ident);
				deletedCount++;
				if (total - deletedCount < NETDB_MIN_ROUTERS) checkForExpiration = false;
			}
		} // m_RouterInfos iteration

		m_RouterInfoBuffersPool.CleanUpMt ();
		m_RouterInfoAddressesPool.CleanUpMt ();
		m_RouterInfoAddressVectorsPool.CleanUpMt ();
		m_IdentitiesPool.CleanUpMt ();

		if (updatedCount > 0)
			LogPrint (eLogInfo, "NetDb: Saved ", updatedCount, " new/updated routers");
		if (deletedCount > 0)
		{
			LogPrint (eLogInfo, "NetDb: Deleting ", deletedCount, " unreachable routers");
			// clean up RouterInfos table
			{
				std::lock_guard<std::mutex> l(m_RouterInfosMutex);
				for (auto it = m_RouterInfos.begin (); it != m_RouterInfos.end ();)
				{
					if (!it->second || it->second->IsUnreachable ())
						it = m_RouterInfos.erase (it);
					else
					{
						it->second->DropProfile ();
						it++;
					}
				}
			}
			// clean up expired floodfills or not floodfills anymore
			{
				std::lock_guard<std::mutex> l(m_FloodfillsMutex);
				m_Floodfills.Cleanup ([](const std::shared_ptr<RouterInfo>& r)->bool
					{
						return r && r->IsFloodfill () && !r->IsUnreachable ();
					});
			}
		}
	}

	void NetDb::RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete, bool direct)
	{
		if (direct && i2p::transport::transports.RoutesRestricted ()) direct = false; // always use tunnels for restricted routes
		auto dest = m_Requests.CreateRequest (destination, false, direct, requestComplete); // non-exploratory
		if (!dest)
		{
			LogPrint (eLogWarning, "NetDb: Destination ", destination.ToBase64(), " is requested already");
			return;
		}

		auto floodfill = GetClosestFloodfill (destination, dest->GetExcludedPeers ());
		if (floodfill)
		{
			if (direct && !floodfill->IsReachableFrom (i2p::context.GetRouterInfo ()) &&
				!i2p::transport::transports.IsConnected (floodfill->GetIdentHash ()))
				direct = false; // floodfill can't be reached directly
			if (direct)
			{
				auto msg = dest->CreateRequestMessage (floodfill->GetIdentHash ());
				msg->onDrop = [this, dest]() { this->m_Requests.SendNextRequest (dest); }; 
				transports.SendMessage (floodfill->GetIdentHash (), msg);
			}	
			else
			{
				auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = pool ? pool->GetNextOutboundTunnel (nullptr, floodfill->GetCompatibleTransports (false)) : nullptr;
				auto inbound = pool ? pool->GetNextInboundTunnel (nullptr, floodfill->GetCompatibleTransports (true)) : nullptr;
				if (outbound &&	inbound)
				{
					auto msg = dest->CreateRequestMessage (floodfill, inbound);
					msg->onDrop = [this, dest]() { this->m_Requests.SendNextRequest (dest); }; 
					outbound->SendTunnelDataMsgTo (floodfill->GetIdentHash (), 0,
						i2p::garlic::WrapECIESX25519MessageForRouter (msg, floodfill->GetIdentity ()->GetEncryptionPublicKey ()));
				}
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

	void NetDb::RequestDestinationFrom (const IdentHash& destination, const IdentHash & from, bool exploratory, RequestedDestination::RequestComplete requestComplete)
	{

		auto dest = m_Requests.CreateRequest (destination, exploratory, true, requestComplete); // non-exploratory
		if (!dest)
		{
			LogPrint (eLogWarning, "NetDb: Destination ", destination.ToBase64(), " is requested already");
			return;
		}
		LogPrint(eLogInfo, "NetDb: Destination ", destination.ToBase64(), " being requested directly from ", from.ToBase64());
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
		if (len < DATABASE_STORE_HEADER_SIZE)
		{
			LogPrint (eLogError, "NetDb: Database store msg is too short ", len, ". Dropped");
			return;
		}
		IdentHash ident (buf + DATABASE_STORE_KEY_OFFSET);
		if (ident.IsZero ())
		{
			LogPrint (eLogDebug, "NetDb: Database store with zero ident, dropped");
			return;
		}
		uint32_t replyToken = bufbe32toh (buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
		size_t offset = DATABASE_STORE_HEADER_SIZE;
		if (replyToken)
		{
			if (len < offset + 36) // 32 + 4
			{
				LogPrint (eLogError, "NetDb: Database store msg with reply token is too short ", len, ". Dropped");
				return;
			}
			uint32_t tunnelID = bufbe32toh (buf + offset);
			offset += 4;
			if (replyToken != 0xFFFFFFFFU) // if not caught on OBEP or IBGW
			{
				IdentHash replyIdent(buf + offset);
				auto deliveryStatus = CreateDeliveryStatusMsg (replyToken);
				if (!tunnelID) // send response directly
					transports.SendMessage (replyIdent, deliveryStatus);
				else
				{
					bool direct = true;
					if (!i2p::transport::transports.IsConnected (replyIdent))
					{
						auto r = FindRouter (replyIdent);
						if (r && !r->IsReachableFrom (i2p::context.GetRouterInfo ()))
							direct = false;
					}	
					if (direct) // send response directly to IBGW
						transports.SendMessage (replyIdent, i2p::CreateTunnelGatewayMsg (tunnelID, deliveryStatus));
					else
					{		
						// send response through exploratory tunnel
						auto pool = i2p::tunnel::tunnels.GetExploratoryPool ();
						auto outbound = pool ? pool->GetNextOutboundTunnel () : nullptr;
						if (outbound)
							outbound->SendTunnelDataMsgTo (replyIdent, tunnelID, deliveryStatus);
						else
							LogPrint (eLogWarning, "NetDb: No outbound tunnels for DatabaseStore reply found");
					}		
				}
			}
			offset += 32;
		}
		// we must send reply back before this check
		if (ident == i2p::context.GetIdentHash ())
		{
			LogPrint (eLogDebug, "NetDb: Database store with own RouterInfo received, dropped");
			return;
		}
		size_t payloadOffset = offset;

		bool updated = false;
		uint8_t storeType = buf[DATABASE_STORE_TYPE_OFFSET];
		if (storeType) // LeaseSet or LeaseSet2
		{
			if (len > MAX_LS_BUFFER_SIZE + offset)
			{
				LogPrint (eLogError, "NetDb: Database store message is too long ", len);
				return;
			}
			if (!context.IsFloodfill ())
			{
				LogPrint (eLogInfo, "NetDb: Not Floodfill, LeaseSet store request ignored for ", ident.ToBase32());
				return;
			}
			else if (!m->from) // unsolicited LS must be received directly
			{
				if (storeType == NETDB_STORE_TYPE_LEASESET) // 1
				{
					if (CheckLogLevel (eLogDebug))
						LogPrint (eLogDebug, "NetDb: Store request: LeaseSet for ", ident.ToBase32());
					updated = AddLeaseSet (ident, buf + offset, len - offset);
				}
				else // all others are considered as LeaseSet2
				{
					if (CheckLogLevel (eLogDebug))
						LogPrint (eLogDebug, "NetDb: Store request: LeaseSet2 of type ", int(storeType), " for ", ident.ToBase32());
					updated = AddLeaseSet2 (ident, buf + offset, len - offset, storeType);
				}
			}
		}
		else // RouterInfo
		{
			if (CheckLogLevel (eLogDebug))
				LogPrint (eLogDebug, "NetDb: Store request: RouterInfo ", ident.ToBase64());
			size_t size = bufbe16toh (buf + offset);
			offset += 2;
			if (size > MAX_RI_BUFFER_SIZE || size > len - offset)
			{
				LogPrint (eLogError, "NetDb: Invalid RouterInfo length ", (int)size);
				return;
			}
			uint8_t uncompressed[MAX_RI_BUFFER_SIZE];
			size_t uncompressedSize = m_Inflator.Inflate (buf + offset, size, uncompressed, MAX_RI_BUFFER_SIZE);
			if (uncompressedSize && uncompressedSize < MAX_RI_BUFFER_SIZE)
				updated = AddRouterInfo (ident, uncompressed, uncompressedSize);
			else
			{
				LogPrint (eLogInfo, "NetDb: Decompression failed ", uncompressedSize);
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
			if (num > 0)
				// try to send next requests
				m_Requests.SendNextRequest (dest);
			else
				// no more requests for destination possible. delete it
				m_Requests.RequestComplete (ident, nullptr);
		}
		else if(!m_FloodfillBootstrap)
			LogPrint (eLogWarning, "NetDb: Requested destination for ", key, " not found");

		// All peers hashs in buffer?
		if(msg->GetPayloadLength() < (size_t) (33 + num * 32))
			return;

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
				LogPrint (eLogDebug, "NetDb: Found new/outdated router. Requesting RouterInfo...");
				if(m_FloodfillBootstrap)
					RequestDestinationFrom(router, m_FloodfillBootstrap->GetIdentHash(), true);
				else if (!IsRouterBanned (router))
					RequestDestination (router);
				else
					LogPrint (eLogDebug, "NetDb: Router ", peerHash, " is banned. Skipped");
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
		if (numExcluded > 512 || (excluded - buf) + numExcluded*32 > (int)msg->GetPayloadLength ())
		{
			LogPrint (eLogWarning, "NetDb: Number of excluded peers", numExcluded, " is too much");
			return;
		}

		std::shared_ptr<I2NPMessage> replyMsg;
		if (lookupType == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP)
		{
			if (!context.IsFloodfill ())
			{
				LogPrint (eLogWarning, "NetDb: Exploratory lookup to non-floodfill dropped");
				return;
			}	
			LogPrint (eLogInfo, "NetDb: Exploratory close to ", key, " ", numExcluded, " excluded");
			std::set<IdentHash> excludedRouters;
			const uint8_t * excluded_ident = excluded;
			for (int i = 0; i < numExcluded; i++)
			{
				excludedRouters.insert (excluded_ident);
				excluded_ident += 32;
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
				// try to find router
				auto router = FindRouter (ident);
				if (router && !router->IsUnreachable ())
				{
					LogPrint (eLogDebug, "NetDb: Requested RouterInfo ", key, " found");
					if (PopulateRouterInfoBuffer (router))
						replyMsg = CreateDatabaseStoreMsg (router);
				}
			}

			if (!replyMsg && (lookupType == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP ||
				lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP))
			{
				// try to find leaseset
				if (context.IsFloodfill ())
				{	
					auto leaseSet = FindLeaseSet (ident);
					if (!leaseSet)
					{
						// no leaseset found
						LogPrint(eLogDebug, "NetDb: Requested LeaseSet not found for ", ident.ToBase32());
					}
					else if (!leaseSet->IsExpired ()) // we don't send back expired leasesets
					{
						LogPrint (eLogDebug, "NetDb: Requested LeaseSet ", key, " found");
						replyMsg = CreateDatabaseStoreMsg (ident, leaseSet);
					}
				}	
				else if (lookupType == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP)
				{
					LogPrint (eLogWarning, "NetDb: Explicit LeaseSet lookup to non-floodfill dropped");
					return;
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
							replyMsg = i2p::garlic::WrapECIESX25519Message (replyMsg, sessionKey, tag);
						}
						else
						{
							const i2p::garlic::SessionTag sessionTag(excluded + 33); // take first tag
							i2p::garlic::ElGamalAESSession garlic (sessionKey, sessionTag);
							replyMsg = garlic.WrapSingleMessage (replyMsg);
						}
						if (!replyMsg)
							LogPrint (eLogError, "NetDb: Failed to wrap message");
					}
					else
						LogPrint(eLogWarning, "NetDb: Encrypted reply requested but no tags provided");
				}
				bool direct = true;
				if (!i2p::transport::transports.IsConnected (replyIdent))
				{
					auto r = FindRouter (replyIdent);
					if (r && !r->IsReachableFrom (i2p::context.GetRouterInfo ()))
						direct = false;
				}	
				if (direct)
					transports.SendMessage (replyIdent, i2p::CreateTunnelGatewayMsg (replyTunnelID, replyMsg));
				else
				{	
					auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
					auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel () : nullptr;
					if (outbound)
						outbound->SendTunnelDataMsgTo (replyIdent, replyTunnelID, replyMsg);
					else
						LogPrint (eLogWarning, "NetDb: Can't send lookup reply to ", replyIdent.ToBase64 (), ". Non reachable and no outbound tunnels");
				}	
			}
			else
				transports.SendMessage (replyIdent, replyMsg);
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
		LogPrint (eLogInfo, "NetDb: Exploring new ", numDestinations, " routers ...");
		for (int i = 0; i < numDestinations; i++)
		{
			RAND_bytes (randomHash, 32);
			auto dest = m_Requests.CreateRequest (randomHash, true, !throughTunnels); // exploratory
			if (!dest)
			{
				LogPrint (eLogWarning, "NetDb: Exploratory destination is requested already");
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
			outbound->SendTunnelDataMsgs (msgs);
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

	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith,
		bool reverse, bool endpoint) const
	{
		return GetRandomRouter (
			[compatibleWith, reverse, endpoint](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router != compatibleWith &&
					(reverse ? (compatibleWith->IsReachableFrom (*router) && router->GetCompatibleTransports (true)):
						router->IsReachableFrom (*compatibleWith)) &&
					router->IsECIES () && !router->IsHighCongestion (false) &&
					(!endpoint || (router->IsV4 () && (!reverse || router->IsPublished (true)))); // endpoint must be ipv4 and published if inbound(reverse)
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomSSU2PeerTestRouter (bool v4, const std::set<IdentHash>& excluded) const
	{
		return GetRandomRouter (
			[v4, &excluded](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router->IsECIES () &&
					router->IsSSU2PeerTesting (v4) && !excluded.count (router->GetIdentHash ());
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomSSU2Introducer (bool v4, const std::set<IdentHash>& excluded) const
	{
		return GetRandomRouter (
			[v4, &excluded](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router->IsSSU2Introducer (v4) &&
					!excluded.count (router->GetIdentHash ());
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetHighBandwidthRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith, 
		bool reverse, bool endpoint) const
	{
		return GetRandomRouter (
			[compatibleWith, reverse, endpoint](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router != compatibleWith &&
					(reverse ? (compatibleWith->IsReachableFrom (*router) && router->GetCompatibleTransports (true)) :
						router->IsReachableFrom (*compatibleWith)) &&
					(router->GetCaps () & RouterInfo::eHighBandwidth) &&
					router->GetVersion () >= NETDB_MIN_HIGHBANDWIDTH_VERSION &&
					router->IsECIES () && !router->IsHighCongestion (true) &&
					(!endpoint || (router->IsV4 () && (!reverse || router->IsPublished (true)))); // endpoint must be ipv4 and published if inbound(reverse)

			});
	}

	template<typename Filter>
	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (Filter filter) const
	{
		if (m_RouterInfos.empty())
			return nullptr;
		uint16_t inds[3];
		RAND_bytes ((uint8_t *)inds, sizeof (inds));
		std::lock_guard<std::mutex> l(m_RouterInfosMutex);
		auto count = m_RouterInfos.size ();
		if(count == 0) return nullptr;
		inds[0] %= count;
		auto it = m_RouterInfos.begin ();
		std::advance (it, inds[0]);
		// try random router
		if (it != m_RouterInfos.end () && !it->second->IsUnreachable () && filter (it->second))
			return it->second;
		// try some routers around
		auto it1 = m_RouterInfos.begin ();
		if (inds[0])
		{
			// before
			inds[1] %= inds[0];
			std::advance (it1, (inds[1] + inds[0])/2);
		}
		else
			it1 = it;
		auto it2 = it;
		if (inds[0] < m_RouterInfos.size () - 1)
		{
			// after
			inds[2] %= (m_RouterInfos.size () - 1 - inds[0]); inds[2] /= 2;
			std::advance (it2, inds[2]);
		}
		// it1 - from, it2 - to
		it = it1;
		while (it != it2 && it != m_RouterInfos.end ())
		{
			if (!it->second->IsUnreachable () && filter (it->second))
				return it->second;
			it++;
		}
		// still not found, try from the beginning
		it = m_RouterInfos.begin ();
		while (it != it1 && it != m_RouterInfos.end ())
		{
			if (!it->second->IsUnreachable () && filter (it->second))
				return it->second;
			it++;
		}
		// still not found, try to the beginning
		it = it2;
		while (it != m_RouterInfos.end ())
		{
			if (!it->second->IsUnreachable () && filter (it->second))
				return it->second;
			it++;
		}
		return nullptr; // seems we have too few routers
	}

	void NetDb::PostI2NPMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		if (msg) m_Queue.Put (msg);
	}

	std::shared_ptr<const RouterInfo> NetDb::GetClosestFloodfill (const IdentHash& destination,
		const std::set<IdentHash>& excluded) const
	{
		IdentHash destKey = CreateRoutingKey (destination);
		std::lock_guard<std::mutex> l(m_FloodfillsMutex);
		return m_Floodfills.FindClosest (destKey, [&excluded](const std::shared_ptr<RouterInfo>& r)->bool
			{
				return r && !r->IsUnreachable () && !r->GetProfile ()->IsUnreachable () &&
					!excluded.count (r->GetIdentHash ());
			});
	}

	std::vector<IdentHash> NetDb::GetClosestFloodfills (const IdentHash& destination, size_t num,
		std::set<IdentHash>& excluded, bool closeThanUsOnly) const
	{
		std::vector<IdentHash> res;
		IdentHash destKey = CreateRoutingKey (destination);
		std::vector<std::shared_ptr<RouterInfo> > v;
		{
			std::lock_guard<std::mutex> l(m_FloodfillsMutex);
			v = m_Floodfills.FindClosest (destKey, num, [&excluded](const std::shared_ptr<RouterInfo>& r)->bool
				{
					return r && !r->IsUnreachable () && !r->GetProfile ()->IsUnreachable () &&
						!excluded.count (r->GetIdentHash ());
				});
		}
		if (v.empty ()) return res;

		XORMetric ourMetric;
		if (closeThanUsOnly) ourMetric = destKey ^ i2p::context.GetIdentHash ();
		for (auto& it: v)
		{
			if (closeThanUsOnly && ourMetric < (destKey ^ it->GetIdentHash ())) break;
			res.push_back (it->GetIdentHash ());
		}
		return res;
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouterInFamily (FamilyID fam) const
	{
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

	void NetDb::ManageRouterInfos ()
	{
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		{
			std::lock_guard<std::mutex> l(m_RouterInfosMutex);
			for (auto& it: m_RouterInfos)
				it.second->UpdateIntroducers (ts);
		}
		SaveUpdated ();
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
		m_LeasesPool.CleanUpMt ();
	}

	bool NetDb::PopulateRouterInfoBuffer (std::shared_ptr<RouterInfo> r)
	{
		if (!r) return false;
		if (r->GetBuffer ()) return true;
		return r->LoadBuffer (m_Storage.Path (r->GetIdentHashBase64 ()));
	}
}
}
