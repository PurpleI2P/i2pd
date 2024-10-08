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
#include <map>
#include <random>
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

	NetDb::NetDb (): m_IsRunning (false), m_Thread (nullptr), m_Reseeder (nullptr), 
		m_Storage("netDb", "r", "routerInfo-", "dat"), m_PersistProfiles (true),
		m_LastExploratorySelectionUpdateTime (0)
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

		if (!m_Requests)
		{	
			m_Requests = std::make_shared<NetDbRequests>();
			m_Requests->Start ();
		}
		
		uint16_t threshold; i2p::config::GetOption("reseed.threshold", threshold);
		if (m_RouterInfos.size () < threshold || m_Floodfills.GetSize () < NETDB_MIN_FLOODFILLS) // reseed if # of router less than threshold or too few floodfiils
		{
			Reseed ();
		}
		else if (!GetRandomRouter (i2p::context.GetSharedRouterInfo (), false, false, false))
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
		if (m_Requests)
			m_Requests->Stop ();
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
		}
		m_Requests = nullptr;
	}

	void NetDb::Run ()
	{
		i2p::util::SetThreadName("NetDB");

		uint64_t lastManage = 0;
		uint64_t lastProfilesCleanup = i2p::util::GetMonotonicMilliseconds (), lastObsoleteProfilesCleanup = lastProfilesCleanup;
		int16_t profilesCleanupVariance = 0, obsoleteProfilesCleanVariance = 0;

		while (m_IsRunning)
		{
			try
			{
				auto msg = m_Queue.GetNextWithTimeout (1000); // 1 sec
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
							case eI2NPDatabaseLookup:
								HandleDatabaseLookupMsg (msg);
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
				if (!i2p::transport::transports.IsOnline () || !i2p::transport::transports.IsRunning ()) 
					continue; // don't manage netdb when offline or transports are not running

				uint64_t mts = i2p::util::GetMonotonicMilliseconds ();
				if (mts >= lastManage + 60000) // manage routers and leasesets every minute
				{
					if (lastManage)
					{
						ManageRouterInfos ();
						ManageLeaseSets ();
					}
					lastManage = mts;
				}

				if (mts >= lastProfilesCleanup + (uint64_t)(i2p::data::PEER_PROFILE_AUTOCLEAN_TIMEOUT + profilesCleanupVariance)*1000)
				{
					m_RouterProfilesPool.CleanUpMt ();
					if (m_PersistProfiles)
					{	
						bool isSaving = m_SavingProfiles.valid ();
						if (isSaving && m_SavingProfiles.wait_for(std::chrono::seconds(0)) == std::future_status::ready) // still active?
						{
							m_SavingProfiles.get ();
							isSaving = false;
						}	
						if (!isSaving)
							m_SavingProfiles = PersistProfiles ();
						else
							LogPrint (eLogWarning, "NetDb: Can't persist profiles. Profiles are being saved to disk");
					}	
					lastProfilesCleanup = mts;
					profilesCleanupVariance = rand () % i2p::data::PEER_PROFILE_AUTOCLEAN_VARIANCE;
				}

				if (mts >= lastObsoleteProfilesCleanup + (uint64_t)(i2p::data::PEER_PROFILE_OBSOLETE_PROFILES_CLEAN_TIMEOUT + obsoleteProfilesCleanVariance)*1000)
				{
					bool isDeleting = m_DeletingProfiles.valid ();
					if (isDeleting && m_DeletingProfiles.wait_for(std::chrono::seconds(0)) == std::future_status::ready) // still active?
					{
						m_DeletingProfiles.get ();
						isDeleting = false;
					}	
					if (!isDeleting)
						m_DeletingProfiles = DeleteObsoleteProfiles ();	
					else
						LogPrint (eLogWarning, "NetDb: Can't delete profiles. Profiles are being deleted from disk");
					lastObsoleteProfilesCleanup = mts;
					obsoleteProfilesCleanVariance = rand () % i2p::data::PEER_PROFILE_OBSOLETE_PROFILES_CLEAN_VARIANCE;
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
						m_Requests->RequestComplete (ident, r);
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
						m_Requests->RequestComplete (ident, nullptr);
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
							r->ResetFloodfill ();
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
			bool isValid = !r->IsUnreachable () && r->HasValidAddresses () && (!r->IsFloodfill () || !r->GetProfile ()->IsUnreachable ());
			if (isValid)
			{
				auto mts = i2p::util::GetMillisecondsSinceEpoch ();
			    isValid = mts + NETDB_EXPIRATION_TIMEOUT_THRESHOLD*1000LL > r->GetTimestamp () && // from future
					(mts < r->GetTimestamp () + NETDB_MAX_EXPIRATION_TIMEOUT*1000LL || // too old
					 context.GetUptime () < NETDB_CHECK_FOR_EXPIRATION_UPTIME/10); // enough uptime
			}
			if (isValid)	
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
							r->ResetFloodfill ();
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
		m_Requests->RequestComplete (ident, r);
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
			{	
				profile->Unreachable (unreachable);
				if (!unreachable && r->IsDeclaredFloodfill () && !r->IsFloodfill () && 
				    r->IsEligibleFloodfill () && profile->IsReal ())
				{
					// enable previously disabled floodfill
					r->SetFloodfill ();
					std::lock_guard<std::mutex> l(m_FloodfillsMutex);
					m_Floodfills.Insert (r);
				}	
			}	
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
		if (m_PersistingRouters.valid ())
		{
			if (m_PersistingRouters.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
				m_PersistingRouters.get ();
			else
			{	
				LogPrint (eLogWarning, "NetDb: Can't save updated routers. Routers are being saved to disk");
				return;
			}	
		}	

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
		bool checkForExpiration = total > NETDB_MIN_ROUTERS && uptime > NETDB_CHECK_FOR_EXPIRATION_UPTIME; // 10 minutes
		if (checkForExpiration && uptime > i2p::transport::SSU2_TO_INTRODUCER_SESSION_DURATION) // 1 hour
			expirationTimeout = i2p::context.IsFloodfill () ? NETDB_FLOODFILL_EXPIRATION_TIMEOUT*1000LL :
				NETDB_MIN_EXPIRATION_TIMEOUT*1000LL + (NETDB_MAX_EXPIRATION_TIMEOUT - NETDB_MIN_EXPIRATION_TIMEOUT)*1000LL*NETDB_MIN_ROUTERS/total;

		std::list<std::pair<std::string, std::shared_ptr<RouterInfo::Buffer> > > saveToDisk;
		std::list<std::string> removeFromDisk;	
			
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
					std::shared_ptr<RouterInfo::Buffer> buffer;
					{
						std::lock_guard<std::mutex> l(m_RouterInfosMutex); // possible collision between DeleteBuffer and Update
						buffer = it.second->GetSharedBuffer ();
						it.second->DeleteBuffer ();
					}
					if (buffer && !it.second->IsUnreachable ()) // don't save bad router
						saveToDisk.push_back(std::make_pair(ident, buffer));
					it.second->SetUnreachable (false);
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
				removeFromDisk.push_back (ident);
				deletedCount++;
				if (total - deletedCount < NETDB_MIN_ROUTERS) checkForExpiration = false;
			}
		} // m_RouterInfos iteration

		if (!saveToDisk.empty () || !removeFromDisk.empty ())
		{
			m_PersistingRouters = std::async (std::launch::async, &NetDb::PersistRouters,
				this, std::move (saveToDisk), std::move (removeFromDisk));
		}	
			
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

	void NetDb::PersistRouters (std::list<std::pair<std::string, std::shared_ptr<RouterInfo::Buffer> > >&& update, 
		std::list<std::string>&& remove)
	{
		for (auto it: update)
			RouterInfo::SaveToFile (m_Storage.Path(it.first), it.second);
		for (auto it: remove)
			m_Storage.Remove (it);
	}	
	
	void NetDb::RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete, bool direct)
	{
		if (direct && (i2p::transport::transports.RoutesRestricted () || i2p::context.IsLimitedConnectivity ())) 
		    direct = false; // always use tunnels for restricted routes or limited connectivity
		if (m_Requests)
			m_Requests->PostRequestDestination (destination, requestComplete, direct);
		else
			LogPrint (eLogError, "NetDb: Requests is null");
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
				int minutesBeforeMidnight = 24*60 - i2p::util::GetMinutesSinceEpoch () % (24*60);
				bool andNextDay = storeType ? minutesBeforeMidnight < NETDB_NEXT_DAY_LEASESET_THRESHOLD:
					minutesBeforeMidnight < NETDB_NEXT_DAY_ROUTER_INFO_THRESHOLD;
				Flood (ident, floodMsg, andNextDay);
			}
			else
				LogPrint (eLogError, "NetDb: Database store message is too long ", floodMsg->len);
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
			std::unordered_set<IdentHash> excludedRouters;
			const uint8_t * excluded_ident = excluded;
			for (int i = 0; i < numExcluded; i++)
			{
				excludedRouters.insert (excluded_ident);
				excluded_ident += 32;
			}
			replyMsg = CreateDatabaseSearchReply (ident, GetExploratoryNonFloodfill (ident, 
				NETDB_MAX_NUM_SEARCH_REPLY_PEER_HASHES, excludedRouters));
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
				std::unordered_set<IdentHash> excludedRouters;
				const uint8_t * exclude_ident = excluded;
				for (int i = 0; i < numExcluded; i++)
				{
					excludedRouters.insert (exclude_ident);
					exclude_ident += 32;
				}
				auto closestFloodfills = GetClosestFloodfills (ident, 3, excludedRouters, false);
				if (closestFloodfills.empty ())
					LogPrint (eLogWarning, "NetDb: No more floodfills for ", key, " found. ", numExcluded, " peers excluded");
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

	void NetDb::Flood (const IdentHash& ident, std::shared_ptr<I2NPMessage> floodMsg, bool andNextDay)
	{
		std::unordered_set<IdentHash> excluded;
		excluded.insert (i2p::context.GetIdentHash ()); // don't flood to itself
		excluded.insert (ident); // don't flood back
		for (int i = 0; i < 3; i++)
		{
			auto floodfill = GetClosestFloodfill (ident, excluded, false); // current day
			if (floodfill)
			{
				const auto& h = floodfill->GetIdentHash();
				transports.SendMessage (h, CopyI2NPMessage(floodMsg));
				excluded.insert (h);
			}
			else
				return; // no more floodfills
		}
		if (andNextDay)
		{
			// flood to two more closest flodfills for next day 
			std::unordered_set<IdentHash> excluded1;
			excluded1.insert (i2p::context.GetIdentHash ()); // don't flood to itself
			excluded1.insert (ident); // don't flood back
			for (int i = 0; i < 2; i++)
			{
				auto floodfill = GetClosestFloodfill (ident, excluded1, true); // next day
				if (floodfill)
				{
					const auto& h = floodfill->GetIdentHash();
					if (!excluded.count (h)) // we didn't send for current day, otherwise skip
						transports.SendMessage (h, CopyI2NPMessage(floodMsg));
					excluded1.insert (h);
				}
				else
					return;
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

	std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith,
		bool reverse, bool endpoint, bool clientTunnel) const
	{
		bool checkIsReal = clientTunnel && i2p::tunnel::tunnels.GetPreciseTunnelCreationSuccessRate () < NETDB_TUNNEL_CREATION_RATE_THRESHOLD && // too low rate
			context.GetUptime () > NETDB_CHECK_FOR_EXPIRATION_UPTIME; // after 10 minutes uptime
		return GetRandomRouter (
			[compatibleWith, reverse, endpoint, clientTunnel, checkIsReal](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router != compatibleWith &&
					(reverse ? (compatibleWith->IsReachableFrom (*router) && router->GetCompatibleTransports (true)):
						router->IsReachableFrom (*compatibleWith)) && !router->IsNAT2NATOnly (*compatibleWith) &&
					router->IsECIES () && !router->IsHighCongestion (clientTunnel) &&
					(!checkIsReal || router->GetProfile ()->IsReal ()) &&
					(!endpoint || (router->IsV4 () && (!reverse || router->IsPublished (true)))); // endpoint must be ipv4 and published if inbound(reverse)
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomSSU2PeerTestRouter (bool v4, const std::unordered_set<IdentHash>& excluded) const
	{
		return GetRandomRouter (
			[v4, &excluded](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router->IsECIES () &&
					router->IsSSU2PeerTesting (v4) && !excluded.count (router->GetIdentHash ());
			});
	}

	std::shared_ptr<const RouterInfo> NetDb::GetRandomSSU2Introducer (bool v4, const std::unordered_set<IdentHash>& excluded) const
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
		bool checkIsReal = i2p::tunnel::tunnels.GetPreciseTunnelCreationSuccessRate () < NETDB_TUNNEL_CREATION_RATE_THRESHOLD && // too low rate
			context.GetUptime () > NETDB_CHECK_FOR_EXPIRATION_UPTIME; // after 10 minutes uptime
		return GetRandomRouter (
			[compatibleWith, reverse, endpoint, checkIsReal](std::shared_ptr<const RouterInfo> router)->bool
			{
				return !router->IsHidden () && router != compatibleWith &&
					(reverse ? (compatibleWith->IsReachableFrom (*router) && router->GetCompatibleTransports (true)) :
						router->IsReachableFrom (*compatibleWith)) && !router->IsNAT2NATOnly (*compatibleWith) &&
					(router->GetCaps () & RouterInfo::eHighBandwidth) &&
					router->GetVersion () >= NETDB_MIN_HIGHBANDWIDTH_VERSION &&
					router->IsECIES () && !router->IsHighCongestion (true) &&
					(!checkIsReal || router->GetProfile ()->IsReal ()) &&
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

	void NetDb::PostDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg)
	{
		if (msg && m_Requests)
			m_Requests->PostDatabaseSearchReplyMsg (msg);
	}	
	
	std::shared_ptr<const RouterInfo> NetDb::GetClosestFloodfill (const IdentHash& destination,
		const std::unordered_set<IdentHash>& excluded, bool nextDay) const
	{
		IdentHash destKey = CreateRoutingKey (destination, nextDay);
		std::lock_guard<std::mutex> l(m_FloodfillsMutex);
		return m_Floodfills.FindClosest (destKey, [&excluded](const std::shared_ptr<RouterInfo>& r)->bool
			{
				return r && !r->IsUnreachable () && !r->GetProfile ()->IsUnreachable () &&
					!excluded.count (r->GetIdentHash ());
			});
	}

	std::vector<IdentHash> NetDb::GetClosestFloodfills (const IdentHash& destination, size_t num,
		std::unordered_set<IdentHash>& excluded, bool closeThanUsOnly) const
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

	std::vector<IdentHash> NetDb::GetExploratoryNonFloodfill (const IdentHash& destination, 
		size_t num, const std::unordered_set<IdentHash>& excluded)
	{
		std::vector<IdentHash> ret;
		if (!num || m_RouterInfos.empty ()) return ret; // empty list
		auto ts = i2p::util::GetMonotonicSeconds ();
		if (ts > m_LastExploratorySelectionUpdateTime +	NETDB_EXPLORATORY_SELECTION_UPDATE_INTERVAL)
		{
			// update selection
			m_ExploratorySelection.clear ();
			std::vector<std::shared_ptr<const RouterInfo> > eligible;
			eligible.reserve (m_RouterInfos.size ());		
			{
				// collect eligible from current netdb
				bool checkIsReal = i2p::tunnel::tunnels.GetPreciseTunnelCreationSuccessRate () < NETDB_TUNNEL_CREATION_RATE_THRESHOLD; // too low rate
				std::lock_guard<std::mutex> l(m_RouterInfosMutex);
				for (const auto& it: m_RouterInfos)
					if (!it.second->IsDeclaredFloodfill () &&
					 	(!checkIsReal || (it.second->HasProfile () && it.second->GetProfile ()->IsReal ())))
							eligible.push_back (it.second);
			}
			if (eligible.size () > NETDB_MAX_EXPLORATORY_SELECTION_SIZE)
			{
				 std::sample (eligible.begin(), eligible.end(), std::back_inserter(m_ExploratorySelection),
				 	NETDB_MAX_EXPLORATORY_SELECTION_SIZE, std::mt19937(ts));
			}	
			else
				std::swap (m_ExploratorySelection, eligible);	
			m_LastExploratorySelectionUpdateTime = ts;
		}	
		
		// sort by distance
		IdentHash destKey = CreateRoutingKey (destination);
		std::map<XORMetric, std::shared_ptr<const RouterInfo> > sorted;
		for (const auto& it: m_ExploratorySelection)
			if (!excluded.count (it->GetIdentHash ())) 
				sorted.emplace (destKey ^ it->GetIdentHash (), it);
		// return first num closest routers
		for (const auto& it: sorted)
		{
			ret.push_back (it.second->GetIdentHash ());
			if (ret.size () >= num) break;
		}	
		return ret;
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
