/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NETDB_H__
#define NETDB_H__
// this file is called NetDb.hpp to resolve conflict with libc's netdb.h on case insensitive fs
#include <inttypes.h>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <thread>
#include <mutex>
#include <future>

#include "Base.h"
#include "Gzip.h"
#include "FS.h"
#include "Queue.h"
#include "I2NPProtocol.h"
#include "RouterInfo.h"
#include "LeaseSet.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "Reseed.h"
#include "NetDbRequests.h"
#include "Family.h"
#include "version.h"
#include "util.h"
#include "KadDHT.h"

namespace i2p
{
namespace data
{
	const int NETDB_MIN_ROUTERS = 90;
	const int NETDB_MIN_FLOODFILLS = 5;
	const int NETDB_NUM_FLOODFILLS_THRESHOLD = 1200;
	const int NETDB_NUM_ROUTERS_THRESHOLD = 4*NETDB_NUM_FLOODFILLS_THRESHOLD;
	const int NETDB_TUNNEL_CREATION_RATE_THRESHOLD = 10; // in %
	const int NETDB_CHECK_FOR_EXPIRATION_UPTIME = 600; // 10 minutes, in seconds  
	const int NETDB_FLOODFILL_EXPIRATION_TIMEOUT = 60 * 60; // 1 hour, in seconds
	const int NETDB_MIN_EXPIRATION_TIMEOUT = 90 * 60; // 1.5 hours
	const int NETDB_MAX_EXPIRATION_TIMEOUT = 27 * 60 * 60; // 27 hours
	const int NETDB_MAX_OFFLINE_EXPIRATION_TIMEOUT = 180; // in days
	const int NETDB_EXPIRATION_TIMEOUT_THRESHOLD = 2*60; // 2 minutes
	const int NETDB_MIN_HIGHBANDWIDTH_VERSION = MAKE_VERSION_NUMBER(0, 9, 58); // 0.9.58
	const int NETDB_MIN_FLOODFILL_VERSION = MAKE_VERSION_NUMBER(0, 9, 59); // 0.9.59
	const int NETDB_MIN_SHORT_TUNNEL_BUILD_VERSION = MAKE_VERSION_NUMBER(0, 9, 51); // 0.9.51
	const size_t NETDB_MAX_NUM_SEARCH_REPLY_PEER_HASHES = 16;
	const size_t NETDB_MAX_EXPLORATORY_SELECTION_SIZE = 500;
	const int NETDB_EXPLORATORY_SELECTION_UPDATE_INTERVAL = 82; // in seconds. for floodfill
	const int NETDB_NEXT_DAY_ROUTER_INFO_THRESHOLD = 45; // in minutes
	const int NETDB_NEXT_DAY_LEASESET_THRESHOLD = 10; // in minutes

	/** function for visiting a leaseset stored in a floodfill */
	typedef std::function<void(const IdentHash, std::shared_ptr<LeaseSet>)> LeaseSetVisitor;

	/** function for visiting a router info we have locally */
	typedef std::function<void(std::shared_ptr<const i2p::data::RouterInfo>)> RouterInfoVisitor;

	/** function for visiting a router info and determining if we want to use it */
	typedef std::function<bool(std::shared_ptr<const i2p::data::RouterInfo>)> RouterInfoFilter;

	class NetDb
	{
		public:

			NetDb ();
			~NetDb ();

			void Start ();
			void Stop ();

			std::shared_ptr<const RouterInfo> AddRouterInfo (const uint8_t * buf, int len);
			bool AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len);
			bool AddLeaseSet (const IdentHash& ident, const uint8_t * buf, int len);
			bool AddLeaseSet2 (const IdentHash& ident, const uint8_t * buf, int len, uint8_t storeType);
			std::shared_ptr<RouterInfo> FindRouter (const IdentHash& ident) const;
			std::shared_ptr<LeaseSet> FindLeaseSet (const IdentHash& destination) const;
			std::shared_ptr<RouterProfile> FindRouterProfile (const IdentHash& ident) const;

			void RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete = nullptr, bool direct = true);
			
			std::shared_ptr<const RouterInfo> GetRandomRouter () const;
			std::shared_ptr<const RouterInfo> GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith, bool reverse, bool endpoint, bool clientTunnel) const;
			std::shared_ptr<const RouterInfo> GetHighBandwidthRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith, bool reverse, bool endpoint) const;
			std::shared_ptr<const RouterInfo> GetRandomSSU2PeerTestRouter (bool v4, const std::unordered_set<IdentHash>& excluded) const;
			std::shared_ptr<const RouterInfo> GetRandomSSU2Introducer (bool v4, const std::unordered_set<IdentHash>& excluded) const;
			std::shared_ptr<const RouterInfo> GetClosestFloodfill (const IdentHash& destination, const std::unordered_set<IdentHash>& excluded, bool nextDay = false) const;
			std::vector<IdentHash> GetClosestFloodfills (const IdentHash& destination, size_t num,
				std::unordered_set<IdentHash>& excluded, bool closeThanUsOnly = false) const;
			std::vector<IdentHash> GetExploratoryNonFloodfill (const IdentHash& destination, size_t num, const std::unordered_set<IdentHash>& excluded);
			std::shared_ptr<const RouterInfo> GetRandomRouterInFamily (FamilyID fam) const;
			void SetUnreachable (const IdentHash& ident, bool unreachable);
			void ExcludeReachableTransports (const IdentHash& ident, RouterInfo::CompatibleTransports transports);

			void PostI2NPMsg (std::shared_ptr<const I2NPMessage> msg);
			void PostDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg); // to NetdbReq thread

			void Reseed ();
			Families& GetFamilies () { return m_Families; };

			// for web interface
			int GetNumRouters () const { return m_RouterInfos.size (); };
			int GetNumFloodfills () const { return m_Floodfills.GetSize (); };
			int GetNumLeaseSets () const { return m_LeaseSets.size (); };

			/** visit all lease sets we currently store */
			void VisitLeaseSets(LeaseSetVisitor v);
			/** visit all router infos we have currently on disk, usually insanely expensive, does not access in memory RI */
			void VisitStoredRouterInfos(RouterInfoVisitor v);
			/** visit all router infos we have loaded in memory, cheaper than VisitLocalRouterInfos but locks access while visiting */
			void VisitRouterInfos(RouterInfoVisitor v);
			/** visit N random router that match using filter, then visit them with a visitor, return number of RouterInfos that were visited */
			size_t VisitRandomRouterInfos(RouterInfoFilter f, RouterInfoVisitor v, size_t n);

			void ClearRouterInfos () { m_RouterInfos.clear (); };
			template<typename... TArgs>
			std::shared_ptr<RouterInfo::Buffer> NewRouterInfoBuffer (TArgs&&... args) 
			{ 
				return m_RouterInfoBuffersPool.AcquireSharedMt (std::forward<TArgs>(args)...); 
			}
			bool PopulateRouterInfoBuffer (std::shared_ptr<RouterInfo> r);
			std::shared_ptr<RouterInfo::Address> NewRouterInfoAddress () { return m_RouterInfoAddressesPool.AcquireSharedMt (); };
			RouterInfo::AddressesPtr NewRouterInfoAddresses ()
			{
				return RouterInfo::AddressesPtr{m_RouterInfoAddressVectorsPool.AcquireMt (),
					std::bind <void (i2p::util::MemoryPoolMt<RouterInfo::Addresses>::*)(RouterInfo::Addresses *)>
						(&i2p::util::MemoryPoolMt<RouterInfo::Addresses>::ReleaseMt,
						&m_RouterInfoAddressVectorsPool, std::placeholders::_1)};
			};
			std::shared_ptr<Lease> NewLease (const Lease& lease) { return m_LeasesPool.AcquireSharedMt (lease); };
			std::shared_ptr<IdentityEx> NewIdentity (const uint8_t * buf, size_t len) { return m_IdentitiesPool.AcquireSharedMt (buf, len); };
			std::shared_ptr<RouterProfile> NewRouterProfile () { return m_RouterProfilesPool.AcquireSharedMt (); };

		private:

			void Load ();
			bool LoadRouterInfo (const std::string& path, uint64_t ts);
			void SaveUpdated ();
			void PersistRouters (std::list<std::pair<std::string, std::shared_ptr<RouterInfo::Buffer> > >&& update, 
				std::list<std::string>&& remove);
			void Run (); 
			void Flood (const IdentHash& ident, std::shared_ptr<I2NPMessage> floodMsg, bool andNextDay = false);
			void ManageRouterInfos ();
			void ManageLeaseSets ();
			void ManageRequests ();

			void ReseedFromFloodfill(const RouterInfo & ri, int numRouters = 40, int numFloodfills = 20);

			std::shared_ptr<const RouterInfo> AddRouterInfo (const uint8_t * buf, int len, bool& updated);
			std::shared_ptr<const RouterInfo> AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len, bool& updated);

			template<typename Filter>
			std::shared_ptr<const RouterInfo> GetRandomRouter (Filter filter) const;

			void HandleDatabaseStoreMsg (std::shared_ptr<const I2NPMessage> msg);
			void HandleDatabaseLookupMsg (std::shared_ptr<const I2NPMessage> msg);
			void HandleNTCP2RouterInfoMsg (std::shared_ptr<const I2NPMessage> m);

		private:

			mutable std::mutex m_LeaseSetsMutex;
			std::unordered_map<IdentHash, std::shared_ptr<LeaseSet> > m_LeaseSets;
			mutable std::mutex m_RouterInfosMutex;
			std::unordered_map<IdentHash, std::shared_ptr<RouterInfo> > m_RouterInfos;
			mutable std::mutex m_FloodfillsMutex;
			DHTTable m_Floodfills;

			bool m_IsRunning;
			std::thread * m_Thread;
			i2p::util::Queue<std::shared_ptr<const I2NPMessage> > m_Queue; // of I2NPDatabaseStoreMsg

			GzipInflator m_Inflator;
			Reseeder * m_Reseeder;
			Families m_Families;
			i2p::fs::HashedStorage m_Storage;

			std::shared_ptr<NetDbRequests> m_Requests;

			bool m_PersistProfiles;
			std::future<void> m_SavingProfiles, m_DeletingProfiles, m_PersistingRouters;

			std::vector<std::shared_ptr<const RouterInfo> > m_ExploratorySelection;
			uint64_t m_LastExploratorySelectionUpdateTime; // in monotonic seconds

			i2p::util::MemoryPoolMt<RouterInfo::Buffer> m_RouterInfoBuffersPool;
			i2p::util::MemoryPoolMt<RouterInfo::Address> m_RouterInfoAddressesPool;
			i2p::util::MemoryPoolMt<RouterInfo::Addresses> m_RouterInfoAddressVectorsPool;
			i2p::util::MemoryPoolMt<Lease> m_LeasesPool;
			i2p::util::MemoryPoolMt<IdentityEx> m_IdentitiesPool;
			i2p::util::MemoryPoolMt<RouterProfile> m_RouterProfilesPool;
	};

	extern NetDb netdb;
}
}

#endif
