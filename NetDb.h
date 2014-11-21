#ifndef NETDB_H__
#define NETDB_H__

#include <inttypes.h>
#include <set>
#include <map>
#include <list>
#include <string>
#include <thread>
#include <mutex>
#include <boost/filesystem.hpp>
#include "Queue.h"
#include "I2NPProtocol.h"
#include "RouterInfo.h"
#include "LeaseSet.h"
#include "Tunnel.h"
#include "TunnelPool.h"

namespace i2p
{
namespace data
{		
	class RequestedDestination
	{
		public:

			RequestedDestination (const IdentHash& destination, bool isLeaseSet, 
			    bool isExploratory = false, i2p::tunnel::TunnelPool * pool = nullptr):
				m_Destination (destination), m_IsLeaseSet (isLeaseSet), m_IsExploratory (isExploratory), 
				m_Pool (pool), m_CreationTime (0) {};
			
			const IdentHash& GetDestination () const { return m_Destination; };
			int GetNumExcludedPeers () const { return m_ExcludedPeers.size (); };
			const std::set<IdentHash>& GetExcludedPeers () { return m_ExcludedPeers; };
			void ClearExcludedPeers ();
			std::shared_ptr<const RouterInfo> GetLastRouter () const { return m_LastRouter; };
			i2p::tunnel::TunnelPool * GetTunnelPool () { return m_Pool; };
			bool IsExploratory () const { return m_IsExploratory; };
			bool IsLeaseSet () const { return m_IsLeaseSet; };
			bool IsExcluded (const IdentHash& ident) const { return m_ExcludedPeers.count (ident); };
			uint64_t GetCreationTime () const { return m_CreationTime; };
			I2NPMessage * CreateRequestMessage (std::shared_ptr<const RouterInfo>, const i2p::tunnel::InboundTunnel * replyTunnel);
			I2NPMessage * CreateRequestMessage (const IdentHash& floodfill);
						
		private:

			IdentHash m_Destination;
			bool m_IsLeaseSet, m_IsExploratory;
			i2p::tunnel::TunnelPool * m_Pool;
			std::set<IdentHash> m_ExcludedPeers;
			std::shared_ptr<const RouterInfo> m_LastRouter;
			uint64_t m_CreationTime;
	};	
	
	class NetDb
	{
		public:

			NetDb ();
			~NetDb ();

			void Start ();
			void Stop ();
			
			void AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len);
			void AddLeaseSet (const IdentHash& ident, const uint8_t * buf, int len, i2p::tunnel::InboundTunnel * from);
			std::shared_ptr<RouterInfo> FindRouter (const IdentHash& ident) const;
			LeaseSet * FindLeaseSet (const IdentHash& destination) const;

			void PublishLeaseSet (const LeaseSet * leaseSet, i2p::tunnel::TunnelPool * pool);
			void RequestDestination (const IdentHash& destination, bool isLeaseSet = false, 
				i2p::tunnel::TunnelPool * pool = nullptr);			
			
			void HandleDatabaseStoreMsg (I2NPMessage * msg);
			void HandleDatabaseSearchReplyMsg (I2NPMessage * msg);
			void HandleDatabaseLookupMsg (I2NPMessage * msg);			

			std::shared_ptr<const RouterInfo> GetRandomRouter () const;
			std::shared_ptr<const RouterInfo> GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith) const;
			std::shared_ptr<const RouterInfo> GetHighBandwidthRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith) const;
			void SetUnreachable (const IdentHash& ident, bool unreachable);			

			void PostI2NPMsg (I2NPMessage * msg);

			// for web interface
			int GetNumRouters () const { return m_RouterInfos.size (); };
			int GetNumFloodfills () const { return m_Floodfills.size (); };
			int GetNumLeaseSets () const { return m_LeaseSets.size (); };
			
		private:

			bool CreateNetDb(boost::filesystem::path directory);
			void Load (const char * directory);
			void SaveUpdated (const char * directory);
			void Run (); // exploratory thread
			void Explore (int numDestinations);
			void Publish ();
			std::shared_ptr<const RouterInfo> GetClosestFloodfill (const IdentHash& destination, const std::set<IdentHash>& excluded) const;
			void ManageLeaseSets ();

			RequestedDestination * CreateRequestedDestination (const IdentHash& dest, 
				bool isLeaseSet, bool isExploratory = false, i2p::tunnel::TunnelPool * pool = nullptr);
			bool DeleteRequestedDestination (const IdentHash& dest); // returns true if found
			void DeleteRequestedDestination (RequestedDestination * dest);

			template<typename Filter>
			std::shared_ptr<const RouterInfo> GetRandomRouter (Filter filter) const;	
		
		private:

			std::map<IdentHash, LeaseSet *> m_LeaseSets;
			mutable std::mutex m_RouterInfosMutex;
			std::map<IdentHash, std::shared_ptr<RouterInfo> > m_RouterInfos;
			mutable std::mutex m_FloodfillsMutex;
			std::list<std::shared_ptr<RouterInfo> > m_Floodfills;
			std::mutex m_RequestedDestinationsMutex;
			std::map<IdentHash, RequestedDestination *> m_RequestedDestinations;
			
			bool m_IsRunning;
			int m_ReseedRetries;
			std::thread * m_Thread;	
			i2p::util::Queue<I2NPMessage> m_Queue; // of I2NPDatabaseStoreMsg

			static const char m_NetDbPath[];
	};

	extern NetDb netdb;
}
}

#endif
