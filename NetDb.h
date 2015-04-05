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
#include "Reseed.h"

namespace i2p
{
namespace data
{		
	class RequestedDestination
	{	
		public:

			typedef std::function<void (std::shared_ptr<RouterInfo>)> RequestComplete;

			RequestedDestination (const IdentHash& destination, bool isExploratory = false):
				m_Destination (destination), m_IsExploratory (isExploratory), m_CreationTime (0) {};
			~RequestedDestination () { if (m_RequestComplete) m_RequestComplete (nullptr); };			

			const IdentHash& GetDestination () const { return m_Destination; };
			int GetNumExcludedPeers () const { return m_ExcludedPeers.size (); };
			const std::set<IdentHash>& GetExcludedPeers () { return m_ExcludedPeers; };
			void ClearExcludedPeers ();
			bool IsExploratory () const { return m_IsExploratory; };
			bool IsExcluded (const IdentHash& ident) const { return m_ExcludedPeers.count (ident); };
			uint64_t GetCreationTime () const { return m_CreationTime; };
			I2NPMessage * CreateRequestMessage (std::shared_ptr<const RouterInfo>, std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel);
			I2NPMessage * CreateRequestMessage (const IdentHash& floodfill);
			
			void SetRequestComplete (const RequestComplete& requestComplete) { m_RequestComplete = requestComplete; };
			bool IsRequestComplete () const { return m_RequestComplete != nullptr; };
			void Success (std::shared_ptr<RouterInfo> r);
			void Fail ();
			
		private:

			IdentHash m_Destination;
			bool m_IsExploratory;
			std::set<IdentHash> m_ExcludedPeers;
			uint64_t m_CreationTime;
			RequestComplete m_RequestComplete;
	};	
	
	class NetDb
	{
		public:

			NetDb ();
			~NetDb ();

			void Start ();
			void Stop ();
			
			void AddRouterInfo (const uint8_t * buf, int len);
			void AddRouterInfo (const IdentHash& ident, const uint8_t * buf, int len);
			void AddLeaseSet (const IdentHash& ident, const uint8_t * buf, int len, std::shared_ptr<i2p::tunnel::InboundTunnel> from);
			std::shared_ptr<RouterInfo> FindRouter (const IdentHash& ident) const;
			std::shared_ptr<LeaseSet> FindLeaseSet (const IdentHash& destination) const;

			void RequestDestination (const IdentHash& destination, RequestedDestination::RequestComplete requestComplete = nullptr);			
			
			void HandleDatabaseStoreMsg (I2NPMessage * msg);
			void HandleDatabaseSearchReplyMsg (I2NPMessage * msg);
			void HandleDatabaseLookupMsg (I2NPMessage * msg);			

			std::shared_ptr<const RouterInfo> GetRandomRouter () const;
			std::shared_ptr<const RouterInfo> GetRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith) const;
			std::shared_ptr<const RouterInfo> GetHighBandwidthRandomRouter (std::shared_ptr<const RouterInfo> compatibleWith) const;
			std::shared_ptr<const RouterInfo> GetRandomPeerTestRouter () const;
			std::shared_ptr<const RouterInfo> GetRandomIntroducer () const;
			std::shared_ptr<const RouterInfo> GetClosestFloodfill (const IdentHash& destination, const std::set<IdentHash>& excluded) const;
			std::shared_ptr<const RouterInfo> GetClosestNonFloodfill (const IdentHash& destination, const std::set<IdentHash>& excluded) const;
			void SetUnreachable (const IdentHash& ident, bool unreachable);			

			void PostI2NPMsg (I2NPMessage * msg);

			void Reseed ();

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
			void ManageLeaseSets ();
			void ManageRequests ();

			template<typename Filter>
			std::shared_ptr<const RouterInfo> GetRandomRouter (Filter filter) const;	
		
		private:

			std::map<IdentHash, std::shared_ptr<LeaseSet> > m_LeaseSets;
			mutable std::mutex m_RouterInfosMutex;
			std::map<IdentHash, std::shared_ptr<RouterInfo> > m_RouterInfos;
			mutable std::mutex m_FloodfillsMutex;
			std::list<std::shared_ptr<RouterInfo> > m_Floodfills;
			std::mutex m_RequestedDestinationsMutex;
			std::map<IdentHash, std::unique_ptr<RequestedDestination> > m_RequestedDestinations;
			
			bool m_IsRunning;
			std::thread * m_Thread;	
			i2p::util::Queue<I2NPMessage> m_Queue; // of I2NPDatabaseStoreMsg

			Reseeder * m_Reseeder;

			static const char m_NetDbPath[];
	};

	extern NetDb netdb;
}
}

#endif
