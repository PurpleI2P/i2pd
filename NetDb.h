#ifndef NETDB_H__
#define NETDB_H__

#include <inttypes.h>
#include <set>
#include <map>
#include <string>
#include <thread>
#include "Queue.h"
#include "I2NPProtocol.h"
#include "RouterInfo.h"
#include "LeaseSet.h"
#include "Tunnel.h"

namespace i2p
{
namespace data
{		
	class RequestedDestination
	{
		public:

			RequestedDestination (const IdentHash& destination, bool isLeaseSet, bool isExploratory = false):
				m_Destination (destination), m_IsLeaseSet (isLeaseSet), m_IsExploratory (isExploratory), 
				m_LastRouter (nullptr), m_LastReplyTunnel (nullptr), m_LastOutboundTunnel (nullptr) {};
			
			const IdentHash& GetDestination () const { return m_Destination; };
			int GetNumExcludedPeers () const { return m_ExcludedPeers.size (); };
			const std::set<IdentHash>& GetExcludedPeers () { return m_ExcludedPeers; };
 			const RouterInfo * GetLastRouter () const { return m_LastRouter; };
			const i2p::tunnel::InboundTunnel * GetLastReplyTunnel () const { return m_LastReplyTunnel; };
			bool IsExploratory () const { return m_IsExploratory; };
			bool IsLeaseSet () const { return m_IsLeaseSet; };
			bool IsExcluded (const IdentHash& ident) const { return m_ExcludedPeers.count (ident); };
			I2NPMessage * CreateRequestMessage (const RouterInfo * router, const i2p::tunnel::InboundTunnel * replyTunnel);
			I2NPMessage * CreateRequestMessage (const IdentHash& floodfill);
			
			i2p::tunnel::OutboundTunnel * GetLastOutboundTunnel () const { return m_LastOutboundTunnel; };
			void SetLastOutboundTunnel (i2p::tunnel::OutboundTunnel * tunnel) { m_LastOutboundTunnel = tunnel; };
			
		private:

			IdentHash m_Destination;
			bool m_IsLeaseSet, m_IsExploratory;
			std::set<IdentHash> m_ExcludedPeers;
			const RouterInfo * m_LastRouter;
			const i2p::tunnel::InboundTunnel * m_LastReplyTunnel;
			i2p::tunnel::OutboundTunnel * m_LastOutboundTunnel;
	};	
	
	class NetDb
	{
		public:

			NetDb ();
			~NetDb ();

			void Start ();
			void Stop ();
			
			void AddRouterInfo (uint8_t * buf, int len);
			void AddLeaseSet (uint8_t * buf, int len);
			RouterInfo * FindRouter (const IdentHash& ident) const;
			LeaseSet * FindLeaseSet (const IdentHash& destination) const;
			
			void RequestDestination (const char * b32); // in base32
			void RequestDestination (const IdentHash& destination, bool isLeaseSet = false);
						
			void HandleDatabaseStoreMsg (uint8_t * buf, size_t len);
			void HandleDatabaseSearchReplyMsg (I2NPMessage * msg);
			
			const RouterInfo * GetRandomNTCPRouter (bool floodfillOnly = false) const;
			const RouterInfo * GetRandomRouter (const RouterInfo * compatibleWith = nullptr, bool floodfillOnly = false) const;

			void PostI2NPMsg (I2NPMessage * msg);
			
		private:

			bool CreateNetDb(const char * directory);
			void Load (const char * directory);
			void Load (const char * directory, bool reseed);
			void SaveUpdated (const char * directory);
			void Run (); // exploratory thread
			void Explore ();
			const RouterInfo * GetClosestFloodfill (const IdentHash& destination, const std::set<IdentHash>& excluded) const;

			RequestedDestination * CreateRequestedDestination (const IdentHash& dest, 
				bool isLeaseSet, bool isExploratory = false);
			void DeleteRequestedDestination (const IdentHash& dest);
			
		private:

			std::map<IdentHash, LeaseSet *> m_LeaseSets;
			std::map<IdentHash, RouterInfo *> m_RouterInfos;
			std::map<IdentHash, RequestedDestination *> m_RequestedDestinations;
			
			bool m_IsRunning;
			int m_reseedRetries = 0;
			std::thread * m_Thread;	
			i2p::util::Queue<I2NPMessage> m_Queue; // of I2NPDatabaseStoreMsg
	};

	extern NetDb netdb;
}
}

#endif
