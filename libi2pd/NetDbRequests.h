/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NETDB_REQUESTS_H__
#define NETDB_REQUESTS_H__

#include <inttypes.h>
#include <memory>
#include <random>
#include <unordered_set>
#include <unordered_map>
#include <list>
#include "Identity.h"
#include "RouterInfo.h"
#include "util.h"

namespace i2p
{
namespace data
{
	const int MAX_NUM_REQUEST_ATTEMPTS = 5;
	const uint64_t MANAGE_REQUESTS_INTERVAL = 1; // in seconds
	const uint64_t MIN_REQUEST_TIME = 5; // in seconds
	const uint64_t MAX_REQUEST_TIME = MAX_NUM_REQUEST_ATTEMPTS * (MIN_REQUEST_TIME + MANAGE_REQUESTS_INTERVAL);
	const uint64_t EXPLORATORY_REQUEST_INTERVAL = 55; // in seconds
	const uint64_t EXPLORATORY_REQUEST_INTERVAL_VARIANCE = 170; // in seconds 
	const uint64_t DISCOVERED_REQUEST_INTERVAL = 360; // in milliseconds
	const uint64_t DISCOVERED_REQUEST_INTERVAL_VARIANCE = 540; // in milliseconds
	const uint64_t MAX_EXPLORATORY_REQUEST_TIME = 30; // in seconds
	const uint64_t REQUEST_CACHE_TIME = MAX_REQUEST_TIME + 40; // in seconds
	const uint64_t REQUESTED_DESTINATIONS_POOL_CLEANUP_INTERVAL = 191; // in seconds
	
	class RequestedDestination
	{
		public:

			typedef std::function<void (std::shared_ptr<RouterInfo>)> RequestComplete;

			RequestedDestination (const IdentHash& destination, bool isExploratory = false, bool direct = true);
			~RequestedDestination ();

			const IdentHash& GetDestination () const { return m_Destination; };
			const std::unordered_set<IdentHash>& GetExcludedPeers () const { return m_ExcludedPeers; };
			int GetNumAttempts () const { return m_NumAttempts; };
			void ClearExcludedPeers ();
			bool IsExploratory () const { return m_IsExploratory; };
			bool IsDirect () const { return m_IsDirect; };
			bool IsActive () const { return m_IsActive; };
			bool IsExcluded (const IdentHash& ident) const;
			uint64_t GetCreationTime () const { return m_CreationTime; };
			uint64_t GetLastRequestTime () const { return m_LastRequestTime; };
			std::shared_ptr<I2NPMessage> CreateRequestMessage (std::shared_ptr<const RouterInfo>, std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel);
			std::shared_ptr<I2NPMessage> CreateRequestMessage (const IdentHash& floodfill);

			void AddRequestComplete (const RequestComplete& requestComplete) { m_RequestComplete.push_back (requestComplete); };
			void ResetRequestComplete () { m_RequestComplete.clear (); };
			void Success (std::shared_ptr<RouterInfo> r);
			void Fail ();

		private:

			void InvokeRequestComplete (std::shared_ptr<RouterInfo> r);
			
		private:

			IdentHash m_Destination;
			bool m_IsExploratory, m_IsDirect, m_IsActive;
			std::unordered_set<IdentHash> m_ExcludedPeers;
			uint64_t m_CreationTime, m_LastRequestTime; // in seconds
			std::list<RequestComplete> m_RequestComplete;
			int m_NumAttempts;
	};

	class NetDbRequests: public std::enable_shared_from_this<NetDbRequests>,
		 private i2p::util::RunnableServiceWithWork
	{
		public:

			NetDbRequests ();
			~NetDbRequests ();
			
			void Start ();
			void Stop ();

			void RequestComplete (const IdentHash& ident, std::shared_ptr<RouterInfo> r);
			void PostDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg);
			void PostRequestDestination (const IdentHash& destination, const RequestedDestination::RequestComplete& requestComplete, bool direct);
			
		private:	

			std::shared_ptr<RequestedDestination> CreateRequest (const IdentHash& destination, bool isExploratory, 
				bool direct = false, RequestedDestination::RequestComplete requestComplete = nullptr);
			std::shared_ptr<RequestedDestination> FindRequest (const IdentHash& ident) const;
			bool SendNextRequest (std::shared_ptr<RequestedDestination> dest);
			
			void HandleDatabaseSearchReplyMsg (std::shared_ptr<const I2NPMessage> msg);
			void RequestRouter (const IdentHash& router);
			void RequestDestination (const IdentHash& destination, const RequestedDestination::RequestComplete& requestComplete, bool direct);
			void Explore (int numDestinations);
			void ManageRequests ();
			// timer
			void ScheduleManageRequests ();
			void HandleManageRequestsTimer (const boost::system::error_code& ecode);
			void ScheduleExploratory (uint64_t interval);
			void HandleExploratoryTimer (const boost::system::error_code& ecode);
			void ScheduleCleanup ();
			void HandleCleanupTimer (const boost::system::error_code& ecode);
			void ScheduleDiscoveredRoutersRequest ();
			void HandleDiscoveredRoutersTimer (const boost::system::error_code& ecode);
			
		private:

			std::unordered_map<IdentHash, std::shared_ptr<RequestedDestination> > m_RequestedDestinations;
			std::list<IdentHash> m_DiscoveredRouterHashes;
			i2p::util::MemoryPoolMt<RequestedDestination> m_RequestedDestinationsPool;
			boost::asio::deadline_timer m_ManageRequestsTimer, m_ExploratoryTimer,
				m_CleanupTimer, m_DiscoveredRoutersTimer;
			std::mt19937 m_Rng;
	};
}
}

#endif
