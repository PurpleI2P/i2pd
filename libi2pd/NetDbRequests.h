/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NETDB_REQUESTS_H__
#define NETDB_REQUESTS_H__

#include <memory>
#include <set>
#include <map>
#include "Identity.h"
#include "RouterInfo.h"

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
			std::shared_ptr<I2NPMessage> CreateRequestMessage (std::shared_ptr<const RouterInfo>, std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel);
			std::shared_ptr<I2NPMessage> CreateRequestMessage (const IdentHash& floodfill);

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

	class NetDbRequests
	{
		public:

			void Start ();
			void Stop ();

			 std::shared_ptr<RequestedDestination> CreateRequest (const IdentHash& destination, bool isExploratory, RequestedDestination::RequestComplete requestComplete = nullptr);
			void RequestComplete (const IdentHash& ident, std::shared_ptr<RouterInfo> r);
			std::shared_ptr<RequestedDestination> FindRequest (const IdentHash& ident) const;
			void ManageRequests ();

		private:

			mutable std::mutex m_RequestedDestinationsMutex;
			std::map<IdentHash, std::shared_ptr<RequestedDestination> > m_RequestedDestinations;
	};
}
}

#endif
