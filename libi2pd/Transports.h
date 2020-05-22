/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TRANSPORTS_H__
#define TRANSPORTS_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>
#include <vector>
#include <queue>
#include <string>
#include <memory>
#include <atomic>
#include <boost/asio.hpp>
#include "TransportSession.h"
#include "NTCPSession.h"
#include "SSU.h"
#include "NTCP2.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "Identity.h"

namespace i2p
{
namespace transport
{
	class DHKeysPairSupplier
	{
		public:

			DHKeysPairSupplier (int size);
			~DHKeysPairSupplier ();
			void Start ();
			void Stop ();
			std::shared_ptr<i2p::crypto::DHKeys> Acquire ();
			void Return (std::shared_ptr<i2p::crypto::DHKeys> pair);

		private:

			void Run ();
			void CreateDHKeysPairs (int num);

		private:

			const int m_QueueSize;
			std::queue<std::shared_ptr<i2p::crypto::DHKeys> > m_Queue;

			bool m_IsRunning;
			std::thread * m_Thread;
			std::condition_variable m_Acquired;
			std::mutex m_AcquiredMutex;
	};

	struct Peer
	{
		int numAttempts;
		std::shared_ptr<const i2p::data::RouterInfo> router;
		std::list<std::shared_ptr<TransportSession> > sessions;
		uint64_t creationTime;
		std::vector<std::shared_ptr<i2p::I2NPMessage> > delayedMessages;

		void Done ()
		{
			for (auto& it: sessions)
				it->Done ();
		}
	};

	const size_t SESSION_CREATION_TIMEOUT = 10; // in seconds
	const int PEER_TEST_INTERVAL = 71; // in minutes
	const int MAX_NUM_DELAYED_MESSAGES = 50;
	class Transports
	{
		public:

			Transports ();
			~Transports ();

			void Start (bool enableNTCP=true, bool enableSSU=true);
			void Stop ();

			bool IsBoundNTCP() const { return m_NTCPServer != nullptr; }
			bool IsBoundSSU() const { return m_SSUServer != nullptr; }
			bool IsBoundNTCP2() const { return m_NTCP2Server != nullptr; }

			bool IsOnline() const { return m_IsOnline; };
			void SetOnline (bool online) { m_IsOnline = online; };

			boost::asio::io_service& GetService () { return *m_Service; };
			std::shared_ptr<i2p::crypto::DHKeys> GetNextDHKeysPair ();
			void ReuseDHKeysPair (std::shared_ptr<i2p::crypto::DHKeys> pair);

			void SendMessage (const i2p::data::IdentHash& ident, std::shared_ptr<i2p::I2NPMessage> msg);
			void SendMessages (const i2p::data::IdentHash& ident, const std::vector<std::shared_ptr<i2p::I2NPMessage> >& msgs);

			void PeerConnected (std::shared_ptr<TransportSession> session);
			void PeerDisconnected (std::shared_ptr<TransportSession> session);
			bool IsConnected (const i2p::data::IdentHash& ident) const;

			void UpdateSentBytes (uint64_t numBytes) { m_TotalSentBytes += numBytes; };
			void UpdateReceivedBytes (uint64_t numBytes) { m_TotalReceivedBytes += numBytes; };
			uint64_t GetTotalSentBytes () const { return m_TotalSentBytes; };
			uint64_t GetTotalReceivedBytes () const { return m_TotalReceivedBytes; };
			uint64_t GetTotalTransitTransmittedBytes () const { return m_TotalTransitTransmittedBytes; }
			void UpdateTotalTransitTransmittedBytes (uint32_t add) { m_TotalTransitTransmittedBytes += add; };
			uint32_t GetInBandwidth () const { return m_InBandwidth; };
			uint32_t GetOutBandwidth () const { return m_OutBandwidth; };
			uint32_t GetTransitBandwidth () const { return m_TransitBandwidth; };
			bool IsBandwidthExceeded () const;
			bool IsTransitBandwidthExceeded () const;
			size_t GetNumPeers () const { return m_Peers.size (); };
			std::shared_ptr<const i2p::data::RouterInfo> GetRandomPeer () const;

			/** get a trusted first hop for restricted routes */
			std::shared_ptr<const i2p::data::RouterInfo> GetRestrictedPeer() const;
			/** do we want to use restricted routes? */
			bool RoutesRestricted() const;
			/** restrict routes to use only these router families for first hops */
			void RestrictRoutesToFamilies(std::set<std::string> families);
			/** restrict routes to use only these routers for first hops */
			void RestrictRoutesToRouters(std::set<i2p::data::IdentHash> routers);

			bool IsRestrictedPeer(const i2p::data::IdentHash & ident) const;

			void PeerTest ();

		private:

			void Run ();
			void RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident);
			void HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, i2p::data::IdentHash ident);
			void PostMessages (i2p::data::IdentHash ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > msgs);
			bool ConnectToPeer (const i2p::data::IdentHash& ident, Peer& peer);
			void HandlePeerCleanupTimer (const boost::system::error_code& ecode);
			void HandlePeerTestTimer (const boost::system::error_code& ecode);

			void UpdateBandwidth ();
			void DetectExternalIP ();

		private:

			bool m_IsOnline, m_IsRunning, m_IsNAT;
			std::thread * m_Thread;
			boost::asio::io_service * m_Service;
			boost::asio::io_service::work * m_Work;
			boost::asio::deadline_timer * m_PeerCleanupTimer, * m_PeerTestTimer;

			NTCPServer * m_NTCPServer;
			SSUServer * m_SSUServer;
			NTCP2Server * m_NTCP2Server;
			mutable std::mutex m_PeersMutex;
			std::map<i2p::data::IdentHash, Peer> m_Peers;

			DHKeysPairSupplier m_DHKeysPairSupplier;

			std::atomic<uint64_t> m_TotalSentBytes, m_TotalReceivedBytes, m_TotalTransitTransmittedBytes;
			uint32_t m_InBandwidth, m_OutBandwidth, m_TransitBandwidth; // bytes per second
			uint64_t m_LastInBandwidthUpdateBytes, m_LastOutBandwidthUpdateBytes, m_LastTransitBandwidthUpdateBytes;
			uint64_t m_LastBandwidthUpdateTime;

			/** which router families to trust for first hops */
			std::vector<std::string> m_TrustedFamilies;
			mutable std::mutex m_FamilyMutex;

			/** which routers for first hop to trust */
			std::vector<i2p::data::IdentHash> m_TrustedRouters;
			mutable std::mutex m_TrustedRoutersMutex;

			i2p::I2NPMessagesHandler m_LoopbackHandler;

		public:

			// for HTTP only
			const NTCPServer * GetNTCPServer () const { return m_NTCPServer; };
			const SSUServer * GetSSUServer () const { return m_SSUServer; };
			const NTCP2Server * GetNTCP2Server () const { return m_NTCP2Server; };
			const decltype(m_Peers)& GetPeers () const { return m_Peers; };
	};

	extern Transports transports;
}
}

#endif
