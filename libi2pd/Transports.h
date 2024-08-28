/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
#include <unordered_map>
#include <vector>
#include <queue>
#include <string>
#include <memory>
#include <atomic>
#include <boost/asio.hpp>
#include "TransportSession.h"
#include "SSU2.h"
#include "NTCP2.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "Identity.h"

namespace i2p
{
namespace transport
{
	template<typename Keys>
	class EphemeralKeysSupplier
	{
	// called from this file only, so implementation is in Transports.cpp
		public:

			EphemeralKeysSupplier (int size);
			~EphemeralKeysSupplier ();
			void Start ();
			void Stop ();
			std::shared_ptr<Keys> Acquire ();
			void Return (std::shared_ptr<Keys> pair);

		private:

			void Run ();
			void CreateEphemeralKeys (int num);

		private:

			const int m_QueueSize;
			std::queue<std::shared_ptr<Keys> > m_Queue;

			bool m_IsRunning;
			std::thread * m_Thread;
			std::condition_variable m_Acquired;
			std::mutex m_AcquiredMutex;
	};
	typedef EphemeralKeysSupplier<i2p::crypto::X25519Keys> X25519KeysPairSupplier;

	const int PEER_ROUTER_INFO_UPDATE_INTERVAL = 31*60; // in seconds
	const int PEER_ROUTER_INFO_UPDATE_INTERVAL_VARIANCE = 7*60; // in seconds
	const size_t PEER_ROUTER_INFO_OVERLOAD_QUEUE_SIZE = 25;
	const int PEER_SELECTION_MIN_INTERVAL = 20; // in seconds
	struct Peer
	{
		int numAttempts;
		std::shared_ptr<const i2p::data::RouterInfo> router;
		std::list<std::shared_ptr<TransportSession> > sessions;
		uint64_t creationTime, nextRouterInfoUpdateTime, lastSelectionTime;
		std::vector<std::shared_ptr<i2p::I2NPMessage> > delayedMessages;
		std::vector<i2p::data::RouterInfo::SupportedTransports> priority;
		bool isHighBandwidth, isEligible;

		Peer (std::shared_ptr<const i2p::data::RouterInfo> r, uint64_t ts):
			numAttempts (0), router (r), creationTime (ts),
			nextRouterInfoUpdateTime (ts + PEER_ROUTER_INFO_UPDATE_INTERVAL),
			lastSelectionTime (0), isHighBandwidth (false), isEligible (false) 
		{
			UpdateParams (router);
		}
			
		void Done ()
		{
			for (auto& it: sessions)
				it->Done ();
			// drop not sent delayed messages
			for (auto& it: delayedMessages)
				it->Drop ();
		}

		void SetRouter (std::shared_ptr<const i2p::data::RouterInfo> r)
		{
			router = r;
			UpdateParams (router);
		}

		bool IsConnected () const { return !sessions.empty (); }
		void UpdateParams (std::shared_ptr<const i2p::data::RouterInfo> router);
	};

	const uint64_t SESSION_CREATION_TIMEOUT = 15; // in seconds
	const int PEER_TEST_INTERVAL = 71; // in minutes
	const int PEER_TEST_DELAY_INTERVAL = 20; // in milliseconds
	const int PEER_TEST_DELAY_INTERVAL_VARIANCE = 30; // in milliseconds
	const int MAX_NUM_DELAYED_MESSAGES = 150;
	const int CHECK_PROFILE_NUM_DELAYED_MESSAGES = 15; // check profile after

	const int TRAFFIC_SAMPLE_COUNT = 301; // seconds

	struct TrafficSample
	{
		uint64_t Timestamp;
		uint64_t TotalReceivedBytes;
		uint64_t TotalSentBytes;
		uint64_t TotalTransitTransmittedBytes;
	};

	class Transports
	{
		public:

			Transports ();
			~Transports ();

			void Start (bool enableNTCP2=true, bool enableSSU2=true);
			void Stop ();
			bool IsRunning () const { return m_IsRunning; }

			bool IsBoundSSU2() const { return m_SSU2Server != nullptr; }
			bool IsBoundNTCP2() const { return m_NTCP2Server != nullptr; }

			bool IsOnline() const { return m_IsOnline; };
			void SetOnline (bool online);

			boost::asio::io_service& GetService () { return *m_Service; };
			std::shared_ptr<i2p::crypto::X25519Keys> GetNextX25519KeysPair ();
			void ReuseX25519KeysPair (std::shared_ptr<i2p::crypto::X25519Keys> pair);

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
			uint32_t GetInBandwidth15s () const { return m_InBandwidth15s; };
			uint32_t GetOutBandwidth15s () const { return m_OutBandwidth15s; };
			uint32_t GetTransitBandwidth15s () const { return m_TransitBandwidth15s; };
			int GetCongestionLevel (bool longTerm) const;
			size_t GetNumPeers () const { return m_Peers.size (); };
			std::shared_ptr<const i2p::data::RouterInfo> GetRandomPeer (bool isHighBandwidth) const;

			/** get a trusted first hop for restricted routes */
			std::shared_ptr<const i2p::data::RouterInfo> GetRestrictedPeer() const;
			/** do we want to use restricted routes? */
			bool RoutesRestricted() const;
			/** restrict routes to use only these router families for first hops */
			void RestrictRoutesToFamilies(const std::set<std::string>& families);
			/** restrict routes to use only these routers for first hops */
			void RestrictRoutesToRouters(const std::set<i2p::data::IdentHash>& routers);

			bool IsRestrictedPeer(const i2p::data::IdentHash & ident) const;

			void PeerTest (bool ipv4 = true, bool ipv6 = true);

			void SetCheckReserved (bool check) { m_CheckReserved = check; };
			bool IsCheckReserved () const { return m_CheckReserved; };
			bool IsInReservedRange (const boost::asio::ip::address& host) const;

		private:

			void Run ();
			void RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident);
			void HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, i2p::data::IdentHash ident);
			void PostMessages (i2p::data::IdentHash ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > msgs);
			bool ConnectToPeer (const i2p::data::IdentHash& ident, std::shared_ptr<Peer> peer);
			void SetPriority (std::shared_ptr<Peer> peer) const;
			void HandlePeerCleanupTimer (const boost::system::error_code& ecode);
			void HandlePeerTestTimer (const boost::system::error_code& ecode);
			void HandleUpdateBandwidthTimer (const boost::system::error_code& ecode);
			void UpdateBandwidthValues (int interval, uint32_t& in, uint32_t& out, uint32_t& transit);

			void DetectExternalIP ();

			template<typename Filter>
				std::shared_ptr<const i2p::data::RouterInfo> GetRandomPeer (Filter filter) const;

		private:

			volatile bool m_IsOnline;
			bool m_IsRunning, m_IsNAT, m_CheckReserved;
			std::thread * m_Thread;
			boost::asio::io_service * m_Service;
			boost::asio::io_service::work * m_Work;
			boost::asio::deadline_timer * m_PeerCleanupTimer, * m_PeerTestTimer, * m_UpdateBandwidthTimer;

			SSU2Server * m_SSU2Server;
			NTCP2Server * m_NTCP2Server;
			mutable std::mutex m_PeersMutex;
			std::unordered_map<i2p::data::IdentHash, std::shared_ptr<Peer> > m_Peers;

			X25519KeysPairSupplier m_X25519KeysPairSupplier;

			std::atomic<uint64_t> m_TotalSentBytes, m_TotalReceivedBytes, m_TotalTransitTransmittedBytes;

			TrafficSample m_TrafficSamples[TRAFFIC_SAMPLE_COUNT];
			int m_TrafficSamplePtr;

			// Bandwidth per second
			uint32_t m_InBandwidth, m_OutBandwidth, m_TransitBandwidth;
			// Bandwidth during last 15 seconds
			uint32_t m_InBandwidth15s, m_OutBandwidth15s, m_TransitBandwidth15s;
			// Bandwidth during last 5 minutes
			uint32_t m_InBandwidth5m, m_OutBandwidth5m, m_TransitBandwidth5m;

			/** which router families to trust for first hops */
			std::vector<i2p::data::FamilyID> m_TrustedFamilies;
			mutable std::mutex m_FamilyMutex;

			/** which routers for first hop to trust */
			std::vector<i2p::data::IdentHash> m_TrustedRouters;
			mutable std::mutex m_TrustedRoutersMutex;

			i2p::I2NPMessagesHandler m_LoopbackHandler;

		public:

			// for HTTP only
			const NTCP2Server * GetNTCP2Server () const { return m_NTCP2Server; };
			const SSU2Server * GetSSU2Server () const { return m_SSU2Server; };
			const decltype(m_Peers)& GetPeers () const { return m_Peers; };
	};

	extern Transports transports;

	void InitAddressFromIface ();
	void InitTransports ();
}
}

#endif
