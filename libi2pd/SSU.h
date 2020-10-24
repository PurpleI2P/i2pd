/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU_H__
#define SSU_H__

#include <inttypes.h>
#include <string.h>
#include <map>
#include <list>
#include <set>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>
#include "Crypto.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "SSUSession.h"

namespace i2p
{
namespace transport
{
	const int SSU_KEEP_ALIVE_INTERVAL = 30; // 30 seconds
	const int SSU_PEER_TEST_TIMEOUT = 60; // 60 seconds
	const int SSU_TO_INTRODUCER_SESSION_DURATION = 3600; // 1 hour
	const int SSU_TERMINATION_CHECK_TIMEOUT = 30; // 30 seconds
	const size_t SSU_MAX_NUM_INTRODUCERS = 3;
	const size_t SSU_SOCKET_RECEIVE_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU_SOCKET_SEND_BUFFER_SIZE = 0x1FFFF; // 128K

	struct SSUPacket
	{
		i2p::crypto::AESAlignedBuffer<SSU_MTU_V6 + 18> buf; // max MTU + iv + size
		boost::asio::ip::udp::endpoint from;
		size_t len;
	};

	class SSUServer
	{
		public:

			SSUServer (int port);
			SSUServer (const boost::asio::ip::address & addr, int port); // ipv6 only constructor
			~SSUServer ();
			void Start ();
			void Stop ();
			void CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest = false, bool v4only = false);
			void CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
				const boost::asio::ip::address& addr, int port, bool peerTest = false);
			void CreateDirectSession (std::shared_ptr<const i2p::data::RouterInfo> router, boost::asio::ip::udp::endpoint remoteEndpoint, bool peerTest);
			std::shared_ptr<SSUSession> FindSession (std::shared_ptr<const i2p::data::RouterInfo> router) const;
			std::shared_ptr<SSUSession> FindSession (const boost::asio::ip::udp::endpoint& e) const;
			std::shared_ptr<SSUSession> GetRandomEstablishedV4Session (std::shared_ptr<const SSUSession> excluded);
			std::shared_ptr<SSUSession> GetRandomEstablishedV6Session (std::shared_ptr<const SSUSession> excluded);
			void DeleteSession (std::shared_ptr<SSUSession> session);
			void DeleteAllSessions ();

			boost::asio::io_service& GetService () { return m_Service; };
			const boost::asio::ip::udp::endpoint& GetEndpoint () const { return m_Endpoint; };
			void Send (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& to);
			void AddRelay (uint32_t tag, std::shared_ptr<SSUSession> relay);
			void RemoveRelay (uint32_t tag);
			std::shared_ptr<SSUSession> FindRelaySession (uint32_t tag);

			void NewPeerTest (uint32_t nonce, PeerTestParticipant role, std::shared_ptr<SSUSession> session = nullptr);
			PeerTestParticipant GetPeerTestParticipant (uint32_t nonce);
			std::shared_ptr<SSUSession> GetPeerTestSession (uint32_t nonce);
			void UpdatePeerTest (uint32_t nonce, PeerTestParticipant role);
			void RemovePeerTest (uint32_t nonce);

		private:

			void OpenSocket ();
			void OpenSocketV6 ();
			void Run ();
			void RunReceivers ();
			void RunReceiversV6 ();
			void Receive ();
			void ReceiveV6 ();
			void HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet);
			void HandleReceivedFromV6 (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet);
			void HandleReceivedPackets (std::vector<SSUPacket *> packets,
				std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSUSession> >* sessions);

			void CreateSessionThroughIntroducer (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest = false);
			template<typename Filter>
			std::shared_ptr<SSUSession> GetRandomV4Session (Filter filter);
			template<typename Filter>
			std::shared_ptr<SSUSession> GetRandomV6Session (Filter filter);

			std::set<SSUSession *> FindIntroducers (int maxNumIntroducers);
			void ScheduleIntroducersUpdateTimer ();
			void HandleIntroducersUpdateTimer (const boost::system::error_code& ecode);

			void SchedulePeerTestsCleanupTimer ();
			void HandlePeerTestsCleanupTimer (const boost::system::error_code& ecode);

			// timer
			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);
			void ScheduleTerminationV6 ();
			void HandleTerminationTimerV6 (const boost::system::error_code& ecode);

		private:

			struct PeerTest
			{
				uint64_t creationTime;
				PeerTestParticipant role;
				std::shared_ptr<SSUSession> session; // for Bob to Alice
			};

			bool m_OnlyV6;
			bool m_IsRunning;
			std::thread * m_Thread, * m_ReceiversThread, * m_ReceiversThreadV6;
			boost::asio::io_service m_Service, m_ReceiversService, m_ReceiversServiceV6;
			boost::asio::io_service::work m_Work, m_ReceiversWork, m_ReceiversWorkV6;
			boost::asio::ip::udp::endpoint m_Endpoint, m_EndpointV6;
			boost::asio::ip::udp::socket m_Socket, m_SocketV6;
			boost::asio::deadline_timer m_IntroducersUpdateTimer, m_PeerTestsCleanupTimer,
				m_TerminationTimer, m_TerminationTimerV6;
			std::list<boost::asio::ip::udp::endpoint> m_Introducers; // introducers we are connected to
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSUSession> > m_Sessions, m_SessionsV6;
			std::map<uint32_t, std::shared_ptr<SSUSession> > m_Relays; // we are introducer
			std::map<uint32_t, PeerTest> m_PeerTests; // nonce -> creation time in milliseconds

		public:
			// for HTTP only
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
			const decltype(m_SessionsV6)& GetSessionsV6 () const { return m_SessionsV6; };
	};
}
}

#endif
