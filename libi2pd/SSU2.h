/*
* Copyright (c) 2022-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_H__
#define SSU2_H__

#include <unordered_map>
#include <mutex>
#include "util.h"
#include "SSU2Session.h"

namespace i2p
{
namespace transport
{
	const int SSU2_TERMINATION_CHECK_TIMEOUT = 25; // in seconds
	const int SSU2_CLEANUP_INTERVAL = 72; // in seconds
	const int SSU2_RESEND_CHECK_TIMEOUT = 400; // in milliseconds
	const int SSU2_RESEND_CHECK_TIMEOUT_VARIANCE = 100; // in milliseconds
	const int SSU2_RESEND_CHECK_MORE_TIMEOUT = 10; // in milliseconds
	const size_t SSU2_MAX_RESEND_PACKETS = 128; // packets to resend at the time
	const size_t SSU2_SOCKET_RECEIVE_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_SOCKET_SEND_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_MAX_NUM_INTRODUCERS = 3;
	const int SSU2_TO_INTRODUCER_SESSION_DURATION = 3600; // 1 hour
	const int SSU2_TO_INTRODUCER_SESSION_EXPIRATION = 4800; // 80 minutes
	const int SSU2_KEEP_ALIVE_INTERVAL = 15; // in seconds
	const int SSU2_KEEP_ALIVE_INTERVAL_VARIANCE = 4; // in seconds
	const int SSU2_PROXY_CONNECT_RETRY_TIMEOUT = 30; // in seconds

	class SSU2Server: private i2p::util::RunnableServiceWithWork
	{
		struct Packet
		{
			uint8_t buf[SSU2_MAX_PACKET_SIZE];
			size_t len;
			boost::asio::ip::udp::endpoint from;
		};

		class ReceiveService: public i2p::util::RunnableService
		{
			public:

				ReceiveService (const std::string& name): RunnableService (name) {};
				boost::asio::io_service& GetService () { return GetIOService (); };
				void Start () { StartIOService (); };
				void Stop () { StopIOService (); };
		};

		public:

			SSU2Server ();
			~SSU2Server () {};

			void Start ();
			void Stop ();
			boost::asio::io_service& GetService () { return GetIOService (); };
			void SetLocalAddress (const boost::asio::ip::address& localAddress);
			bool SetProxy (const std::string& address, uint16_t port);
			bool UsesProxy () const { return m_IsThroughProxy; };
			bool IsSupported (const boost::asio::ip::address& addr) const;
			uint16_t GetPort (bool v4) const;
			bool IsSyncClockFromPeers () const { return m_IsSyncClockFromPeers; };

			void AddSession (std::shared_ptr<SSU2Session> session);
			void RemoveSession (uint64_t connID);
			void AddSessionByRouterHash (std::shared_ptr<SSU2Session> session);
			bool AddPendingOutgoingSession (std::shared_ptr<SSU2Session> session);
			void RemovePendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep);
			std::shared_ptr<SSU2Session> FindSession (const i2p::data::IdentHash& ident) const;
			std::shared_ptr<SSU2Session> FindPendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep) const;
			std::shared_ptr<SSU2Session> GetRandomSession (i2p::data::RouterInfo::CompatibleTransports remoteTransports,
				const i2p::data::IdentHash& excluded) const;

			void AddRelay (uint32_t tag, std::shared_ptr<SSU2Session> relay);
			void RemoveRelay (uint32_t tag);
			std::shared_ptr<SSU2Session> FindRelaySession (uint32_t tag);

			void Send (const uint8_t * header, size_t headerLen, const uint8_t * payload, size_t payloadLen,
				const boost::asio::ip::udp::endpoint& to);
			void Send (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen,
				const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to);

			bool CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
				std::shared_ptr<const i2p::data::RouterInfo::Address> address, bool peerTest = false);
			bool StartPeerTest (std::shared_ptr<const i2p::data::RouterInfo> router, bool v4);

			void UpdateOutgoingToken (const boost::asio::ip::udp::endpoint& ep, uint64_t token, uint32_t exp);
			uint64_t FindOutgoingToken (const boost::asio::ip::udp::endpoint& ep);
			uint64_t GetIncomingToken (const boost::asio::ip::udp::endpoint& ep);
			std::pair<uint64_t, uint32_t> NewIncomingToken (const boost::asio::ip::udp::endpoint& ep);

			void RescheduleIntroducersUpdateTimer ();
			void RescheduleIntroducersUpdateTimerV6 ();

			i2p::util::MemoryPool<SSU2SentPacket>& GetSentPacketsPool () { return m_SentPacketsPool; };
			i2p::util::MemoryPool<SSU2IncompleteMessage>& GetIncompleteMessagesPool () { return m_IncompleteMessagesPool; };
			i2p::util::MemoryPool<SSU2IncompleteMessage::Fragment>& GetFragmentsPool () { return m_FragmentsPool; };

		private:

			boost::asio::ip::udp::socket& OpenSocket (const boost::asio::ip::udp::endpoint& localEndpoint);
			void Receive (boost::asio::ip::udp::socket& socket);
			void HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred,
				Packet * packet, boost::asio::ip::udp::socket& socket);
			void HandleReceivedPacket (Packet * packet);
			void HandleReceivedPackets (std::vector<Packet *> packets);
			void ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);

			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);

			void ScheduleCleanup ();
			void HandleCleanupTimer (const boost::system::error_code& ecode);

			void ScheduleResend (bool more);
			void HandleResendTimer (const boost::system::error_code& ecode);

			void ConnectThroughIntroducer (std::shared_ptr<SSU2Session> session);
			std::list<std::shared_ptr<SSU2Session> > FindIntroducers (int maxNumIntroducers,
				bool v4, const std::set<i2p::data::IdentHash>& excluded) const;
			void UpdateIntroducers (bool v4);
			void ScheduleIntroducersUpdateTimer ();
			void HandleIntroducersUpdateTimer (const boost::system::error_code& ecode, bool v4);
			void ScheduleIntroducersUpdateTimerV6 ();

			void SendThroughProxy (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen,
				const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to);
			void ProcessNextPacketFromProxy (uint8_t * buf, size_t len);
			void ConnectToProxy ();
			void ReconnectToProxy ();
			void HandshakeWithProxy ();
			void ReadHandshakeWithProxyReply ();
			void SendUDPAssociateRequest ();
			void ReadUDPAssociateReply ();
			void ReadUDPAssociateSocket (); // handle if closed by peer

		private:

			ReceiveService m_ReceiveService;
			boost::asio::ip::udp::socket m_SocketV4, m_SocketV6;
			boost::asio::ip::address m_AddressV4, m_AddressV6;
			std::unordered_map<uint64_t, std::shared_ptr<SSU2Session> > m_Sessions;
			std::unordered_map<i2p::data::IdentHash, std::shared_ptr<SSU2Session> > m_SessionsByRouterHash;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSU2Session> > m_PendingOutgoingSessions;
			mutable std::mutex m_PendingOutgoingSessionsMutex;
			std::map<boost::asio::ip::udp::endpoint, std::pair<uint64_t, uint32_t> > m_IncomingTokens, m_OutgoingTokens; // remote endpoint -> (token, expires in seconds)
			std::map<uint32_t, std::shared_ptr<SSU2Session> > m_Relays; // we are introducer, relay tag -> session
			std::list<i2p::data::IdentHash> m_Introducers, m_IntroducersV6; // introducers we are connected to
			i2p::util::MemoryPoolMt<Packet> m_PacketsPool;
			i2p::util::MemoryPool<SSU2SentPacket> m_SentPacketsPool;
			i2p::util::MemoryPool<SSU2IncompleteMessage> m_IncompleteMessagesPool;
			i2p::util::MemoryPool<SSU2IncompleteMessage::Fragment> m_FragmentsPool;
			boost::asio::deadline_timer m_TerminationTimer, m_CleanupTimer, m_ResendTimer,
				m_IntroducersUpdateTimer, m_IntroducersUpdateTimerV6;
			std::shared_ptr<SSU2Session> m_LastSession;
			bool m_IsPublished; // if we maintain introducers
			bool m_IsSyncClockFromPeers;

			// proxy
			bool m_IsThroughProxy;
			uint8_t m_UDPRequestHeader[SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE];
			std::unique_ptr<boost::asio::ip::tcp::endpoint> m_ProxyEndpoint;
			std::unique_ptr<boost::asio::ip::tcp::socket> m_UDPAssociateSocket;
			std::unique_ptr<boost::asio::ip::udp::endpoint> m_ProxyRelayEndpoint;
			std::unique_ptr<boost::asio::deadline_timer> m_ProxyConnectRetryTimer;

		public:

			// for HTTP/I2PControl
			const decltype(m_Sessions)& GetSSU2Sessions () const { return m_Sessions; };
	};
}
}

#endif
