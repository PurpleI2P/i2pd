/*
* Copyright (c) 2022-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_H__
#define SSU2_H__

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <array>
#include <mutex>
#include <random>
#include "util.h"
#include "SSU2Session.h"
#include "Socks5.h"

namespace i2p
{
namespace transport
{
	const int SSU2_TERMINATION_CHECK_TIMEOUT = 23; // in seconds
	const int SSU2_TERMINATION_CHECK_TIMEOUT_VARIANCE = 5; // in seconds
	const int SSU2_CLEANUP_INTERVAL = 72; // in seconds
	const int SSU2_RESEND_CHECK_TIMEOUT = 40; // in milliseconds
	const int SSU2_RESEND_CHECK_TIMEOUT_VARIANCE = 10; // in milliseconds
	const int SSU2_RESEND_CHECK_MORE_TIMEOUT = 4; // in milliseconds
	const int SSU2_RESEND_CHECK_MORE_TIMEOUT_VARIANCE = 9; // in milliseconds
	const size_t SSU2_MAX_RESEND_PACKETS = 128; // packets to resend at the time
	const uint64_t SSU2_SOCKET_MIN_BUFFER_SIZE = 128 * 1024;
	const uint64_t SSU2_SOCKET_MAX_BUFFER_SIZE = 4 * 1024 * 1024;
	const size_t SSU2_MAX_NUM_INTRODUCERS = 3;
	const size_t SSU2_MIN_RECEIVED_PACKET_SIZE = 40; // 16 byte short header + 8 byte minimum payload + 16 byte MAC
	const int SSU2_TO_INTRODUCER_SESSION_DURATION = 3600; // 1 hour
	const int SSU2_TO_INTRODUCER_SESSION_EXPIRATION = 4800; // 80 minutes
	const int SSU2_KEEP_ALIVE_INTERVAL = 15; // in seconds
	const int SSU2_KEEP_ALIVE_INTERVAL_VARIANCE = 4; // in seconds
	const int SSU2_PROXY_CONNECT_RETRY_TIMEOUT = 30; // in seconds
	const int SSU2_HOLE_PUNCH_EXPIRATION = 150; // in seconds
	const size_t SSU2_MAX_NUM_PACKETS_PER_BATCH = 32;

	class SSU2Server: private i2p::util::RunnableServiceWithWork
	{
		struct Packet
		{
			uint8_t buf[SSU2_MAX_PACKET_SIZE];
			size_t len;
			boost::asio::ip::udp::endpoint from;
		};

		struct Packets: public std::array<Packet *, SSU2_MAX_NUM_PACKETS_PER_BATCH>
		{
			size_t numPackets = 0;
			bool AddPacket (Packet *p) 
			{
				if (p && numPackets < size ()) 
				{ 
					data()[numPackets] = p; numPackets++; 
					return true;
				} 
				return false;
			} 
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
			bool IsConnectedRecently (const boost::asio::ip::udp::endpoint& ep);
			void AddConnectedRecently (const boost::asio::ip::udp::endpoint& ep, uint64_t ts);
			std::mt19937& GetRng () { return m_Rng; }
			bool IsMaxNumIntroducers (bool v4) const { return (v4 ? m_Introducers.size () : m_IntroducersV6.size ()) >= SSU2_MAX_NUM_INTRODUCERS; }
			bool IsSyncClockFromPeers () const { return m_IsSyncClockFromPeers; };
			void AdjustTimeOffset (int64_t offset, std::shared_ptr<const i2p::data::IdentityEx> from);

			void AddSession (std::shared_ptr<SSU2Session> session);
			void RemoveSession (uint64_t connID);
			void RequestRemoveSession (uint64_t connID);
			void AddSessionByRouterHash (std::shared_ptr<SSU2Session> session);
			bool AddPendingOutgoingSession (std::shared_ptr<SSU2Session> session);
			void RemovePendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep);
			std::shared_ptr<SSU2Session> FindSession (const i2p::data::IdentHash& ident);
			std::shared_ptr<SSU2Session> FindPendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep) const;
			std::shared_ptr<SSU2Session> GetRandomPeerTestSession (i2p::data::RouterInfo::CompatibleTransports remoteTransports,
				const i2p::data::IdentHash& excluded);

			void AddRelay (uint32_t tag, std::shared_ptr<SSU2Session> relay);
			void RemoveRelay (uint32_t tag);
			std::shared_ptr<SSU2Session> FindRelaySession (uint32_t tag);

			bool AddPeerTest (uint32_t nonce, std::shared_ptr<SSU2Session> aliceSession, uint64_t ts); 
			std::shared_ptr<SSU2Session> GetPeerTest (uint32_t nonce);	
		
			bool AddRequestedPeerTest (uint32_t nonce, std::shared_ptr<SSU2PeerTestSession> session, uint64_t ts);
			std::shared_ptr<SSU2PeerTestSession> GetRequestedPeerTest (uint32_t nonce);		
		
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
			void HandleReceivedPackets (Packets * packets);
			void ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);

			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);

			void ScheduleCleanup ();
			void HandleCleanupTimer (const boost::system::error_code& ecode);

			void ScheduleResend (bool more);
			void HandleResendTimer (const boost::system::error_code& ecode);

			void ConnectThroughIntroducer (std::shared_ptr<SSU2Session> session);
			std::vector<std::shared_ptr<SSU2Session> > FindIntroducers (int maxNumIntroducers,
				bool v4, const std::unordered_set<i2p::data::IdentHash>& excluded);
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
			std::unordered_map<i2p::data::IdentHash, std::weak_ptr<SSU2Session> > m_SessionsByRouterHash;
			mutable std::mutex m_SessionsByRouterHashMutex;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSU2Session> > m_PendingOutgoingSessions;
			mutable std::mutex m_PendingOutgoingSessionsMutex;
			std::map<boost::asio::ip::udp::endpoint, std::pair<uint64_t, uint32_t> > m_IncomingTokens, m_OutgoingTokens; // remote endpoint -> (token, expires in seconds)
			std::unordered_map<uint32_t, std::weak_ptr<SSU2Session> > m_Relays; // we are introducer, relay tag -> session
			std::unordered_map<uint32_t, std::pair <std::weak_ptr<SSU2Session>, uint64_t > > m_PeerTests; // nonce->(Alice, timestamp). We are Bob
			std::list<std::pair<i2p::data::IdentHash, uint32_t> > m_Introducers, m_IntroducersV6; // introducers we are connected to
			i2p::util::MemoryPoolMt<Packet> m_PacketsPool;
			i2p::util::MemoryPoolMt<Packets> m_PacketsArrayPool;
			i2p::util::MemoryPool<SSU2SentPacket> m_SentPacketsPool;
			i2p::util::MemoryPool<SSU2IncompleteMessage> m_IncompleteMessagesPool;
			i2p::util::MemoryPool<SSU2IncompleteMessage::Fragment> m_FragmentsPool;
			boost::asio::deadline_timer m_TerminationTimer, m_CleanupTimer, m_ResendTimer,
				m_IntroducersUpdateTimer, m_IntroducersUpdateTimerV6;
			std::shared_ptr<SSU2Session> m_LastSession;
			bool m_IsPublished; // if we maintain introducers
			bool m_IsSyncClockFromPeers;
			int64_t m_PendingTimeOffset; // during peer test
			std::shared_ptr<const i2p::data::IdentityEx> m_PendingTimeOffsetFrom;
			std::mt19937 m_Rng;
			std::map<boost::asio::ip::udp::endpoint, uint64_t> m_ConnectedRecently; // endpoint -> last activity time in seconds
			std::unordered_map<uint32_t, std::pair <std::weak_ptr<SSU2PeerTestSession>, uint64_t > > m_RequestedPeerTests; // nonce->(Alice, timestamp) 
		
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
