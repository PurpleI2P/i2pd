/*
* Copyright (c) 2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_H__
#define SSU2_H__

#include <unordered_map>
#include "util.h"
#include "SSU2Session.h"

namespace i2p
{
namespace transport
{
	const int SSU2_TERMINATION_CHECK_TIMEOUT = 30; // 30 seconds
	const size_t SSU2_SOCKET_RECEIVE_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_SOCKET_SEND_BUFFER_SIZE = 0x1FFFF; // 128K
		
	class SSU2Server: private i2p::util::RunnableServiceWithWork
	{
		struct Packet
		{
			uint8_t buf[SSU2_MTU];
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

			void AddSession (std::shared_ptr<SSU2Session> session);
			void RemoveSession (uint64_t connID);
			void AddSessionByRouterHash (std::shared_ptr<SSU2Session> session);
			void AddPendingOutgoingSession (std::shared_ptr<SSU2Session> session);
			std::shared_ptr<SSU2Session> FindSession (const i2p::data::IdentHash& ident) const;
			std::shared_ptr<SSU2Session> GetRandomSession (i2p::data::RouterInfo::CompatibleTransports remoteTransports) const;
		
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
			uint64_t FindOutgoingToken (const boost::asio::ip::udp::endpoint& ep) const;
			uint64_t GetIncomingToken (const boost::asio::ip::udp::endpoint& ep);

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

			void ScheduleResend ();
			void HandleResendTimer (const boost::system::error_code& ecode);

			void ConnectThroughIntroducer (std::shared_ptr<SSU2Session> session);

		private:

			ReceiveService m_ReceiveService;
			boost::asio::ip::udp::socket m_SocketV4, m_SocketV6;
			std::unordered_map<uint64_t, std::shared_ptr<SSU2Session> > m_Sessions;
			std::map<i2p::data::IdentHash, std::shared_ptr<SSU2Session> > m_SessionsByRouterHash;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSU2Session> > m_PendingOutgoingSessions;
			std::map<boost::asio::ip::udp::endpoint, std::pair<uint64_t, uint32_t> > m_IncomingTokens, m_OutgoingTokens; // remote endpoint -> (token, expires in seconds)
			std::map<uint32_t, std::shared_ptr<SSU2Session> > m_Relays; // we are introducer, relay tag -> session
			i2p::util::MemoryPoolMt<Packet> m_PacketsPool;
			boost::asio::deadline_timer m_TerminationTimer, m_ResendTimer;
			std::shared_ptr<SSU2Session> m_LastSession;

		public:

			// for HTTP/I2PControl
			const decltype(m_Sessions)& GetSSU2Sessions () const { return m_Sessions; };
	};
}
}

#endif
