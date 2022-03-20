/*
* Copyright (c) 2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_H__
#define SSU2_H__

#include <memory>
#include <map>
#include <unordered_map>
#include <boost/asio.hpp>
#include "Crypto.h"
#include "RouterInfo.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	const int SSU2_CONNECT_TIMEOUT = 5; // 5 seconds
	const int SSU2_TERMINATION_TIMEOUT = 330; // 5.5 minutes
	const int SSU2_TERMINATION_CHECK_TIMEOUT = 30; // 30 seconds
	const size_t SSU2_SOCKET_RECEIVE_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_SOCKET_SEND_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_MTU = 1488;
	
	enum SSU2MessageType
	{
		eSSU2SessionRequest = 0,
		eSSU2SessionCreated = 1,
		eSSU2Retry = 9
	};

	enum SSU2BlockType
	{
		eSSU2BlkDateTime = 0,
		eSSU2BlkOptions, // 1
		eSSU2BlkRouterInfo, // 2
		eSSU2BlkI2NPMessage, // 3
		eSSU2BlkFirstFragment, // 4
		eSSU2BlkFollowOnFragment, // 5
		eSSU2BlkTermination, // 6
		eSSU2BlkRelayRequest, // 7
		eSSU2BlkRelayResponse, // 8
		eSSU2BlkRelayIntro, // 9
		eSSU2BlkPeerTest, // 10
		eSSU2BlkNextNonce, // 11
		eSSU2BlkAck, // 12
		eSSU2BlkAddress, // 13
		eSSU2BlkIntroKey, // 14
		eSSU2BlkRelayTagRequest, // 15
		eSSU2BlkRelayTag, // 16
		eSSU2BlkNewToken, // 17
		eSSU2BlkPathChallenge, // 18
		eSSU2BlkPathResponse, // 19
		eSSU2BlkFirstPacketNumber, // 20
		eSSU2BlkPadding = 254
	};
	
	class SSU2Server;
	class SSU2Session: public TransportSession, public std::enable_shared_from_this<SSU2Session>
	{
		union Header
		{
			uint64_t ll[2];
			uint8_t buf[16];
			struct
			{
				uint64_t connID;
				uint8_t packetNum[4];
				uint8_t type;
				uint8_t flags[3];
			} h;
		};
	
		public:

			SSU2Session (SSU2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr,
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr = nullptr, bool peerTest = false);
			~SSU2Session ();

			void SetRemoteEndpoint (const boost::asio::ip::udp::endpoint& ep) { m_RemoteEndpoint = ep; };

			void Connect ();
			void Done () override {};
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) override {};
			
			void ProcessSessionRequest (uint64_t connID, uint8_t * buf, size_t len);
			bool ProcessSessionCreated (uint8_t * buf, size_t len);
			bool ProcessRetry (uint8_t * buf, size_t len);
			
		private:

			void SendSessionRequest (uint64_t token = 0);
			void SendSessionCreated (const uint8_t * X);

			void HandlePayload (const uint8_t * buf, size_t len);
			bool ExtractEndpoint (const uint8_t * buf, size_t size, boost::asio::ip::udp::endpoint& ep);
			size_t CreateAddressBlock (const boost::asio::ip::udp::endpoint& ep, uint8_t * buf, size_t len);
			
		private:

			SSU2Server& m_Server;
			std::shared_ptr<i2p::crypto::X25519Keys> m_EphemeralKeys;
			std::unique_ptr<i2p::crypto::NoiseSymmetricState> m_NoiseState;
			std::shared_ptr<const i2p::data::RouterInfo::Address> m_Address;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			uint64_t m_DestConnID, m_SourceConnID;
	};

	class SSU2Server:  private i2p::util::RunnableServiceWithWork
	{
		struct Packet
		{
			uint8_t buf[SSU2_MTU]; 
			size_t len;
			boost::asio::ip::udp::endpoint from;
		};	
		
		public:

			SSU2Server ();
			~SSU2Server () {};

			void Start ();
			void Stop ();
			boost::asio::io_service& GetService () { return GetIOService (); };
			
			void AddSession (uint64_t connID, std::shared_ptr<SSU2Session> session);
			void AddPendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep, std::shared_ptr<SSU2Session> session);

			void Send (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen, 
				const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to);

			bool CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
				std::shared_ptr<const i2p::data::RouterInfo::Address> address);
			
		private:

			boost::asio::ip::udp::socket& OpenSocket (const boost::asio::ip::udp::endpoint& localEndpoint);
			void Receive (boost::asio::ip::udp::socket& socket);
			void HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred, 
				Packet * packet, boost::asio::ip::udp::socket& socket);
			void ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);

			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);
			
		private:

			boost::asio::ip::udp::socket m_Socket, m_SocketV6;
			std::unordered_map<uint64_t, std::shared_ptr<SSU2Session> > m_Sessions;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSU2Session> > m_PendingOutgoingSessions;
			i2p::util::MemoryPoolMt<Packet> m_PacketsPool;
			boost::asio::deadline_timer m_TerminationTimer;
	};	
}
}

#endif
