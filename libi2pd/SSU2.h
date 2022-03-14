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
	const int SSU2_TERMINATION_TIMEOUT = 330; // 5.5 minutes
	const size_t SSU2_SOCKET_RECEIVE_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_SOCKET_SEND_BUFFER_SIZE = 0x1FFFF; // 128K
	const size_t SSU2_MTU = 1488;
	
	enum SSU2MessageType
	{
		eSSU2SessionRequest = 0,
		eSSU2SessionCreated = 1
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
			
			void Done () override {};
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) override {};
			
			void ProcessSessionRequest (uint64_t connID, uint8_t * buf, size_t len);
			bool ProcessSessionCreated (uint8_t * buf, size_t len);
			
		private:

			void SendSessionRequest ();
			void SendSessionCreated (const uint8_t * X);
				
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
			
		private:

			void OpenSocket (int port);
			void Receive ();
			void HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred, Packet * packet);
			void ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			
		private:

			boost::asio::ip::udp::socket m_Socket;
			std::unordered_map<uint64_t, std::shared_ptr<SSU2Session> > m_Sessions;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSU2Session> > m_PendingOutgoingSessions;
			i2p::util::MemoryPoolMt<Packet> m_PacketsPool;
	};	
}
}

#endif
