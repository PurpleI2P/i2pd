/*
* Copyright (c) 2013-2019, The PurpleI2P Project
*
* This file is part of Purple dotnet project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef DNCP_H__
#define DNCP_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <thread>
#include <map>
#include <boost/asio.hpp>
#include "Destination.h"

namespace dotnet
{
namespace client
{
	const uint8_t DNCP_PROTOCOL_BYTE = 0x2A;
	const size_t DNCP_SESSION_BUFFER_SIZE = 4096;

	const size_t DNCP_HEADER_LENGTH_OFFSET = 0;
	const size_t DNCP_HEADER_TYPE_OFFSET = DNCP_HEADER_LENGTH_OFFSET + 4;
	const size_t DNCP_HEADER_SIZE = DNCP_HEADER_TYPE_OFFSET + 1;

	const uint8_t DNCP_GET_DATE_MESSAGE = 32;
	const uint8_t DNCP_SET_DATE_MESSAGE = 33;
	const uint8_t DNCP_CREATE_SESSION_MESSAGE = 1;
	const uint8_t DNCP_RECONFIGURE_SESSION_MESSAGE = 2;
	const uint8_t DNCP_SESSION_STATUS_MESSAGE = 20;
	const uint8_t DNCP_DESTROY_SESSION_MESSAGE = 3;
	const uint8_t DNCP_REQUEST_VARIABLE_LEASESET_MESSAGE = 37;
	const uint8_t DNCP_CREATE_LEASESET_MESSAGE = 4;
	const uint8_t DNCP_CREATE_LEASESET2_MESSAGE = 41;
	const uint8_t DNCP_SEND_MESSAGE_MESSAGE = 5;
	const uint8_t DNCP_SEND_MESSAGE_EXPIRES_MESSAGE = 36;
	const uint8_t DNCP_MESSAGE_PAYLOAD_MESSAGE = 31;
	const uint8_t DNCP_MESSAGE_STATUS_MESSAGE = 22;
	const uint8_t DNCP_HOST_LOOKUP_MESSAGE = 38;
	const uint8_t DNCP_HOST_REPLY_MESSAGE = 39;
	const uint8_t DNCP_DEST_LOOKUP_MESSAGE = 34;
	const uint8_t DNCP_DEST_REPLY_MESSAGE = 35;
	const uint8_t DNCP_GET_BANDWIDTH_LIMITS_MESSAGE = 8;
	const uint8_t DNCP_BANDWIDTH_LIMITS_MESSAGE = 23;

	enum DNCPMessageStatus
	{
		eDNCPMessageStatusAccepted = 1,
		eDNCPMessageStatusGuaranteedSuccess = 4,
		eDNCPMessageStatusGuaranteedFailure = 5,
		eDNCPMessageStatusNoLeaseSet = 21
	};

	// params
	const char DNCP_PARAM_DONT_PUBLISH_LEASESET[] = "dncp.dontPublishLeaseSet";
	const char DNCP_PARAM_MESSAGE_RELIABILITY[] = "dncp.messageReliability";

	class DNCPSession;
	class DNCPDestination: public LeaseSetDestination
	{
		public:

			DNCPDestination (std::shared_ptr<DNCPSession> owner, std::shared_ptr<const dotnet::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params);

			void SetEncryptionPrivateKey (const uint8_t * key);
			void LeaseSetCreated (const uint8_t * buf, size_t len); // called from DNCPSession
			void LeaseSet2Created (uint8_t storeType, const uint8_t * buf, size_t len); // called from DNCPSession
			void SendMsgTo (const uint8_t * payload, size_t len, const dotnet::data::IdentHash& ident, uint32_t nonce); // called from DNCPSession

			// implements LocalDestination
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx) const;
			std::shared_ptr<const dotnet::data::IdentityEx> GetIdentity () const { return m_Identity; };

		protected:

			// DNCP
			void HandleDataMessage (const uint8_t * buf, size_t len);
			void CreateNewLeaseSet (std::vector<std::shared_ptr<dotnet::tunnel::InboundTunnel> > tunnels);

		private:

			std::shared_ptr<DNCPDestination> GetSharedFromThis ()
			{ return std::static_pointer_cast<DNCPDestination>(shared_from_this ()); }
			bool SendMsg (std::shared_ptr<DNNPMessage> msg, std::shared_ptr<const dotnet::data::LeaseSet> remote);

		private:

			std::shared_ptr<DNCPSession> m_Owner;
			std::shared_ptr<const dotnet::data::IdentityEx> m_Identity;
			uint8_t m_EncryptionPrivateKey[256];
			std::shared_ptr<dotnet::crypto::CryptoKeyDecryptor> m_Decryptor;
			uint64_t m_LeaseSetExpirationTime;
	};

	class DNCPServer;
	class DNCPSession: public std::enable_shared_from_this<DNCPSession>
	{
		public:

#ifdef ANDROID
			typedef boost::asio::local::stream_protocol proto;
#else
			typedef boost::asio::ip::tcp proto;
#endif

			DNCPSession (DNCPServer& owner, std::shared_ptr<proto::socket> socket);

			~DNCPSession ();

			void Start ();
			void Stop ();
			uint16_t GetSessionID () const { return m_SessionID; };
			std::shared_ptr<const DNCPDestination> GetDestination () const { return m_Destination; };

			// called from DNCPDestination
			void SendDNCPMessage (uint8_t type, const uint8_t * payload, size_t len);
			void SendMessagePayloadMessage (const uint8_t * payload, size_t len);
			void SendMessageStatusMessage (uint32_t nonce, DNCPMessageStatus status);

			// message handlers
			void GetDateMessageHandler (const uint8_t * buf, size_t len);
			void CreateSessionMessageHandler (const uint8_t * buf, size_t len);
			void DestroySessionMessageHandler (const uint8_t * buf, size_t len);
			void ReconfigureSessionMessageHandler (const uint8_t * buf, size_t len);
			void CreateLeaseSetMessageHandler (const uint8_t * buf, size_t len);
			void CreateLeaseSet2MessageHandler (const uint8_t * buf, size_t len);
			void SendMessageMessageHandler (const uint8_t * buf, size_t len);
			void SendMessageExpiresMessageHandler (const uint8_t * buf, size_t len);
			void HostLookupMessageHandler (const uint8_t * buf, size_t len);
			void DestLookupMessageHandler (const uint8_t * buf, size_t len);
			void GetBandwidthLimitsMessageHandler (const uint8_t * buf, size_t len);

		private:

			void ReadProtocolByte ();
			void ReceiveHeader ();
			void HandleReceivedHeader (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void ReceivePayload ();
			void HandleReceivedPayload (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleMessage ();
			void Terminate ();

			void HandleDNCPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, const uint8_t * buf);
			std::string ExtractString (const uint8_t * buf, size_t len);
			size_t PutString (uint8_t * buf, size_t len, const std::string& str);
			void ExtractMapping (const uint8_t * buf, size_t len, std::map<std::string, std::string>& mapping);

			void SendSessionStatusMessage (uint8_t status);
			void SendHostReplyMessage (uint32_t requestID, std::shared_ptr<const dotnet::data::IdentityEx> identity);

		private:

			DNCPServer& m_Owner;
			std::shared_ptr<proto::socket> m_Socket;
			uint8_t m_Header[DNCP_HEADER_SIZE], * m_Payload;
			size_t m_PayloadLen;

			std::shared_ptr<DNCPDestination> m_Destination;
			uint16_t m_SessionID;
			uint32_t m_MessageID;
			bool m_IsSendAccepted;
	};
	typedef void (DNCPSession::*DNCPMessageHandler)(const uint8_t * buf, size_t len);

	class DNCPServer
	{
		public:

			DNCPServer (const std::string& interface, int port);
			~DNCPServer ();

			void Start ();
			void Stop ();
			boost::asio::io_service& GetService () { return m_Service; };

			bool InsertSession (std::shared_ptr<DNCPSession> session);
			void RemoveSession (uint16_t sessionID);

		private:

			void Run ();

			void Accept ();

			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<DNCPSession::proto::socket> socket);

		private:

			DNCPMessageHandler m_MessagesHandlers[256];
			std::map<uint16_t, std::shared_ptr<DNCPSession> > m_Sessions;

			bool m_IsRunning;
			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			DNCPSession::proto::acceptor m_Acceptor;

		public:

			const decltype(m_MessagesHandlers)& GetMessagesHandlers () const { return m_MessagesHandlers; };

			// for HTTP
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
	};
}
}

#endif

