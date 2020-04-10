/*
* Copyright (c) 2013-2019, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2CP_H__
#define I2CP_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <thread>
#include <map>
#include <boost/asio.hpp>
#include "util.h"
#include "Destination.h"

namespace i2p
{
namespace client
{
	const uint8_t I2CP_PROTOCOL_BYTE = 0x2A;
	const size_t I2CP_SESSION_BUFFER_SIZE = 4096;
	const size_t I2CP_MAX_MESSAGE_LENGTH = 65535;
	
	const size_t I2CP_HEADER_LENGTH_OFFSET = 0;
	const size_t I2CP_HEADER_TYPE_OFFSET = I2CP_HEADER_LENGTH_OFFSET + 4;
	const size_t I2CP_HEADER_SIZE = I2CP_HEADER_TYPE_OFFSET + 1;

	const uint8_t I2CP_GET_DATE_MESSAGE = 32;
	const uint8_t I2CP_SET_DATE_MESSAGE = 33;
	const uint8_t I2CP_CREATE_SESSION_MESSAGE = 1;
	const uint8_t I2CP_RECONFIGURE_SESSION_MESSAGE = 2;
	const uint8_t I2CP_SESSION_STATUS_MESSAGE = 20;
	const uint8_t I2CP_DESTROY_SESSION_MESSAGE = 3;
	const uint8_t I2CP_REQUEST_VARIABLE_LEASESET_MESSAGE = 37;
	const uint8_t I2CP_CREATE_LEASESET_MESSAGE = 4;
	const uint8_t I2CP_CREATE_LEASESET2_MESSAGE = 41;
	const uint8_t I2CP_SEND_MESSAGE_MESSAGE = 5;
	const uint8_t I2CP_SEND_MESSAGE_EXPIRES_MESSAGE = 36;
	const uint8_t I2CP_MESSAGE_PAYLOAD_MESSAGE = 31;
	const uint8_t I2CP_MESSAGE_STATUS_MESSAGE = 22;
	const uint8_t I2CP_HOST_LOOKUP_MESSAGE = 38;
	const uint8_t I2CP_HOST_REPLY_MESSAGE = 39;
	const uint8_t I2CP_DEST_LOOKUP_MESSAGE = 34;
	const uint8_t I2CP_DEST_REPLY_MESSAGE = 35;
	const uint8_t I2CP_GET_BANDWIDTH_LIMITS_MESSAGE = 8;
	const uint8_t I2CP_BANDWIDTH_LIMITS_MESSAGE = 23;

	enum I2CPMessageStatus
	{
		eI2CPMessageStatusAccepted = 1,
		eI2CPMessageStatusGuaranteedSuccess = 4,
		eI2CPMessageStatusGuaranteedFailure = 5,
		eI2CPMessageStatusNoLeaseSet = 21
	};

	// params
	const char I2CP_PARAM_DONT_PUBLISH_LEASESET[] = "i2cp.dontPublishLeaseSet";
	const char I2CP_PARAM_MESSAGE_RELIABILITY[] = "i2cp.messageReliability";

	class I2CPSession;
	class I2CPDestination: private i2p::util::RunnableService, public LeaseSetDestination
	{
		public:

			I2CPDestination (std::shared_ptr<I2CPSession> owner, std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params);
			~I2CPDestination ();
			
			void Start ();
			void Stop ();
			
			void SetEncryptionPrivateKey (const uint8_t * key);
			void SetEncryptionType (i2p::data::CryptoKeyType keyType) { m_EncryptionKeyType = keyType; };
			void LeaseSetCreated (const uint8_t * buf, size_t len); // called from I2CPSession
			void LeaseSet2Created (uint8_t storeType, const uint8_t * buf, size_t len); // called from I2CPSession
			void SendMsgTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint32_t nonce); // called from I2CPSession

			// implements LocalDestination
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, i2p::data::CryptoKeyType preferredCrypto) const;
			bool SupportsEncryptionType (i2p::data::CryptoKeyType keyType) const { return m_EncryptionKeyType == keyType; };
			// TODO: implement GetEncryptionPublicKey 
			std::shared_ptr<const i2p::data::IdentityEx> GetIdentity () const { return m_Identity; };

		protected:

			// I2CP
			void HandleDataMessage (const uint8_t * buf, size_t len);
			void CreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels);

		private:

			std::shared_ptr<I2CPDestination> GetSharedFromThis ()
			{ return std::static_pointer_cast<I2CPDestination>(shared_from_this ()); }
			bool SendMsg (std::shared_ptr<I2NPMessage> msg, std::shared_ptr<const i2p::data::LeaseSet> remote);

		private:

			std::shared_ptr<I2CPSession> m_Owner;
			std::shared_ptr<const i2p::data::IdentityEx> m_Identity;
			uint8_t m_EncryptionPrivateKey[256];
			i2p::data::CryptoKeyType m_EncryptionKeyType;
			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> m_Decryptor;
			uint64_t m_LeaseSetExpirationTime;
	};

	class I2CPServer;
	class I2CPSession: public std::enable_shared_from_this<I2CPSession>
	{
		public:

#ifdef ANDROID
			typedef boost::asio::local::stream_protocol proto;
#else
			typedef boost::asio::ip::tcp proto;
#endif

			I2CPSession (I2CPServer& owner, std::shared_ptr<proto::socket> socket);

			~I2CPSession ();

			void Start ();
			void Stop ();
			uint16_t GetSessionID () const { return m_SessionID; };
			std::shared_ptr<const I2CPDestination> GetDestination () const { return m_Destination; };

			// called from I2CPDestination
			void SendI2CPMessage (uint8_t type, const uint8_t * payload, size_t len);
			void SendMessagePayloadMessage (const uint8_t * payload, size_t len);
			void SendMessageStatusMessage (uint32_t nonce, I2CPMessageStatus status);

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

			void HandleI2CPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, const uint8_t * buf);
			std::string ExtractString (const uint8_t * buf, size_t len);
			size_t PutString (uint8_t * buf, size_t len, const std::string& str);
			void ExtractMapping (const uint8_t * buf, size_t len, std::map<std::string, std::string>& mapping);

			void SendSessionStatusMessage (uint8_t status);
			void SendHostReplyMessage (uint32_t requestID, std::shared_ptr<const i2p::data::IdentityEx> identity);

		private:

			I2CPServer& m_Owner;
			std::shared_ptr<proto::socket> m_Socket;
			uint8_t m_Header[I2CP_HEADER_SIZE], * m_Payload;
			size_t m_PayloadLen;

			std::shared_ptr<I2CPDestination> m_Destination;
			uint16_t m_SessionID;
			uint32_t m_MessageID;
			bool m_IsSendAccepted;
	};
	typedef void (I2CPSession::*I2CPMessageHandler)(const uint8_t * buf, size_t len);

	class I2CPServer
	{
		public:

			I2CPServer (const std::string& interface, int port);
			~I2CPServer ();

			void Start ();
			void Stop ();
			boost::asio::io_service& GetService () { return m_Service; };

			bool InsertSession (std::shared_ptr<I2CPSession> session);
			void RemoveSession (uint16_t sessionID);

		private:

			void Run ();

			void Accept ();

			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<I2CPSession::proto::socket> socket);

		private:

			I2CPMessageHandler m_MessagesHandlers[256];
			std::map<uint16_t, std::shared_ptr<I2CPSession> > m_Sessions;

			bool m_IsRunning;
			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			I2CPSession::proto::acceptor m_Acceptor;

		public:

			const decltype(m_MessagesHandlers)& GetMessagesHandlers () const { return m_MessagesHandlers; };

			// for HTTP
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
	};
}
}

#endif

