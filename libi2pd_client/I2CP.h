/*
* Copyright (c) 2013-2022, The PurpleI2P Project
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
#include "Streaming.h"

namespace i2p
{
namespace client
{
	const uint8_t I2CP_PROTOCOL_BYTE = 0x2A;
	const size_t I2CP_SESSION_BUFFER_SIZE = 4096;
	const size_t I2CP_MAX_MESSAGE_LENGTH = 65535;
	const size_t I2CP_MAX_SEND_QUEUE_SIZE = 1024*1024; // in bytes, 1M
	const int I2CP_LEASESET_CREATION_TIMEOUT = 10; // in seconds

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

	enum I2CPSessionStatus
	{
		eI2CPSessionStatusDestroyed = 0,
		eI2CPSessionStatusCreated = 1,
		eI2CPSessionStatusUpdated = 2,
		eI2CPSessionStatusInvalid = 3,
		eI2CPSessionStatusRefused = 4
	};

	// params
	const char I2CP_PARAM_MESSAGE_RELIABILITY[] = "i2cp.messageReliability";

	class I2CPSession;
	class I2CPDestination: public LeaseSetDestination
	{
		public:

			I2CPDestination (boost::asio::io_service& service, std::shared_ptr<I2CPSession> owner,
				std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params);
			~I2CPDestination () {};

			void Stop ();

			void SetEncryptionPrivateKey (const uint8_t * key);
			void SetEncryptionType (i2p::data::CryptoKeyType keyType) { m_EncryptionKeyType = keyType; };
			void SetECIESx25519EncryptionPrivateKey (const uint8_t * key);
			void LeaseSetCreated (const uint8_t * buf, size_t len); // called from I2CPSession
			void LeaseSet2Created (uint8_t storeType, const uint8_t * buf, size_t len); // called from I2CPSession
			void SendMsgTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint32_t nonce); // called from I2CPSession

			// implements LocalDestination
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, i2p::data::CryptoKeyType preferredCrypto) const;
			bool SupportsEncryptionType (i2p::data::CryptoKeyType keyType) const;
			const uint8_t * GetEncryptionPublicKey (i2p::data::CryptoKeyType keyType) const; // for 4 only
			std::shared_ptr<const i2p::data::IdentityEx> GetIdentity () const { return m_Identity; };

		protected:

			// I2CP
			void HandleDataMessage (const uint8_t * buf, size_t len);
			void CreateNewLeaseSet (const std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> >& tunnels);

		private:

			std::shared_ptr<I2CPDestination> GetSharedFromThis ()
			{ return std::static_pointer_cast<I2CPDestination>(shared_from_this ()); }
			bool SendMsg (std::shared_ptr<I2NPMessage> msg, std::shared_ptr<const i2p::data::LeaseSet> remote);

			void PostCreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels);

		private:

			std::shared_ptr<I2CPSession> m_Owner;
			std::shared_ptr<const i2p::data::IdentityEx> m_Identity;
			i2p::data::CryptoKeyType m_EncryptionKeyType;
			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> m_Decryptor; // standard
			std::shared_ptr<i2p::crypto::ECIESX25519AEADRatchetDecryptor> m_ECIESx25519Decryptor;
			uint8_t m_ECIESx25519PrivateKey[32];
			uint64_t m_LeaseSetExpirationTime;
			bool m_IsCreatingLeaseSet;
			boost::asio::deadline_timer m_LeaseSetCreationTimer;
			i2p::util::MemoryPoolMt<I2NPMessageBuffer<I2NP_MAX_MESSAGE_SIZE> > m_I2NPMsgsPool;
	};

	class RunnableI2CPDestination: private i2p::util::RunnableService, public I2CPDestination
	{
		public:

			RunnableI2CPDestination (std::shared_ptr<I2CPSession> owner, std::shared_ptr<const i2p::data::IdentityEx> identity,
				bool isPublic, const std::map<std::string, std::string>& params);
			~RunnableI2CPDestination ();

			void Start ();
			void Stop ();
	};

	class I2CPServer;
	class I2CPSession: public std::enable_shared_from_this<I2CPSession>
	{
		public:

			I2CPSession (I2CPServer& owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket);

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

			void HandleI2CPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			std::string ExtractString (const uint8_t * buf, size_t len);
			size_t PutString (uint8_t * buf, size_t len, const std::string& str);
			void ExtractMapping (const uint8_t * buf, size_t len, std::map<std::string, std::string>& mapping);
			void SendSessionStatusMessage (I2CPSessionStatus status);
			void SendHostReplyMessage (uint32_t requestID, std::shared_ptr<const i2p::data::IdentityEx> identity);

		private:

			I2CPServer& m_Owner;
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			uint8_t m_Header[I2CP_HEADER_SIZE], m_Payload[I2CP_MAX_MESSAGE_LENGTH];
			size_t m_PayloadLen;

			std::shared_ptr<I2CPDestination> m_Destination;
			uint16_t m_SessionID;
			uint32_t m_MessageID;
			bool m_IsSendAccepted;

			// to client
			bool m_IsSending;
			uint8_t m_SendBuffer[I2CP_MAX_MESSAGE_LENGTH];
			i2p::stream::SendBufferQueue m_SendQueue;
	};
	typedef void (I2CPSession::*I2CPMessageHandler)(const uint8_t * buf, size_t len);

	class I2CPServer: private i2p::util::RunnableService
	{
		public:

			I2CPServer (const std::string& interface, int port, bool isSingleThread);
			~I2CPServer ();

			void Start ();
			void Stop ();
			boost::asio::io_service& GetService () { return GetIOService (); };
			bool IsSingleThread () const { return m_IsSingleThread; };

			bool InsertSession (std::shared_ptr<I2CPSession> session);
			void RemoveSession (uint16_t sessionID);
			std::shared_ptr<I2CPSession> FindSessionByIdentHash (const i2p::data::IdentHash& ident) const;

		private:

			void Run ();

			void Accept ();

			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);

		private:

			bool m_IsSingleThread;
			I2CPMessageHandler m_MessagesHandlers[256];
			std::map<uint16_t, std::shared_ptr<I2CPSession> > m_Sessions;

			boost::asio::ip::tcp::acceptor m_Acceptor;

		public:

			const decltype(m_MessagesHandlers)& GetMessagesHandlers () const { return m_MessagesHandlers; };

			// for HTTP
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
	};
}
}

#endif
