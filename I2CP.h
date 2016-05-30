/*
* Copyright (c) 2013-2016, The PurpleI2P Project
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
#include <boost/asio.hpp>
#include "Destination.h"

namespace i2p
{
namespace client
{
	const uint8_t I2CP_PRTOCOL_BYTE = 0x2A;
	const size_t I2CP_SESSION_BUFFER_SIZE = 4096;

	const size_t I2CP_HEADER_LENGTH_OFFSET = 0;
	const size_t I2CP_HEADER_TYPE_OFFSET = I2CP_HEADER_LENGTH_OFFSET + 4;
	const size_t I2CP_HEADER_SIZE = I2CP_HEADER_TYPE_OFFSET + 1;	

	const uint8_t I2CP_GET_DATE_MESSAGE = 32;
	const uint8_t I2CP_SET_DATE_MESSAGE = 33;
	const uint8_t I2CP_CREATE_SESSION_MESSAGE = 1;
	const uint8_t I2CP_SESSION_STATUS_MESSAGE = 20;	
	const uint8_t I2CP_REQUEST_VARIABLE_LEASESET_MESSAGE = 37;
	const uint8_t I2CP_CREATE_LEASESET_MESSAGE = 4;	
	const uint8_t I2CP_SEND_MESSAGE_MESSAGE = 5;	

	class I2CPSession;
	class I2CPDestination: public LeaseSetDestination
	{
		public:

			I2CPDestination (I2CPSession& owner, std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic);

			void SetEncryptionPrivateKey (const uint8_t * key);
			void LeaseSetCreated (const uint8_t * buf, size_t len); // called from I2CPSession
			void SendMsgTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident); // called from I2CPSession

		protected:

			// implements LocalDestination
			const uint8_t * GetEncryptionPrivateKey () const { return m_EncryptionPrivateKey; };
			std::shared_ptr<const i2p::data::IdentityEx> GetIdentity () const { return m_Identity; };

			// I2CP
			void HandleDataMessage (const uint8_t * buf, size_t len) { /* TODO */ };
			void CreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels);

		private:

			I2CPSession& m_Owner;
			std::shared_ptr<const i2p::data::IdentityEx> m_Identity;
			uint8_t m_EncryptionPrivateKey[256];
			uint64_t m_LeaseSetExpirationTime;
	};

	class I2CPServer;
	class I2CPSession: public std::enable_shared_from_this<I2CPSession>
	{
		public:

			I2CPSession (I2CPServer& owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			~I2CPSession ();

			uint16_t GetSessionID () const { return m_SessionID; };
			void SendI2CPMessage (uint8_t type, const uint8_t * payload, size_t len);
			
			// message handlers
			void GetDateMessageHandler (const uint8_t * buf, size_t len);
			void CreateSessionMessageHandler (const uint8_t * buf, size_t len);
			void CreateLeaseSetMessageHandler (const uint8_t * buf, size_t len);
			void SendMessageMessageHandler (const uint8_t * buf, size_t len);

		private:
			
			void ReadProtocolByte ();
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleNextMessage (const uint8_t * buf);
			void Terminate ();
			
			void HandleI2CPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, const uint8_t * buf);
			std::string ExtractString (const uint8_t * buf, size_t len);
			size_t PutString (uint8_t * buf, size_t len, const std::string& str);

			void SendSessionStatusMessage (uint8_t status);

		private:

			I2CPServer& m_Owner;
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			uint8_t m_Buffer[I2CP_SESSION_BUFFER_SIZE], * m_NextMessage;
			size_t m_NextMessageLen, m_NextMessageOffset;

			std::shared_ptr<I2CPDestination> m_Destination;
			uint16_t m_SessionID;
	};
	typedef void (I2CPSession::*I2CPMessageHandler)(const uint8_t * buf, size_t len);
	
	class I2CPServer
	{
		public:

			I2CPServer (const std::string& interface, int port);

		private:
			
			I2CPMessageHandler m_MessagesHandlers[256];

		public:

			const decltype(m_MessagesHandlers)& GetMessagesHandlers () const { return m_MessagesHandlers; };
	};	
}
}

#endif

