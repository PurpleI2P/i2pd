/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TRANSPORT_SESSION_H__
#define TRANSPORT_SESSION_H__

#include <inttypes.h>
#include <iostream>
#include <memory>
#include <vector>
#include <mutex>
#include "Identity.h"
#include "Crypto.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "Timestamp.h"

namespace i2p
{
namespace transport
{
	const size_t IPV4_HEADER_SIZE = 20;
	const size_t IPV6_HEADER_SIZE = 40;
	const size_t UDP_HEADER_SIZE = 8;

	class SignedData
	{
		public:

			SignedData () {}
			SignedData (const SignedData& other)
			{
				m_Stream << other.m_Stream.rdbuf ();
			}

			void Reset ()
			{
				m_Stream.str("");
			}

			void Insert (const uint8_t * buf, size_t len)
			{
				m_Stream.write ((char *)buf, len);
			}

			template<typename T>
			void Insert (T t)
			{
				m_Stream.write ((char *)&t, sizeof (T));
			}

			bool Verify (std::shared_ptr<const i2p::data::IdentityEx> ident, const uint8_t * signature) const
			{
				return ident->Verify ((const uint8_t *)m_Stream.str ().c_str (), m_Stream.str ().size (), signature);
			}

			void Sign (const i2p::data::PrivateKeys& keys, uint8_t * signature) const
			{
				keys.Sign ((const uint8_t *)m_Stream.str ().c_str (), m_Stream.str ().size (), signature);
			}

		private:

			std::stringstream m_Stream;
	};

	const int64_t TRANSPORT_SESSION_SLOWNESS_THRESHOLD = 500; // in milliseconds
	const int64_t TRANSPORT_SESSION_MAX_HANDSHAKE_INTERVAL = 10000; // in milliseconds
	class TransportSession
	{
		public:

			TransportSession (std::shared_ptr<const i2p::data::RouterInfo> router, int terminationTimeout):
				m_NumSentBytes (0), m_NumReceivedBytes (0), m_SendQueueSize (0),
				m_IsOutgoing (router), m_TerminationTimeout (terminationTimeout),
				m_LastActivityTimestamp (i2p::util::GetSecondsSinceEpoch ()),
				m_HandshakeInterval (0)
			{
				if (router)
					m_RemoteIdentity = router->GetRouterIdentity ();
				m_CreationTime = m_LastActivityTimestamp;
			}

			virtual ~TransportSession () {};
			virtual void Done () = 0;

			std::string GetIdentHashBase64() const { return m_RemoteIdentity ? m_RemoteIdentity->GetIdentHash().ToBase64() : ""; }

			std::shared_ptr<const i2p::data::IdentityEx> GetRemoteIdentity ()
			{
				std::lock_guard<std::mutex> l(m_RemoteIdentityMutex);
				return m_RemoteIdentity;
			}
			void SetRemoteIdentity (std::shared_ptr<const i2p::data::IdentityEx> ident)
			{
				std::lock_guard<std::mutex> l(m_RemoteIdentityMutex);
				m_RemoteIdentity = ident;
			}

			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			size_t GetSendQueueSize () const { return m_SendQueueSize; };
			bool IsOutgoing () const { return m_IsOutgoing; };
			bool IsSlow () const { return m_HandshakeInterval > TRANSPORT_SESSION_SLOWNESS_THRESHOLD &&
				m_HandshakeInterval < TRANSPORT_SESSION_MAX_HANDSHAKE_INTERVAL; };
			
			int GetTerminationTimeout () const { return m_TerminationTimeout; };
			void SetTerminationTimeout (int terminationTimeout) { m_TerminationTimeout = terminationTimeout; };
			bool IsTerminationTimeoutExpired (uint64_t ts) const
			{
				return ts >= m_LastActivityTimestamp + GetTerminationTimeout () ||
					ts + GetTerminationTimeout () < m_LastActivityTimestamp;
			};

			uint32_t GetCreationTime () const { return m_CreationTime; };
			void SetCreationTime (uint32_t ts) { m_CreationTime = ts; }; // for introducers

			virtual uint32_t GetRelayTag () const { return 0; };
			virtual void SendLocalRouterInfo (bool update = false) { SendI2NPMessages ({ CreateDatabaseStoreMsg () }); };
			virtual void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) = 0;
			virtual bool IsEstablished () const = 0;

		protected:

			std::shared_ptr<const i2p::data::IdentityEx> m_RemoteIdentity;
			mutable std::mutex m_RemoteIdentityMutex;
			size_t m_NumSentBytes, m_NumReceivedBytes, m_SendQueueSize;
			bool m_IsOutgoing;
			int m_TerminationTimeout;
			uint64_t m_LastActivityTimestamp;
			uint32_t m_CreationTime; // seconds since epoch
			int64_t m_HandshakeInterval; // in milliseconds between SessionRequest->SessionCreated or SessionCreated->SessionConfirmed
	};

	// SOCKS5 proxy
	const uint8_t SOCKS5_VER = 0x05;
	const uint8_t SOCKS5_CMD_CONNECT = 0x01;
	const uint8_t SOCKS5_CMD_UDP_ASSOCIATE = 0x03;
	const uint8_t SOCKS5_ATYP_IPV4 = 0x01;
	const uint8_t SOCKS5_ATYP_IPV6 = 0x04;
	const size_t SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE = 10;
	const size_t SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE = 22;
}
}

#endif
