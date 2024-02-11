/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
	const uint64_t TRANSPORT_SESSION_BANDWIDTH_UPDATE_MIN_INTERVAL = 5; // in seconds
	class TransportSession
	{
		public:

			TransportSession (std::shared_ptr<const i2p::data::RouterInfo> router, int terminationTimeout):
				m_IsOutgoing (router), m_TerminationTimeout (terminationTimeout), m_HandshakeInterval (0), 
				m_SendQueueSize (0), m_NumSentBytes (0), m_NumReceivedBytes (0),
				m_LastBandWidthUpdateNumSentBytes (0), m_LastBandWidthUpdateNumReceivedBytes (0),
				m_LastActivityTimestamp (i2p::util::GetSecondsSinceEpoch ()), 
				m_LastBandwidthUpdateTimestamp (m_LastActivityTimestamp), m_InBandwidth (0), m_OutBandwidth (0)
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
			void UpdateNumSentBytes (size_t len)
			{
				m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
				m_NumSentBytes += len;
				UpdateBandwidth ();
			}	
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			void UpdateNumReceivedBytes (size_t len)
			{
				m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
				m_NumReceivedBytes += len;
				UpdateBandwidth ();
			}		
			size_t GetSendQueueSize () const { return m_SendQueueSize; };
			void SetSendQueueSize (size_t s) { m_SendQueueSize = s; };
			bool IsOutgoing () const { return m_IsOutgoing; };
			bool IsSlow () const { return m_HandshakeInterval > TRANSPORT_SESSION_SLOWNESS_THRESHOLD &&
				m_HandshakeInterval < TRANSPORT_SESSION_MAX_HANDSHAKE_INTERVAL; };
			bool IsBandwidthExceeded (bool isHighBandwidth) const
			{
				auto limit = isHighBandwidth ? i2p::data::HIGH_BANDWIDTH_LIMIT*1024 : i2p::data::LOW_BANDWIDTH_LIMIT*1024; // convert to bytes
				return std::max (m_InBandwidth, m_OutBandwidth) > limit;
			}	
			
			int GetTerminationTimeout () const { return m_TerminationTimeout; };
			void SetTerminationTimeout (int terminationTimeout) { m_TerminationTimeout = terminationTimeout; };
			bool IsTerminationTimeoutExpired (uint64_t ts) const
			{
				return ts >= m_LastActivityTimestamp + GetTerminationTimeout () ||
					ts + GetTerminationTimeout () < m_LastActivityTimestamp;
			};

			uint32_t GetCreationTime () const { return m_CreationTime; };
			void SetCreationTime (uint32_t ts) { m_CreationTime = ts; }; // for introducers

			uint64_t GetLastActivityTimestamp () const { return m_LastActivityTimestamp; };
			void SetLastActivityTimestamp (uint64_t ts) { m_LastActivityTimestamp = ts; };
			
			virtual uint32_t GetRelayTag () const { return 0; };
			virtual void SendLocalRouterInfo (bool update = false) { SendI2NPMessages ({ CreateDatabaseStoreMsg () }); };
			virtual void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) = 0;
			virtual bool IsEstablished () const = 0;

		private:

			void UpdateBandwidth ()
			{
				int64_t interval = m_LastActivityTimestamp - m_LastBandwidthUpdateTimestamp;
				if (interval < 0 || interval > 60*10) // 10 minutes 
				{
					// clock was adjusted, copy new values
					m_LastBandWidthUpdateNumSentBytes = m_NumSentBytes;
					m_LastBandWidthUpdateNumReceivedBytes = m_NumReceivedBytes;
					m_LastBandwidthUpdateTimestamp = m_LastActivityTimestamp;
					return;
				}	
				if ((uint64_t)interval > TRANSPORT_SESSION_BANDWIDTH_UPDATE_MIN_INTERVAL)
				{	
					m_OutBandwidth = (m_NumSentBytes - m_LastBandWidthUpdateNumSentBytes)/interval;
					m_LastBandWidthUpdateNumSentBytes = m_NumSentBytes;
					m_InBandwidth = (m_NumReceivedBytes - m_LastBandWidthUpdateNumReceivedBytes)/interval;
					m_LastBandWidthUpdateNumReceivedBytes = m_NumReceivedBytes;
					m_LastBandwidthUpdateTimestamp = m_LastActivityTimestamp;
				}	
			}	
			
		protected:

			std::shared_ptr<const i2p::data::IdentityEx> m_RemoteIdentity;
			mutable std::mutex m_RemoteIdentityMutex;
			bool m_IsOutgoing;
			int m_TerminationTimeout;
			uint32_t m_CreationTime; // seconds since epoch
			int64_t m_HandshakeInterval; // in milliseconds between SessionRequest->SessionCreated or SessionCreated->SessionConfirmed

		private:

			size_t m_SendQueueSize, m_NumSentBytes, m_NumReceivedBytes, 
				m_LastBandWidthUpdateNumSentBytes, m_LastBandWidthUpdateNumReceivedBytes;
			uint64_t m_LastActivityTimestamp, m_LastBandwidthUpdateTimestamp;	
			uint32_t m_InBandwidth, m_OutBandwidth;
	};
}
}

#endif
