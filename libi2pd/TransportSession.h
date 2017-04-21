#ifndef TRANSPORT_SESSION_H__
#define TRANSPORT_SESSION_H__

#include <inttypes.h>
#include <iostream>
#include <memory>
#include <vector>
#include "Identity.h"
#include "Crypto.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "Timestamp.h"

namespace i2p
{
namespace transport
{
	class SignedData
	{
		public:

			SignedData () {}
			SignedData (const SignedData& other) 
			{
				m_Stream << other.m_Stream.rdbuf ();
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

	class TransportSession
	{
		public:

			TransportSession (std::shared_ptr<const i2p::data::RouterInfo> router, int terminationTimeout): 
				m_DHKeysPair (nullptr), m_NumSentBytes (0), m_NumReceivedBytes (0), m_IsOutgoing (router), m_TerminationTimeout (terminationTimeout), 
				m_LastActivityTimestamp (i2p::util::GetSecondsSinceEpoch ())
			{
				if (router)
					m_RemoteIdentity = router->GetRouterIdentity ();
			}

			virtual ~TransportSession () {};
			virtual void Done () = 0;

			std::string GetIdentHashBase64() const { return m_RemoteIdentity ? m_RemoteIdentity->GetIdentHash().ToBase64() : ""; }
			
			std::shared_ptr<const i2p::data::IdentityEx> GetRemoteIdentity () { return m_RemoteIdentity; };
			void SetRemoteIdentity (std::shared_ptr<const i2p::data::IdentityEx> ident) { m_RemoteIdentity = ident; };
			
			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			bool IsOutgoing () const { return m_IsOutgoing; };
			
			int GetTerminationTimeout () const { return m_TerminationTimeout; };
			void SetTerminationTimeout (int terminationTimeout) { m_TerminationTimeout = terminationTimeout; };	
			bool IsTerminationTimeoutExpired (uint64_t ts) const 
			{ return ts >= m_LastActivityTimestamp + GetTerminationTimeout (); };	

			virtual void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) = 0;
			
		protected:

			std::shared_ptr<const i2p::data::IdentityEx> m_RemoteIdentity; 
			std::shared_ptr<i2p::crypto::DHKeys> m_DHKeysPair; // X - for client and Y - for server
			size_t m_NumSentBytes, m_NumReceivedBytes;
			bool m_IsOutgoing;
			int m_TerminationTimeout;
			uint64_t m_LastActivityTimestamp;
	};	
}
}

#endif
