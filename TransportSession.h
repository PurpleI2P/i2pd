#ifndef TRANSPORT_SESSION_H__
#define TRANSPORT_SESSION_H__

#include <inttypes.h>
#include <iostream>
#include <memory>
#include <vector>
#include "Identity.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"

namespace i2p
{
namespace transport
{
	struct DHKeysPair // transient keys for transport sessions
	{
		uint8_t publicKey[256];
		uint8_t privateKey[256];
	};	

	class SignedData
	{
		public:

			SignedData () {};
			void Insert (const uint8_t * buf, size_t len) 
			{ 
				m_Stream.write ((char *)buf, len); 
			}			

			template<typename T>
			void Insert (T t)
			{
				m_Stream.write ((char *)&t, sizeof (T)); 
			}

			bool Verify (const i2p::data::IdentityEx& ident, const uint8_t * signature) const
			{
				return ident.Verify ((const uint8_t *)m_Stream.str ().c_str (), m_Stream.str ().size (), signature); 
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

			TransportSession (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter): 
				m_RemoteRouter (in_RemoteRouter), m_DHKeysPair (nullptr) 
			{
				if (m_RemoteRouter)
					m_RemoteIdentity = m_RemoteRouter->GetRouterIdentity ();
			}

			virtual ~TransportSession () { delete m_DHKeysPair; };
			virtual void Done () = 0;
			
			std::shared_ptr<const i2p::data::RouterInfo> GetRemoteRouter () { return m_RemoteRouter; };
			const i2p::data::IdentityEx& GetRemoteIdentity () { return m_RemoteIdentity; };

			virtual void SendI2NPMessage (I2NPMessage * msg) = 0;
			virtual void SendI2NPMessages (const std::vector<I2NPMessage *>& msgs) = 0;
			
		protected:

			std::shared_ptr<const i2p::data::RouterInfo> m_RemoteRouter;
			i2p::data::IdentityEx m_RemoteIdentity; 
			DHKeysPair * m_DHKeysPair; // X - for client and Y - for server
	};	
}
}

#endif
