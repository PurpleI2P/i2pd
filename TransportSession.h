#ifndef TRANSPORT_SESSION_H__
#define TRANSPORT_SESSION_H__

#include <inttypes.h>
#include "Identity.h"
#include "RouterInfo.h"

namespace i2p
{
namespace transport
{
	struct DHKeysPair // transient keys for transport sessions
	{
		uint8_t publicKey[256];
		uint8_t privateKey[256];
	};	

	class TransportSession
	{
		public:

			TransportSession (const i2p::data::RouterInfo * in_RemoteRouter): 
				m_RemoteRouter (in_RemoteRouter), m_DHKeysPair (nullptr) 
			{
				if (m_RemoteRouter)
					m_RemoteIdentity = m_RemoteRouter->GetRouterIdentity ();
			}

			virtual ~TransportSession () { delete m_DHKeysPair; };
			
			const i2p::data::RouterInfo * GetRemoteRouter () { return m_RemoteRouter; };
			const i2p::data::IdentityEx& GetRemoteIdentity () { return m_RemoteIdentity; };

		protected:

			const i2p::data::RouterInfo * m_RemoteRouter;
			i2p::data::IdentityEx m_RemoteIdentity; 
			DHKeysPair * m_DHKeysPair; // X - for client and Y - for server
	};	
}
}

#endif
