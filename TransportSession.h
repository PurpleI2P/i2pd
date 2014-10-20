#ifndef TRANSPORT_SESSION_H__
#define TRANSPORT_SESSION_H__

#include <inttypes.h>

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

			TransportSession (): m_DHKeysPair (nullptr) {};
			virtual ~TransportSession () { delete m_DHKeysPair; };
			
		protected:

			DHKeysPair * m_DHKeysPair; // X - for client and Y - for server
	};	
}
}

#endif
