#ifndef DATAGRAM_H__
#define DATAGRAM_H__

#include <inttypes.h>

namespace i2p
{
namespace client
{
	class ClientDestination;
}
namespace datagram
{
	const size_t MAX_DATAGRAM_SIZE = 32768;
	class DatagramDestination
	{
		public:

			DatagramDestination (i2p::client::ClientDestination& owner): m_Owner (owner) {};
			~DatagramDestination () {};				

			void HandleDataMessagePayload (const uint8_t * buf, size_t len);

		private:

			i2p::client::ClientDestination& m_Owner;
	};		
}
}

#endif

