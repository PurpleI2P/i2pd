#ifndef DATAGRAM_H__
#define DATAGRAM_H__

#include <inttypes.h>
#include <functional>
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"

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
		typedef std::function<void (const i2p::data::IdentityEx& ident, const uint8_t *, size_t)> Receiver;

		public:

			DatagramDestination (i2p::client::ClientDestination& owner);
			~DatagramDestination () {};				

			void SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::LeaseSet& remote);
			void HandleDataMessagePayload (const uint8_t * buf, size_t len);

			void SetReceiver (const Receiver& receiver) { m_Receiver = receiver; };
			void ResetReceiver () { m_Receiver = nullptr; };

		private:

			I2NPMessage * CreateDataMessage (const uint8_t * payload, size_t len);
			void SendMsg (I2NPMessage * msg, const i2p::data::LeaseSet& remote);
			void HandleDatagram (const uint8_t * buf, size_t len);

		private:

			i2p::client::ClientDestination& m_Owner;
			Receiver m_Receiver;
	};		
}
}

#endif

