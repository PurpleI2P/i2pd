#ifndef DATAGRAM_H__
#define DATAGRAM_H__

#include <inttypes.h>
#include <memory>
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
		typedef std::function<void (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)> Receiver;

		public:

			DatagramDestination (i2p::client::ClientDestination& owner);
			~DatagramDestination () {};				

			void SendDatagramTo (const uint8_t * payload, size_t len, std::shared_ptr<const i2p::data::LeaseSet> remote);
			void HandleDataMessagePayload (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

			void SetReceiver (const Receiver& receiver) { m_Receiver = receiver; };
			void ResetReceiver () { m_Receiver = nullptr; };

		private:

			I2NPMessage * CreateDataMessage (const uint8_t * payload, size_t len);
			void SendMsg (I2NPMessage * msg, std::shared_ptr<const i2p::data::LeaseSet> remote);
			void HandleDatagram (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

		private:

			i2p::client::ClientDestination& m_Owner;
			Receiver m_Receiver;
	};		
}
}

#endif

