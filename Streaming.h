#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include "LeaseSet.h"

namespace i2p
{
namespace stream
{
	const uint16_t PACKET_FLAG_SYNCHRONIZE = 0x0001;
	const uint16_t PACKET_FLAG_CLOSE = 0x0002;
	const uint16_t PACKET_FLAG_RESET = 0x0004;
	const uint16_t PACKET_FLAG_SIGNATURE_INCLUDED = 0x0008;
	const uint16_t PACKET_FLAG_SIGNATURE_REQUESTED = 0x0010;
	const uint16_t PACKET_FLAG_FROM_INCLUDED = 0x0020;
	const uint16_t PACKET_FLAG_DELAY_REQUESTED = 0x0040;
	const uint16_t PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED = 0x0080;
	const uint16_t PACKET_FLAG_PROFILE_INTERACTIVE = 0x0100;
	const uint16_t PACKET_FLAG_ECHO = 0x0200;
	const uint16_t PACKET_FLAG_NO_ACK = 0x0400;

	class StreamingDestination
	{
		public:

			void HandleNextPacket (const uint8_t * buf, size_t len);
	};	

	// assuming data is I2CP message
	void HandleDataMessage (i2p::data::IdentHash * destination, const uint8_t * buf, size_t len);
}		
}	

#endif
