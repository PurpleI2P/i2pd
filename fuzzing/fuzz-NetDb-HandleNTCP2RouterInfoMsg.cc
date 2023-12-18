

#include <stdint.h>
#include <stddef.h>

#include <I2NPProtocol.h>
#include <NetDb.hpp>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	i2p::I2NPMessageType msgType;


	if(size < 1)
		return true;

	msgType = (i2p::I2NPMessageType) data[0];

	data++;
	size--;

	i2p::data::netdb.HandleNTCP2RouterInfoMsg(
		i2p::CreateI2NPMessage(msgType, data, size));

	return true;
}
