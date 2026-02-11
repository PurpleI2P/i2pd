
#include <I2NPProtocol.h>
#include <NetDb.hpp>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	if(size < 1)
		return true;

	i2p::I2NPMessageType msgType = (i2p::I2NPMessageType) *data;
	data++;
	size--;

	i2p::data::netdb.PostDatabaseSearchReplyMsg(
		i2p::CreateI2NPMessage(msgType, data, size));

	return true;
}
