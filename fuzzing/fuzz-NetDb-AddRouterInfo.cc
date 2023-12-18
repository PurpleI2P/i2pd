

#include <stdint.h>
#include <stddef.h>

#include <NetDb.hpp>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	i2p::data::netdb.AddRouterInfo(data, size);

	return true;
}
