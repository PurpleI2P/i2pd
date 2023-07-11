

#include <stdint.h>
#include <stddef.h>

#include <I2NPProtocol.h>
#include <RouterContext.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	uint8_t clearText[i2p::ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];


	if(size < i2p::TUNNEL_BUILD_RECORD_SIZE)
		return true;

	i2p::context.DecryptTunnelBuildRecord(data, clearText);

	return true;
}
