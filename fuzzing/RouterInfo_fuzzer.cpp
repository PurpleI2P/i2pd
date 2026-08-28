
#include <RouterInfo.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	i2p::data::RouterInfo	ri(data, size);

	return true;
}
