
#include <util.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	i2p::util::Mapping	mapping;
	mapping.FromBuffer(data, size);

	return true;
}
