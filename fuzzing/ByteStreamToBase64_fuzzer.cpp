
#include <Base.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	(void) i2p::data::ByteStreamToBase64(data, size);

	return true;
}
