
#include <Base.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	if(size < 2)
		return true;

	size_t outlen = (data[0] << 8) | data[1];
	data += 2;
	size -= 2;

	uint8_t * out = new uint8_t[outlen];

	i2p::data::Base32ToByteStream(
		std::basic_string_view((const char *) data, size),
		out,
		outlen);

	delete[] out;

	return true;
}
