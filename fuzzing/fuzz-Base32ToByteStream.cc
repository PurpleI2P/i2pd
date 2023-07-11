

#include <stdint.h>
#include <stddef.h>

#include <Base.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	size_t outlen;
	uint8_t * out;


	if(size < 2)
		return true;

	outlen = (data[0] << 8) | data[1];
	outlen++;

	data += 2;
	size -= 2;

	out = new uint8_t[outlen];
	i2p::data::Base32ToByteStream((const char *) data, size, out, outlen);
	delete [] out;

	return true;
}
