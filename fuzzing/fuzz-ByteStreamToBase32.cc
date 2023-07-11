

#include <stdint.h>
#include <stddef.h>

#include <Base.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	size_t outlen;
	char * out;


	if(size < (2 + 1))
		return true;

	outlen = (data[0] << 8) | data[1];
	outlen++;

	data += 2;
	size -= 2;

	out = new char[outlen];
	i2p::data::ByteStreamToBase32(data, size, out, outlen);
	delete [] out;

	return true;
}
