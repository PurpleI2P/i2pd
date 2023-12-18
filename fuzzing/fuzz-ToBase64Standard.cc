

#include <stdint.h>
#include <stddef.h>
#include <string>

#include <Base.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	std::string str((const char *) data, size);


	i2p::data::ToBase64Standard(str);

	return true;
}
