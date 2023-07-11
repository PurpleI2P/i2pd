

#include <stdint.h>
#include <stddef.h>

#include <LeaseSet.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	i2p::data::LeaseSet * ls;


	ls = new i2p::data::LeaseSet(data, size, false);
	delete ls;

	return true;
}
