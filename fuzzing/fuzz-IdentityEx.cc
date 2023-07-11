

#include <stdint.h>
#include <stddef.h>

#include <Identity.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	i2p::data::IdentityEx *	ident;


	ident = new i2p::data::IdentityEx(data, size);
	delete ident;

	return true;
}
