

#include <stdint.h>
#include <stddef.h>
#include <string>

#include <Blinding.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	std::string str((const char *) data, size);
	i2p::data::BlindedPublicKey * bpk;


	bpk = new i2p::data::BlindedPublicKey(str);
	delete bpk;

	return true;
}
