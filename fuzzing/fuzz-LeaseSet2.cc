

#include <stdint.h>
#include <stddef.h>

#include <LeaseSet.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	uint8_t storeType;
	i2p::data::LeaseSet2 * ls;


	if(size < 1)
		return true;

	storeType = data[0];

	// Same check as in NetDb::HandleDatabaseStoreMsg()
	if(storeType == i2p::data::NETDB_STORE_TYPE_LEASESET)
		return true;

	data++;
	size--;

	// Same check as in NetDb::HandleDatabaseStoreMsg()
	if(size > i2p::data::MAX_LS_BUFFER_SIZE)
		return true;

	ls = new i2p::data::LeaseSet2(storeType, data, size, false);
	delete ls;

	return true;
}
