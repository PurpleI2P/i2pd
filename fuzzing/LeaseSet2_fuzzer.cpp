
#include <LeaseSet.h>

#include "fuzzing.h"


bool
fuzzing_testinput(const uint8_t * data, size_t size)
{
	if(size < 1)
		return true;

	uint8_t storeType = *data;
	data++;
	size--;

	// Same pre-constraint checks used in NetDb::HandleDatabaseStoreMsg()
	if(storeType == i2p::data::NETDB_STORE_TYPE_LEASESET)
		return true;

	if(size > i2p::data::MAX_LS_BUFFER_SIZE)
		return true;

	i2p::data::LeaseSet2(storeType, data, size, false);

	return true;
}
