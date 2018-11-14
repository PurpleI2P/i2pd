#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>

namespace i2p
{
namespace util
{
	uint64_t GetMillisecondsSinceEpoch ();
	uint32_t GetHoursSinceEpoch ();
	uint64_t GetSecondsSinceEpoch ();

	void RequestNTPTimeSync ();
}
}

#endif

