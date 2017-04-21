#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>
#include <chrono>

namespace i2p
{
namespace util
{
	inline uint64_t GetMillisecondsSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(
			  	 std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	inline uint32_t GetHoursSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::hours>(
			  	 std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	inline uint64_t GetSecondsSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(
			  	 std::chrono::system_clock::now().time_since_epoch()).count ();
	}
}
}

#endif

