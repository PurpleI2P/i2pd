#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>
#include <chrono>
#include"Config.h"


namespace i2p
{
	namespace util
	{

		static int64_t g_TimeOffset = 0; // in seconds
		inline void setTimeOffset(int64_t ts){g_TimeOffset=ts;}

		bool timeCorrecting(uint32_t signedOnTime, uint32_t ts, uint32_t skew, const char * ErrorMsg);



		inline uint64_t GetSecondsSinceEpoch ()
		{
			bool Time_Correcting, Time_UseNTP; i2p::config::GetOption("time.correcting", Time_Correcting);i2p::config::GetOption("time.use_ntp", Time_UseNTP);

			auto tmp_time = std::chrono::duration_cast<std::chrono::seconds>(
				 std::chrono::system_clock::now().time_since_epoch()).count ();

			return (Time_Correcting || Time_UseNTP)  ? tmp_time + i2p::util::g_TimeOffset  : tmp_time;
		}

		inline uint64_t GetMillisecondsSinceEpoch ()
		{
			return GetSecondsSinceEpoch()*1000;
		}

		inline uint32_t GetHoursSinceEpoch ()
		{
			return GetSecondsSinceEpoch()/120;
		}


	}
}

#endif

