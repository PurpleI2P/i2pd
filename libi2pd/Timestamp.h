#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>
#include <chrono>
#include"Config.h"


namespace i2p
{
	namespace util
	{
		template <typename Type> auto getTime(void) 
		-> decltype(std::chrono::duration_cast<Type>(
				 std::chrono::system_clock::now().time_since_epoch()).count ())

		{
			return std::chrono::duration_cast<Type>(
				 std::chrono::system_clock::now().time_since_epoch()).count ();
		}

		template <typename Type> auto getTime(uint64_t offset) 
		-> decltype(getTime<Type>()){

				bool Time_Correcting, Time_UseNTP; i2p::config::GetOption("time.correcting", Time_Correcting);i2p::config::GetOption("time.use_ntp", Time_UseNTP);
				return (Time_Correcting || Time_UseNTP)  ?  getTime<Type>() + offset  :  getTime<Type>();
		}

		static int64_t g_TimeOffset = 0; // in seconds
		inline void setTimeOffset(int64_t ts){g_TimeOffset=ts;}

		bool timeCorrecting(uint32_t signedOnTime, uint32_t ts, uint32_t skew, const char * ErrorMsg);
		void SyncTimeWithNTP (void);


		inline uint64_t GetSecondsSinceEpoch ()
		{
			return getTime<std::chrono::seconds>(i2p::util::g_TimeOffset);
		}

		inline uint64_t GetMillisecondsSinceEpoch ()
		{
			return getTime<std::chrono::milliseconds>(i2p::util::g_TimeOffset*1000);
		}

		inline uint32_t GetHoursSinceEpoch ()
		{
			return getTime<std::chrono::hours>(i2p::util::g_TimeOffset/120);
		}


	}
}

#endif

