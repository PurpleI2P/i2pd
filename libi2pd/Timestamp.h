#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>
#include <chrono>
#include"Config.h"
#include "Log.h"

namespace i2p
{
	namespace util
	{
		constexpr char NTPMaxTimeConnecting = 15;
		extern int64_t g_TimeOffset; // in seconds

		enum class TimeType{
			milliseconds, seconds, hours
		};

		template <typename Type> inline uint64_t getTime(void) 
		{
			return std::chrono::duration_cast<Type>(
				 std::chrono::system_clock::now().time_since_epoch()).count ();
		}

		template <typename Type> auto getTime(TimeType tt) -> decltype(getTime<Type>()){


				LogPrint (eLogDebug, "I2Pd Time Correcting: offset = ", g_TimeOffset );



				bool Time_Correcting, Time_UseNTP; 
				i2p::config::GetOption("time.correcting", Time_Correcting);
				i2p::config::GetOption("time.use_ntp", Time_UseNTP);
				if(Time_Correcting || Time_UseNTP) 
					LogPrint (eLogDebug, "I2Pd Time Correcting: Return time with offset ", getTime<Type>() + g_TimeOffset );
				else
					LogPrint(eLogDebug, "I2Pd Time Correcting: return real time");
				if(Time_Correcting || Time_UseNTP){
					auto tmpTime = getTime<Type>() ;
					switch(tt){
						case TimeType::milliseconds:
							return tmpTime+g_TimeOffset*1000;
						case TimeType::seconds:
							return tmpTime+g_TimeOffset;
							break;
						case TimeType::hours:
							if(tmpTime)
								return tmpTime + g_TimeOffset/120;
							break;
					}
				}
				return getTime<Type>();
				
		}

		
		

		bool timeCorrecting(uint32_t signedOnTime, uint32_t ts, uint32_t skew, const char * ErrorMsg);
		bool SyncTimeWithNTP (void);


		inline uint64_t GetSecondsSinceEpoch ()
		{
			return getTime<std::chrono::seconds>();
		}

		inline uint64_t GetMillisecondsSinceEpoch ()
		{
			return getTime<std::chrono::milliseconds>();
		}

		inline uint32_t GetHoursSinceEpoch ()
		{
			return getTime<std::chrono::hours>();
		}


	}
}

#endif

