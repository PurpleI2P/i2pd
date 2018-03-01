#include <inttypes.h>
#include <string.h>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#include "Log.h"
#include "I2PEndian.h"
#include "Timestamp.h"
#include"RouterContext.h"


#ifdef WIN32
	#ifndef _WIN64
		#define _USE_32BIT_TIME_T
	#endif
#endif

namespace i2p
{
namespace util
{
	int64_t g_TimeOffset;
	static inline void setTimeOffset(int64_t ts){g_TimeOffset=ts;}
	


	bool timeCorrecting(uint32_t signedOnTime, uint32_t ts, uint32_t skew, const char * ErrorMsg){

				bool Time_Correcting; i2p::config::GetOption("time.correcting", Time_Correcting);
			
				if( !Time_Correcting ){
					LogPrint (eLogError, ErrorMsg, (int)ts - signedOnTime, ". Check your clock");
					i2p::context.SetError (eRouterErrorClockSkew);					
					return false;
				}

				if (signedOnTime > 2208988800U) signedOnTime -= 2208988800U; // 1/1/1970 from 1/1/1900

				LogPrint (eLogWarning, "I2Pd Time correcting: timeCorrecting ");
				i2p::util::setTimeOffset( signedOnTime < ts - skew ? -signedOnTime : signedOnTime );
				return true;	
	}


	//TODO: ...Syncing with option

	bool SyncTimeWithNTP (void)
	{
		
		bool UseNTP; i2p::config::GetOption("time.use_ntp", UseNTP);
		if(!UseNTP) return false;

		std::string address; i2p::config::GetOption("time.ntp_server", address);

		std::vector<std::string> addresses;
		boost::split(addresses, address, boost::is_any_of(","));
				
		for ( auto addr : addresses ){
			LogPrint (eLogInfo, "I2Pd Time Correcting: SyncingWithNTP with server ", addr);
			boost::asio::io_service service;
			boost::asio::ip::udp::resolver::query query (boost::asio::ip::udp::v4 (), addr, "ntp");
			boost::system::error_code ec;
			auto it = boost::asio::ip::udp::resolver (service).resolve (query, ec);
			if (!ec && it != boost::asio::ip::udp::resolver::iterator())
			{
				auto ep = (*it).endpoint (); // take first one
				boost::asio::ip::udp::socket socket (service);
				socket.open (boost::asio::ip::udp::v4 (), ec);
				if (!ec)
				{
					uint8_t buf[48];// 48 bytes NTP request/response
					memset (buf, 0, 48);
					htobe32buf (buf, (3 << 27) | (3 << 24)); // RFC 4330
					size_t len = 0;
					try
					{
						socket.send_to (boost::asio::buffer (buf, 48), ep);
						int i = 0;
						while (!socket.available() && i < NTPMaxTimeConnecting) // 10 seconds max
						{
							std::this_thread::sleep_for (std::chrono::seconds(1));
							i++;
						}
						if( i == NTPMaxTimeConnecting ) throw( std::runtime_error("timeout" )  );	
						if (socket.available ())
							len = socket.receive_from (boost::asio::buffer (buf, 48), ep);
						if(len < 8) throw( std::runtime_error("len of answer not equal 8") );

						auto ourTs = GetSecondsSinceEpoch ();
						uint32_t ts = bufbe32toh (buf + 32);
						LogPrint (eLogDebug, "I2Pd Time Correcting: SyncingWithNTP ",ourTs, " < our  not our > ", ts);
						if (ts > 2208988800U) ts -= 2208988800U; // 1/1/1970 from 1/1/1900

						setTimeOffset( ts - ourTs );

						LogPrint (eLogDebug, "I2Pd Time Correcting: ", addr, " time offset from system time is ", g_TimeOffset, " seconds");	
						break;

					}catch (std::exception& e)
						{
							LogPrint (eLogError, "NTP error: ", e.what ());
						}

				}
			}
			
		}
		return true;
	}
}
}

