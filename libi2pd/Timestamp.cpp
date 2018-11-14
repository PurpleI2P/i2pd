#include <inttypes.h>
#include <string.h>
#include <string>
#include <vector>
#include <chrono>
#include <future>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include "Config.h"
#include "Log.h"
#include "I2PEndian.h"
#include "Timestamp.h"

#ifdef WIN32
	#ifndef _WIN64
		#define _USE_32BIT_TIME_T
	#endif
#endif

namespace i2p
{
namespace util
{
	static uint64_t GetLocalMillisecondsSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(
				 std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	static uint32_t GetLocalHoursSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::hours>(
				 std::chrono::system_clock::now().time_since_epoch()).count ();
	}

	static uint64_t GetLocalSecondsSinceEpoch ()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(
				 std::chrono::system_clock::now().time_since_epoch()).count ();
	}


	static int64_t g_TimeOffset = 0; // in seconds

	static void SyncTimeWithNTP (const std::string& address)
	{
		LogPrint (eLogInfo,  "Timestamp: NTP request to ", address);
		boost::asio::io_service service;
		boost::asio::ip::udp::resolver::query query (boost::asio::ip::udp::v4 (), address, "ntp");
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
					while (!socket.available() && i < 10) // 10 seconds max
					{
						std::this_thread::sleep_for (std::chrono::seconds(1));
						i++;
					}
					if (socket.available ())
						len = socket.receive_from (boost::asio::buffer (buf, 48), ep);
				}
				catch (std::exception& e)
				{
					LogPrint (eLogError, "Timestamp: NTP error: ", e.what ());
				}
				if (len >= 8)
				{
					auto ourTs = GetLocalSecondsSinceEpoch ();
					uint32_t ts = bufbe32toh (buf + 32);
					if (ts > 2208988800U) ts -= 2208988800U; // 1/1/1970 from 1/1/1900
					g_TimeOffset = ts - ourTs;
					LogPrint (eLogInfo, "Timestamp: ", address, " time offset from system time is ", g_TimeOffset, " seconds");
				}
			}
			else
				LogPrint (eLogError, "Timestamp: Couldn't open UDP socket");
		}
		else
			LogPrint (eLogError, "Timestamp: Couldn't resove address ", address);
	}

	void RequestNTPTimeSync ()
	{
		std::string ntpservers; i2p::config::GetOption("nettime.ntpservers", ntpservers);
		if (ntpservers.length () > 0)
		{
			std::vector<std::string> ntpList;
			boost::split (ntpList, ntpservers, boost::is_any_of(","), boost::token_compress_on);
			if (ntpList.size () > 0)
				std::async (std::launch::async, SyncTimeWithNTP, ntpList[rand () % ntpList.size ()]);
		}
	}

	uint64_t GetMillisecondsSinceEpoch ()
	{
		return GetLocalMillisecondsSinceEpoch () + g_TimeOffset*1000;
	}

	uint32_t GetHoursSinceEpoch ()
	{
		return GetLocalHoursSinceEpoch () + g_TimeOffset/3600;
	}

	uint64_t GetSecondsSinceEpoch ()
	{
		return GetLocalSecondsSinceEpoch () + g_TimeOffset;
	}
}
}

