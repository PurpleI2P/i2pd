#include <inttypes.h>
#include <string.h>
#include <boost/asio.hpp>
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
	static int64_t g_TimeOffset = 0; // in seconds

	void SyncTimeWithNTP (const std::string& address)
	{
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
					LogPrint (eLogError, "NTP error: ", e.what ());
				}
				if (len >= 8)
				{
					auto ourTs = GetSecondsSinceEpoch ();
					uint32_t ts = bufbe32toh (buf + 32);
					if (ts > 2208988800U) ts -= 2208988800U; // 1/1/1970 from 1/1/1900
					g_TimeOffset = ts - ourTs;
					LogPrint (eLogInfo,  address, " time offset from system time is ", g_TimeOffset, " seconds");
				}
			}
		}
	}
}
}

