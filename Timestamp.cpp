#include <inttypes.h>
#include <string.h>
#include <boost/asio.hpp>
#include "Log.h"
#include "I2PEndian.h"
#include "Timestamp.h"

namespace i2p
{
namespace util
{
	std::chrono::seconds g_TimeOffset (0);

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
					len = socket.receive_from (boost::asio::buffer (buf, 48), ep);
				}
				catch (std::exception& e)
				{
				}	
				if (len >= 8)
				{
					uint32_t ts = bufbe32toh (buf + 32);
					if (ts > 2208988800U) ts -= 2208988800U; // 1/1/1970 from 1/1/1900
					g_TimeOffset = std::chrono::seconds(ts) - std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
					LogPrint (eLogInfo,  address, " time offset from system time is ", g_TimeOffset.count (), " seconds");
				}	
			}
		}
	}	
}
}

