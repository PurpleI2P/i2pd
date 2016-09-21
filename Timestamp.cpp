#include <inttypes.h>
#include <string.h>
#include <boost/asio.hpp>
#include "I2PEndian.h"
#include "Timestamp.h"

namespace i2p
{
namespace util
{
	std::chrono::system_clock::duration g_TimeOffset = std::chrono::system_clock::duration::zero ();

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
				uint8_t request[48];// 48 bytes NTP request
				memset (request, 0, 48);
				request[0] = 0x80; // client mode, version 0
				uint8_t * response = new uint8_t[1500]; // MTU
				size_t len = 0;
				try
				{
					socket.send_to (boost::asio::buffer (request, 48), ep);
					len = socket.receive_from (boost::asio::buffer (response, 1500), ep);
				}
				catch (std::exception& e)
				{
				}	
				if (len >= 8)
				{
					uint32_t ts = bufbe32toh (response + 4);
					if (ts > 2208988800U) ts -= 2208988800U; // 1/1/1970 from 1/1/1900
				}	
				delete[] response;
			}
		}
	}	
}
}

