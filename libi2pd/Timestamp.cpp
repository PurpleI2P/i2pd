/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <time.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
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
		LogPrint (eLogInfo, "Timestamp: NTP request to ", address);
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

	NTPTimeSync::NTPTimeSync (): m_IsRunning (false), m_Timer (m_Service)
	{
		i2p::config::GetOption("nettime.ntpsyncinterval", m_SyncInterval);
		std::string ntpservers; i2p::config::GetOption("nettime.ntpservers", ntpservers);
		boost::split (m_NTPServersList, ntpservers, boost::is_any_of(","), boost::token_compress_on);
	}

	NTPTimeSync::~NTPTimeSync ()
	{
		Stop ();
	}

	void NTPTimeSync::Start()
	{
		if (m_NTPServersList.size () > 0)
		{
			m_IsRunning = true;
			LogPrint(eLogInfo, "Timestamp: NTP time sync starting");
			m_Service.post (std::bind (&NTPTimeSync::Sync, this));
			m_Thread.reset (new std::thread (std::bind (&NTPTimeSync::Run, this)));
		}
		else
			LogPrint (eLogWarning, "Timestamp: No NTP server found");
	}

	void NTPTimeSync::Stop ()
	{
		if (m_IsRunning)
		{
			LogPrint(eLogInfo, "Timestamp: NTP time sync stopping");
			m_IsRunning = false;
			m_Timer.cancel ();
			m_Service.stop ();
			if (m_Thread)
			{
				m_Thread->join ();
				m_Thread.reset (nullptr);
			}
		}
	}

	void NTPTimeSync::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Timestamp: NTP time sync exception: ", ex.what ());
			}
		}
	}

	void NTPTimeSync::Sync ()
	{
		if (m_NTPServersList.size () > 0)
			SyncTimeWithNTP (m_NTPServersList[rand () % m_NTPServersList.size ()]);
		else
			m_IsRunning = false;

		if (m_IsRunning)
		{
			m_Timer.expires_from_now (boost::posix_time::hours (m_SyncInterval));
			m_Timer.async_wait ([this](const boost::system::error_code& ecode)
			{
				if (ecode != boost::asio::error::operation_aborted)
					Sync ();
			});
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

	void GetCurrentDate (char * date)
	{
		GetDateString (GetSecondsSinceEpoch (), date);
	}

	void GetDateString (uint64_t timestamp, char * date)
	{
		using clock = std::chrono::system_clock;
		auto t = clock::to_time_t (clock::time_point (std::chrono::seconds(timestamp)));
		struct tm tm;
#ifdef _WIN32
		gmtime_s(&tm, &t);
		sprintf_s(date, 9, "%04i%02i%02i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
#else
		gmtime_r(&t, &tm);
		sprintf(date, "%04i%02i%02i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
#endif
	}
}
}
