/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TIMESTAMP_H__
#define TIMESTAMP_H__

#include <inttypes.h>
#include <thread>
#include <vector>
#include <string>
#include <boost/asio.hpp>

namespace i2p
{
namespace util
{
	uint64_t GetMillisecondsSinceEpoch ();
	uint64_t GetSecondsSinceEpoch ();
	uint32_t GetMinutesSinceEpoch ();
	uint32_t GetHoursSinceEpoch ();

	void GetCurrentDate (char * date); // returns date as YYYYMMDD string, 9 bytes
	void GetDateString (uint64_t timestamp, char * date); // timestap is seconds since epoch, returns date as YYYYMMDD string, 9 bytes

	class NTPTimeSync
	{
		public:

			NTPTimeSync ();
			~NTPTimeSync ();

			void Start ();
			void Stop ();

		private:

			void Run ();
			void Sync ();

		private:

			bool m_IsRunning;
			std::unique_ptr<std::thread> m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::deadline_timer m_Timer;
			int m_SyncInterval;
			std::vector<std::string> m_NTPServersList;
	};
}
}

#endif
