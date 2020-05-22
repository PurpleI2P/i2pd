/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef LOG_H__
#define LOG_H__

#include <ctime>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <memory>
#include <thread>
#include <functional>
#include "Queue.h"

#ifndef _WIN32
#include <syslog.h>
#endif

enum LogLevel
{
	eLogNone = 0,
	eLogError,
	eLogWarning,
	eLogInfo,
	eLogDebug,
	eNumLogLevels
};

enum LogType {
	eLogStdout = 0,
	eLogStream,
	eLogFile,
#ifndef _WIN32
	eLogSyslog,
#endif
};

namespace i2p {
namespace log {

	struct LogMsg; /* forward declaration */

	class Log
	{
		private:

			enum LogType  m_Destination;
			enum LogLevel m_MinLevel;
			std::shared_ptr<std::ostream> m_LogStream;
			std::string m_Logfile;
			std::time_t m_LastTimestamp;
			char m_LastDateTime[64];
			i2p::util::Queue<std::shared_ptr<LogMsg> > m_Queue;
			bool m_HasColors;
			std::string m_TimeFormat;
			volatile bool m_IsRunning;
			std::thread * m_Thread;

		private:

			/** prevent making copies */
			Log (const Log &);
			const Log& operator=(const Log&);

			void Run ();
			void Process (std::shared_ptr<LogMsg> msg);

			/**
			 * @brief Makes formatted string from unix timestamp
			 * @param ts  Second since epoch
			 *
			 * This function internally caches the result for last provided value
			 */
			const char * TimeAsString(std::time_t ts);

		public:

			Log ();
			~Log ();

			LogType  GetLogType  () { return m_Destination; };
			LogLevel GetLogLevel () { return m_MinLevel; };

			void Start ();
			void Stop ();

			/**
			 * @brief  Sets minimal allowed level for log messages
			 * @param  level  String with wanted minimal msg level
			 */
			void     SetLogLevel (const std::string& level);

			/**
			 * @brief Sets log destination to logfile
			 * @param path  Path to logfile
			 */
			void SendTo (const std::string &path);

			/**
			 * @brief Sets log destination to given output stream
			 * @param os  Output stream
			 */
			void SendTo (std::shared_ptr<std::ostream> os);

			/**
			 * @brief  Sets format for timestamps in log
			 * @param  format  String with timestamp format
			 */
			void SetTimeFormat (std::string format) { m_TimeFormat = format; };

	#ifndef _WIN32
			/**
			 * @brief Sets log destination to syslog
			 * @param name     Wanted program name
			 * @param facility Wanted log category
			 */
			void SendTo (const char *name, int facility);
	#endif

			/**
			 * @brief  Format log message and write to output stream/syslog
			 * @param  msg  Pointer to processed message
			 */
			void Append(std::shared_ptr<i2p::log::LogMsg> &);

			/** @brief  Reopen log file */
			void Reopen();
	};

	/**
	 * @struct LogMsg
	 * @brief Log message container
	 *
	 * We creating it somewhere with LogPrint(),
	 * then put in MsgQueue for later processing.
	 */
	struct LogMsg {
		std::time_t timestamp;
		std::string text; /**< message text as single string */
		LogLevel level;   /**< message level */
		std::thread::id tid; /**< id of thread that generated message */

		LogMsg (LogLevel lvl, std::time_t ts, const std::string & txt): timestamp(ts), text(txt), level(lvl) {};
	};

	Log & Logger();

	typedef std::function<void (const std::string&)>  ThrowFunction;
	ThrowFunction GetThrowFunction ();
	void SetThrowFunction (ThrowFunction f);
} // log
} // i2p

/** internal usage only -- folding args array to single string */
template<typename TValue>
void LogPrint (std::stringstream& s, TValue&& arg) noexcept
{
	s << std::forward<TValue>(arg);
}

#if (__cplusplus < 201703L) // below C++ 17
/** internal usage only -- folding args array to single string */
template<typename TValue, typename... TArgs>
void LogPrint (std::stringstream& s, TValue&& arg, TArgs&&... args) noexcept
{
	LogPrint (s, std::forward<TValue>(arg));
	LogPrint (s, std::forward<TArgs>(args)...);
}
#endif

/**
 * @brief Create log message and send it to queue
 * @param level Message level (eLogError, eLogInfo, ...)
 * @param args Array of message parts
 */
template<typename... TArgs>
void LogPrint (LogLevel level, TArgs&&... args) noexcept
{
	i2p::log::Log &log = i2p::log::Logger();
	if (level > log.GetLogLevel ())
		return;

	// fold message to single string
	std::stringstream ss("");

#if (__cplusplus >= 201703L) // C++ 17 or higher
	(LogPrint (ss, std::forward<TArgs>(args)), ...);
#else
	LogPrint (ss, std::forward<TArgs>(args)...);
#endif

	auto msg = std::make_shared<i2p::log::LogMsg>(level, std::time(nullptr), ss.str());
	msg->tid = std::this_thread::get_id();
	log.Append(msg);
}

/**
 * @brief Throw fatal error message with the list of arguments
 * @param args Array of message parts
 */
template<typename... TArgs>
void ThrowFatal (TArgs&&... args) noexcept
{
	auto f = i2p::log::GetThrowFunction ();
	if (!f) return;
	// fold message to single string
	std::stringstream ss("");
#if (__cplusplus >= 201703L) // C++ 17 or higher
	(LogPrint (ss, std::forward<TArgs>(args)), ...);
#else
	LogPrint (ss, std::forward<TArgs>(args)...);
#endif
	f (ss.str ());
}

#endif // LOG_H__
