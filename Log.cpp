/*
* Copyright (c) 2013-2016, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"

namespace i2p {
namespace log {
	Log logger;
	/**
	 * @enum Maps our loglevel to their symbolic name
	 */
	static const char * g_LogLevelStr[eNumLogLevels] =
	{
		"error", // eLogError
		"warn",  // eLogWarn
		"info",  // eLogInfo
		"debug"	 // eLogDebug
	};

#ifndef _WIN32
	/**
	 * @brief  Maps our log levels to syslog one
	 * @return syslog priority LOG_*, as defined in syslog.h
	 */
	static inline int GetSyslogPrio (enum LogLevel l) {
		int priority = LOG_DEBUG;
		switch (l) {
			case eLogError   : priority = LOG_ERR;     break;
			case eLogWarning : priority = LOG_WARNING; break;
			case eLogInfo    : priority = LOG_INFO;    break;
			case eLogDebug   : priority = LOG_DEBUG;   break;
			default          : priority = LOG_DEBUG;   break;
		}
		return priority;
	}
#endif

	Log::Log():
	m_Destination(eLogStdout), m_MinLevel(eLogInfo),
	m_LogStream (nullptr), m_Logfile(""), m_IsReady(false)
	{
	}

	Log::~Log ()
	{
		switch (m_Destination) {
#ifndef _WIN32
			case eLogSyslog :
				closelog();
				break;
#endif
			case eLogFile:
			case eLogStream:
				m_LogStream->flush();
				break;
			default:
				/* do nothing */
				break;
		}
		Process();
	}

	void Log::SetLogLevel (const std::string& level) {
		if      (level == "error") { m_MinLevel = eLogError; }
		else if (level == "warn")  { m_MinLevel = eLogWarning; }
		else if (level == "info")  { m_MinLevel = eLogInfo;  }
		else if (level == "debug") { m_MinLevel = eLogDebug; }
		else {
			LogPrint(eLogError, "Log: unknown loglevel: ", level);
			return;
		}
		LogPrint(eLogInfo, "Log: min messages level set to ", level);
	}
	
	const char * Log::TimeAsString(std::time_t t) {
		if (t != m_LastTimestamp) {
			strftime(m_LastDateTime, sizeof(m_LastDateTime), "%H:%M:%S", localtime(&t));
			m_LastTimestamp = t;
		}
		return m_LastDateTime;
	}

	/**
	 * @note This function better to be run in separate thread due to disk i/o.
	 * Unfortunately, with current startup process with late fork() this
	 * will give us nothing but pain. Maybe later. See in NetDb as example.
	 */
	void Log::Process() {
		std::unique_lock<std::mutex> l(m_OutputLock);
		std::hash<std::thread::id> hasher;
		unsigned short short_tid;
		while (1) {
			auto msg = m_Queue.GetNextWithTimeout (1);
			if (!msg)
				break;
			short_tid = (short) (hasher(msg->tid) % 1000);
			switch (m_Destination) {
#ifndef _WIN32
				case eLogSyslog:
					syslog(GetSyslogPrio(msg->level), "[%03u] %s", short_tid, msg->text.c_str());
					break;
#endif
				case eLogFile:
				case eLogStream:
					*m_LogStream << TimeAsString(msg->timestamp)
						<< "@" << short_tid
						<< "/" << g_LogLevelStr[msg->level]
						<< " - " << msg->text << std::endl;
					break;
				case eLogStdout:
				default:
					std::cout    << TimeAsString(msg->timestamp)
						<< "@" << short_tid
						<< "/" << g_LogLevelStr[msg->level]
						<< " - " << msg->text << std::endl;
					break;
			} // switch
		} // while
	}

	void Log::Append(std::shared_ptr<i2p::log::LogMsg> & msg) {
		m_Queue.Put(msg);
		if (!m_IsReady)
			return;
		Process();
	}

	void Log::SendTo (const std::string& path) {
		auto flags = std::ofstream::out | std::ofstream::app;
		auto os = std::make_shared<std::ofstream> (path, flags);
		if (os->is_open ()) {
			m_Logfile = path;
			m_Destination = eLogFile;
			m_LogStream = os;
			return;
		}
		LogPrint(eLogError, "Log: can't open file ", path);
	}

	void Log::SendTo (std::shared_ptr<std::ostream> os) {
		m_Destination = eLogStream;
		m_LogStream = os;
	}

#ifndef _WIN32
	void Log::SendTo(const char *name, int facility) {
		m_Destination = eLogSyslog;
		m_LogStream = nullptr;
		openlog(name, LOG_CONS | LOG_PID, facility);
	}
#endif

	void Log::Reopen() {
		if (m_Destination == eLogFile)
			SendTo(m_Logfile);
	}

	Log & Logger() {
		return logger;
	}
} // log
} // i2p
