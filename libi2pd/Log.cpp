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
	static Log logger;
	/**
	 * @brief Maps our loglevel to their symbolic name
	 */
	static const char * g_LogLevelStr[eNumLogLevels] =
	{
		"error", // eLogError
		"warn",  // eLogWarn
		"info",  // eLogInfo
		"debug"	 // eLogDebug
	};

	/**
	 * @brief Colorize log output -- array of terminal control sequences
	 * @note Using ISO 6429 (ANSI) color sequences
	 */
#ifdef _WIN32
	static const char *LogMsgColors[] = { "", "", "", "", "" };
#else /* UNIX */
	static const char *LogMsgColors[] = {
		[eLogError]     = "\033[1;31m", /* red */
		[eLogWarning]   = "\033[1;33m", /* yellow */
		[eLogInfo]      = "\033[1;36m", /* cyan */
		[eLogDebug]     = "\033[1;34m", /* blue */
		[eNumLogLevels] = "\033[0m",    /* reset */
	};
#endif

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
	m_LogStream (nullptr), m_Logfile(""), m_HasColors(true), m_TimeFormat("%H:%M:%S"),
	m_IsRunning (false), m_Thread (nullptr)
	{
	}

	Log::~Log ()
	{
		delete m_Thread;
	}

	void Log::Start ()
	{
		if (!m_IsRunning)
		{	
			m_IsRunning = true;	
			m_Thread = new std::thread (std::bind (&Log::Run, this));
		}
	}

	void Log::Stop ()	
	{
		switch (m_Destination) 
		{
#ifndef _WIN32
			case eLogSyslog :
				closelog();
				break;
#endif
			case eLogFile:
			case eLogStream:
					if (m_LogStream) m_LogStream->flush();
				break;
			default:
				/* do nothing */
				break;
		}
		m_IsRunning = false;
		m_Queue.WakeUp ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = nullptr;
		}		
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
			strftime(m_LastDateTime, sizeof(m_LastDateTime), m_TimeFormat.c_str(), localtime(&t));
			m_LastTimestamp = t;
		}
		return m_LastDateTime;
	}

	/**
	 * @note This function better to be run in separate thread due to disk i/o.
	 * Unfortunately, with current startup process with late fork() this
	 * will give us nothing but pain. Maybe later. See in NetDb as example.
	 */
	void Log::Process(std::shared_ptr<LogMsg> msg) 
	{
		if (!msg) return;
		std::hash<std::thread::id> hasher;
		unsigned short short_tid;
		short_tid = (short) (hasher(msg->tid) % 1000);
		switch (m_Destination) {
#ifndef _WIN32
			case eLogSyslog:
				syslog(GetSyslogPrio(msg->level), "[%03u] %s", short_tid, msg->text.c_str());
				break;
#endif
			case eLogFile:
			case eLogStream:
				if (m_LogStream)
					*m_LogStream << TimeAsString(msg->timestamp)
						<< "@" << short_tid
						<< "/" << g_LogLevelStr[msg->level]
						<< " - " << msg->text << std::endl;
				break;
			case eLogStdout:
			default:
				std::cout    << TimeAsString(msg->timestamp)
					<< "@" << short_tid
					<< "/" << LogMsgColors[msg->level] << g_LogLevelStr[msg->level] << LogMsgColors[eNumLogLevels]
					<< " - " << msg->text << std::endl;
				break;
		} // switch
	}

	void Log::Run ()
	{
		Reopen ();
		while (m_IsRunning)
		{
			std::shared_ptr<LogMsg> msg;
			while (msg = m_Queue.Get ())
				Process (msg);
			if (m_LogStream) m_LogStream->flush();
			if (m_IsRunning)
				m_Queue.Wait ();
		}
	}		

	void Log::Append(std::shared_ptr<i2p::log::LogMsg> & msg) 
	{
		m_Queue.Put(msg);
	}

	void Log::SendTo (const std::string& path) 
	{
		if (m_LogStream) m_LogStream = nullptr; // close previous	
		auto flags = std::ofstream::out | std::ofstream::app;
		auto os = std::make_shared<std::ofstream> (path, flags);
		if (os->is_open ()) 
		{
			m_HasColors = false;
			m_Logfile = path;
			m_Destination = eLogFile;
			m_LogStream = os;
			return;
		}
		LogPrint(eLogError, "Log: can't open file ", path);
	}

	void Log::SendTo (std::shared_ptr<std::ostream> os) {
		m_HasColors = false;
		m_Destination = eLogStream;
		m_LogStream = os;
	}

#ifndef _WIN32
	void Log::SendTo(const char *name, int facility) {
		m_HasColors = false;
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
