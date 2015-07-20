#ifndef LOG_H__
#define LOG_H__

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#include <chrono>
#include "Queue.h"

enum LogLevel
{
	eLogError = 0,
	eLogWarning,
	eLogInfo,
	eLogDebug,
	eNumLogLevels
};

class Log;
struct LogMsg
{
	std::stringstream s;
	Log * log;
	LogLevel level;

	LogMsg (Log * l = nullptr, LogLevel lv = eLogInfo): log (l), level (lv) {};

	void Process();
};

class Log: public i2p::util::MsgQueue<LogMsg>
{
	public:

		Log (): m_LogStream (nullptr) { SetOnEmpty (std::bind (&Log::Flush, this)); };
		~Log () { delete m_LogStream; };

		void SetLogFile (const std::string& fullFilePath);
		void SetLogStream (std::ostream * logStream);
		std::ostream * GetLogStream () const { return m_LogStream; };
		const std::string& GetTimestamp ();

	private:

		void Flush ();

	private:

		std::ostream * m_LogStream;
		std::string m_Timestamp;
#if !defined(__APPLE__)
#if (__GNUC__ == 4) && (__GNUC_MINOR__ <= 6) // gcc 4.6
		std::chrono::monotonic_clock::time_point m_LastTimestampUpdate;
#else
		std::chrono::steady_clock::time_point m_LastTimestampUpdate;
#endif
#else
		std::chrono::steady_clock::time_point m_LastTimestampUpdate;
#endif
};

extern Log * g_Log;

inline void StartLog (const std::string& fullFilePath)
{
	if (!g_Log)
	{
		auto log = new Log ();
		if (fullFilePath.length () > 0)
			log->SetLogFile (fullFilePath);
		g_Log = log;
	}
}

inline void StartLog (std::ostream * s)
{
	if (!g_Log)
	{
		auto log = new Log ();
		if (s)
			log->SetLogStream (s);
		g_Log = log;
	}
}

inline void StopLog ()
{
	if (g_Log)
	{
		auto log = g_Log;
		g_Log = nullptr;
		log->Stop ();
		delete log;
	}
}

template<typename TValue>
void LogPrint (std::stringstream& s, TValue arg)
{
	s << arg;
}

template<typename TValue, typename... TArgs>
void LogPrint (std::stringstream& s, TValue arg, TArgs... args)
{
	LogPrint (s, arg);
	LogPrint (s, args...);
}

template<typename... TArgs>
void LogPrint (LogLevel level, TArgs... args)
{
	LogMsg * msg = new LogMsg (g_Log, level);
	LogPrint (msg->s, args...);
	msg->s << std::endl;
	if (g_Log)
		g_Log->Put (msg);
	else
	{
		msg->Process ();
		delete msg;
	}
}

template<typename... TArgs>
void LogPrint (TArgs... args)
{
	LogPrint (eLogInfo, args...);
}

#endif
