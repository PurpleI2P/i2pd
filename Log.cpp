#include <boost/date_time/posix_time/posix_time.hpp>
#include "Log.h"

Log * g_Log = nullptr;

static const char * g_LogLevelStr[eNumLogLevels] =
{
	"error", // eLogError
	"warn",  // eLogWarning
	"info",  // eLogInfo
	"debug"	 // eLogDebug 
};

/** convert LogLevel enum to syslog priority level */
static int ToSyslogLevel(LogLevel lvl)
{
  switch (lvl) {
  case eLogError:
    return LOG_ERR;
  case eLogWarning:
    return LOG_WARNING;
  case eLogInfo:
    return LOG_INFO;
  case eLogDebug:
    return LOG_DEBUG;
  default:
    // WTF? invalid log level?
    return LOG_CRIT;
  }
}


void LogMsg::Process()
{
  if (log && log->SyslogEnabled()) {
    // only log to syslog
    syslog(ToSyslogLevel(level), "%s", s.str().c_str());
    return;
  }
	auto stream = log ? log->GetLogStream () : nullptr;
	auto& output = stream ? *stream : std::cout;	
	if (log)	
		output << log->GetTimestamp ();
	else
		output << boost::posix_time::second_clock::local_time().time_of_day ();
	output << "/" << g_LogLevelStr[level] << " - ";
	output << s.str();
}

const std::string& Log::GetTimestamp ()
{
#if (__GNUC__ == 4) && (__GNUC_MINOR__ <= 6) && !defined(__clang__)	
	auto ts = std::chrono::monotonic_clock::now ();	
#else	
	auto ts = std::chrono::steady_clock::now ();	
#endif	
	if (ts > m_LastTimestampUpdate + std::chrono::milliseconds (500)) // 0.5 second
	{
		m_LastTimestampUpdate = ts;
		m_Timestamp = boost::posix_time::to_simple_string (boost::posix_time::second_clock::local_time().time_of_day ());
	}		
	return m_Timestamp;
}

void Log::Flush ()
{
	if (m_LogStream)
		m_LogStream->flush();
}

void Log::SetLogFile (const std::string& fullFilePath, bool truncate)
{
	m_FullFilePath = fullFilePath;	
	auto mode = std::ofstream::out | std::ofstream::binary;
	mode |= truncate ? std::ofstream::trunc : std::ofstream::app;
	auto logFile = std::make_shared<std::ofstream> (fullFilePath, mode);
	if (logFile->is_open ())
	{
		SetLogStream (logFile);
		LogPrint(eLogInfo, "Log: will send messages to ",  fullFilePath);
	}	
}

void Log::ReopenLogFile ()
{
	if (m_FullFilePath.length () > 0)
	{
		SetLogFile (m_FullFilePath, false); // don't truncate
		LogPrint(eLogInfo, "Log: file ", m_FullFilePath,  " reopen");
	}
}


void Log::SetLogLevel (const std::string& level)
{
  if      (level == "error") { m_MinLevel = eLogError; }
  else if (level == "warn")  { m_MinLevel = eLogWarning;  }
  else if (level == "info")  { m_MinLevel = eLogInfo;  }
  else if (level == "debug") { m_MinLevel = eLogDebug; }
  else {
		LogPrint(eLogError, "Log: Unknown loglevel: ", level);
		return;
  }
  LogPrint(eLogInfo, "Log: min msg level set to ", level);
}

void Log::SetLogStream (std::shared_ptr<std::ostream> logStream)
{
	m_LogStream = logStream;
}

void Log::StartSyslog(const std::string & ident, const int facility)
{
	m_Ident = ident;
	openlog(m_Ident.c_str(), LOG_PID, facility);
}

void Log::StopSyslog()
{
	closelog();
	m_Ident.clear();
}

bool Log::SyslogEnabled()
{
	return m_Ident.size() > 0;
}
