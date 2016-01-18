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

void LogMsg::Process()
{
	auto& output = (log && log->GetLogStream ()) ? *log->GetLogStream () : std::cerr;	
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

void Log::SetLogFile (const std::string& fullFilePath)
{
	auto logFile = new std::ofstream (fullFilePath, std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
	if (logFile->is_open ())
	{
		SetLogStream (logFile);
		LogPrint(eLogInfo, "Log: will send messages to ",  fullFilePath);
	}	
	else
		delete logFile;
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
  LogPrint(eLogInfo, "Log: min messages level set to ", level);
}

void Log::SetLogStream (std::ostream * logStream)
{
	if (m_LogStream) delete m_LogStream;	
	m_LogStream = logStream;
}
