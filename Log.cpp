#include "Log.h"
#include <boost/date_time/posix_time/posix_time.hpp>

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
	output << boost::posix_time::second_clock::local_time().time_of_day () <<  
		"/" << g_LogLevelStr[level] << " - ";
	output << s.str();
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
		LogPrint("Logging to file ",  fullFilePath, " enabled.");
	}	
	else
		delete logFile;
}

void Log::SetLogStream (std::ostream * logStream)
{
	if (m_LogStream) delete m_LogStream;	
	m_LogStream = logStream;
}
