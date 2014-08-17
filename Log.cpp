#include "Log.h"
#include <boost/date_time/posix_time/posix_time.hpp>

Log * g_Log = nullptr;

void LogMsg::Process()
{
	output << boost::posix_time::second_clock::local_time().time_of_day () << " - ";
	output << s.str();
}

void Log::Flush ()
{
	if (m_LogFile)
		m_LogFile->flush();
}

void Log::SetLogFile (const std::string& fullFilePath)
{
	if (m_LogFile) delete m_LogFile;
	m_LogFile = new std::ofstream (fullFilePath, std::ofstream::out | std::ofstream::binary | std::ofstream::trunc);
	if (m_LogFile->is_open ())
		LogPrint("Logging to file ",  fullFilePath, " enabled.");
	else
	{
		delete m_LogFile;
		m_LogFile = nullptr;
	}
}
