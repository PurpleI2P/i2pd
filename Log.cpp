#include "Log.h"

Log g_Log;

void LogMsg::Process()
{
	output << s.str();

	std::cout << s.str (); // TODO: delete later
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
