#include "Log.h"

#include "Daemon.h"

Log g_Log;

void LogMsg::Process()
{
	if (Daemon.isLogging == 1 && Daemon.logfile.is_open())
		Daemon.logfile << s.str();

	output << s.str();
}

void Log::Flush ()
{
	if (Daemon.isLogging == 1 && Daemon.logfile.is_open())
		Daemon.logfile.flush();
}

