#include "Log.h"

#include "Daemon.h"

i2p::util::MsgQueue<LogMsg> g_Log;

void LogMsg::Process()
{
	if (Daemon.isLogging == 1 && Daemon.logfile.is_open())
	{
		Daemon.logfile << s.str();
		Daemon.logfile.flush();
	}
	output << s.str();
}