#include "Daemon.h"

#ifndef _WIN32

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "Log.h"
#include "util.h"


void handle_signal(int sig)
{
	switch (sig)
	{
	case SIGHUP:
		if (i2p::util::config::GetArg("daemon", 0) == 1)
		{
			static bool first=true;
			if (first)
			{
				first=false;
				return;
			}
		}
		LogPrint("Reloading config.");
		i2p::util::filesystem::ReadConfigFile(i2p::util::config::mapArgs, i2p::util::config::mapMultiArgs);
		break;
	case SIGABRT:
	case SIGTERM:
	case SIGINT:
		Daemon.running = 0; // Exit loop
		break;
	}
}


namespace i2p
{
	namespace util
	{
		bool DaemonLinux::start()
		{
			if (isDaemon == 1)
			{
				pid_t pid;
				pid = fork();
				if (pid > 0)
				{
					g_Log.Stop();
					return 0;
				}
				if (pid < 0)
				{
					return -1;
				}

				umask(0);
				int sid = setsid();
				if (sid < 0)
				{
					LogPrint("Error, could not create process group.");
					return -1;
				}
				chdir(i2p::util::filesystem::GetDataDir().string().c_str());
			}

			// Pidfile
			pidfile = i2p::util::filesystem::GetDataDir().string();
			pidfile.append("/i2pd.pid");
			pidFilehandle = open(pidfile.c_str(), O_RDWR | O_CREAT, 0600);
			if (pidFilehandle == -1)
			{
				LogPrint("Error, could not create pid file (", pidfile, ")\nIs an instance already running?");
				return -1;
			}
			if (lockf(pidFilehandle, F_TLOCK, 0) == -1)
			{
				LogPrint("Error, could not lock pid file (", pidfile, ")\nIs an instance already running?");
				return -1;
			}
			char pid[10];
			sprintf(pid, "%d\n", getpid());
			write(pidFilehandle, pid, strlen(pid));

			// Signal handler
			struct sigaction sa;
			sa.sa_handler = handle_signal;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART;
			sigaction(SIGHUP, &sa, 0);
			sigaction(SIGABRT, &sa, 0);
			sigaction(SIGTERM, &sa, 0);
			sigaction(SIGINT, &sa, 0);

			return Daemon_Singleton::start();
		}

		bool DaemonLinux::stop()
		{
			Daemon_Singleton::stop();

			close(pidFilehandle);
			unlink(pidfile.c_str());

			return true;
		}

	}
}

#endif
