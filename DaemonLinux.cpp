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
				if (pid > 0) // parent
					::exit (EXIT_SUCCESS);

				if (pid < 0) // error
					return false;

				// child
				umask(0);
				int sid = setsid();
				if (sid < 0)
				{
					LogPrint("Error, could not create process group.");
					return false;
				}
				chdir(i2p::util::filesystem::GetDataDir().string().c_str());

				// close stdin/stdout/stderr descriptors
				::close (0);
				::open ("/dev/null", O_RDWR);
				::close (1);
				::open ("/dev/null", O_RDWR);	
				::close (2);
				::open ("/dev/null", O_RDWR);
			}

			// Pidfile
			pidfile = IsService () ? "/var/run" : i2p::util::filesystem::GetDataDir().string();
			pidfile.append("/i2pd.pid");
			pidFilehandle = open(pidfile.c_str(), O_RDWR | O_CREAT, 0600);
			if (pidFilehandle == -1)
			{
				LogPrint("Error, could not create pid file (", pidfile, ")\nIs an instance already running?");
				return false;
			}
			if (lockf(pidFilehandle, F_TLOCK, 0) == -1)
			{
				LogPrint("Error, could not lock pid file (", pidfile, ")\nIs an instance already running?");
				return false;
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
			close(pidFilehandle);
			unlink(pidfile.c_str());

			return Daemon_Singleton::stop();			
		}

	}
}

#endif
