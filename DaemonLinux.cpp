#include "Daemon.h"

#ifndef _WIN32

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "Config.h"
#include "Log.h"
#include "util.h"

void handle_signal(int sig)
{
	switch (sig)
	{
	case SIGHUP:
		LogPrint(eLogInfo, "Daemon: Got SIGHUP, doing nothing");
		// TODO:
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
				{
					LogPrint(eLogError, "Daemon: could not fork: ", strerror(errno));
					return false;
				}

				// child
				umask(S_IWGRP | S_IRWXO); // 0027
				int sid = setsid();
				if (sid < 0)
				{
					LogPrint(eLogError, "Daemon: could not create process group.");
					return false;
				}
				std::string d(i2p::util::filesystem::GetDataDir().string ()); // make a copy
				if (chdir(d.c_str()) != 0)
				{
					LogPrint(eLogError, "Daemon: could not chdir: ", strerror(errno));
					return false;
				}

				// close stdin/stdout/stderr descriptors
				::close (0);
				::open ("/dev/null", O_RDWR);
				::close (1);
				::open ("/dev/null", O_RDWR);	
				::close (2);
				::open ("/dev/null", O_RDWR);
			}

			// Pidfile
			// this code is c-styled and a bit ugly, but we need fd for locking pidfile
			std::string pidfile; i2p::config::GetOption("pidfile", pidfile);
			if (pidfile == "") {
				pidfile = IsService () ? "/var/run" : i2p::util::filesystem::GetDataDir().string();
				pidfile.append("/i2pd.pid");
			}
			if (pidfile != "") {
				pidFH = open(pidfile.c_str(), O_RDWR | O_CREAT, 0600);
				if (pidFH < 0)
				{
					LogPrint(eLogError, "Daemon: could not create pid file ", pidfile, ": ", strerror(errno));
					return false;
				}
				if (lockf(pidFH, F_TLOCK, 0) != 0)
				{
					LogPrint(eLogError, "Daemon: could not lock pid file ", pidfile, ": ", strerror(errno));
					return false;
				}
				char pid[10];
				sprintf(pid, "%d\n", getpid());
				ftruncate(pidFH, 0);
				if (write(pidFH, pid, strlen(pid)) < 0)
				{
					LogPrint(eLogError, "Daemon: could not write pidfile: ", strerror(errno));
					return false;
				}
			}

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
			unlink(pidfile.c_str());

			return Daemon_Singleton::stop();			
		}
	}
}

#endif
