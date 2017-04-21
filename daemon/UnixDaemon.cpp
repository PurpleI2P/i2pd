#include "Daemon.h"

#ifndef _WIN32

#include <signal.h>
#include <stdlib.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "Config.h"
#include "FS.h"
#include "Log.h"
#include "RouterContext.h"
#include "ClientContext.h"

void handle_signal(int sig)
{
	switch (sig)
	{
		case SIGHUP:
			LogPrint(eLogInfo, "Daemon: Got SIGHUP, reopening tunnel configuration...");
			i2p::client::context.ReloadConfig();
		break;
		case SIGUSR1:
			LogPrint(eLogInfo, "Daemon: Got SIGUSR1, reopening logs...");
			i2p::log::Logger().Reopen ();
		break;
		case SIGINT:
			if (i2p::context.AcceptsTunnels () && !Daemon.gracefulShutdownInterval)
			{
				i2p::context.SetAcceptsTunnels (false);
				Daemon.gracefulShutdownInterval = 10*60; // 10 minutes
				LogPrint(eLogInfo, "Graceful shutdown after ", Daemon.gracefulShutdownInterval, " seconds");
			}
			else
				Daemon.running = 0;
		break;
		case SIGABRT:
		case SIGTERM:
			Daemon.running = 0; // Exit loop
		break;
		case SIGPIPE:
			LogPrint(eLogInfo, "SIGPIPE received");
		break;
	}
}

namespace i2p
{
	namespace util
	{
		bool DaemonLinux::start()
		{
			if (isDaemon)
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
				std::string d = i2p::fs::GetDataDir();
				if (chdir(d.c_str()) != 0)
				{
					LogPrint(eLogError, "Daemon: could not chdir: ", strerror(errno));
					return false;
				}

				// point std{in,out,err} descriptors to /dev/null
				freopen("/dev/null", "r", stdin);
				freopen("/dev/null", "w", stdout);
				freopen("/dev/null", "w", stderr);
			}

			// set proc limits
			struct rlimit limit;
			uint16_t nfiles; i2p::config::GetOption("limits.openfiles", nfiles);
			getrlimit(RLIMIT_NOFILE, &limit);
			if (nfiles == 0) {
				LogPrint(eLogInfo, "Daemon: using system limit in ", limit.rlim_cur, " max open files");
			} else if (nfiles <= limit.rlim_max) {
				limit.rlim_cur = nfiles;
				if (setrlimit(RLIMIT_NOFILE, &limit) == 0) {
					LogPrint(eLogInfo, "Daemon: set max number of open files to ",
						nfiles, " (system limit is ", limit.rlim_max, ")");
				} else {
					LogPrint(eLogError, "Daemon: can't set max number of open files: ", strerror(errno));
				}
			} else {
				LogPrint(eLogError, "Daemon: limits.openfiles exceeds system limit: ", limit.rlim_max);
			}
			uint32_t cfsize; i2p::config::GetOption("limits.coresize", cfsize);
			if (cfsize) // core file size set
			{
				cfsize *= 1024;
				getrlimit(RLIMIT_CORE, &limit);
				if (cfsize <= limit.rlim_max) {
					limit.rlim_cur = cfsize;
					if (setrlimit(RLIMIT_CORE, &limit) != 0) {
						LogPrint(eLogError, "Daemon: can't set max size of coredump: ", strerror(errno));
					} else if (cfsize == 0) {
						LogPrint(eLogInfo, "Daemon: coredumps disabled");
					} else {
						LogPrint(eLogInfo, "Daemon: set max size of core files to ", cfsize / 1024, "Kb");
					}
				} else {
					LogPrint(eLogError, "Daemon: limits.coresize exceeds system limit: ", limit.rlim_max);
				}
			}

			// Pidfile
			// this code is c-styled and a bit ugly, but we need fd for locking pidfile
			std::string pidfile; i2p::config::GetOption("pidfile", pidfile);
			if (pidfile == "") {
				pidfile = i2p::fs::DataDirPath("i2pd.pid");
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
			gracefulShutdownInterval = 0; // not specified

			// Signal handler
			struct sigaction sa;
			sa.sa_handler = handle_signal;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART;
			sigaction(SIGHUP, &sa, 0);
			sigaction(SIGUSR1, &sa, 0);
			sigaction(SIGABRT, &sa, 0);
			sigaction(SIGTERM, &sa, 0);
			sigaction(SIGINT, &sa, 0);
			sigaction(SIGPIPE, &sa, 0);			

			return Daemon_Singleton::start();
		}

		bool DaemonLinux::stop()
		{
			i2p::fs::Remove(pidfile);

			return Daemon_Singleton::stop();
		}

		void DaemonLinux::run ()
		{
			while (running)
			{
				std::this_thread::sleep_for (std::chrono::seconds(1));
				if (gracefulShutdownInterval)
				{
					gracefulShutdownInterval--; // - 1 second
					if (gracefulShutdownInterval <= 0)
					{
						LogPrint(eLogInfo, "Graceful shutdown");
						return;
					}
				}
			}
		}
	}
}

#endif
