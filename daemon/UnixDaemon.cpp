/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Daemon.h"

#ifndef _WIN32

#include <signal.h>
#include <stdlib.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <errno.h>
#if defined(__OpenBSD__)
#include <map>
#include <utility>
#endif

#include "Config.h"
#include "FS.h"
#include "Log.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "Transports.h"
#include "util.h"

#if defined(__OpenBSD__)
namespace
{
std::string ParentDirectory(const std::string& path)
{
	if (path.empty())
		return "";
	auto pos = path.find_last_of('/');
	if (pos == std::string::npos)
		return "";
	if (pos == 0)
		return "/";
	return path.substr(0, pos);
}

void AddRule(std::map<std::string, std::string>& rules, const std::string& path, const char* perms)
{
	if (path.empty())
		return;
	std::string normalized = path;
	while (normalized.size() > 1 && normalized.back() == '/')
		normalized.pop_back();
	auto it = rules.find(normalized);
	if (it == rules.end())
		rules.emplace(std::move(normalized), std::string(perms));
	else
		for (const char* p = perms; *p; ++p)
			if (it->second.find(*p) == std::string::npos)
				it->second.push_back(*p);
}
}

static bool ConfigureOpenBSDSandbox(const std::string& pidfile, bool isDaemon)
{
	std::map<std::string, std::string> rules;
	const auto& dataDir = i2p::fs::GetDataDir();
	if (!dataDir.empty())
		AddRule(rules, dataDir, "rwc");
	const auto& certsDir = i2p::fs::GetCertsDir();
	if (!certsDir.empty())
		AddRule(rules, certsDir, "r");

	AddRule(rules, "/etc", "r");
	AddRule(rules, "/dev/null", "rw");
	AddRule(rules, "/dev/urandom", "r");
	AddRule(rules, "/dev/log", "rw");

	auto allowWritablePath = [&rules](const std::string& path)
	{
		if (path.empty() || path.front() != '/')
			return;
		auto parent = ParentDirectory(path);
		if (parent.empty() || parent == "/")
			AddRule(rules, path, "rwc");
		else
			AddRule(rules, parent, "rwc");
	};

	allowWritablePath(pidfile);

	std::string logsOption;
	i2p::config::GetOption("log", logsOption);
	bool logToFile = logsOption == "file";
	if (!logToFile && logsOption != "syslog")
	{
		if (isDaemon && (logsOption.empty() || logsOption == "stdout"))
			logToFile = true;
	}

	if (logToFile)
	{
		std::string logfile;
		i2p::config::GetOption("logfile", logfile);
		if (logfile.empty())
			logfile = i2p::fs::DataDirPath("i2pd.log");
		if (!logfile.empty())
		{
			if (logfile.front() != '/')
				logfile = i2p::fs::DataDirPath(logfile);
			allowWritablePath(logfile);
		}
	}

	for (const auto& rule : rules)
	{
		if (unveil(rule.first.c_str(), rule.second.c_str()) == -1)
		{
			LogPrint(eLogError, "Daemon: unveil failed for ", rule.first, ": ", strerror(errno));
			return false;
		}
	}

	if (unveil(nullptr, nullptr) == -1)
	{
		LogPrint(eLogError, "Daemon: unveil lock failed: ", strerror(errno));
		return false;
	}

	constexpr const char* promises = "stdio rpath wpath cpath inet dns proc fattr thread unix";
	if (pledge(promises, nullptr) == -1)
	{
		LogPrint(eLogError, "Daemon: pledge(", promises, ") failed: ", strerror(errno));
		return false;
	}
	return true;
}
#endif // __OpenBSD__

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
		case SIGTSTP:
			LogPrint(eLogInfo, "Daemon: Got SIGTSTP, disconnecting from network...");
			i2p::transport::transports.SetOnline(false);
		break;
		case SIGCONT:
			LogPrint(eLogInfo, "Daemon: Got SIGCONT, restoring connection to network...");
			i2p::transport::transports.SetOnline(true);
		break;
	}
}

namespace i2p
{
	namespace util
	{
		bool DaemonUnix::start()
		{
			if (isDaemon)
			{
				pid_t pid;
				pid = fork();
				if (pid > 0) // parent
					::exit (EXIT_SUCCESS);

				if (pid < 0) // error
				{
					LogPrint(eLogError, "Daemon: Could not fork: ", strerror(errno));
					std::cerr << "i2pd: Could not fork: " << strerror(errno) << std::endl;
					return false;
				}

				// child
				umask(S_IWGRP | S_IRWXO); // 0027
				int sid = setsid();
				if (sid < 0)
				{
					LogPrint(eLogError, "Daemon: Could not create process group.");
					std::cerr << "i2pd: Could not create process group." << std::endl;
					return false;
				}
				std::string d = i2p::fs::GetDataDir();
				if (chdir(d.c_str()) != 0)
				{
					LogPrint(eLogError, "Daemon: Could not chdir: ", strerror(errno));
					std::cerr << "i2pd: Could not chdir: " << strerror(errno) << std::endl;
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
				LogPrint(eLogInfo, "Daemon: Using system limit in ", limit.rlim_cur, " max open files");
			} else if (nfiles <= limit.rlim_max) {
				limit.rlim_cur = nfiles;
				if (setrlimit(RLIMIT_NOFILE, &limit) == 0) {
					LogPrint(eLogInfo, "Daemon: Set max number of open files to ",
						nfiles, " (system limit is ", limit.rlim_max, ")");
				} else {
					LogPrint(eLogError, "Daemon: Can't set max number of open files: ", strerror(errno));
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
						LogPrint(eLogError, "Daemon: Can't set max size of coredump: ", strerror(errno));
					} else if (cfsize == 0) {
						LogPrint(eLogInfo, "Daemon: coredumps disabled");
					} else {
						LogPrint(eLogInfo, "Daemon: Set max size of core files to ", cfsize / 1024, "Kb");
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
#if defined(__OpenBSD__)
			if (!ConfigureOpenBSDSandbox(pidfile, isDaemon))
				return false;
#endif
			if (pidfile != "") {
				pidFH = open(pidfile.c_str(), O_RDWR | O_CREAT, 0600);
				if (pidFH < 0)
				{
					LogPrint(eLogError, "Daemon: Could not create pid file ", pidfile, ": ", strerror(errno));
					std::cerr << "i2pd: Could not create pid file " << pidfile << ": " << strerror(errno) << std::endl;
					return false;
				}

#ifndef ANDROID
				if (lockf(pidFH, F_TLOCK, 0) != 0)
#else
				struct flock fl;
				fl.l_len = 0;
				fl.l_type = F_WRLCK;
				fl.l_whence = SEEK_SET;
				fl.l_start = 0;

				if (fcntl(pidFH, F_SETLK, &fl) != 0)
#endif
				{
					LogPrint(eLogError, "Daemon: Could not lock pid file ", pidfile, ": ", strerror(errno));
					std::cerr << "i2pd: Could not lock pid file " << pidfile << ": " << strerror(errno) << std::endl;
					return false;
				}

				char pid[10];
				sprintf(pid, "%d\n", getpid());
				ftruncate(pidFH, 0);
				if (write(pidFH, pid, strlen(pid)) < 0)
				{
					LogPrint(eLogCritical, "Daemon: Could not write pidfile ", pidfile, ": ", strerror(errno));
					std::cerr << "i2pd: Could not write pidfile " << pidfile << ": " << strerror(errno) << std::endl;
					return false;
				}
			}
			gracefulShutdownInterval = 0; // not specified

			// handle signal TSTP
			bool handleTSTP; i2p::config::GetOption("unix.handle_sigtstp", handleTSTP);

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
			if (handleTSTP)
			{
				sigaction(SIGTSTP, &sa, 0);
				sigaction(SIGCONT, &sa, 0);
			}

			return Daemon_Singleton::start();
		}

		bool DaemonUnix::stop()
		{
			i2p::fs::Remove(pidfile);
			return Daemon_Singleton::stop();
		}

		void DaemonUnix::run ()
		{
			i2p::util::SetThreadName ("i2pd-daemon");
			while (running)
			{
				std::this_thread::sleep_for (std::chrono::seconds(1));
				if (gracefulShutdownInterval)
				{
					gracefulShutdownInterval--; // - 1 second
					if (gracefulShutdownInterval <= 0 || i2p::tunnel::tunnels.CountTransitTunnels() <= 0)
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
