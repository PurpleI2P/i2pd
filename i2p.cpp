#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS // to use freopen
#endif

#include <iostream>
#include <thread>
#include <cryptopp/integer.h>
#include <boost/filesystem.hpp>

#ifndef _WIN32
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#else
#include "./Win32/Win32Service.h"
#endif

#include "Log.h"
#include "base64.h"
#include "Transports.h"
#include "NTCPSession.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "HTTPServer.h"
#include "util.h"


#ifdef _WIN32
// Internal name of the service
#define SERVICE_NAME             "i2pService"

// Displayed name of the service
#define SERVICE_DISPLAY_NAME     "i2p router service"

// Service start options.
#define SERVICE_START_TYPE       SERVICE_DEMAND_START

// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES     ""

// The name of the account under which the service should run
#define SERVICE_ACCOUNT          "NT AUTHORITY\\LocalService"

// The password to the service account name
#define SERVICE_PASSWORD         NULL
#endif

// Global
volatile int running = 1;
volatile int isDaemon;

#ifndef _WIN32
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
      running = 0; // Exit loop
    break;
  }
}
#endif


int main( int argc, char* argv[] )
{
  i2p::util::config::OptionParser(argc,argv);
  volatile int isDaemon = i2p::util::config::GetArg("-daemon", 0);
#ifdef _WIN32
  setlocale(LC_CTYPE, "");
  SetConsoleCP(1251);
  SetConsoleOutputCP(1251);
  setlocale(LC_ALL, "Russian");
#endif


  LogPrint("\n\n\n\ni2pd starting\n");
  LogPrint("data directory: ", i2p::util::filesystem::GetDataDir().string());
  i2p::util::filesystem::ReadConfigFile(i2p::util::config::mapArgs, i2p::util::config::mapMultiArgs);

#ifdef _WIN32
	std::string serviceControl = i2p::util::config::GetArg("-service", "none");
	if (serviceControl == "install")
	{
		InstallService(
			SERVICE_NAME,               // Name of service
			SERVICE_DISPLAY_NAME,       // Name to display
			SERVICE_START_TYPE,         // Service start type
			SERVICE_DEPENDENCIES,       // Dependencies
			SERVICE_ACCOUNT,            // Service running account
			SERVICE_PASSWORD            // Password of the account
			);
		return 0;
	}
	else if (serviceControl == "remove")
	{
		UninstallService(SERVICE_NAME);
		return 0;
	}
	else if (serviceControl != "none")
	{
		printf(" --service=install  to install the service.\n");
		printf(" --service=remove   to remove the service.\n");
		return 0;
	}
	else if (isDaemon)
	{
		std::string logfile = i2p::util::filesystem::GetDataDir().string();
		logfile.append("\\debug.log");
		FILE* openResult = freopen(logfile.c_str(), "a", stdout);
		if (!openResult)
		{
			return -17;
		}
		LogPrint("Service logging enabled.");
		I2PService service(SERVICE_NAME);
		if (!I2PService::Run(service))
		{
			LogPrint("Service failed to run w/err 0x%08lx\n", GetLastError());
		}
		return 0;
	}
#endif

  volatile int isLogging = i2p::util::config::GetArg("-log", 0);

  if (isLogging == 1)
  {
    std::string logfile = i2p::util::filesystem::GetDataDir().string();
#ifndef _WIN32
    logfile.append("/debug.log");
#else
    logfile.append("\\debug.log");
#endif
    FILE* openResult = freopen(logfile.c_str(),"a",stdout);
	// It seems that we need to add FLUSH() for LogPrint and call it in some important places
	if (!openResult)
	{
		LogPrint("Can't do [freopen()].");
		return -17;
	}
    LogPrint("Logging to file enabled.");
  }


#ifndef _WIN32
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
  std::string pidfile = i2p::util::filesystem::GetDataDir().string();
  pidfile.append("/i2pd.pid");
  int pidFilehandle = open(pidfile.c_str(), O_RDWR|O_CREAT, 0600);
  if (pidFilehandle == -1 )
  {
    LogPrint("Error, could not create pid file (", pidfile, ")\nIs an instance already running?");
    return -1;
  }
  if (lockf(pidFilehandle,F_TLOCK,0) == -1)
  {
    LogPrint("Error, could not lock pid file (", pidfile, ")\nIs an instance already running?");
    return -1;
  }
  char pid[10];
  sprintf(pid,"%d\n",getpid());
  write(pidFilehandle, pid, strlen(pid));

  // Signal handler
  struct sigaction sa;
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGHUP,&sa,0);
  sigaction(SIGABRT,&sa,0);
  sigaction(SIGTERM,&sa,0);
  sigaction(SIGINT,&sa,0);
#endif

  //TODO: This is an ugly workaround. fix it.
  //TODO: Autodetect public IP.
  i2p::context.OverrideNTCPAddress(i2p::util::config::GetCharArg("-host", "127.0.0.1"),
      i2p::util::config::GetArg("-port", 17070));

  i2p::util::HTTPServer httpServer (i2p::util::config::GetArg("-httpport", 7070));

  httpServer.Start ();
  i2p::data::netdb.Start ();
  i2p::transports.Start ();
  i2p::tunnel::tunnels.Start ();

  while (running)
  {
    //TODO Meeh: Find something better to do here.
    std::this_thread::sleep_for (std::chrono::seconds(1));
  }
  LogPrint("Shutdown started.");

  i2p::tunnel::tunnels.Stop ();
  i2p::transports.Stop ();
  i2p::data::netdb.Stop ();
  httpServer.Stop ();

  if (isLogging == 1)
  {
    fclose (stdout);
  }
#ifndef _WIN32
  close(pidFilehandle);
  unlink(pidfile.c_str());
#endif
  return 0;
}
