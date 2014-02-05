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


// Global
int running = 1;

#ifndef _WIN32
void handle_sighup(int n)
{
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
}
void handle_shutdown(int sig)
{
  running = 0; // Exit loop
}
#endif


int main( int argc, char* argv[] )
{
  i2p::util::config::OptionParser(argc,argv);
#ifdef _WIN32
  setlocale(LC_CTYPE, "");
  SetConsoleCP(1251);
  SetConsoleOutputCP(1251);
  setlocale(LC_ALL, "Russian");
#endif


  LogPrint("\n\n\n\ni2pd starting\n");
  LogPrint("data directory: ", i2p::util::filesystem::GetDataDir().string());
  i2p::util::filesystem::ReadConfigFile(i2p::util::config::mapArgs, i2p::util::config::mapMultiArgs);

#ifndef _WIN32
  struct sigaction sa;
  sa.sa_handler = handle_sighup;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGHUP,&sa,0) == -1)
  {
    LogPrint("Failed to install SIGHUP handler.");
  }

  if (i2p::util::config::GetArg("-daemon", 0) == 1)
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
  }

  // Handle shutdown
  signal(SIGABRT, &handle_shutdown);
  signal(SIGTERM, &handle_shutdown);
  signal(SIGINT, &handle_shutdown);
#endif

  if (i2p::util::config::GetArg("-log", 0) == 1)
  {
    std::string logfile = i2p::util::filesystem::GetDataDir().string();
#ifndef _WIN32
    logfile.append("/debug.log");
#else
    logfile.append("\\debug.log");
#endif
    LogPrint("Logging to file enabled.");
    freopen(logfile.c_str(),"a",stdout);
  }

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

  if (i2p::util::config::GetArg("-log", 0) == 1)
  {
    fclose (stdout);
  }
  return 0;
}
