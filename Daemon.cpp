#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS // to use freopen
#endif

#include "Daemon.h"

#include "Log.h"
#include "base64.h"
#include "Transports.h"
#include "NTCPSession.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "Garlic.h"
#include "util.h"
#include "Streaming.h"

namespace i2p
{
	namespace util
	{
		bool Daemon_Singleton::start()
		{
			isDaemon = i2p::util::config::GetArg("-daemon", 0);
			isLogging = i2p::util::config::GetArg("-log", 0);

			//TODO: This is an ugly workaround. fix it.
			//TODO: Autodetect public IP.
			i2p::context.OverrideNTCPAddress(i2p::util::config::GetCharArg("-host", "127.0.0.1"),
				i2p::util::config::GetArg("-port", 17070));

			if (isLogging == 1)
			{
				std::string logfile = i2p::util::filesystem::GetDataDir().string();
#ifndef _WIN32
				logfile.append("/debug.log");
#else
				logfile.append("\\debug.log");
#endif
				freopen(logfile.c_str(), "a", stdout);
				LogPrint("Logging to file enabled.");
			}

			httpServer = new i2p::util::HTTPServer(i2p::util::config::GetArg("-httpport", 7070));
			httpServer->Start();

			i2p::data::netdb.Start();
			i2p::transports.Start();
			i2p::tunnel::tunnels.Start();
			i2p::garlic::routing.Start();
			i2p::stream::StartStreaming();

			httpProxy = new i2p::proxy::HTTPProxy(i2p::util::config::GetArg("-httpproxyport", 4446));
			httpProxy->Start();

			return true;
		}

		bool Daemon_Singleton::stop()
		{
			LogPrint("Shutdown started.");

			httpProxy->Stop();
			i2p::stream::StopStreaming();
			i2p::garlic::routing.Stop();
			i2p::tunnel::tunnels.Stop();
			i2p::transports.Stop();
			i2p::data::netdb.Stop();
			httpServer->Stop();

			delete httpProxy; httpProxy = NULL;
			delete httpServer; httpServer = NULL;

			if (isLogging == 1)
			{
				fclose(stdout);
			}

			return true;
		}
	}
}