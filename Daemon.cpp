#include <thread>

#include "Daemon.h"

#include "Log.h"
#include "base64.h"
#include "version.h"
#include "Transports.h"
#include "NTCPSession.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "Garlic.h"
#include "util.h"
#include "Streaming.h"
#include "Destination.h"
#include "HTTPServer.h"
#include "ClientContext.h"

namespace i2p
{
	namespace util
	{
		class Daemon_Singleton::Daemon_Singleton_Private
		{
		public:
			Daemon_Singleton_Private() : httpServer(nullptr)
			{};
			~Daemon_Singleton_Private() 
			{
				delete httpServer;
			};

			i2p::util::HTTPServer *httpServer;
		};

		Daemon_Singleton::Daemon_Singleton() : running(1), d(*new Daemon_Singleton_Private()) {};
		Daemon_Singleton::~Daemon_Singleton() {
			delete &d;
		};

		bool Daemon_Singleton::IsService () const
		{
#ifndef _WIN32
			return i2p::util::config::GetArg("-service", 0);
#else
			return false;
#endif
		}

		bool Daemon_Singleton::init(int argc, char* argv[])
		{
			i2p::util::config::OptionParser(argc, argv);
			i2p::context.Init ();

			LogPrint("\n\n\n\ni2pd starting\n");
			LogPrint("Version ", VERSION);
			LogPrint("data directory: ", i2p::util::filesystem::GetDataDir().string());
			i2p::util::filesystem::ReadConfigFile(i2p::util::config::mapArgs, i2p::util::config::mapMultiArgs);

			isDaemon = i2p::util::config::GetArg("-daemon", 0);
			isLogging = i2p::util::config::GetArg("-log", 1);

			int port = i2p::util::config::GetArg("-port", 0);
			if (port)
				i2p::context.UpdatePort (port);					
			const char * host = i2p::util::config::GetCharArg("-host", "");
			if (host && host[0])
				i2p::context.UpdateAddress (host);	

			if (i2p::util::config::GetArg("-unreachable", 0))
				i2p::context.SetUnreachable ();

			LogPrint("CMD parameters:");
			for (int i = 0; i < argc; ++i)
				LogPrint(i, "  ", argv[i]);

			return true;
		}
			
		bool Daemon_Singleton::start()
		{
			// initialize log			
			if (isLogging)
			{
				if (isDaemon)
				{
					std::string logfile_path = IsService () ? "/var/log" : i2p::util::filesystem::GetDataDir().string();
	#ifndef _WIN32
					logfile_path.append("/i2pd.log");
	#else
					logfile_path.append("\\i2pd.log");
	#endif
					StartLog (logfile_path);
				}
				else
					StartLog (""); // write to stdout
			}

			d.httpServer = new i2p::util::HTTPServer(i2p::util::config::GetArg("-httpport", 7070));
			d.httpServer->Start();
			LogPrint("HTTP Server started");
			i2p::data::netdb.Start();
			LogPrint("NetDB started");
			i2p::transport::transports.Start();
			LogPrint("Transports started");
			i2p::tunnel::tunnels.Start();
			LogPrint("Tunnels started");
			i2p::client::context.Start ();
			LogPrint("Client started");
			
			return true;
		}

		bool Daemon_Singleton::stop()
		{
			LogPrint("Shutdown started.");
			i2p::client::context.Stop();
			LogPrint("Client stoped");
			i2p::tunnel::tunnels.Stop();
			LogPrint("Tunnels stoped");
			i2p::transport::transports.Stop();
			LogPrint("Transports stoped");
			i2p::data::netdb.Stop();
			LogPrint("NetDB stoped");
			d.httpServer->Stop();
			LogPrint("HTTP Server stoped");
			StopLog ();

			delete d.httpServer; d.httpServer = nullptr;

			return true;
		}
	}
}
