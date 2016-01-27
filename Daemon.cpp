#include <thread>
#include <memory>

#include "Daemon.h"

#include "Log.h"
#include "Base.h"
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
#include "I2PControl.h"
#include "ClientContext.h"
#include "Crypto.h"

#ifdef USE_UPNP
#include "UPnP.h"
#endif

namespace i2p
{
	namespace util
	{
		class Daemon_Singleton::Daemon_Singleton_Private
		{
		public:
			Daemon_Singleton_Private() {};
			~Daemon_Singleton_Private() {};

			std::unique_ptr<i2p::util::HTTPServer> httpServer;
			std::unique_ptr<i2p::client::I2PControlService> m_I2PControlService;

#ifdef USE_UPNP
			i2p::transport::UPnP m_UPnP;
#endif	
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
			i2p::crypto::InitCrypto ();
			i2p::util::config::OptionParser(argc, argv);
			i2p::context.Init ();

			LogPrint(eLogInfo, "i2pd v", VERSION, " starting");
			LogPrint(eLogDebug, "FS: data directory: ", i2p::util::filesystem::GetDataDir().string());
			i2p::util::config::ReadConfigFile(i2p::util::filesystem::GetConfigFile());

			isDaemon = i2p::util::config::GetArg("-daemon", 0);
			isLogging = i2p::util::config::GetArg("-log", (int)isDaemon);

			int port = i2p::util::config::GetArg("-port", 0);
			if (port)
				i2p::context.UpdatePort (port);					
			std::string host = i2p::util::config::GetArg("-host", "");
			if (host != "")
				i2p::context.UpdateAddress (boost::asio::ip::address::from_string (host));	

			i2p::context.SetSupportsV6 (i2p::util::config::GetArg("-v6", 0));
			i2p::context.SetAcceptsTunnels (!i2p::util::config::GetArg("-notransit", 0));
			bool isFloodfill = i2p::util::config::GetArg("-floodfill", 0);
			i2p::context.SetFloodfill (isFloodfill);
			auto bandwidth = i2p::util::config::GetArg("-bandwidth", "");
			if (bandwidth.length () > 0)
			{
				if (bandwidth[0] > 'O')
					i2p::context.SetExtraBandwidth ();
				else if (bandwidth[0] > 'L')
					i2p::context.SetHighBandwidth ();
				else
					i2p::context.SetLowBandwidth ();
			}	
			else if (isFloodfill)
				i2p::context.SetExtraBandwidth ();
			LogPrint(eLogDebug, "Daemon: CMD parameters:");
			for (int i = 0; i < argc; ++i)
				LogPrint(eLogDebug, i, ":  ", argv[i]);

			return true;
		}
			
		bool Daemon_Singleton::start()
		{
			// initialize log			
			if (isLogging)
			{				
				std::string logfile_path = IsService () ? "/var/log/i2pd" : i2p::util::filesystem::GetDataDir().string();
#ifndef _WIN32
				logfile_path.append("/i2pd.log");
#else
				logfile_path.append("\\i2pd.log");
#endif
				StartLog (logfile_path);
			}
			else
				StartLog (""); // write to stdout
			g_Log->SetLogLevel(i2p::util::config::GetArg("-loglevel", "info"));
			
			std::string httpAddr = i2p::util::config::GetArg("-httpaddress", "127.0.0.1");
			uint16_t    httpPort = i2p::util::config::GetArg("-httpport", 7070);
			LogPrint(eLogInfo, "Daemon: staring HTTP Server at ", httpAddr, ":", httpPort);
			d.httpServer = std::unique_ptr<i2p::util::HTTPServer>(new i2p::util::HTTPServer(httpAddr, httpPort));
			d.httpServer->Start();

			LogPrint(eLogInfo, "Daemon: starting NetDB");
			i2p::data::netdb.Start();

#ifdef USE_UPNP
			LogPrint(eLogInfo, "Daemon: starting UPnP");
			d.m_UPnP.Start ();
#endif			
			LogPrint(eLogInfo, "Daemon: starting Transports");
			i2p::transport::transports.Start();

			LogPrint(eLogInfo, "Daemon: starting Tunnels");
			i2p::tunnel::tunnels.Start();

			LogPrint(eLogInfo, "Daemon: starting Client");
			i2p::client::context.Start ();

			// I2P Control Protocol
			std::string i2pcpAddr = i2p::util::config::GetArg("-i2pcontroladdress", "127.0.0.1");
			uint16_t    i2pcpPort = i2p::util::config::GetArg("-i2pcontrolport", 0);
			if (i2pcpPort)
			{
				LogPrint(eLogInfo, "Daemon: starting I2PControl at ", i2pcpAddr, ":", i2pcpPort);
				d.m_I2PControlService = std::unique_ptr<i2p::client::I2PControlService>(new i2p::client::I2PControlService (i2pcpAddr, i2pcpPort));
				d.m_I2PControlService->Start ();
			}
			return true;
		}

		bool Daemon_Singleton::stop()
		{
			LogPrint(eLogInfo, "Daemon: shutting down");
			LogPrint(eLogInfo, "Daemon: stopping Client");
			i2p::client::context.Stop();
			LogPrint(eLogInfo, "Daemon: stopping Tunnels");
			i2p::tunnel::tunnels.Stop();
#ifdef USE_UPNP
			LogPrint(eLogInfo, "Daemon: stopping UPnP");
			d.m_UPnP.Stop ();
#endif			
			LogPrint(eLogInfo, "Daemon: stopping Transports");
			i2p::transport::transports.Stop();
			LogPrint(eLogInfo, "Daemon: stopping NetDB");
			i2p::data::netdb.Stop();
			LogPrint(eLogInfo, "Daemon: stopping HTTP Server");
			d.httpServer->Stop();
			d.httpServer = nullptr;
			if (d.m_I2PControlService)
			{
				LogPrint(eLogInfo, "Daemon: stopping I2PControl");
				d.m_I2PControlService->Stop ();
				d.m_I2PControlService = nullptr;
			}	
			i2p::crypto::TerminateCrypto ();
			StopLog ();

			return true;
		}
	}
}
