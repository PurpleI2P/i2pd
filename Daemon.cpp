#include <thread>
#include <memory>

#include "Daemon.h"

#include "Config.h"
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
			bool service = false;
#ifndef _WIN32
			i2p::config::GetOption("service", service);
#endif
			return service;
		}

		bool Daemon_Singleton::init(int argc, char* argv[])
		{
			i2p::config::Init();
			i2p::config::ParseCmdline(argc, argv);

			std::string config  = i2p::util::filesystem::GetConfigFile().string();
			std::string tunconf = i2p::util::filesystem::GetTunnelsConfigFile().string();
			std::string datadir = i2p::util::filesystem::GetDataDir().string();

			i2p::config::ParseConfig(config);
			i2p::config::Finalize();

			i2p::crypto::InitCrypto ();
			i2p::context.Init ();

			i2p::config::GetOption("daemon", isDaemon);

			// TODO: move log init here

			LogPrint(eLogInfo,  "i2pd v", VERSION, " starting");
			LogPrint(eLogDebug, "FS: main config file: ", config);
			LogPrint(eLogDebug, "FS: tunnels config: ",   tunconf);
			LogPrint(eLogDebug, "FS: data directory: ", datadir);

			uint16_t port; i2p::config::GetOption("port", port);
			if (!i2p::config::IsDefault("port"))
			{	
				LogPrint(eLogInfo, "Daemon: accepting incoming connections at port ", port);
				i2p::context.UpdatePort (port);
			}	

			std::string host; i2p::config::GetOption("host", host);
			if (!i2p::config::IsDefault("host"))
			{
				LogPrint(eLogInfo, "Daemon: setting address for incoming connections to ", host);
				i2p::context.UpdateAddress (boost::asio::ip::address::from_string (host));	
			}

			bool ipv6;    i2p::config::GetOption("ipv6", ipv6);
			bool transit; i2p::config::GetOption("notransit", transit);
			i2p::context.SetSupportsV6     (ipv6);
			i2p::context.SetAcceptsTunnels (!transit);

			bool isFloodfill; i2p::config::GetOption("floodfill", isFloodfill);
			char bandwidth;   i2p::config::GetOption("bandwidth", bandwidth);

			if (isFloodfill) 
			{
				LogPrint(eLogInfo, "Daemon: router will be floodfill");
				i2p::context.SetFloodfill (true);
			}	
			else
				i2p::context.SetFloodfill (false);
			if (bandwidth != '-')
			{
				LogPrint(eLogInfo, "Daemon: bandwidth set to ", bandwidth);
				if (bandwidth > 'O') 
					i2p::context.SetExtraBandwidth (); 
				else if (bandwidth > 'L')
					i2p::context.SetHighBandwidth (); 
				else 
					i2p::context.SetLowBandwidth ();
			}
			else if (isFloodfill) 
			{
				LogPrint(eLogInfo, "Daemon: floodfill bandwidth set to 'extra'");
				i2p::context.SetExtraBandwidth ();
			} 
			else
			{
				LogPrint(eLogInfo, "Daemon: bandwidth set to 'low'");
				i2p::context.SetLowBandwidth ();
			}

			std::string family; i2p::config::GetOption("family", family);
			i2p::context.SetFamily (family);
			if (family.length () > 0)
				LogPrint(eLogInfo, "Daemon: family set to ", family);	
			
			return true;
		}
			
		bool Daemon_Singleton::start()
		{
			std::string logs     = ""; i2p::config::GetOption("log",      logs);
			std::string logfile  = ""; i2p::config::GetOption("logfile",  logfile);
			std::string loglevel = ""; i2p::config::GetOption("loglevel", loglevel);

			if (isDaemon && (logs == "" || logs == "stdout"))
				logs = "file";

			if (logs == "file")
			{
				if (logfile == "")
				{
					// use autodetect of logfile
					logfile = IsService () ? "/var/log" : i2p::util::filesystem::GetDataDir().string();
#ifndef _WIN32
					logfile.append("/i2pd.log");
#else
					logfile.append("\\i2pd.log");
#endif
				}
				StartLog (logfile);
			} else {
				// use stdout
				StartLog ("");
			}
			SetLogLevel(loglevel);
			
			bool http; i2p::config::GetOption("http.enabled", http);
			if (http) {
				std::string httpAddr; i2p::config::GetOption("http.address", httpAddr);
				uint16_t    httpPort; i2p::config::GetOption("http.port",    httpPort);
				LogPrint(eLogInfo, "Daemon: starting HTTP Server at ", httpAddr, ":", httpPort);
				d.httpServer = std::unique_ptr<i2p::util::HTTPServer>(new i2p::util::HTTPServer(httpAddr, httpPort));
				d.httpServer->Start();
			}

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
			bool i2pcontrol; i2p::config::GetOption("i2pcontrol.enabled", i2pcontrol);
			if (i2pcontrol) {
				std::string i2pcpAddr; i2p::config::GetOption("i2pcontrol.address", i2pcpAddr);
				uint16_t    i2pcpPort; i2p::config::GetOption("i2pcontrol.port",    i2pcpPort);
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
			if (d.httpServer) {
				LogPrint(eLogInfo, "Daemon: stopping HTTP Server");
				d.httpServer->Stop();
				d.httpServer = nullptr;
			}
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
