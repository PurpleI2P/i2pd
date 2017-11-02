#include <thread>
#include <memory>

#include "Daemon.h"

#include "Config.h"
#include "Log.h"
#include "FS.h"
#include "Base.h"
#include "version.h"
#include "Transports.h"
#include "NTCPSession.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "HTTP.h"
#include "NetDb.hpp"
#include "Garlic.h"
#include "Streaming.h"
#include "Destination.h"
#include "HTTPServer.h"
#include "I2PControl.h"
#include "ClientContext.h"
#include "Crypto.h"
#include "UPnP.h"
#include "util.h"

#include "Event.h"
#include "Websocket.h"

namespace i2p
{
	namespace util
	{
		class Daemon_Singleton::Daemon_Singleton_Private
		{
		public:
			Daemon_Singleton_Private() {};
			~Daemon_Singleton_Private() {};

			std::unique_ptr<i2p::http::HTTPServer> httpServer;
			std::unique_ptr<i2p::client::I2PControlService> m_I2PControlService;
			std::unique_ptr<i2p::transport::UPnP> UPnP;
#ifdef WITH_EVENTS
			std::unique_ptr<i2p::event::WebsocketServer> m_WebsocketServer;
#endif
		};

		Daemon_Singleton::Daemon_Singleton() : isDaemon(false), running(true), d(*new Daemon_Singleton_Private()) {}
		Daemon_Singleton::~Daemon_Singleton() {
			delete &d;
		}

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

			std::string config;  i2p::config::GetOption("conf",    config);
			std::string datadir; i2p::config::GetOption("datadir", datadir);
			i2p::fs::DetectDataDir(datadir, IsService());
			i2p::fs::Init();

			datadir = i2p::fs::GetDataDir();
			// TODO: drop old name detection in v2.8.0
			if (config == "")
			{
				config = i2p::fs::DataDirPath("i2p.conf");
				if (i2p::fs::Exists (config)) {
					LogPrint(eLogWarning, "Daemon: please rename i2p.conf to i2pd.conf here: ", config);
				} else {
					config = i2p::fs::DataDirPath("i2pd.conf");
					if (!i2p::fs::Exists (config)) {
						// use i2pd.conf only if exists
						config = ""; /* reset */
					}
				}
			}

			i2p::config::ParseConfig(config);
			i2p::config::Finalize();

			i2p::config::GetOption("daemon", isDaemon);

			std::string logs     = ""; i2p::config::GetOption("log",      logs);
			std::string logfile  = ""; i2p::config::GetOption("logfile",  logfile);
			std::string loglevel = ""; i2p::config::GetOption("loglevel", loglevel);
			bool logclftime;           i2p::config::GetOption("logclftime", logclftime);

			/* setup logging */
			if (logclftime)
				i2p::log::Logger().SetTimeFormat ("[%d/%b/%Y:%H:%M:%S %z]");

			if (isDaemon && (logs == "" || logs == "stdout"))
				logs = "file";

			i2p::log::Logger().SetLogLevel(loglevel);
			if (logs == "file") {
				if (logfile == "")
					logfile = i2p::fs::DataDirPath("i2pd.log");
				LogPrint(eLogInfo, "Log: will send messages to ", logfile);
				i2p::log::Logger().SendTo (logfile);
#ifndef _WIN32
			} else if (logs == "syslog") {
				LogPrint(eLogInfo, "Log: will send messages to syslog");
				i2p::log::Logger().SendTo("i2pd", LOG_DAEMON);
#endif
			} else {
				// use stdout -- default
			}

			LogPrint(eLogInfo,	"i2pd v", VERSION, " starting");
#ifdef AESNI
			LogPrint(eLogInfo,	"AESNI enabled");
#endif
#if defined(__AVX__)
			LogPrint(eLogInfo,	"AVX enabled"); 
#endif
			LogPrint(eLogDebug, "FS: main config file: ", config);
			LogPrint(eLogDebug, "FS: data directory: ", datadir);

			bool precomputation; i2p::config::GetOption("precomputation.elgamal", precomputation);
			i2p::crypto::InitCrypto (precomputation);

			int netID; i2p::config::GetOption("netid", netID);
			i2p::context.SetNetID (netID);
			i2p::context.Init ();

			bool ipv6;		i2p::config::GetOption("ipv6", ipv6);
			bool ipv4;		i2p::config::GetOption("ipv4", ipv4);
#ifdef MESHNET
			// manual override for meshnet
			ipv4 = false;
			ipv6 = true;
#endif
			uint16_t port; i2p::config::GetOption("port", port);
			if (!i2p::config::IsDefault("port"))
			{
				LogPrint(eLogInfo, "Daemon: accepting incoming connections at port ", port);
				i2p::context.UpdatePort (port);
			}
			i2p::context.SetSupportsV6		 (ipv6);
			i2p::context.SetSupportsV4		 (ipv4);

			bool transit; i2p::config::GetOption("notransit", transit);
			i2p::context.SetAcceptsTunnels (!transit);
			uint16_t transitTunnels; i2p::config::GetOption("limits.transittunnels", transitTunnels);
			SetMaxNumTransitTunnels (transitTunnels);

			bool isFloodfill; i2p::config::GetOption("floodfill", isFloodfill);
			if (isFloodfill) {
				LogPrint(eLogInfo, "Daemon: router will be floodfill");
				i2p::context.SetFloodfill (true);
			}	else {
				i2p::context.SetFloodfill (false);
			}

			/* this section also honors 'floodfill' flag, if set above */
			std::string bandwidth; i2p::config::GetOption("bandwidth", bandwidth);
			if (bandwidth.length () > 0)
			{
				if (bandwidth[0] >= 'K' && bandwidth[0] <= 'X')
				{
					i2p::context.SetBandwidth (bandwidth[0]);
					LogPrint(eLogInfo, "Daemon: bandwidth set to ", i2p::context.GetBandwidthLimit (), "KBps");
				}
				else
				{
					auto value = std::atoi(bandwidth.c_str());
					if (value > 0)
					{
						i2p::context.SetBandwidth (value);
						LogPrint(eLogInfo, "Daemon: bandwidth set to ", i2p::context.GetBandwidthLimit (), " KBps");
					}
					else
					{
						LogPrint(eLogInfo, "Daemon: unexpected bandwidth ", bandwidth, ". Set to 'low'");
						i2p::context.SetBandwidth (i2p::data::CAPS_FLAG_LOW_BANDWIDTH2);
					}
				}
			}
			else if (isFloodfill)
			{
				LogPrint(eLogInfo, "Daemon: floodfill bandwidth set to 'extra'");
				i2p::context.SetBandwidth (i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH1);
			}
			else
			{
				LogPrint(eLogInfo, "Daemon: bandwidth set to 'low'");
				i2p::context.SetBandwidth (i2p::data::CAPS_FLAG_LOW_BANDWIDTH2);
			}

			int shareRatio; i2p::config::GetOption("share", shareRatio);
			i2p::context.SetShareRatio (shareRatio);

			std::string family; i2p::config::GetOption("family", family);
			i2p::context.SetFamily (family);
			if (family.length () > 0)
				LogPrint(eLogInfo, "Daemon: family set to ", family);

      bool trust; i2p::config::GetOption("trust.enabled", trust);
      if (trust)
      {
        LogPrint(eLogInfo, "Daemon: explicit trust enabled");
        std::string fam; i2p::config::GetOption("trust.family", fam);
				std::string routers; i2p::config::GetOption("trust.routers", routers);
				bool restricted = false;
        if (fam.length() > 0)
        {
					std::set<std::string> fams;
					size_t pos = 0, comma;
					do
					{
						comma = fam.find (',', pos);
						fams.insert (fam.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));
						pos = comma + 1;
					}
					while (comma != std::string::npos);
					i2p::transport::transports.RestrictRoutesToFamilies(fams);
					restricted  = fams.size() > 0;
        }
				if (routers.length() > 0) {
					std::set<i2p::data::IdentHash> idents;
					size_t pos = 0, comma;
					do
					{
						comma = routers.find (',', pos);
						i2p::data::IdentHash ident;
						ident.FromBase64 (routers.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));
						idents.insert (ident);
						pos = comma + 1;
					}
					while (comma != std::string::npos);
					LogPrint(eLogInfo, "Daemon: setting restricted routes to use ", idents.size(), " trusted routesrs");
					i2p::transport::transports.RestrictRoutesToRouters(idents);
					restricted = idents.size() > 0;
				}
				if(!restricted)
					LogPrint(eLogError, "Daemon: no trusted routers of families specififed");
      }
      bool hidden; i2p::config::GetOption("trust.hidden", hidden);
      if (hidden)
      {
        LogPrint(eLogInfo, "Daemon: using hidden mode");
        i2p::data::netdb.SetHidden(true);
      }
      return true;
		}

		bool Daemon_Singleton::start()
		{
			i2p::log::Logger().Start();
			LogPrint(eLogInfo, "Daemon: starting NetDB");
			i2p::data::netdb.Start();

			bool upnp; i2p::config::GetOption("upnp.enabled", upnp);
			if (upnp) {
				d.UPnP = std::unique_ptr<i2p::transport::UPnP>(new i2p::transport::UPnP);
				d.UPnP->Start ();
			}

			bool ntcp; i2p::config::GetOption("ntcp", ntcp);
			bool ssu; i2p::config::GetOption("ssu", ssu);
			LogPrint(eLogInfo, "Daemon: starting Transports");
			if(!ssu) LogPrint(eLogInfo, "Daemon: ssu disabled");
			if(!ntcp) LogPrint(eLogInfo, "Daemon: ntcp disabled");

			i2p::transport::transports.Start(ntcp, ssu);
			if (i2p::transport::transports.IsBoundNTCP() || i2p::transport::transports.IsBoundSSU()) {
				LogPrint(eLogInfo, "Daemon: Transports started");
			} else {
				LogPrint(eLogError, "Daemon: failed to start Transports");
				/** shut down netdb right away */
				i2p::transport::transports.Stop();
				i2p::data::netdb.Stop();
				return false;
			}

			bool http; i2p::config::GetOption("http.enabled", http);
			if (http) {
				std::string httpAddr; i2p::config::GetOption("http.address", httpAddr);
				uint16_t		httpPort; i2p::config::GetOption("http.port",		 httpPort);
				LogPrint(eLogInfo, "Daemon: starting HTTP Server at ", httpAddr, ":", httpPort);
				d.httpServer = std::unique_ptr<i2p::http::HTTPServer>(new i2p::http::HTTPServer(httpAddr, httpPort));
				d.httpServer->Start();
			}


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
#ifdef WITH_EVENTS

			bool websocket; i2p::config::GetOption("websockets.enabled", websocket);
			if(websocket) {
				std::string websocketAddr; i2p::config::GetOption("websockets.address", websocketAddr);
				uint16_t		websocketPort; i2p::config::GetOption("websockets.port",		websocketPort);
				LogPrint(eLogInfo, "Daemon: starting Websocket server at ", websocketAddr, ":", websocketPort);
				d.m_WebsocketServer = std::unique_ptr<i2p::event::WebsocketServer>(new i2p::event::WebsocketServer (websocketAddr, websocketPort));
				d.m_WebsocketServer->Start();
				i2p::event::core.SetListener(d.m_WebsocketServer->ToListener());
			}
#endif
			return true;
		}

		bool Daemon_Singleton::stop()
		{
#ifdef WITH_EVENTS
			i2p::event::core.SetListener(nullptr);
#endif
			LogPrint(eLogInfo, "Daemon: shutting down");
			LogPrint(eLogInfo, "Daemon: stopping Client");
			i2p::client::context.Stop();
			LogPrint(eLogInfo, "Daemon: stopping Tunnels");
			i2p::tunnel::tunnels.Stop();

			if (d.UPnP) {
				d.UPnP->Stop ();
				d.UPnP = nullptr;
			}

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
#ifdef WITH_EVENTS
			if (d.m_WebsocketServer) {
				LogPrint(eLogInfo, "Daemon: stopping Websocket server");
				d.m_WebsocketServer->Stop();
				d.m_WebsocketServer = nullptr;
			}
#endif
			i2p::crypto::TerminateCrypto ();
			i2p::log::Logger().Stop();

			return true;
		}
}
}
