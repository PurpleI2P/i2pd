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
#include "DotNetControl.h"
#include "ClientContext.h"
#include "Crypto.h"
#include "UPnP.h"
#include "Timestamp.h"
#include "util.h"

#include "Event.h"
#include "Websocket.h"

namespace dotnet
{
	namespace util
	{
		class Daemon_Singleton::Daemon_Singleton_Private
		{
		public:
			Daemon_Singleton_Private() {};
			~Daemon_Singleton_Private() {};

			std::unique_ptr<dotnet::http::HTTPServer> httpServer;
			std::unique_ptr<dotnet::client::DotNetControlService> m_DotNetControlService;
			std::unique_ptr<dotnet::transport::UPnP> UPnP;
			std::unique_ptr<dotnet::util::NTPTimeSync> m_NTPSync;
#ifdef WITH_EVENTS
			std::unique_ptr<dotnet::event::WebsocketServer> m_WebsocketServer;
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
			dotnet::config::GetOption("service", service);
#endif
			return service;
		}

        bool Daemon_Singleton::init(int argc, char* argv[]) {
            return init(argc, argv, nullptr);
        }

        bool Daemon_Singleton::init(int argc, char* argv[], std::shared_ptr<std::ostream> logstream)
        {
			dotnet::config::Init();
			dotnet::config::ParseCmdline(argc, argv);

			std::string config;  dotnet::config::GetOption("conf",    config);
			std::string datadir; dotnet::config::GetOption("datadir", datadir);
			dotnet::fs::DetectDataDir(datadir, IsService());
			dotnet::fs::Init();

			datadir = dotnet::fs::GetDataDir();
			// TODO: drop old name detection in v2.8.0
			if (config == "")
			{
				config = dotnet::fs::DataDirPath("dotnet.conf");
				if (dotnet::fs::Exists (config)) {
					LogPrint(eLogWarning, "Daemon: please rename dotnet.conf to dotnet.conf here: ", config);
				} else {
					config = dotnet::fs::DataDirPath("dotnet.conf");
					if (!dotnet::fs::Exists (config)) {
						// use dotnet.conf only if exists
						config = ""; /* reset */
					}
				}
			}

			dotnet::config::ParseConfig(config);
			dotnet::config::Finalize();

			dotnet::config::GetOption("daemon", isDaemon);

			std::string logs     = ""; dotnet::config::GetOption("log",      logs);
			std::string logfile  = ""; dotnet::config::GetOption("logfile",  logfile);
			std::string loglevel = ""; dotnet::config::GetOption("loglevel", loglevel);
			bool logclftime;           dotnet::config::GetOption("logclftime", logclftime);

			/* setup logging */
			if (logclftime)
				dotnet::log::Logger().SetTimeFormat ("[%d/%b/%Y:%H:%M:%S %z]");

			if (isDaemon && (logs == "" || logs == "stdout"))
				logs = "file";

			dotnet::log::Logger().SetLogLevel(loglevel);
            if (logstream) {
                LogPrint(eLogInfo, "Log: will send messages to std::ostream");
                dotnet::log::Logger().SendTo (logstream);
            } else if (logs == "file") {
				if (logfile == "")
					logfile = dotnet::fs::DataDirPath("dotnet.log");
				LogPrint(eLogInfo, "Log: will send messages to ", logfile);
				dotnet::log::Logger().SendTo (logfile);
#ifndef _WIN32
			} else if (logs == "syslog") {
				LogPrint(eLogInfo, "Log: will send messages to syslog");
				dotnet::log::Logger().SendTo("dotnet", LOG_DAEMON);
#endif
			} else {
				// use stdout -- default
			}

			LogPrint(eLogInfo,	"dotnet v", VERSION, " starting");
			LogPrint(eLogDebug, "FS: main config file: ", config);
			LogPrint(eLogDebug, "FS: data directory: ", datadir);

			bool precomputation; dotnet::config::GetOption("precomputation.elgamal", precomputation);
			dotnet::crypto::InitCrypto (precomputation);

			int netID; dotnet::config::GetOption("netid", netID);
			dotnet::context.SetNetID (netID);
			dotnet::context.Init ();

			bool ipv6;		dotnet::config::GetOption("ipv6", ipv6);
			bool ipv4;		dotnet::config::GetOption("ipv4", ipv4);
#ifdef MESHNET
			// manual override for meshnet
			ipv4 = false;
			ipv6 = true;
#endif
			uint16_t port; dotnet::config::GetOption("port", port);
			if (!dotnet::config::IsDefault("port"))
			{
				LogPrint(eLogInfo, "Daemon: accepting incoming connections at port ", port);
				dotnet::context.UpdatePort (port);
			}
			dotnet::context.SetSupportsV6		 (ipv6);
			dotnet::context.SetSupportsV4		 (ipv4);

			bool ntcp;   dotnet::config::GetOption("ntcp", ntcp);
			dotnet::context.PublishNTCPAddress (ntcp, !ipv6);  
			bool ntcp2; dotnet::config::GetOption("ntcp2.enabled", ntcp2);
			if (ntcp2)
			{
				bool published; dotnet::config::GetOption("ntcp2.published", published);
				if (published)
				{
					uint16_t ntcp2port; dotnet::config::GetOption("ntcp2.port", ntcp2port);
					if (!ntcp && !ntcp2port) ntcp2port = port; // use standard port
					dotnet::context.PublishNTCP2Address (ntcp2port, true); // publish
					if (ipv6)
					{
						std::string ipv6Addr; dotnet::config::GetOption("ntcp2.addressv6", ipv6Addr);
						auto addr = boost::asio::ip::address_v6::from_string (ipv6Addr);
						if (!addr.is_unspecified () && addr != boost::asio::ip::address_v6::any ())
							dotnet::context.UpdateNTCP2V6Address (addr); // set ipv6 address if configured
					}
				}
				else
					dotnet::context.PublishNTCP2Address (port, false); // unpublish
			}

			bool transit; dotnet::config::GetOption("notransit", transit);
			dotnet::context.SetAcceptsTunnels (!transit);
			uint16_t transitTunnels; dotnet::config::GetOption("limits.transittunnels", transitTunnels);
			SetMaxNumTransitTunnels (transitTunnels);

			bool isFloodfill; dotnet::config::GetOption("floodfill", isFloodfill);
			if (isFloodfill) {
				LogPrint(eLogInfo, "Daemon: router will be floodfill");
				dotnet::context.SetFloodfill (true);
			}	else {
				dotnet::context.SetFloodfill (false);
			}

			/* this section also honors 'floodfill' flag, if set above */
			std::string bandwidth; dotnet::config::GetOption("bandwidth", bandwidth);
			if (bandwidth.length () > 0)
			{
				if (bandwidth[0] >= 'K' && bandwidth[0] <= 'X')
				{
					dotnet::context.SetBandwidth (bandwidth[0]);
					LogPrint(eLogInfo, "Daemon: bandwidth set to ", dotnet::context.GetBandwidthLimit (), "KBps");
				}
				else
				{
					auto value = std::atoi(bandwidth.c_str());
					if (value > 0)
					{
						dotnet::context.SetBandwidth (value);
						LogPrint(eLogInfo, "Daemon: bandwidth set to ", dotnet::context.GetBandwidthLimit (), " KBps");
					}
					else
					{
						LogPrint(eLogInfo, "Daemon: unexpected bandwidth ", bandwidth, ". Set to 'low'");
						dotnet::context.SetBandwidth (dotnet::data::CAPS_FLAG_LOW_BANDWIDTH2);
					}
				}
			}
			else if (isFloodfill)
			{
				LogPrint(eLogInfo, "Daemon: floodfill bandwidth set to 'extra'");
				dotnet::context.SetBandwidth (dotnet::data::CAPS_FLAG_EXTRA_BANDWIDTH1);
			}
			else
			{
				LogPrint(eLogInfo, "Daemon: bandwidth set to 'low'");
				dotnet::context.SetBandwidth (dotnet::data::CAPS_FLAG_LOW_BANDWIDTH2);
			}

			int shareRatio; dotnet::config::GetOption("share", shareRatio);
			dotnet::context.SetShareRatio (shareRatio);

			std::string family; dotnet::config::GetOption("family", family);
			dotnet::context.SetFamily (family);
			if (family.length () > 0)
				LogPrint(eLogInfo, "Daemon: family set to ", family);

      bool trust; dotnet::config::GetOption("trust.enabled", trust);
      if (trust)
      {
        LogPrint(eLogInfo, "Daemon: explicit trust enabled");
        std::string fam; dotnet::config::GetOption("trust.family", fam);
				std::string routers; dotnet::config::GetOption("trust.routers", routers);
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
					dotnet::transport::transports.RestrictRoutesToFamilies(fams);
					restricted  = fams.size() > 0;
        }
				if (routers.length() > 0) {
					std::set<dotnet::data::IdentHash> idents;
					size_t pos = 0, comma;
					do
					{
						comma = routers.find (',', pos);
						dotnet::data::IdentHash ident;
						ident.FromBase64 (routers.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));
						idents.insert (ident);
						pos = comma + 1;
					}
					while (comma != std::string::npos);
					LogPrint(eLogInfo, "Daemon: setting restricted routes to use ", idents.size(), " trusted routers");
					dotnet::transport::transports.RestrictRoutesToRouters(idents);
					restricted = idents.size() > 0;
				}
				if(!restricted)
					LogPrint(eLogError, "Daemon: no trusted routers of families specififed");
      }
      bool hidden; dotnet::config::GetOption("trust.hidden", hidden);
      if (hidden)
      {
        LogPrint(eLogInfo, "Daemon: using hidden mode");
        dotnet::data::netdb.SetHidden(true);
      }
      return true;
		}

		bool Daemon_Singleton::start()
		{
			dotnet::log::Logger().Start();
			LogPrint(eLogInfo, "Daemon: starting NetDB");
			dotnet::data::netdb.Start();

			bool upnp; dotnet::config::GetOption("upnp.enabled", upnp);
			if (upnp) {
				d.UPnP = std::unique_ptr<dotnet::transport::UPnP>(new dotnet::transport::UPnP);
				d.UPnP->Start ();
			}

			bool nettime; dotnet::config::GetOption("nettime.enabled", nettime);
			if (nettime)
			{
				d.m_NTPSync = std::unique_ptr<dotnet::util::NTPTimeSync>(new dotnet::util::NTPTimeSync);
				d.m_NTPSync->Start ();
			}

			bool ntcp; dotnet::config::GetOption("ntcp", ntcp);
			bool ssu; dotnet::config::GetOption("ssu", ssu);
			LogPrint(eLogInfo, "Daemon: starting Transports");
			if(!ssu) LogPrint(eLogInfo, "Daemon: ssu disabled");
			if(!ntcp) LogPrint(eLogInfo, "Daemon: ntcp disabled");

			dotnet::transport::transports.Start(ntcp, ssu);
			if (dotnet::transport::transports.IsBoundNTCP() || dotnet::transport::transports.IsBoundSSU() || dotnet::transport::transports.IsBoundNTCP2()) 
				LogPrint(eLogInfo, "Daemon: Transports started");
			else 
			{
				LogPrint(eLogError, "Daemon: failed to start Transports");
				/** shut down netdb right away */
				dotnet::transport::transports.Stop();
				dotnet::data::netdb.Stop();
				return false;
			}

			bool http; dotnet::config::GetOption("http.enabled", http);
			if (http) {
				std::string httpAddr; dotnet::config::GetOption("http.address", httpAddr);
				uint16_t		httpPort; dotnet::config::GetOption("http.port",		 httpPort);
				LogPrint(eLogInfo, "Daemon: starting HTTP Server at ", httpAddr, ":", httpPort);
				d.httpServer = std::unique_ptr<dotnet::http::HTTPServer>(new dotnet::http::HTTPServer(httpAddr, httpPort));
				d.httpServer->Start();
			}


			LogPrint(eLogInfo, "Daemon: starting Tunnels");
			dotnet::tunnel::tunnels.Start();

			LogPrint(eLogInfo, "Daemon: starting Client");
			dotnet::client::context.Start ();

			// DOTNET Control Protocol
			bool dotnetcontrol; dotnet::config::GetOption("dotnetcontrol.enabled", dotnetcontrol);
			if (dotnetcontrol) {
				std::string dotnetcpAddr; dotnet::config::GetOption("dotnetcontrol.address", dotnetcpAddr);
				uint16_t    dotnetcpPort; dotnet::config::GetOption("dotnetcontrol.port",    dotnetcpPort);
				LogPrint(eLogInfo, "Daemon: starting DotNetControl at ", dotnetcpAddr, ":", dotnetcpPort);
				d.m_DotNetControlService = std::unique_ptr<dotnet::client::DotNetControlService>(new dotnet::client::DotNetControlService (dotnetcpAddr, dotnetcpPort));
				d.m_DotNetControlService->Start ();
			}
#ifdef WITH_EVENTS

			bool websocket; dotnet::config::GetOption("websockets.enabled", websocket);
			if(websocket) {
				std::string websocketAddr; dotnet::config::GetOption("websockets.address", websocketAddr);
				uint16_t		websocketPort; dotnet::config::GetOption("websockets.port",		websocketPort);
				LogPrint(eLogInfo, "Daemon: starting Websocket server at ", websocketAddr, ":", websocketPort);
				d.m_WebsocketServer = std::unique_ptr<dotnet::event::WebsocketServer>(new dotnet::event::WebsocketServer (websocketAddr, websocketPort));
				d.m_WebsocketServer->Start();
				dotnet::event::core.SetListener(d.m_WebsocketServer->ToListener());
			}
#endif
			return true;
		}

		bool Daemon_Singleton::stop()
		{
#ifdef WITH_EVENTS
			dotnet::event::core.SetListener(nullptr);
#endif
			LogPrint(eLogInfo, "Daemon: shutting down");
			LogPrint(eLogInfo, "Daemon: stopping Client");
			dotnet::client::context.Stop();
			LogPrint(eLogInfo, "Daemon: stopping Tunnels");
			dotnet::tunnel::tunnels.Stop();

			if (d.UPnP) 
			{
				d.UPnP->Stop ();
				d.UPnP = nullptr;
			}

			if (d.m_NTPSync)
			{
				d.m_NTPSync->Stop ();
				d.m_NTPSync = nullptr;
			}

			LogPrint(eLogInfo, "Daemon: stopping Transports");
			dotnet::transport::transports.Stop();
			LogPrint(eLogInfo, "Daemon: stopping NetDB");
			dotnet::data::netdb.Stop();
			if (d.httpServer) {
				LogPrint(eLogInfo, "Daemon: stopping HTTP Server");
				d.httpServer->Stop();
				d.httpServer = nullptr;
			}
			if (d.m_DotNetControlService)
			{
				LogPrint(eLogInfo, "Daemon: stopping DotNetControl");
				d.m_DotNetControlService->Stop ();
				d.m_DotNetControlService = nullptr;
			}
#ifdef WITH_EVENTS
			if (d.m_WebsocketServer) {
				LogPrint(eLogInfo, "Daemon: stopping Websocket server");
				d.m_WebsocketServer->Stop();
				d.m_WebsocketServer = nullptr;
			}
#endif
			dotnet::crypto::TerminateCrypto ();
			dotnet::log::Logger().Stop();

			return true;
		}
}
}
