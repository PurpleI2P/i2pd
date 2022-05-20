/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <thread>
#include <memory>

#include "Daemon.h"

#include "Config.h"
#include "Log.h"
#include "FS.h"
#include "Base.h"
#include "version.h"
#include "Transports.h"
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
#include "Timestamp.h"
#include "util.h"
#include "I18N.h"

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
		std::unique_ptr<i2p::util::NTPTimeSync> m_NTPSync;
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

	void Daemon_Singleton::setDataDir(std::string path)
	{
		if (path != "")
			DaemonDataDir = path;
	}

	bool Daemon_Singleton::init(int argc, char* argv[]) {
		return init(argc, argv, nullptr);
	}

	bool Daemon_Singleton::init(int argc, char* argv[], std::shared_ptr<std::ostream> logstream)
	{
		i2p::config::Init();
		i2p::config::ParseCmdline(argc, argv);

		std::string config; i2p::config::GetOption("conf", config);
		std::string datadir;
		if(DaemonDataDir != "") {
			datadir = DaemonDataDir;
		} else {
			i2p::config::GetOption("datadir", datadir);
		}

		i2p::fs::DetectDataDir(datadir, IsService());
		i2p::fs::Init();

		datadir = i2p::fs::GetDataDir();

		if (config == "")
		{
			config = i2p::fs::DataDirPath("i2pd.conf");
			if (!i2p::fs::Exists (config)) {
				// use i2pd.conf only if exists
				config = ""; /* reset */
			}
		}

		i2p::config::ParseConfig(config);
		i2p::config::Finalize();

		i2p::config::GetOption("daemon", isDaemon);

		std::string certsdir; i2p::config::GetOption("certsdir", certsdir);
		i2p::fs::SetCertsDir(certsdir);

		certsdir = i2p::fs::GetCertsDir();

		std::string logs     = ""; i2p::config::GetOption("log",        logs);
		std::string logfile  = ""; i2p::config::GetOption("logfile",    logfile);
		std::string loglevel = ""; i2p::config::GetOption("loglevel",   loglevel);
		bool logclftime;           i2p::config::GetOption("logclftime", logclftime);

		/* setup logging */
		if (logclftime)
			i2p::log::Logger().SetTimeFormat ("[%d/%b/%Y:%H:%M:%S %z]");

#ifdef WIN32_APP
		// Win32 app with GUI supports only logging to file
		logs = "file";
#else
		if (isDaemon && (logs == "" || logs == "stdout"))
			logs = "file";
#endif

		i2p::log::Logger().SetLogLevel(loglevel);
		if (logstream) {
			LogPrint(eLogInfo, "Log: Sending messages to std::ostream");
			i2p::log::Logger().SendTo (logstream);
		} else if (logs == "file") {
			if (logfile == "")
				logfile = i2p::fs::DataDirPath("i2pd.log");
			LogPrint(eLogInfo, "Log: Sending messages to ", logfile);
			i2p::log::Logger().SendTo (logfile);
#ifndef _WIN32
		} else if (logs == "syslog") {
			LogPrint(eLogInfo, "Log: Sending messages to syslog");
			i2p::log::Logger().SendTo("i2pd", LOG_DAEMON);
#endif
		} else {
			// use stdout -- default
		}

		LogPrint(eLogNone,  "i2pd v", VERSION, " (", I2P_VERSION, ") starting...");
		LogPrint(eLogDebug, "FS: Main config file: ", config);
		LogPrint(eLogDebug, "FS: Data directory: ", datadir);
		LogPrint(eLogDebug, "FS: Certificates directory: ", certsdir);

		bool precomputation; i2p::config::GetOption("precomputation.elgamal", precomputation);
		bool aesni; i2p::config::GetOption("cpuext.aesni", aesni);
		bool avx; i2p::config::GetOption("cpuext.avx", avx);
		bool forceCpuExt; i2p::config::GetOption("cpuext.force", forceCpuExt);
		i2p::crypto::InitCrypto (precomputation, aesni, avx, forceCpuExt);

		int netID; i2p::config::GetOption("netid", netID);
		i2p::context.SetNetID (netID);
		i2p::context.Init ();

		bool ipv6; i2p::config::GetOption("ipv6", ipv6);
		bool ipv4; i2p::config::GetOption("ipv4", ipv4);

		// ifname -> address
		std::string ifname; i2p::config::GetOption("ifname", ifname);
		if (ipv4 && i2p::config::IsDefault ("address4"))
		{
			std::string ifname4; i2p::config::GetOption("ifname4", ifname4);
			if (!ifname4.empty ())
				i2p::config::SetOption ("address4", i2p::util::net::GetInterfaceAddress(ifname4, false).to_string ()); // v4
			else if (!ifname.empty ())
				i2p::config::SetOption ("address4", i2p::util::net::GetInterfaceAddress(ifname, false).to_string ()); // v4
		}
		if (ipv6 && i2p::config::IsDefault ("address6"))
		{
			std::string ifname6; i2p::config::GetOption("ifname6", ifname6);
			if (!ifname6.empty ())
				i2p::config::SetOption ("address6", i2p::util::net::GetInterfaceAddress(ifname6, true).to_string ()); // v6
			else if (!ifname.empty ())
				i2p::config::SetOption ("address6", i2p::util::net::GetInterfaceAddress(ifname, true).to_string ()); // v6
		}

		bool ygg; i2p::config::GetOption("meshnets.yggdrasil", ygg);
		boost::asio::ip::address_v6 yggaddr;
		if (ygg)
		{
			std::string yggaddress; i2p::config::GetOption ("meshnets.yggaddress", yggaddress);
			if (!yggaddress.empty ())
			{
				yggaddr = boost::asio::ip::address_v6::from_string (yggaddress);
				if (yggaddr.is_unspecified () || !i2p::util::net::IsYggdrasilAddress (yggaddr) ||
					!i2p::util::net::IsLocalAddress (yggaddr))
				{
					LogPrint(eLogWarning, "Daemon: Can't find Yggdrasil address ", yggaddress);
					ygg = false;
				}
			}
			else
			{
				yggaddr = i2p::util::net::GetYggdrasilAddress ();
				if (yggaddr.is_unspecified ())
				{
					LogPrint(eLogWarning, "Daemon: Yggdrasil is not running. Disabled");
					ygg = false;
				}
			}
		}

		uint16_t port; i2p::config::GetOption("port", port);
		if (!i2p::config::IsDefault("port"))
		{
			LogPrint(eLogInfo, "Daemon: Accepting incoming connections at port ", port);
			i2p::context.UpdatePort (port);
		}
		i2p::context.SetSupportsV6 (ipv6);
		i2p::context.SetSupportsV4 (ipv4);
		i2p::context.SetSupportsMesh (ygg, yggaddr);

		i2p::context.RemoveNTCPAddress (!ipv6); // TODO: remove later
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
		{
			bool published; i2p::config::GetOption("ntcp2.published", published);
			if (published)
			{
				std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
				if (!ntcp2proxy.empty ()) published = false;
			}
			if (published)
			{
				uint16_t ntcp2port; i2p::config::GetOption("ntcp2.port", ntcp2port);
				if (!ntcp2port) ntcp2port = port; // use standard port
				i2p::context.PublishNTCP2Address (ntcp2port, true, ipv4, ipv6, false); // publish
				if (ipv6)
				{
					std::string ipv6Addr; i2p::config::GetOption("ntcp2.addressv6", ipv6Addr);
					auto addr = boost::asio::ip::address_v6::from_string (ipv6Addr);
					if (!addr.is_unspecified () && addr != boost::asio::ip::address_v6::any ())
						i2p::context.UpdateNTCP2V6Address (addr); // set ipv6 address if configured
				}
			}
			else
				i2p::context.PublishNTCP2Address (port, false, ipv4, ipv6, false); // unpublish
		}
		if (ygg)
		{
			i2p::context.PublishNTCP2Address (port, true, false, false, true);
			i2p::context.UpdateNTCP2V6Address (yggaddr);
			if (!ipv4 && !ipv6)
				i2p::context.SetStatus (eRouterStatusMesh);
		}
		bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
		if (ssu2)
		{
			bool published; i2p::config::GetOption("ssu2.published", published);
			if (published)
			{
				uint16_t ssu2port; i2p::config::GetOption("ssu2.port", ssu2port);
				i2p::context.PublishSSU2Address (ssu2port, true, ipv4, ipv6); // publish
			}
			else
				i2p::context.PublishSSU2Address (0, false, ipv4, ipv6); // unpublish
		}

		bool transit; i2p::config::GetOption("notransit", transit);
		i2p::context.SetAcceptsTunnels (!transit);
		uint16_t transitTunnels; i2p::config::GetOption("limits.transittunnels", transitTunnels);
		SetMaxNumTransitTunnels (transitTunnels);

		bool isFloodfill; i2p::config::GetOption("floodfill", isFloodfill);
		if (isFloodfill) {
			LogPrint(eLogInfo, "Daemon: Router configured as floodfill");
			i2p::context.SetFloodfill (true);
		}
		else
		{
			i2p::context.SetFloodfill (false);
		}

		/* this section also honors 'floodfill' flag, if set above */
		std::string bandwidth; i2p::config::GetOption("bandwidth", bandwidth);
		if (bandwidth.length () > 0)
		{
			if (bandwidth[0] >= 'K' && bandwidth[0] <= 'X')
			{
				i2p::context.SetBandwidth (bandwidth[0]);
				LogPrint(eLogInfo, "Daemon: Bandwidth set to ", i2p::context.GetBandwidthLimit (), "KBps");
			}
			else
			{
				auto value = std::atoi(bandwidth.c_str());
				if (value > 0)
				{
					i2p::context.SetBandwidth (value);
					LogPrint(eLogInfo, "Daemon: Bandwidth set to ", i2p::context.GetBandwidthLimit (), " KBps");
				}
				else
				{
					LogPrint(eLogInfo, "Daemon: Unexpected bandwidth ", bandwidth, ". Set to 'low'");
					i2p::context.SetBandwidth (i2p::data::CAPS_FLAG_LOW_BANDWIDTH2);
				}
			}
		}
		else if (isFloodfill)
		{
			LogPrint(eLogInfo, "Daemon: Floodfill bandwidth set to 'extra'");
			i2p::context.SetBandwidth (i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH2);
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
			LogPrint(eLogInfo, "Daemon: Router family set to ", family);

		bool trust; i2p::config::GetOption("trust.enabled", trust);
		if (trust)
		{
			LogPrint(eLogInfo, "Daemon: Explicit trust enabled");
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
				restricted = fams.size() > 0;
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
				LogPrint(eLogInfo, "Daemon: Setting restricted routes to use ", idents.size(), " trusted routers");
				i2p::transport::transports.RestrictRoutesToRouters(idents);
				restricted = idents.size() > 0;
			}
			if(!restricted)
				LogPrint(eLogError, "Daemon: No trusted routers of families specified");
		}

		bool hidden; i2p::config::GetOption("trust.hidden", hidden);
		if (hidden)
		{
			LogPrint(eLogInfo, "Daemon: Hidden mode enabled");
			i2p::data::netdb.SetHidden(true);
		}

		std::string httpLang; i2p::config::GetOption("http.lang", httpLang);
		i2p::i18n::SetLanguage(httpLang);

		return true;
	}

	bool Daemon_Singleton::start()
	{
		i2p::log::Logger().Start();
		LogPrint(eLogInfo, "Daemon: Starting NetDB");
		i2p::data::netdb.Start();

		bool upnp; i2p::config::GetOption("upnp.enabled", upnp);
		if (upnp) {
			d.UPnP = std::unique_ptr<i2p::transport::UPnP>(new i2p::transport::UPnP);
			d.UPnP->Start ();
		}

		bool nettime; i2p::config::GetOption("nettime.enabled", nettime);
		if (nettime)
		{
			d.m_NTPSync = std::unique_ptr<i2p::util::NTPTimeSync>(new i2p::util::NTPTimeSync);
			d.m_NTPSync->Start ();
		}

		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
		bool ssu; i2p::config::GetOption("ssu", ssu);
		bool checkInReserved; i2p::config::GetOption("reservedrange", checkInReserved);
		LogPrint(eLogInfo, "Daemon: Starting Transports");
		if(!ssu) LogPrint(eLogInfo, "Daemon: SSU disabled");
		if(!ntcp2) LogPrint(eLogInfo, "Daemon: NTCP2 disabled");

		i2p::transport::transports.SetCheckReserved(checkInReserved);
		i2p::transport::transports.Start(ntcp2, ssu, ssu2);
		if (i2p::transport::transports.IsBoundSSU() || i2p::transport::transports.IsBoundNTCP2())
			LogPrint(eLogInfo, "Daemon: Transports started");
		else
		{
			LogPrint(eLogError, "Daemon: Failed to start Transports");
			/** shut down netdb right away */
			i2p::transport::transports.Stop();
			i2p::data::netdb.Stop();
			return false;
		}

		bool http; i2p::config::GetOption("http.enabled", http);
		if (http) {
			std::string httpAddr; i2p::config::GetOption("http.address", httpAddr);
			uint16_t    httpPort; i2p::config::GetOption("http.port", httpPort);
			LogPrint(eLogInfo, "Daemon: Starting Webconsole at ", httpAddr, ":", httpPort);
			try
			{
				d.httpServer = std::unique_ptr<i2p::http::HTTPServer>(new i2p::http::HTTPServer(httpAddr, httpPort));
				d.httpServer->Start();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Daemon: Failed to start Webconsole: ", ex.what ());
				ThrowFatal ("Unable to start webconsole at ", httpAddr, ":", httpPort, ": ", ex.what ());
			}
		}


		LogPrint(eLogInfo, "Daemon: Starting Tunnels");
		i2p::tunnel::tunnels.Start();

		LogPrint(eLogInfo, "Daemon: Starting Client");
		i2p::client::context.Start ();

		// I2P Control Protocol
		bool i2pcontrol; i2p::config::GetOption("i2pcontrol.enabled", i2pcontrol);
		if (i2pcontrol) {
			std::string i2pcpAddr; i2p::config::GetOption("i2pcontrol.address", i2pcpAddr);
			uint16_t    i2pcpPort; i2p::config::GetOption("i2pcontrol.port",    i2pcpPort);
			LogPrint(eLogInfo, "Daemon: Starting I2PControl at ", i2pcpAddr, ":", i2pcpPort);
			try
			{
				d.m_I2PControlService = std::unique_ptr<i2p::client::I2PControlService>(new i2p::client::I2PControlService (i2pcpAddr, i2pcpPort));
				d.m_I2PControlService->Start ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Daemon: Failed to start I2PControl: ", ex.what ());
				ThrowFatal ("Unable to start I2PControl service at ", i2pcpAddr, ":", i2pcpPort, ": ", ex.what ());
			}
		}
		return true;
	}

	bool Daemon_Singleton::stop()
	{
		LogPrint(eLogInfo, "Daemon: Shutting down");
		LogPrint(eLogInfo, "Daemon: Stopping Client");
		i2p::client::context.Stop();
		LogPrint(eLogInfo, "Daemon: Stopping Tunnels");
		i2p::tunnel::tunnels.Stop();

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

		LogPrint(eLogInfo, "Daemon: Stopping Transports");
		i2p::transport::transports.Stop();
		LogPrint(eLogInfo, "Daemon: Stopping NetDB");
		i2p::data::netdb.Stop();
		if (d.httpServer) {
			LogPrint(eLogInfo, "Daemon: Stopping HTTP Server");
			d.httpServer->Stop();
			d.httpServer = nullptr;
		}
		if (d.m_I2PControlService)
		{
			LogPrint(eLogInfo, "Daemon: Stopping I2PControl");
			d.m_I2PControlService->Stop ();
			d.m_I2PControlService = nullptr;
		}
		i2p::crypto::TerminateCrypto ();
		i2p::log::Logger().Stop();

		return true;
	}
}
}
