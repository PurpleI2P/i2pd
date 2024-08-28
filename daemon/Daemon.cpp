/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
		i2p::config::GetOption("service", service);
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
		bool forceCpuExt; i2p::config::GetOption("cpuext.force", forceCpuExt);
		bool ssu; i2p::config::GetOption("ssu", ssu);
		if (!ssu && i2p::config::IsDefault ("precomputation.elgamal"))
			precomputation = false; // we don't elgamal table if no ssu, unless it's specified explicitly
		i2p::crypto::InitCrypto (precomputation, aesni, forceCpuExt);

		i2p::transport::InitAddressFromIface (); // get address4/6 from interfaces

		int netID; i2p::config::GetOption("netid", netID);
		i2p::context.SetNetID (netID);

		bool checkReserved; i2p::config::GetOption("reservedrange", checkReserved);
		i2p::transport::transports.SetCheckReserved(checkReserved);

		i2p::context.Init ();

		i2p::transport::InitTransports ();

		bool isFloodfill; i2p::config::GetOption("floodfill", isFloodfill);
		if (isFloodfill)
		{
			LogPrint(eLogInfo, "Daemon: Router configured as floodfill");
			i2p::context.SetFloodfill (true);
		}
		else
			i2p::context.SetFloodfill (false);

		bool transit; i2p::config::GetOption("notransit", transit);
		i2p::context.SetAcceptsTunnels (!transit);
		uint32_t transitTunnels; i2p::config::GetOption("limits.transittunnels", transitTunnels);
		if (isFloodfill && i2p::config::IsDefault ("limits.transittunnels"))
			transitTunnels *= 2; // double default number of transit tunnels for floodfill
		i2p::tunnel::tunnels.SetMaxNumTransitTunnels (transitTunnels);

		/* this section also honors 'floodfill' flag, if set above */
		std::string bandwidth; i2p::config::GetOption("bandwidth", bandwidth);
		if (bandwidth.length () > 0)
		{
			if (bandwidth.length () == 1 && ((bandwidth[0] >= 'K' && bandwidth[0] <= 'P') || bandwidth[0] == 'X' ))
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
			i2p::context.SetHidden(true);
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
		LogPrint(eLogInfo, "Daemon: Starting Transports");
		if(!ssu2) LogPrint(eLogInfo, "Daemon: SSU2 disabled");
		if(!ntcp2) LogPrint(eLogInfo, "Daemon: NTCP2 disabled");

		i2p::transport::transports.Start(ntcp2, ssu2);
		if (i2p::transport::transports.IsBoundSSU2() || i2p::transport::transports.IsBoundNTCP2())
			LogPrint(eLogInfo, "Daemon: Transports started");
		else
		{
			LogPrint(eLogCritical, "Daemon: Failed to start Transports");
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
				LogPrint (eLogCritical, "Daemon: Failed to start Webconsole: ", ex.what ());
				ThrowFatal ("Unable to start webconsole at ", httpAddr, ":", httpPort, ": ", ex.what ());
			}
		}

		LogPrint(eLogInfo, "Daemon: Starting Tunnels");
		i2p::tunnel::tunnels.Start();

		LogPrint(eLogInfo, "Daemon: Starting Router context");
		i2p::context.Start();

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
				LogPrint (eLogCritical, "Daemon: Failed to start I2PControl: ", ex.what ());
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
		LogPrint(eLogInfo, "Daemon: Stopping Router context");
		i2p::context.Stop();
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
