/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <boost/program_options/cmdline.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include "Identity.h"
#include "Config.h"
#include "version.h"

using namespace boost::program_options;

namespace i2p {
namespace config {
	options_description m_OptionsDesc;
	variables_map m_Options;

	void Init()
	{
		options_description general("General options");
		general.add_options()
			("help",                                                          "Show this message")
			("version",                                                       "Show i2pd version")
			("conf", value<std::string>()->default_value(""),                 "Path to main i2pd config file (default: try ~/.i2pd/i2pd.conf or /var/lib/i2pd/i2pd.conf)")
			("tunconf", value<std::string>()->default_value(""),              "Path to config with tunnels list and options (default: try ~/.i2pd/tunnels.conf or /var/lib/i2pd/tunnels.conf)")
			("tunnelsdir", value<std::string>()->default_value(""),           "Path to extra tunnels' configs folder (default: ~/.i2pd/tunnels.d or /var/lib/i2pd/tunnels.d")
			("pidfile", value<std::string>()->default_value(""),              "Path to pidfile (default: ~/i2pd/i2pd.pid or /var/lib/i2pd/i2pd.pid)")
			("log", value<std::string>()->default_value(""),                  "Logs destination: stdout, file, syslog (stdout if not set)")
			("logfile", value<std::string>()->default_value(""),              "Path to logfile (stdout if not set, autodetect if daemon)")
			("loglevel", value<std::string>()->default_value("warn"),         "Set the minimal level of log messages (debug, info, warn, error, none)")
			("logclftime", bool_switch()->default_value(false),               "Write full CLF-formatted date and time to log (default: disabled, write only time)")
			("family", value<std::string>()->default_value(""),               "Specify a family, router belongs to")
			("datadir", value<std::string>()->default_value(""),              "Path to storage of i2pd data (RI, keys, peer profiles, ...)")
			("host", value<std::string>()->default_value("0.0.0.0"),          "External IP")
			("ifname", value<std::string>()->default_value(""),               "Network interface to bind to")
			("ifname4", value<std::string>()->default_value(""),              "Network interface to bind to for ipv4")
			("ifname6", value<std::string>()->default_value(""),              "Network interface to bind to for ipv6")
			("nat", value<bool>()->default_value(true),                       "Should we assume we are behind NAT? (default: enabled)")
			("port", value<uint16_t>()->default_value(0),                     "Port to listen for incoming connections (default: auto)")
			("ipv4", value<bool>()->default_value(true),                      "Enable communication through ipv4 (default: enabled)")
			("ipv6", bool_switch()->default_value(false),                     "Enable communication through ipv6 (default: disabled)")
			("netid", value<int>()->default_value(I2PD_NET_ID),               "Specify NetID. Main I2P is 2")
			("daemon", bool_switch()->default_value(false),                   "Router will go to background after start (default: disabled)")
			("service", bool_switch()->default_value(false),                  "Router will use system folders like '/var/lib/i2pd' (default: disabled)")
			("notransit", bool_switch()->default_value(false),                "Router will not accept transit tunnels at startup (default: disabled)")
			("floodfill", bool_switch()->default_value(false),                "Router will be floodfill (default: disabled)")
			("bandwidth", value<std::string>()->default_value(""),            "Bandwidth limit: integer in KBps or letters: L (32), O (256), P (2048), X (>9000)")
			("share", value<int>()->default_value(100),                       "Limit of transit traffic from max bandwidth in percents. (default: 100)")
			("ntcp", value<bool>()->default_value(false),                     "Enable NTCP transport (default: disabled)")
			("ssu", value<bool>()->default_value(true),                       "Enable SSU transport (default: enabled)")
			("ntcpproxy", value<std::string>()->default_value(""),            "Proxy URL for NTCP transport")
#ifdef _WIN32
			("svcctl", value<std::string>()->default_value(""),               "Windows service management ('install' or 'remove')")
			("insomnia", bool_switch()->default_value(false),                 "Prevent system from sleeping (default: disabled)")
			("close", value<std::string>()->default_value("ask"),             "Action on close: minimize, exit, ask")
#endif
		;

		options_description limits("Limits options");
		limits.add_options()
			("limits.coresize", value<uint32_t>()->default_value(0),          "Maximum size of corefile in Kb (0 - use system limit)")
			("limits.openfiles", value<uint16_t>()->default_value(0),         "Maximum number of open files (0 - use system default)")
			("limits.transittunnels", value<uint16_t>()->default_value(2500), "Maximum active transit sessions (default:2500)")
			("limits.ntcpsoft", value<uint16_t>()->default_value(0),          "Threshold to start probabilistic backoff with ntcp sessions (default: use system limit)")
			("limits.ntcphard", value<uint16_t>()->default_value(0),          "Maximum number of ntcp sessions (default: use system limit)")
			("limits.ntcpthreads", value<uint16_t>()->default_value(1),       "Maximum number of threads used by NTCP DH worker (default: 1)")
		;

		options_description httpserver("HTTP Server options");
		httpserver.add_options()
			("http.enabled", value<bool>()->default_value(true),                "Enable or disable webconsole")
			("http.address", value<std::string>()->default_value("127.0.0.1"),  "Webconsole listen address")
			("http.port", value<uint16_t>()->default_value(7070),               "Webconsole listen port")
			("http.auth", value<bool>()->default_value(false),                  "Enable Basic HTTP auth for webconsole")
			("http.user", value<std::string>()->default_value("i2pd"),          "Username for basic auth")
			("http.pass", value<std::string>()->default_value(""),              "Password for basic auth (default: random, see logs)")
			("http.strictheaders", value<bool>()->default_value(true),          "Enable strict host checking on WebUI")
			("http.hostname", value<std::string>()->default_value("localhost"), "Expected hostname for WebUI")
			("http.webroot", value<std::string>()->default_value("/"),          "WebUI root path (default: / )")
		;

		options_description httpproxy("HTTP Proxy options");
		httpproxy.add_options()
			("httpproxy.enabled", value<bool>()->default_value(true),                 "Enable or disable HTTP Proxy")
			("httpproxy.address", value<std::string>()->default_value("127.0.0.1"),   "HTTP Proxy listen address")
			("httpproxy.port", value<uint16_t>()->default_value(4444),                "HTTP Proxy listen port")
			("httpproxy.keys", value<std::string>()->default_value(""),               "File to persist HTTP Proxy keys")
			("httpproxy.signaturetype", value<i2p::data::SigningKeyType>()->
				default_value(i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519),      "Signature type for new keys. 7 (EdDSA) by default")
			("httpproxy.inbound.length", value<std::string>()->default_value("3"),    "HTTP proxy inbound tunnel length")
			("httpproxy.outbound.length", value<std::string>()->default_value("3"),   "HTTP proxy outbound tunnel length")
			("httpproxy.inbound.quantity", value<std::string>()->default_value("5"),  "HTTP proxy inbound tunnels quantity")
			("httpproxy.outbound.quantity", value<std::string>()->default_value("5"), "HTTP proxy outbound tunnels quantity")
			("httpproxy.latency.min", value<std::string>()->default_value("0"),       "HTTP proxy min latency for tunnels")
			("httpproxy.latency.max", value<std::string>()->default_value("0"),       "HTTP proxy max latency for tunnels")
			("httpproxy.outproxy", value<std::string>()->default_value(""),           "HTTP proxy upstream out proxy url")
			("httpproxy.addresshelper", value<bool>()->default_value(true),           "Enable or disable addresshelper")
			("httpproxy.i2cp.leaseSetType", value<std::string>()->default_value("1"), "Local destination's LeaseSet type")
			("httpproxy.i2cp.leaseSetEncType", value<std::string>()->default_value("0"), "Local destination's LeaseSet encryption type")
		;

		options_description socksproxy("SOCKS Proxy options");
		socksproxy.add_options()
			("socksproxy.enabled", value<bool>()->default_value(true),                 "Enable or disable SOCKS Proxy")
			("socksproxy.address", value<std::string>()->default_value("127.0.0.1"),   "SOCKS Proxy listen address")
			("socksproxy.port", value<uint16_t>()->default_value(4447),                "SOCKS Proxy listen port")
			("socksproxy.keys", value<std::string>()->default_value(""),               "File to persist SOCKS Proxy keys")
			("socksproxy.signaturetype", value<i2p::data::SigningKeyType>()->
				default_value(i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519),       "Signature type for new keys. 7 (EdDSA) by default")
			("socksproxy.inbound.length", value<std::string>()->default_value("3"),    "SOCKS proxy inbound tunnel length")
			("socksproxy.outbound.length", value<std::string>()->default_value("3"),   "SOCKS proxy outbound tunnel length")
			("socksproxy.inbound.quantity", value<std::string>()->default_value("5"),  "SOCKS proxy inbound tunnels quantity")
			("socksproxy.outbound.quantity", value<std::string>()->default_value("5"), "SOCKS proxy outbound tunnels quantity")
			("socksproxy.latency.min", value<std::string>()->default_value("0"),       "SOCKS proxy min latency for tunnels")
			("socksproxy.latency.max", value<std::string>()->default_value("0"),       "SOCKS proxy max latency for tunnels")
			("socksproxy.outproxy.enabled", value<bool>()->default_value(false),       "Enable or disable SOCKS outproxy")
			("socksproxy.outproxy", value<std::string>()->default_value("127.0.0.1"),  "Upstream outproxy address for SOCKS Proxy")
			("socksproxy.outproxyport", value<uint16_t>()->default_value(9050),        "Upstream outproxy port for SOCKS Proxy")
			("socksproxy.i2cp.leaseSetType", value<std::string>()->default_value("1"), "Local destination's LeaseSet type")
			("socksproxy.i2cp.leaseSetEncType", value<std::string>()->default_value("0"), "Local destination's LeaseSet encryption type")
		;

		options_description sam("SAM bridge options");
		sam.add_options()
			("sam.enabled", value<bool>()->default_value(true),               "Enable or disable SAM Application bridge")
			("sam.address", value<std::string>()->default_value("127.0.0.1"), "SAM listen address")
			("sam.port", value<uint16_t>()->default_value(7656),              "SAM listen port")
			("sam.singlethread", value<bool>()->default_value(true),          "Sessions run in the SAM bridge's thread")
		;

		options_description bob("BOB options");
		bob.add_options()
			("bob.enabled", value<bool>()->default_value(false),              "Enable or disable BOB command channel")
			("bob.address", value<std::string>()->default_value("127.0.0.1"), "BOB listen address")
			("bob.port", value<uint16_t>()->default_value(2827),              "BOB listen port")
		;

		options_description i2cp("I2CP options");
		i2cp.add_options()
			("i2cp.enabled", value<bool>()->default_value(false),              "Enable or disable I2CP")
			("i2cp.address", value<std::string>()->default_value("127.0.0.1"), "I2CP listen address")
			("i2cp.port", value<uint16_t>()->default_value(7654),              "I2CP listen port")
		;

		options_description i2pcontrol("I2PControl options");
		i2pcontrol.add_options()
			("i2pcontrol.enabled", value<bool>()->default_value(false),                    "Enable or disable I2P Control Protocol")
			("i2pcontrol.address", value<std::string>()->default_value("127.0.0.1"),       "I2PCP listen address")
			("i2pcontrol.port", value<uint16_t>()->default_value(7650),                    "I2PCP listen port")
			("i2pcontrol.password", value<std::string>()->default_value("itoopie"),        "I2PCP access password")
			("i2pcontrol.cert", value<std::string>()->default_value("i2pcontrol.crt.pem"), "I2PCP connection certificate")
			("i2pcontrol.key", value<std::string>()->default_value("i2pcontrol.key.pem"),  "I2PCP connection certificate key")
		;

		bool upnp_default = false;
#if (defined(USE_UPNP) && (defined(WIN32_APP) || defined(ANDROID)))
		upnp_default = true; // enable UPNP for windows GUI and android by default
#endif
		options_description upnp("UPnP options");
		upnp.add_options()
			("upnp.enabled", value<bool>()->default_value(upnp_default), "Enable or disable UPnP: automatic port forwarding")
			("upnp.name", value<std::string>()->default_value("I2Pd"),   "Name i2pd appears in UPnP forwarding list")
		;

		options_description precomputation("Precomputation options");
		precomputation.add_options()
			("precomputation.elgamal",
#if defined(__x86_64__)
				value<bool>()->default_value(false),
#else
				value<bool>()->default_value(true),
#endif
				"Enable or disable elgamal precomputation table")
		;

		options_description reseed("Reseed options");
		reseed.add_options()
			("reseed.verify", value<bool>()->default_value(false),        "Verify .su3 signature")
			("reseed.threshold", value<uint16_t>()->default_value(25),    "Minimum number of known routers before requesting reseed")
			("reseed.floodfill", value<std::string>()->default_value(""), "Path to router info of floodfill to reseed from")
			("reseed.file", value<std::string>()->default_value(""),      "Path to local .su3 file or HTTPS URL to reseed from")
			("reseed.zipfile", value<std::string>()->default_value(""),   "Path to local .zip file to reseed from")
			("reseed.proxy", value<std::string>()->default_value(""),     "url for reseed proxy, supports http/socks")
			("reseed.urls", value<std::string>()->default_value(
				"https://reseed.i2p-projekt.de/,"
			    "https://reseed.diva.exchange/,"
				"https://reseed.i2p2.no/,"
				"https://reseed-fr.i2pd.xyz/,"
				"https://reseed.memcpy.io/,"
				"https://reseed.onion.im/,"
				"https://i2pseed.creativecowpat.net:8443/,"
			    "https://reseed.i2pgit.org/,"                                                				
				"https://i2p.novg.net/"
			),                                                            "Reseed URLs, separated by comma")
		;

		options_description addressbook("AddressBook options");
		addressbook.add_options()
			("addressbook.defaulturl", value<std::string>()->default_value(
				"http://joajgazyztfssty4w2on5oaqksz6tqoxbduy553y34mf4byv6gpq.b32.i2p/export/alive-hosts.txt"
			),                                                                     "AddressBook subscription URL for initial setup")
			("addressbook.subscriptions", value<std::string>()->default_value(""), "AddressBook subscriptions URLs, separated by comma");

		options_description trust("Trust options");
		trust.add_options()
			("trust.enabled", value<bool>()->default_value(false),     "Enable explicit trust options")
			("trust.family", value<std::string>()->default_value(""),  "Router Familiy to trust for first hops")
			("trust.routers", value<std::string>()->default_value(""), "Only Connect to these routers")
			("trust.hidden", value<bool>()->default_value(false),      "Should we hide our router from other routers?")
		;

		// Save deprecated websocket options for compatibility
		options_description websocket("Websocket Options");
		websocket.add_options()
			("websockets.enabled", value<bool>()->default_value(false),     "Deprecated option")
			("websockets.address", value<std::string>()->default_value(""), "Deprecated option")
			("websockets.port", value<uint16_t>()->default_value(0),        "Deprecated option")
		;

		options_description exploratory("Exploratory Options");
		exploratory.add_options()
			("exploratory.inbound.length", value<int>()->default_value(2),    "Exploratory inbound tunnel length")
			("exploratory.outbound.length", value<int>()->default_value(2),   "Exploratory outbound tunnel length")
			("exploratory.inbound.quantity", value<int>()->default_value(3),  "Exploratory inbound tunnels quantity")
			("exploratory.outbound.quantity", value<int>()->default_value(3), "Exploratory outbound tunnels quantity")
		;

		options_description ntcp2("NTCP2 Options");
		ntcp2.add_options()
			("ntcp2.enabled", value<bool>()->default_value(true),          "Enable NTCP2 (default: enabled)")
			("ntcp2.published", value<bool>()->default_value(true),        "Publish NTCP2 (default: enabled)")
			("ntcp2.port", value<uint16_t>()->default_value(0),            "Port to listen for incoming NTCP2 connections (default: auto)")
			("ntcp2.addressv6", value<std::string>()->default_value("::"), "Address to bind NTCP2 on")
			("ntcp2.proxy", value<std::string>()->default_value(""),       "Proxy URL for NTCP2 transport")
		;

		options_description nettime("Time sync options");
		nettime.add_options()
			("nettime.enabled", value<bool>()->default_value(false),       "Disable time sync (default: disabled)")
			("nettime.ntpservers", value<std::string>()->default_value(
				"0.pool.ntp.org,"
				"1.pool.ntp.org,"
				"2.pool.ntp.org,"
				"3.pool.ntp.org"
			),                                                             "Comma separated list of NTCP servers")
			("nettime.ntpsyncinterval", value<int>()->default_value(72),   "NTP sync interval in hours (default: 72)")
		;

		options_description persist("Network information persisting options");
		persist.add_options()
			("persist.profiles", value<bool>()->default_value(true),       "Persist peer profiles (default: true)")
			("persist.addressbook", value<bool>()->default_value(true),    "Persist full addresses (default: true)")
		;

		m_OptionsDesc
			.add(general)
			.add(limits)
			.add(httpserver)
			.add(httpproxy)
			.add(socksproxy)
			.add(sam)
			.add(bob)
			.add(i2cp)
			.add(i2pcontrol)
			.add(upnp)
			.add(precomputation)
			.add(reseed)
			.add(addressbook)
			.add(trust)
			.add(websocket) // deprecated
			.add(exploratory)
			.add(ntcp2)
			.add(nettime)
			.add(persist)
		;
	}

	void ParseCmdline(int argc, char* argv[], bool ignoreUnknown)
	{
		try
		{
			auto style = boost::program_options::command_line_style::unix_style
				| boost::program_options::command_line_style::allow_long_disguise;
			style &=   ~ boost::program_options::command_line_style::allow_guessing;
			if (ignoreUnknown)
				store(command_line_parser(argc, argv).options(m_OptionsDesc).style (style).allow_unregistered().run(), m_Options);
			else
				store(parse_command_line(argc, argv, m_OptionsDesc, style), m_Options);
		}
		catch (boost::program_options::error& e)
		{
			std::cerr << "args: " << e.what() << std::endl;
			exit(EXIT_FAILURE);
		}

		if (!ignoreUnknown && (m_Options.count("help") || m_Options.count("h")))
		{
			std::cout << "i2pd version " << I2PD_VERSION << " (" << I2P_VERSION << ")" << std::endl;
			std::cout << m_OptionsDesc;
			exit(EXIT_SUCCESS);
		}
		else if (m_Options.count("version"))
		{
			std::cout << "i2pd version " << I2PD_VERSION << " (" << I2P_VERSION << ")" << std::endl;
			std::cout << "Boost version "
					  << BOOST_VERSION / 100000     << "."  // maj. version
					  << BOOST_VERSION / 100 % 1000 << "."  // min. version
					  << BOOST_VERSION % 100                // patch version
					  << std::endl;
#if defined(OPENSSL_VERSION_TEXT)
			std::cout << OPENSSL_VERSION_TEXT << std::endl;
#endif
#if defined(LIBRESSL_VERSION_TEXT)
			std::cout << LIBRESSL_VERSION_TEXT << std::endl;
#endif

			exit(EXIT_SUCCESS);
		}
	}

	void ParseConfig(const std::string& path)
	{
		if (path == "") return;

		std::ifstream config(path, std::ios::in);

		if (!config.is_open())
		{
			std::cerr << "missing/unreadable config file: " << path << std::endl;
			exit(EXIT_FAILURE);
		}

		try
		{
			store(boost::program_options::parse_config_file(config, m_OptionsDesc), m_Options);
		}
		catch (boost::program_options::error& e)
		{
			std::cerr << e.what() << std::endl;
			exit(EXIT_FAILURE);
		};
	}

	void Finalize()
	{
		notify(m_Options);
	}

	bool IsDefault(const char *name)
	{
		if (!m_Options.count(name))
			throw "try to check non-existent option";

		if (m_Options[name].defaulted())
			return true;
		return false;
	}

	bool GetOptionAsAny(const char *name, boost::any& value)
	{
		if (!m_Options.count(name))
			return false;
		value = m_Options[name];
		return true;
	}

	bool GetOptionAsAny(const std::string& name, boost::any& value)
	{
		return GetOptionAsAny (name.c_str (), value);
	}

} // namespace config
} // namespace i2p
