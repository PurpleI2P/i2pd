/*
* Copyright (c) 2013-2016, The PurpleI2P Project
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

#include "Config.h"
#include "version.h"

using namespace boost::program_options;

namespace i2p {
namespace config {
  options_description m_OptionsDesc;
  variables_map       m_Options;

  /* list of renamed options */
  std::map<std::string, std::string> remapped_options = {
    { "tunnelscfg",          "tunconf" },
    { "v6",                  "ipv6" },
    { "httpaddress",         "http.address" },
    { "httpport",            "http.port"    },
    { "httpproxyaddress",    "httpproxy.address"  },
    { "httpproxyport",       "httpproxy.port"     },
    { "socksproxyaddress",   "socksproxy.address" },
    { "socksproxyport",      "socksproxy.port"    },
    { "samaddress",          "sam.address" },
    { "samport",             "sam.port"    },
    { "bobaddress",          "bob.address" },
    { "bobport",             "bob.port"    },
    { "i2pcontroladdress",   "i2pcontrol.address" },
    { "i2pcontroladdress",   "i2pcontrol.port"    },
    { "proxykeys",           "httpproxy.keys" },
  };
  /* list of options, that loose their argument and become simple switch */
  std::set<std::string> boolean_options = {
    "daemon", "floodfill", "notransit", "service", "ipv6"
  };

  /* this function is a solid piece of shit, remove it after 2.6.0 */
  std::pair<std::string, std::string> old_syntax_parser(const std::string& s) {
    std::string name  = "";
    std::string value = "";
    std::size_t pos = 0;
    /* shortcuts -- -h */
    if (s.length() == 2 && s.at(0) == '-' && s.at(1) != '-')
      return make_pair(s.substr(1), "");
    /* old-style -- -log, /log, etc */
    if (s.at(0) == '/' || (s.at(0) == '-' && s.at(1) != '-')) {
      if ((pos = s.find_first_of("= ")) != std::string::npos) {
        name  = s.substr(1, pos - 1);
        value = s.substr(pos + 1);
      } else {
        name  = s.substr(1, pos);
        value = "";
      }
      if (boolean_options.count(name) > 0 && value != "")
        std::cerr << "args: don't give an argument to switch option: " << s << std::endl;
      if (m_OptionsDesc.find_nothrow(name, false)) {
        std::cerr << "args: option " << s << " style is DEPRECATED, use --" << name << " instead" << std::endl;
        return std::make_pair(name, value);
      }
      if (remapped_options.count(name) > 0) {
        name = remapped_options[name];
        std::cerr << "args: option " << s << " is DEPRECATED, use --" << name << " instead" << std::endl;
        return std::make_pair(name, value);
      } /* else */
    }
    /* long options -- --help */
    if (s.substr(0, 2) == "--") {
      if ((pos = s.find_first_of("= ")) != std::string::npos) {
        name  = s.substr(2, pos - 2);
        value = s.substr(pos + 1);
      } else {
        name  = s.substr(2, pos);
        value = "";
      }
      if (boolean_options.count(name) > 0 && value != "") {
        std::cerr << "args: don't give an argument to switch option: " << s << std::endl;
        value = "";
      }
      if (m_OptionsDesc.find_nothrow(name, false))
        return std::make_pair(name, value);
      if (remapped_options.count(name) > 0) {
        name = remapped_options[name];
        std::cerr << "args: option " << s << " is DEPRECATED, use --" << name << " instead" << std::endl;
        return std::make_pair(name, value);
      } /* else */
    }
    std::cerr << "args: unknown option -- " << s << std::endl;
    return std::make_pair("", "");
  }

  void Init() {
    options_description general("General options");
    general.add_options()
      ("help",     "Show this message")
      ("conf",      value<std::string>()->default_value(""),     "Path to main i2pd config file (default: try ~/.i2pd/i2p.conf or /var/lib/i2pd/i2p.conf)")
      ("tunconf",   value<std::string>()->default_value(""),     "Path to config with tunnels list and options (default: try ~/.i2pd/tunnels.cfg or /var/lib/i2pd/tunnels.cfg)")
      ("pidfile",   value<std::string>()->default_value(""),     "Path to pidfile (default: ~/i2pd/i2pd.pid or /var/lib/i2pd/i2pd.pid)")
      ("log",       value<std::string>()->default_value(""),     "Logs destination: stdout, file (stdout if not set, file - otherwise, for compatibility)")
      ("logfile",   value<std::string>()->default_value(""),     "Path to logfile (stdout if not set, autodetect if daemon)")
      ("loglevel",  value<std::string>()->default_value("info"), "Set the minimal level of log messages (debug, info, warn, error)")
	  ("family",    value<std::string>()->default_value(""),     "Specify a family, router belongs to")
	  ("datadir",   value<std::string>()->default_value(""),     "Path to storage of i2pd data (RI, keys, peer profiles, ...)")
      ("host",      value<std::string>()->default_value("0.0.0.0"),     "External IP")
      ("port",      value<uint16_t>()->default_value(0),                "Port to listen for incoming connections (default: auto)")
      ("ipv6",      value<bool>()->zero_tokens()->default_value(false), "Enable communication through ipv6")
      ("daemon",    value<bool>()->zero_tokens()->default_value(false), "Router will go to background after start")
      ("service",   value<bool>()->zero_tokens()->default_value(false), "Router will use system folders like '/var/lib/i2pd'")
      ("notransit", value<bool>()->zero_tokens()->default_value(false), "Router will not accept transit tunnels at startup")
      ("floodfill", value<bool>()->zero_tokens()->default_value(false), "Router will be floodfill")
      ("bandwidth", value<char>()->default_value('-'), "Bandwidth limiting: L - 32kbps, O - 256Kbps, P - unlimited")
#ifdef _WIN32
      ("svcctl",    value<std::string>()->default_value(""),     "Windows service management ('install' or 'remove')")
#endif
      ;

    options_description httpserver("HTTP Server options");
    httpserver.add_options()
      ("http.enabled",        value<bool>()->default_value(true),               "Enable or disable webconsole")
      ("http.address",        value<std::string>()->default_value("127.0.0.1"), "Webconsole listen address")
      ("http.port",           value<uint16_t>()->default_value(7070),           "Webconsole listen port")
      ;

    options_description httpproxy("HTTP Proxy options");
    httpproxy.add_options()
      ("httpproxy.enabled",   value<bool>()->default_value(true),                         "Enable or disable HTTP Proxy")
      ("httpproxy.address",   value<std::string>()->default_value("127.0.0.1"),           "HTTP Proxy listen address")
      ("httpproxy.port",      value<uint16_t>()->default_value(4444),                     "HTTP Proxy listen port")
      ("httpproxy.keys",      value<std::string>()->default_value(""),  "File to persist HTTP Proxy keys")
      ;

    options_description socksproxy("SOCKS Proxy options");
    socksproxy.add_options()
      ("socksproxy.enabled",  value<bool>()->default_value(true),                         "Enable or disable SOCKS Proxy")
      ("socksproxy.address",  value<std::string>()->default_value("127.0.0.1"),           "SOCKS Proxy listen address")
      ("socksproxy.port",     value<uint16_t>()->default_value(4447),                     "SOCKS Proxy listen port")
      ("socksproxy.keys",     value<std::string>()->default_value(""), "File to persist SOCKS Proxy keys")
      ;

    options_description sam("SAM bridge options");
    sam.add_options()
      ("sam.enabled",         value<bool>()->default_value(false),                        "Enable or disable SAM Application bridge")
      ("sam.address",         value<std::string>()->default_value("127.0.0.1"),           "SAM listen address")
      ("sam.port",            value<uint16_t>()->default_value(7656),                     "SAM listen port")
      ;

    options_description bob("BOB options");
    bob.add_options()
      ("bob.enabled",         value<bool>()->default_value(false),                        "Enable or disable BOB command channel")
      ("bob.address",         value<std::string>()->default_value("127.0.0.1"),           "BOB listen address")
      ("bob.port",            value<uint16_t>()->default_value(2827),                     "BOB listen port")
      ;

    options_description i2pcontrol("I2PControl options");
    i2pcontrol.add_options()
      ("i2pcontrol.enabled",  value<bool>()->default_value(false),                        "Enable or disable I2P Control Protocol")
      ("i2pcontrol.address",  value<std::string>()->default_value("127.0.0.1"),           "I2PCP listen address")
      ("i2pcontrol.port",     value<uint16_t>()->default_value(7650),                     "I2PCP listen port")
      ("i2pcontrol.password", value<std::string>()->default_value("itoopie"),             "I2PCP access password")
      ("i2pcontrol.cert",     value<std::string>()->default_value("i2pcontrol.crt.pem"),  "I2PCP connection cerificate")
      ("i2pcontrol.key",      value<std::string>()->default_value("i2pcontrol.key.pem"),  "I2PCP connection cerificate key")
      ;

    m_OptionsDesc
      .add(general)
      .add(httpserver)
      .add(httpproxy)
      .add(socksproxy)
      .add(sam)
      .add(bob)
      .add(i2pcontrol)
      ;
  }

  void ParseCmdline(int argc, char* argv[]) {
    try {
      auto style = boost::program_options::command_line_style::unix_style
                 | boost::program_options::command_line_style::allow_long_disguise;
      style &=   ~ boost::program_options::command_line_style::allow_guessing;
      store(parse_command_line(argc, argv, m_OptionsDesc, style, old_syntax_parser), m_Options);
    } catch (boost::program_options::error& e) {
      std::cerr << "args: " << e.what() << std::endl;
      exit(EXIT_FAILURE);
    }

    if (m_Options.count("help") || m_Options.count("h")) {
      std::cout << "i2pd version " << I2PD_VERSION << " (" << I2P_VERSION << ")" << std::endl;
      std::cout << m_OptionsDesc;
      exit(EXIT_SUCCESS);
    }
  }

  void ParseConfig(const std::string& path) {
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

  void Finalize() {
    notify(m_Options);
  }

  bool IsDefault(const char *name) {
    if (!m_Options.count(name))
      throw "try to check non-existent option";

    if (m_Options[name].defaulted())
      return true;
    return false;
  }
} // namespace config
} // namespace i2p
