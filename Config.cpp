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

  void Init() {
    options_description general("General options");
    general.add_options()
      ("help,h",   "Show this message")
      ("conf,c",    value<std::string>()->default_value(""),     "Path to main i2pd config file (default: try ~/.i2pd/i2p.conf or /var/lib/i2pd/i2p.conf)")
      ("tunconf",   value<std::string>()->default_value(""),     "Path to config with tunnels list and options (default: try ~/.i2pd/tunnels.cfg or /var/lib/i2pd/tunnels.cfg)")
      ("pidfile",   value<std::string>()->default_value(""),     "Write pidfile to given path")
      ("log",       value<bool>()->zero_tokens(),                "Write logs to file instead stdout")
      ("loglevel",  value<std::string>()->default_value("info"), "Set the minimal level of log messages (debug, info, warn, error)")
      ("host",      value<std::string>()->default_value(""),     "External IP (deprecated)")
      ("port,p",    value<uint16_t>()->default_value(4567),      "Port to listen for incoming connections")
      ("ipv6,6",    value<bool>()->zero_tokens(),      "Enable communication through ipv6")
      ("daemon",    value<bool>()->zero_tokens(),      "Router will go to background after start")
      ("service",   value<bool>()->zero_tokens(),      "Router will use system folders like '/var/lib/i2pd'")
      ("notransit", value<bool>()->zero_tokens(),      "Router will not forward transit traffic")
      ("floodfill", value<bool>()->zero_tokens(),      "Router will try to become floodfill")
      ("bandwidth", value<char>()->default_value('O'), "Bandwidth limiting: L - 32kbps, O - 256Kbps, P - unlimited")
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
      ("httpproxy.port",      value<uint16_t>()->default_value(4446),                     "HTTP Proxy listen port")
      ("httpproxy.keys",      value<std::string>()->default_value("httpproxy-keys.dat"),  "HTTP Proxy encryption keys")
      ;

    options_description socksproxy("SOCKS Proxy options");
    socksproxy.add_options()
      ("socksproxy.enabled",  value<bool>()->default_value(true),                         "Enable or disable SOCKS Proxy")
      ("socksproxy.address",  value<std::string>()->default_value("127.0.0.1"),           "SOCKS Proxy listen address")
      ("socksproxy.port",     value<uint16_t>()->default_value(4447),                     "SOCKS Proxy listen port")
      ("socksproxy.keys",     value<std::string>()->default_value("socksproxy-keys.dat"), "SOCKS Proxy encryption keys")
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
      store(parse_command_line(argc, argv, m_OptionsDesc), m_Options);
    } catch (boost::program_options::error e) {
      std::cerr << "args: " << e.what() << std::endl;
      exit(EXIT_FAILURE);
    }

    if (m_Options.count("help")) {
      std::cout << "i2pd version " << I2PD_VERSION << " (" << I2P_VERSION << ")" << std::endl;
      std::cout << m_OptionsDesc;
      exit(EXIT_SUCCESS);
    }
  }

  void ParseConfig(const std::string& path) {
    std::ifstream config(path, std::ios::in);

    if (!config.is_open()) {
      std::cerr << "missing/unreadable config file: " << path << std::endl;
      exit(EXIT_FAILURE);
    }

    try {
      store(boost::program_options::parse_config_file(config, m_OptionsDesc), m_Options);
    } catch (boost::program_options::error e) {
      std::cerr << e.what() << std::endl;
      exit(EXIT_FAILURE);
    };
  }

  void Finalize() {
    notify(m_Options);
  };
} // namespace config
} // namespace i2p
