#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

/**
 * Functions to parse and store i2pd parameters
 *
 * General usage flow:
 *   Init() -- early as possible
 *   ParseCmdline() -- somewhere close to main()
 *   ParseConfig()  -- after detecting path to config
 *   Finalize()     -- right after all Parse*() functions called
 *   GetOption()    -- may be called after Finalize()
 */

namespace i2p {
namespace config {
  extern boost::program_options::variables_map m_Options;

  /**
   * @brief  Initialize list of acceptable parameters
   *
   * Should be called before any Parse* functions.
   */
  void Init();

  /**
   * @brief  Parse cmdline parameters, and show help if requested
   * @param  argc  Cmdline arguments count, should be passed from main().
   * @param  argv  Cmdline parameters array, should be passed from main()
   *
   * If --help is given in parameters, shows it's list with description
   * terminates the program with exitcode 0.
   *
   * In case of parameter misuse boost throws an exception.
   * We internally handle type boost::program_options::unknown_option,
   * and then terminate program with exitcode 1.
   *
   * Other exceptions will be passed to higher level.
   */
  void ParseCmdline(int argc, char* argv[], bool ignoreUnknown = false);

  /**
   * @brief  Load and parse given config file
   * @param  path  Path to config file
   *
   * If error occured when opening file path is points to,
   * we show the error message and terminate program.
   *
   * In case of parameter misuse boost throws an exception.
   * We internally handle type boost::program_options::unknown_option,
   * and then terminate program with exitcode 1.
   *
   * Other exceptions will be passed to higher level.
   */
  void ParseConfig(const std::string& path);

  /**
   * @brief  Used to combine options from cmdline, config and default values
   */
  void Finalize();

  /* @brief  Accessor to parameters by name
   * @param  name  Name of the requested parameter
   * @param  value Variable where to store option
   * @return this function returns false if parameter not found
   *
   * Example: uint16_t port; GetOption("sam.port", port);
   */
  template<typename T>
  bool GetOption(const char *name, T& value) {
    if (!m_Options.count(name))
      return false;
    value = m_Options[name].as<T>();
    return true;
  }

  template<typename T>
  bool GetOption(const std::string& name, T& value) 
  {
    return GetOption (name.c_str (), value);
  }	

  bool GetOptionAsAny(const char *name, boost::any& value);
  bool GetOptionAsAny(const std::string& name, boost::any& value);

  /**
   * @brief  Set value of given parameter
   * @param  name  Name of settable parameter
   * @param  value New parameter value
   * @return true if value set up successful, false otherwise
   *
   * Example: uint16_t port = 2827; SetOption("bob.port", port);
   */
  template<typename T>
  bool SetOption(const char *name, const T& value) {
    if (!m_Options.count(name))
      return false;
    m_Options.at(name).value() = value;
    notify(m_Options);
    return true;
  }

  /**
   * @brief  Check is value explicitly given or default
   * @param  name  Name of checked parameter
   * @return true if value set to default, false othervise
   */
  bool IsDefault(const char *name);
}
}

#endif // CONFIG_H
