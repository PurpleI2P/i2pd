/*
* Copyright (c) 2013-2016, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <vector>
#include <string>
#include <iostream>
#include <sstream>

namespace i2p {
namespace fs {
  extern std::string dirSep;

  /**
   * @brief Class to work with NetDb & Router profiles
   *
   * Usage:
   *
   * const char alphabet[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
   * auto h = HashedStorage("name", "y", "z-", ".txt");
   * h.SetRoot("/tmp/hs-test");
   * h.Init(alphabet, 8); <- creates needed dirs, 8 is size of alphabet
   * h.Path("abcd");      <- returns /tmp/hs-test/name/ya/z-abcd.txt
   * h.Remove("abcd");    <- removes /tmp/hs-test/name/ya/z-abcd.txt, if it exists
   * std::vector<std::string> files;
   * h.Traverse(files);   <- finds all files in storage and saves in given vector
   */
  class HashedStorage {
    protected:
      std::string root;
      std::string name;
      std::string prefix1;
      std::string prefix2;
      std::string suffix;

    public:
      HashedStorage(const char *n, const char *p1, const char *p2, const char *s):
        name(n), prefix1(p1), prefix2(p2), suffix(s) {};

      bool Init(const char* chars, size_t cnt);
      const std::string & GetRoot() { return this->root; }
      void SetRoot(const std::string & path);
      std::string Path(const std::string & ident);
      void Remove(const std::string & ident);
      void Traverse(std::vector<std::string> & files);
  };

  /** @brief Returns current application name, default 'i2pd' */
	const std::string & GetAppName ();
  /** @brief Set applicaton name, affects autodetection of datadir */
	void SetAppName (const std::string& name);

  /** @brief Returns datadir path */
  const std::string & GetDataDir();

  /**
   * @brief Set datadir either from cmdline option or using autodetection
   * @param cmdline_param  Value of cmdline parameter --datadir=<something>
   * @param isService      Value of cmdline parameter --service
   *
   * Examples of autodetected paths:
   *
   *   Windows < Vista: C:\Documents and Settings\Username\Application Data\i2pd\
   *   Windows >= Vista: C:\Users\Username\AppData\Roaming\i2pd\
   *   Mac: /Library/Application Support/i2pd/ or ~/Library/Application Support/i2pd/
   *   Unix: /var/lib/i2pd/ (system=1) >> ~/.i2pd/ or /tmp/i2pd/
   */
  void DetectDataDir(const std::string & cmdline_datadir, bool isService = false);

  /**
   * @brief Create subdirectories inside datadir
   */
  bool Init();

  /**
   * @brief Get list of files in directory
   * @param path  Path to directory
   * @param files Vector to store found files
   * @return true on success and false if directory not exists
   */
  bool ReadDir(const std::string & path, std::vector<std::string> & files);

  /**
   * @brief Remove file with given path
   * @param path Absolute path to file
   * @return true on success, false if file not exists, throws exception on error
   */
  bool Remove(const std::string & path);

  /**
   * @brief Check existence of file
   * @param path Absolute path to file
   * @return true if file exists, false otherwise
   */
  bool Exists(const std::string & path);

  template<typename T>
  void _ExpandPath(std::stringstream & path, T c) {
    path << i2p::fs::dirSep << c;
  }

  template<typename T, typename ... Other>
  void _ExpandPath(std::stringstream & path, T c, Other ... other) {
    _ExpandPath(path, c);
    _ExpandPath(path, other ...);
  }

  /**
   * @brief Get path relative to datadir
   *
   * Examples (with datadir = "/tmp/i2pd"):
   *
   * i2p::fs::Path("test")             -> '/tmp/i2pd/test'
   * i2p::fs::Path("test", "file.txt") -> '/tmp/i2pd/test/file.txt'
   */
  template<typename ... Other>
  std::string DataDirPath(Other ... components) {
    std::stringstream s("");
    s << i2p::fs::GetDataDir();
    _ExpandPath(s, components ...);

    return s.str();
  }

  /* accessors */
  HashedStorage & GetNetDB();
  HashedStorage & GetPeerProfiles();
} // fs
} // i2p
