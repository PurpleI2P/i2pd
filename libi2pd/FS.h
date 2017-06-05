/*
* Copyright (c) 2013-2016, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef FS_H__
#define FS_H__

#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <functional>

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
   * h.SetPlace("/tmp/hs-test");
   * h.GetName()          -> gives "name"
   * h.GetRoot()          -> gives "/tmp/hs-test/name"
   * h.Init(alphabet, 8); <- creates needed dirs, 8 is size of alphabet
   * h.Path("abcd");      <- returns /tmp/hs-test/name/ya/z-abcd.txt
   * h.Remove("abcd");    <- removes /tmp/hs-test/name/ya/z-abcd.txt, if it exists
   * std::vector<std::string> files;
   * h.Traverse(files);   <- finds all files in storage and saves in given vector
   */
  class HashedStorage {
    protected:
      std::string root;    /**< path to storage with it's name included */
      std::string name;    /**< name of the storage */
      std::string prefix1; /**< hashed directory prefix */
      std::string prefix2; /**< prefix of file in storage */
      std::string suffix;  /**< suffix of file in storage (extension) */

    public:
      typedef std::function<void(const std::string &)> FilenameVisitor;
      HashedStorage(const char *n, const char *p1, const char *p2, const char *s):
        name(n), prefix1(p1), prefix2(p2), suffix(s) {};

      /** create subdirs in storage */
      bool Init(const char* chars, size_t cnt);
      const std::string & GetRoot() const { return root; }
      const std::string & GetName() const { return name; }
      /** set directory where to place storage directory */
      void SetPlace(const std::string & path);
      /** path to file with given ident */
      std::string Path(const std::string & ident) const;
      /** remove file by ident */
      void Remove(const std::string & ident);
      /** find all files in storage and store list in provided vector */
      void Traverse(std::vector<std::string> & files);
      /** visit every file in this storage with a visitor */
      void Iterate(FilenameVisitor v);
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

  uint32_t GetLastUpdateTime (const std::string & path); // seconds since epoch			
 
  bool CreateDirectory (const std::string& path);	

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

	template<typename Storage, typename... Filename>
	std::string StorageRootPath (const Storage& storage, Filename... filenames)
	{
		std::stringstream s("");
		s << storage.GetRoot ();
		_ExpandPath(s, filenames...);

		return s.str();
	}	

} // fs
} // i2p

#endif // /* FS_H__ */
