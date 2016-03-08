/*
* Copyright (c) 2013-2016, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>
#include <boost/filesystem.hpp>

#ifdef WIN32
#include <shlobj.h>
#endif

#include "Base.h"
#include "FS.h"
#include "Log.h"

namespace i2p {
namespace fs {
  std::string appName = "i2pd";
  std::string dataDir = "";
#ifdef _WIN32
  std::string dirSep = "\\";
#else
  std::string dirSep = "/";
#endif

  const std::string & GetAppName () {
    return appName;
  }

  void SetAppName (const std::string& name) {
    appName = name;
  }

  const std::string & GetDataDir () {
    return dataDir;
  }

  void DetectDataDir(const std::string & cmdline_param, bool isService) {
    if (cmdline_param != "") {
      dataDir = cmdline_param;
      return;
    }
#if defined(WIN32) || defined(_WIN32)
    char localAppData[MAX_PATH];
    SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, localAppData);
    dataDir = std::string(localAppData) + "\\" + appName;
    return;
#elif defined(MAC_OSX)
    char *home = getenv("HOME");
    dataDir = (home != NULL && strlen(home) > 0) ? home : "";
    dataDir += "/Library/Application Support/" + appName;
    return;
#else /* other unix */
    char *home = getenv("HOME");
    if (isService) {
      dataDir = "/var/lib/" + appName;
    } else if (home != NULL && strlen(home) > 0) {
      dataDir = std::string(home) + "/." + appName;
    } else {
      dataDir = "/tmp/" + appName;
    }
    return;
#endif
  }

  bool Init() {
    if (!boost::filesystem::exists(dataDir))
      boost::filesystem::create_directory(dataDir);
    std::string destinations = DataDirPath("destinations");
    if (!boost::filesystem::exists(destinations))
      boost::filesystem::create_directory(destinations);

    return true;
  }

  bool ReadDir(const std::string & path, std::vector<std::string> & files) {
    if (!boost::filesystem::exists(path))
      return false;
    boost::filesystem::directory_iterator it(path);
    boost::filesystem::directory_iterator end;

    for ( ; it != end; it++) {
      if (!boost::filesystem::is_regular_file(it->status()))
        continue;
      files.push_back(it->path().string());
    }

    return true;
  }

  bool Exists(const std::string & path) {
    return boost::filesystem::exists(path);
  }

  bool Remove(const std::string & path) {
    if (!boost::filesystem::exists(path))
      return false;
    return boost::filesystem::remove(path);
  }

  void HashedStorage::SetPlace(const std::string &path) {
    root = path + i2p::fs::dirSep + name;
  }

  bool HashedStorage::Init(const char * chars, size_t count) {
    if (!boost::filesystem::exists(root)) {
      boost::filesystem::create_directories(root);
    }
    
    for (size_t i = 0; i < count; i++) {
      auto p = root + i2p::fs::dirSep + prefix1 + chars[i];
      if (boost::filesystem::exists(p))
        continue;
      if (boost::filesystem::create_directory(p))
        continue; /* ^ throws exception on failure */
      return false;
    }
    return true;
  }

  std::string HashedStorage::Path(const std::string & ident) const {
    std::string safe_ident = ident;
    std::replace(safe_ident.begin(), safe_ident.end(), '/',  '-');
    std::replace(safe_ident.begin(), safe_ident.end(), '\\', '-');

    std::stringstream t("");
    t << this->root << i2p::fs::dirSep;
    t << prefix1 << safe_ident[0] << i2p::fs::dirSep;
    t << prefix2 << safe_ident    << "." << suffix;

    return t.str();
  }

  void HashedStorage::Remove(const std::string & ident) {
    std::string path = Path(ident);
    if (!boost::filesystem::exists(path))
      return;
    boost::filesystem::remove(path);
  }

  void HashedStorage::Traverse(std::vector<std::string> & files) {
    boost::filesystem::path p(root);
    boost::filesystem::recursive_directory_iterator it(p);
    boost::filesystem::recursive_directory_iterator end;

    for ( ; it != end; it++) {
      if (!boost::filesystem::is_regular_file( it->status() ))
        continue;
      const std::string & t = it->path().string();
      files.push_back(t);
    }
  }
} // fs
} // i2p
