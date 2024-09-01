/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>

#if defined(MAC_OSX)
#if !STD_FILESYSTEM
#include <boost/system/system_error.hpp>
#endif
#include <TargetConditionals.h>
#endif

#ifdef _WIN32
#include <shlobj.h>
#include <windows.h>
#include <codecvt>
#endif

#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Garlic.h"

#if STD_FILESYSTEM
#include <filesystem>
namespace fs_lib = std::filesystem;
#else
#include <boost/filesystem.hpp>
namespace fs_lib = boost::filesystem;
#endif

namespace i2p {
namespace fs {
	std::string appName = "i2pd";
	std::string dataDir = "";
	std::string certsDir = "";
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

	const std::string & GetCertsDir () {
		return certsDir;
	}

	const std::string GetUTF8DataDir () {
#ifdef _WIN32
		int size = MultiByteToWideChar(CP_ACP, 0,
			dataDir.c_str(), dataDir.size(), nullptr, 0);
		std::wstring utf16Str(size, L'\0');
		MultiByteToWideChar(CP_ACP, 0,
			dataDir.c_str(), dataDir.size(), &utf16Str[0], size);
		int utf8Size = WideCharToMultiByte(CP_UTF8, 0,
			utf16Str.c_str(), utf16Str.size(), nullptr, 0, nullptr, nullptr);
		std::string utf8Str(utf8Size, '\0');
		WideCharToMultiByte(CP_UTF8, 0,
			utf16Str.c_str(), utf16Str.size(), &utf8Str[0], utf8Size, nullptr, nullptr);
		return utf8Str;
#else
		return dataDir; // linux, osx, android uses UTF-8 by default
#endif
	}

	void DetectDataDir(const std::string & cmdline_param, bool isService) {
		// with 'datadir' option
		if (cmdline_param != "") {
			dataDir = cmdline_param;
			return;
		}

#if !defined(MAC_OSX) && !defined(ANDROID)
		// with 'service' option
		if (isService) {
#ifdef _WIN32
			wchar_t commonAppData[MAX_PATH];
			if(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, commonAppData) != S_OK)
			{
#ifdef WIN32_APP
				MessageBox(NULL, TEXT("Unable to get common AppData path!"), TEXT("I2Pd: error"), MB_ICONERROR | MB_OK);
#else
				fprintf(stderr, "Error: Unable to get common AppData path!");
#endif
				exit(1);
			}
			else
			{
#if ((BOOST_VERSION >= 108500) || STD_FILESYSTEM)
				dataDir = fs_lib::path(commonAppData).string() + "\\" + appName;
#else
				dataDir = fs_lib::wpath(commonAppData).string() + "\\" + appName;
#endif
			}
#else
			dataDir = "/var/lib/" + appName;
#endif
			return;
		}
#endif

		// detect directory as usual
#ifdef _WIN32
		wchar_t localAppData[MAX_PATH];

		// check executable directory first
		if(!GetModuleFileNameW(NULL, localAppData, MAX_PATH))
		{
#ifdef WIN32_APP
			MessageBox(NULL, TEXT("Unable to get application path!"), TEXT("I2Pd: error"), MB_ICONERROR | MB_OK);
#else
			fprintf(stderr, "Error: Unable to get application path!");
#endif
			exit(1);
		}
		else
		{
#if ((BOOST_VERSION >= 108500) || STD_FILESYSTEM)
			auto execPath = fs_lib::path(localAppData).parent_path();
#else
			auto execPath = fs_lib::wpath(localAppData).parent_path();
#endif

			// if config file exists in .exe's folder use it
			if(fs_lib::exists(execPath/"i2pd.conf")) // TODO: magic string
			{
				dataDir = execPath.string ();
			} else // otherwise %appdata%
			{
				if(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, localAppData) != S_OK)
				{
#ifdef WIN32_APP
					MessageBox(NULL, TEXT("Unable to get AppData path!"), TEXT("I2Pd: error"), MB_ICONERROR | MB_OK);
#else
					fprintf(stderr, "Error: Unable to get AppData path!");
#endif
					exit(1);
				}
				else
				{
#if ((BOOST_VERSION >= 108500) || STD_FILESYSTEM)
					dataDir = fs_lib::path(localAppData).string() + "\\" + appName;
#else
					dataDir = fs_lib::wpath(localAppData).string() + "\\" + appName;
#endif
				}
			}
		}
		return;
#elif defined(MAC_OSX)
		char *home = getenv("HOME");
		dataDir = (home != NULL && strlen(home) > 0) ? home : "";
		dataDir += "/Library/Application Support/" + appName;
		return;
#elif defined(__HAIKU__)
		char *home = getenv("HOME");
		if (home != NULL && strlen(home) > 0) {
			dataDir = std::string(home) + "/config/settings/" + appName;
		} else {
			dataDir = "/tmp/" + appName;
		}
		return;
#else /* other unix */
#if defined(ANDROID)
		const char * ext = getenv("EXTERNAL_STORAGE");
		if (!ext) ext = "/sdcard";
		if (fs_lib::exists(ext))
		{
			dataDir = std::string (ext) + "/" + appName;
			return;
		}
#endif // ANDROID
		// use /home/user/.i2pd or /tmp/i2pd
		char *home = getenv("HOME");
		if (home != NULL && strlen(home) > 0) {
			dataDir = std::string(home) + "/." + appName;
		} else {
			dataDir = "/tmp/" + appName;
		}
		return;
#endif
	}

	void SetCertsDir(const std::string & cmdline_certsdir) {
		if (cmdline_certsdir != "")
		{
			if (cmdline_certsdir[cmdline_certsdir.length()-1] == '/')
				certsDir = cmdline_certsdir.substr(0, cmdline_certsdir.size()-1); // strip trailing slash
			else
				certsDir = cmdline_certsdir;
		}
		else
		{
			certsDir = i2p::fs::DataDirPath("certificates");
		}
		return;
	}

	bool Init() {
		if (!fs_lib::exists(dataDir))
			fs_lib::create_directory(dataDir);

		std::string destinations = DataDirPath("destinations");
		if (!fs_lib::exists(destinations))
			fs_lib::create_directory(destinations);

		std::string tags = DataDirPath("tags");
		if (!fs_lib::exists(tags))
			fs_lib::create_directory(tags);
		else
			i2p::garlic::CleanUpTagsFiles ();

		return true;
	}

	bool ReadDir(const std::string & path, std::vector<std::string> & files) {
		if (!fs_lib::exists(path))
			return false;
		fs_lib::directory_iterator it(path);
		fs_lib::directory_iterator end;

		for ( ; it != end; it++) {
			if (!fs_lib::is_regular_file(it->status()))
				continue;
			files.push_back(it->path().string());
		}

		return true;
	}

	bool Exists(const std::string & path) {
		return fs_lib::exists(path);
	}

	uint32_t GetLastUpdateTime (const std::string & path)
	{
		if (!fs_lib::exists(path))
			return 0;
#if STD_FILESYSTEM
		std::error_code ec;
		auto t = std::filesystem::last_write_time (path, ec);
		if (ec) return 0;
/*#if __cplusplus >= 202002L // C++ 20 or higher
		const auto sctp = std::chrono::clock_cast<std::chrono::system_clock>(t);
#else	*/	// TODO: wait until implemented
		const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
		    t - decltype(t)::clock::now() + std::chrono::system_clock::now());
/*#endif */	
   		return std::chrono::system_clock::to_time_t(sctp);	
#else		
		boost::system::error_code ec;
		auto t = boost::filesystem::last_write_time (path, ec);
		return ec ? 0 : t;
#endif		
	}

	bool Remove(const std::string & path) {
		if (!fs_lib::exists(path))
			return false;
		return fs_lib::remove(path);
	}

	bool CreateDirectory (const std::string& path)
	{
		if (fs_lib::exists(path) && fs_lib::is_directory (fs_lib::status (path)))
			return true;
		return fs_lib::create_directory(path);
	}

	void HashedStorage::SetPlace(const std::string &path) {
		root = path + i2p::fs::dirSep + name;
	}

	bool HashedStorage::Init(const char * chars, size_t count) {
		if (!fs_lib::exists(root)) {
			fs_lib::create_directories(root);
		}

		for (size_t i = 0; i < count; i++) {
			auto p = root + i2p::fs::dirSep + prefix1 + chars[i];
			if (fs_lib::exists(p))
				continue;
#if TARGET_OS_SIMULATOR
			// ios simulator fs says it is case sensitive, but it is not
			boost::system::error_code ec;
			if (fs_lib::create_directory(p, ec))
				continue;
			switch (ec.value()) {
				case boost::system::errc::file_exists:
				case boost::system::errc::success:
					continue;
				default:
					throw boost::system::system_error( ec, __func__ );
			}
#else
			if (fs_lib::create_directory(p))
				continue; /* ^ throws exception on failure */
#endif
			return false;
		}
		return true;
	}

	std::string HashedStorage::Path(const std::string & ident) const {
		std::string safe_ident = ident;
		std::replace(safe_ident.begin(), safe_ident.end(), '/',	'-');
		std::replace(safe_ident.begin(), safe_ident.end(), '\\', '-');

		std::stringstream t("");
		t << this->root << i2p::fs::dirSep;
		t << prefix1 << safe_ident[0] << i2p::fs::dirSep;
		t << prefix2 << safe_ident    << "." << suffix;

		return t.str();
	}

	void HashedStorage::Remove(const std::string & ident) {
		std::string path = Path(ident);
		if (!fs_lib::exists(path))
			return;
		fs_lib::remove(path);
	}

	void HashedStorage::Traverse(std::vector<std::string> & files) {
		Iterate([&files] (const std::string & fname) {
			files.push_back(fname);
		});
	}

	void HashedStorage::Iterate(FilenameVisitor v)
	{
		fs_lib::path p(root);
		fs_lib::recursive_directory_iterator it(p);
		fs_lib::recursive_directory_iterator end;

		for ( ; it != end; it++) {
			if (!fs_lib::is_regular_file( it->status() ))
				continue;
			const std::string & t = it->path().string();
			v(t);
		}
	}
} // fs
} // i2p
