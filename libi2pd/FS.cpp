/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>
#include <fstream>

#if defined(MAC_OSX)
#include <TargetConditionals.h>
#endif

#if defined(__HAIKU__)
#include <FindDirectory.h>
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

namespace i2p
{
namespace fs
{
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
				dataDir = (std::filesystem::path(commonAppData)/appName).string ();
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
			auto execPath = std::filesystem::path(localAppData).parent_path();

			// if config file exists in .exe's folder use it
			if(std::filesystem::exists(execPath/"i2pd.conf")) // TODO: magic string
				dataDir = execPath.string ();
			else // otherwise %appdata%
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
					dataDir = (std::filesystem::path(localAppData)/appName).string();
			}
		}
		return;
#elif defined(MAC_OSX)
		char *home = getenv("HOME");
		dataDir = (home != NULL && strlen(home) > 0) ? home : "";
		dataDir += "/Library/Application Support/" + appName;
		return;
#elif defined(__HAIKU__)
		char home[PATH_MAX]; // /boot/home/config/settings
		if (find_directory(B_USER_SETTINGS_DIRECTORY, -1, false, home, PATH_MAX) == B_OK)
			dataDir = std::string(home) + "/" + appName;
		else
			dataDir = "/tmp/" + appName;
		return;
#else /* other unix */
#if defined(ANDROID)
		const char * ext = getenv("EXTERNAL_STORAGE");
		if (!ext) ext = "/sdcard";
		if (std::filesystem::exists(ext))
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
		if (!std::filesystem::exists(dataDir))
			std::filesystem::create_directory(dataDir);

		std::string destinations = DataDirPath("destinations");
		if (!std::filesystem::exists(destinations))
			std::filesystem::create_directory(destinations);

		std::string tags = DataDirPath("tags");
		if (!std::filesystem::exists(tags))
			std::filesystem::create_directory(tags);
		else
			i2p::garlic::CleanUpTagsFiles ();

		return true;
	}

	bool ReadDir(const std::filesystem::path& path, std::vector<std::filesystem::path>& files)
	{
		if (!std::filesystem::exists(path))
			return false;
		std::filesystem::directory_iterator it(path);
		std::filesystem::directory_iterator end;

		for ( ; it != end; it++) {
			if (!std::filesystem::is_regular_file(it->status()))
				continue;
			files.push_back(it->path());
		}

		return true;
	}

	bool Exists(const std::string & path) {
		return std::filesystem::exists(path);
	}

	uint32_t GetLastUpdateTime (const std::string & path)
	{
		if (!std::filesystem::exists(path))
			return 0;

		std::error_code ec;
		auto t = std::filesystem::last_write_time (path, ec);
		if (ec) return 0;
#if __cpp_lib_chrono >= 201907L // std::chrono::clock_cast
		const auto sctp = std::chrono::clock_cast<std::chrono::system_clock>(t);
#else
		const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
		    t - decltype(t)::clock::now() + std::chrono::system_clock::now());
#endif
		return std::chrono::system_clock::to_time_t(sctp);
	}

	bool Remove(const std::string & path)
	{
		if (!std::filesystem::exists(path))
			return false;
		return std::filesystem::remove(path);
	}

	bool Rename (std::string_view from, std::string_view to)
	{
		try
		{
			std::filesystem::rename (from, to);
		}
		catch (std::exception& ex)
		{
			LogPrint (eLogError, "FS: Can't rename from ", from, " to ", to, " : ", ex.what());
			return false;
		}
		return true;
	}

	bool CreateDirectory (const std::string& path)
	{
		if (std::filesystem::exists(path) && std::filesystem::is_directory (std::filesystem::status (path)))
			return true;
		return std::filesystem::create_directory(path);
	}

	std::filesystem::path CreatePrivateFile (const std::filesystem::path& path)
	{
		std::ofstream f (path, std::ofstream::out | std::ofstream::app);
		std::error_code ec;
		std::filesystem::permissions (path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
			std::filesystem::perm_options::replace, ec);
		if (ec)
			LogPrint (eLogWarning, "FS: Can't restrict access to ", path.string (), ": ", ec.message ());
		return path;
	}

	void HashedStorage::SetPlace (const std::filesystem::path& p)
	{
		root = p/name;
	}

	bool HashedStorage::Init(std::span<const char> chars)
	{
		try
		{
			if (!std::filesystem::exists (root))
				std::filesystem::create_directories(root);

			for (auto ch: chars)
			{
				auto p = root/(prefix1 + ch);
				if (std::filesystem::exists(p))
					continue;
#if TARGET_OS_SIMULATOR
				// ios simulator fs says it is case sensitive, but it is not
				std::error_code ec;
				if (std::filesystem::create_directory(p, ec))
					continue;
				switch (ec.value())
				{
					case std::errc::file_exists:
					case std::errc::success:
						continue;
					default:
						throw std::system_error( ec, __func__ );
				}
#else
				if (std::filesystem::create_directory(p))
					continue; /* ^ throws exception on failure */
#endif
				return false;
			}
		}
		catch (std::exception& ex)
		{
			LogPrint (eLogCritical, "FS: Can't init storage ", root, ": ", ex.what());
			ThrowFatal ("Can't init FS storage ", root, ": ", ex.what());
			return false;
		}
		return true;
	}

	std::filesystem::path HashedStorage::Path(const std::string& ident) const
	{
		std::string safe_ident = ident;
		std::replace(safe_ident.begin(), safe_ident.end(), '/',	'-');
		std::replace(safe_ident.begin(), safe_ident.end(), '\\', '-');

		return root/(prefix1 + safe_ident[0])/(prefix2 + safe_ident + "." + suffix);
	}

	void HashedStorage::Remove(const std::string& ident)
	{
		auto p = Path (ident);
		if (!std::filesystem::exists(p))
			return;
		std::filesystem::remove(p);
	}

	std::vector<std::filesystem::path> HashedStorage::Traverse ()
	{
		std::vector<std::filesystem::path> files;
		Iterate([&files] (const std::filesystem::path& p)
			{
				files.push_back (p);
			});
		return files;
	}

	void HashedStorage::Iterate(FilenameVisitor v)
	{
		std::filesystem::recursive_directory_iterator it (root);
		std::filesystem::recursive_directory_iterator end;

		for ( ; it != end; it++)
		{
			if (!std::filesystem::is_regular_file (it->status()))
				continue;
			v(it->path ());
		}
	}
} // fs
} // i2p
