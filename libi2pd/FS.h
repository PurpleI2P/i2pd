/*
* Copyright (c) 2013-2026, The PurpleI2P Project
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
#include <span>
#include <functional>
#include <filesystem>
#include <inttypes.h>

namespace i2p
{
namespace fs
{
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
	class HashedStorage final
	{
		public:

			using FilenameVisitor = std::function<void(const std::filesystem::path& )>;
			HashedStorage(const std::filesystem::path& n, std::string_view p1, std::string_view p2, std::string_view s):
				name(n), prefix1(p1), prefix2(p2), suffix(s) {};

			/** create subdirs in storage */
			bool Init(std::span<const char> chars);
			const std::filesystem::path& GetRoot() const { return root; }
			const std::filesystem::path& GetName() const { return name; }
			/** set directory where to place storage directory */
			void SetPlace (const std::filesystem::path& p);
			/** path to file with given ident */
			std::filesystem::path Path(const std::string& ident) const;
			/** remove file by ident */
			void Remove(const std::string& ident);
			/** find all files in storage and return  */
			std::vector<std::filesystem::path> Traverse ();
			/** visit every file in this storage with a visitor */
			void Iterate(FilenameVisitor v);

		private:

			std::filesystem::path root;    /**< path to storage with it's name included */
			std::filesystem::path name;    /**< name of the storage */
			std::string prefix1; /**< hashed directory prefix */
			std::string prefix2; /**< prefix of file in storage */
			std::string suffix;  /**< suffix of file in storage (extension) */
	};

	/** @brief Returns current application name, default 'i2pd' */
	const std::string & GetAppName ();
	/** @brief Set application name, affects autodetection of datadir */
	void SetAppName (const std::string& name);

	/** @brief Returns datadir path */
	const std::filesystem::path& GetDataDir();

	/** @brief Returns certsdir path */
	const std::filesystem::path& GetCertsDir();

	/** @brief Returns datadir path in UTF-8 encoding */
	std::string GetUTF8DataDir();

	/**
	 * @brief Set datadir either from cmdline option or using autodetection
	 * @param cmdline_param Value of cmdline parameter --datadir=<something>
	 * @param isService Value of cmdline parameter --service
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
	 * @brief Set certsdir either from cmdline option or using autodetection
	 * @param cmdline_param Value of cmdline parameter --certsdir=<something>
	 *
	 * Examples of autodetected paths:
	 *
	 *   Windows < Vista: C:\Documents and Settings\Username\Application Data\i2pd\certificates
	 *   Windows >= Vista: C:\Users\Username\AppData\Roaming\i2pd\certificates
	 *   Mac: /Library/Application Support/i2pd/ or ~/Library/Application Support/i2pd/certificates
	 *   Unix: /var/lib/i2pd/certificates (system=1) >> ~/.i2pd/ or /tmp/i2pd/certificates
	 */
	void SetCertsDir(const std::string & cmdline_certsdir);

	/**
	 * @brief Create subdirectories inside datadir
	 */
	bool Init();

	/**
	 * @brief Get list of files in directory
	 * @param path Path to directory
	 * @param files Vector to store found files
	 * @return true on success and false if directory not exists
	 */
	bool ReadDir(const std::filesystem::path& path, std::vector<std::filesystem::path> & files);

	/**
	 * @brief Remove file with given path
	 * @param path Absolute path to file
	 * @return true on success, false if file not exists, throws exception on error
	 */
	bool Remove (const std::filesystem::path& path);

	bool Rename (std::string_view from, std::string_view to);

	uint32_t GetLastUpdateTime (const std::filesystem::path& path); // seconds since epoch

	bool CreateDirectory (const std::filesystem::path& path);
	std::filesystem::path CreatePrivateFile (const std::filesystem::path& path);

	/**
	 * @brief Get path relative to datadir
	 *
	 * Examples (with datadir = "/tmp/i2pd"):
	 *
	 * i2p::fs::Path("test")             -> '/tmp/i2pd/test'
	 * i2p::fs::Path("test", "file.txt") -> '/tmp/i2pd/test/file.txt'
	 */
	template<typename ... Other>
	std::filesystem::path DataDirPath(Other ... components)
	{
		return (i2p::fs::GetDataDir()/.../components);
	}

	template<typename Storage, typename... Filename>
	std::filesystem::path StorageRootPath (const Storage& storage, Filename... filenames)
	{
		return storage.GetRoot ()/(filenames/...);
	}

} // fs
} // i2p

#endif // /* FS_H__ */
