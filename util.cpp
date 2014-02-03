#include <string>
#include <algorithm>
#include <cctype>
#include <functional>
#include <fstream>
#include <set>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/algorithm/string.hpp>
#include "util.h"
#include "Log.h"

#ifdef WIN32
#include <Windows.h>
#include <shlobj.h>
#endif

namespace i2p
{
namespace util
{

namespace config
{
	std::map<std::string, std::string> mapArgs;
	std::map<std::string, std::vector<std::string> > mapMultiArgs;

	void OptionParser(int argc, const char* const argv[])
	{
		mapArgs.clear();
		mapMultiArgs.clear();
		for (int i = 1; i < argc; i++)
		{
			std::string strKey (argv[i]);
			std::string strValue;
			size_t has_data = strKey.find('=');
			if (has_data != std::string::npos)
			{
				strValue = strKey.substr(has_data+1);
				strKey = strKey.substr(0, has_data);
			}

#ifdef WIN32
			boost::to_lower(strKey);
			if (boost::algorithm::starts_with(strKey, "/"))
				strKey = "-" + strKey.substr(1);
#endif
			if (strKey[0] != '-')
				break;

			mapArgs[strKey] = strValue;
			mapMultiArgs[strKey].push_back(strValue);
		}

		BOOST_FOREACH(PAIRTYPE(const std::string,std::string)& entry, mapArgs)
		{
			std::string name = entry.first;

			//  interpret --foo as -foo (as long as both are not set)
			if (name.find("--") == 0)
			{
				std::string singleDash(name.begin()+1, name.end());
				if (mapArgs.count(singleDash) == 0)
					mapArgs[singleDash] = entry.second;
				name = singleDash;
			}
		}
	}

	const char* GetCharArg(const std::string& strArg, const std::string& nDefault)
	{
		if (mapArgs.count(strArg))
			return mapArgs[strArg].c_str();
		return nDefault.c_str();
	}

	std::string GetArg(const std::string& strArg, const std::string& strDefault)
	{
		if (mapArgs.count(strArg))
			return mapArgs[strArg];
		return strDefault;
	}

	int GetArg(const std::string& strArg, int nDefault)
	{
		if (mapArgs.count(strArg))
			return atoi(mapArgs[strArg].c_str());
		return nDefault;
	}
}

namespace filesystem
{
	const boost::filesystem::path &GetDataDir()
	{
		static boost::filesystem::path path;

		if (i2p::util::config::mapArgs.count("-datadir")) {
			path = boost::filesystem::system_complete(i2p::util::config::mapArgs["-datadir"]);
		} else {
			path = GetDefaultDataDir();
		}

		if (!boost::filesystem::exists( path ))
		{
			// Create data directory
			if (!boost::filesystem::create_directory( path ))
			{
				LogPrint("Failed to create data directory!");
				path = "";
				return path;
			}
		}
		if (!boost::filesystem::is_directory(path)) {
			path = GetDefaultDataDir();
		}
		return path;
	}

	boost::filesystem::path GetConfigFile()
	{
		boost::filesystem::path pathConfigFile(i2p::util::config::GetArg("-conf", "i2p.conf"));
		if (!pathConfigFile.is_complete()) pathConfigFile = GetDataDir() / pathConfigFile;
		return pathConfigFile;
	}

	void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet,
						std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet)
	{
		boost::filesystem::ifstream streamConfig(GetConfigFile());
		if (!streamConfig.good())
			return; // No i2pd.conf file is OK

		std::set<std::string> setOptions;
		setOptions.insert("*");

		for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
		{
			// Don't overwrite existing settings so command line settings override i2pd.conf
			std::string strKey = std::string("-") + it->string_key;
			if (mapSettingsRet.count(strKey) == 0)
			{
				mapSettingsRet[strKey] = it->value[0];
			}
			mapMultiSettingsRet[strKey].push_back(it->value[0]);
		}
	}

	boost::filesystem::path GetDefaultDataDir()
	{
		// Windows < Vista: C:\Documents and Settings\Username\Application Data\i2pd
		// Windows >= Vista: C:\Users\Username\AppData\Roaming\i2pd
		// Mac: ~/Library/Application Support/i2pd
		// Unix: ~/.i2pd
#ifdef WIN32
		// Windows
		char localAppData[MAX_PATH];
		SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, localAppData);
		return boost::filesystem::path(std::string(localAppData) + "\\i2pd");
#else
		boost::filesystem::path pathRet;
		char* pszHome = getenv("HOME");
		if (pszHome == NULL || strlen(pszHome) == 0)
			pathRet = boost::filesystem::path("/");
		else
			pathRet = boost::filesystem::path(pszHome);
#ifdef MAC_OSX
		// Mac
		pathRet /= "Library/Application Support";
		boost::filesystem::create_directory(pathRet);
		return pathRet / "i2pd";
#else
		// Unix
		return pathRet / ".i2pd";
#endif
#endif
	}
}

namespace http
{
	std::string httpRequest(const std::string& address)
	{
		try
		{
			i2p::util::http::url u(address);
			boost::asio::ip::tcp::iostream site;
			// please don't uncomment following line because it's not compatible with boost 1.46
			// 1.46 is default boost for Ubuntu 12.04 LTS
			//site.expires_from_now (boost::posix_time::seconds(30));
			site.connect(u.host_, "http");
			if (site)
			{
				// User-Agent is needed to get the server list routerInfo files.
				site << "GET " << u.path_ << " HTTP/1.0\r\nHost: " << u.host_
				<< "\r\nAccept: */*\r\n" << "User-Agent: Wget/1.11.4\r\n" << "Connection: close\r\n\r\n";
				// read response
				std::string version, statusMessage;
				site >> version; // HTTP version
				int status;
				site >> status; // status
				std::getline (site, statusMessage);
				if (status == 200) // OK
				{
					std::string header;
					while (std::getline(site, header) && header != "\r"){}
					std::stringstream ss;
					ss << site.rdbuf();
					return ss.str();
				}
				else
				{
					LogPrint ("HTTP response ", status);
					return "";
				}
			}
			else
			{
				LogPrint ("Can't connect to ", address);
				return "";
			}
		}
		catch (std::exception& ex)
		{
			LogPrint ("Failed to download ", address, " : ", ex.what ());
			return "";
		}
	}

	url::url(const std::string& url_s)
	{
		parse(url_s);
	}

	void url::parse(const std::string& url_s)
	{
		const std::string prot_end("://");
		std::string::const_iterator prot_i = search(url_s.begin(), url_s.end(),
										   prot_end.begin(), prot_end.end());
		protocol_.reserve(distance(url_s.begin(), prot_i));
		transform(url_s.begin(), prot_i,
			  back_inserter(protocol_),
			  std::ptr_fun<int,int>(tolower)); // protocol is icase
		if( prot_i == url_s.end() )
			return;
		advance(prot_i, prot_end.length());
		std::string::const_iterator path_i = find(prot_i, url_s.end(), '/');
		host_.reserve(distance(prot_i, path_i));
		transform(prot_i, path_i,
			  back_inserter(host_),
			  std::ptr_fun<int,int>(tolower)); // host is icase
		std::string::const_iterator query_i = find(path_i, url_s.end(), '?');
		path_.assign(path_i, query_i);
		if( query_i != url_s.end() )
			++query_i;
		query_.assign(query_i, url_s.end());
	}

}




} // Namespace end
}
