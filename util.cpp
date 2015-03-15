#include <cstdlib>
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
#include <boost/lexical_cast.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/algorithm/string.hpp>
#include "util.h"
#include "Log.h"

#if defined(__linux__) || defined(__FreeBSD_kernel__)
#include <sys/types.h>
#include <ifaddrs.h>
#elif defined(WIN32)
#include <stdlib.h>
#include <string.h>
#include <stdio.h>    
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shlobj.h>

#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int inet_pton(int af, const char *src, void *dst)
{ /* This function was written by Petar Korponai?. See
http://stackoverflow.com/questions/15660203/inet-pton-identifier-not-found */
	struct sockaddr_storage ss;
	int size = sizeof (ss);
	char src_copy[INET6_ADDRSTRLEN + 1];

	ZeroMemory (&ss, sizeof (ss));
	strncpy_s (src_copy, src, INET6_ADDRSTRLEN + 1);
	src_copy[INET6_ADDRSTRLEN] = 0;

	if (WSAStringToAddress (src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0)
	{
		switch (af)
		{
		case AF_INET:
			*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
			return 1;
		case AF_INET6:
			*(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
			return 1;
		}
	}
	return 0;
}
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
	std::string appName ("i2pd");	

	void SetAppName (const std::string& name)
	{
		appName = name;
	}

	std::string GetAppName ()
	{
		return appName;
	}

	const boost::filesystem::path &GetDataDir()
	{
		static boost::filesystem::path path;

		// TODO: datadir parameter is useless because GetDataDir is called before OptionParser
		// and mapArgs is not initialized yet
		/*if (i2p::util::config::mapArgs.count("-datadir")) 
			path = boost::filesystem::system_complete(i2p::util::config::mapArgs["-datadir"]);
		else */
			path = GetDefaultDataDir();

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
		if (!boost::filesystem::is_directory(path)) 
			path = GetDefaultDataDir();
		return path;
	}

	std::string GetFullPath (const std::string& filename)
	{
		std::string fullPath = GetDataDir ().string ();
#ifndef _WIN32
		fullPath.append ("/");
#else
		fullPath.append ("\\");
#endif
		fullPath.append (filename);
		return fullPath;
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
		// Unix: ~/.i2pd or /var/lib/i2pd is system=1
#ifdef WIN32
		// Windows
		char localAppData[MAX_PATH];
		SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, localAppData);
		return boost::filesystem::path(std::string(localAppData) + "\\" + appName);
#else
		if (i2p::util::config::GetArg("-service", 0)) // use system folder
			return boost::filesystem::path(std::string ("/var/lib/") + appName);
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
		return pathRet / appName;
#else
		// Unix
		return pathRet / (std::string (".") + appName);
#endif
#endif
	}

	boost::filesystem::path GetCertificatesDir()
	{
		return GetDataDir () / "certificates";
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
			if (u.port_ == 80)
				site.connect(u.host_, "http");
			else
			{
				std::stringstream ss; ss << u.port_;
				site.connect(u.host_, ss.str());
			}
			if (site)
			{
				// User-Agent is needed to get the server list routerInfo files.
				site << "GET " << u.path_ << " HTTP/1.1\r\nHost: " << u.host_
				<< "\r\nAccept: */*\r\n" << "User-Agent: Wget/1.11.4\r\n" << "Connection: close\r\n\r\n";
				// read response and extract content				
				return GetHttpContent (site);
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

	std::string GetHttpContent (std::istream& response)
	{
		std::string version, statusMessage;
		response >> version; // HTTP version
		int status;
		response >> status; // status
		std::getline (response, statusMessage);
		if (status == 200) // OK
		{
			bool isChunked = false;
			std::string header;
			while (!response.eof () && header != "\r")
			{
				std::getline(response, header);
				auto colon = header.find (':');
				if (colon != std::string::npos)
				{
					std::string field = header.substr (0, colon);
					if (field == i2p::util::http::TRANSFER_ENCODING)
						isChunked = (header.find ("chunked", colon + 1) != std::string::npos);
				}	
			}

			std::stringstream ss;
			if (isChunked)
				MergeChunkedResponse (response, ss);
			else	
				ss << response.rdbuf();
			return ss.str();
		}
		else
		{
			LogPrint ("HTTP response ", status);
			return "";
		}
	}

	void MergeChunkedResponse (std::istream& response, std::ostream& merged)
	{
		while (!response.eof ())
		{	
			std::string hexLen;
			int len;
			std::getline (response, hexLen);
			std::istringstream iss (hexLen);
			iss >> std::hex >> len;
			if (!len) break;
			char * buf = new char[len];
			response.read (buf, len);
			merged.write (buf, len);
			delete[] buf;
			std::getline (response, hexLen); // read \r\n after chunk
		}
	}	
	
	int httpRequestViaI2pProxy(const std::string& address, std::string &content)
	{
		content = "";
		try
		{
			boost::asio::ip::tcp::iostream site;
			// please don't uncomment following line because it's not compatible with boost 1.46
			// 1.46 is default boost for Ubuntu 12.04 LTS
			//site.expires_from_now (boost::posix_time::seconds(30));
			{
				std::stringstream ss; ss << i2p::util::config::GetArg("-httpproxyport", 4446);
				site.connect("127.0.0.1", ss.str());
			}
			if (site)
			{
				i2p::util::http::url u(address);
				std::stringstream ss;
				ss << "GET " << address << " HTTP/1.0" << std::endl;
				ss << "Host: " << u.host_ << std::endl;
				ss << "Accept: */*" << std::endl;
				ss << "User - Agent: Wget / 1.11.4" << std::endl;
				ss << "Connection: close" << std::endl;
				ss << std::endl;
				site << ss.str();

				// read response
				std::string version, statusMessage;
				site >> version; // HTTP version
				int status;
				site >> status; // status
				std::getline(site, statusMessage);
				if (status == 200) // OK
				{
					std::string header;
					while (std::getline(site, header) && header != "\r"){}
					std::stringstream ss;
					ss << site.rdbuf();
					content = ss.str();
					return status;
				}
				else
				{
					LogPrint("HTTP response ", status);
					return status;
				}
			}
			else
			{
				LogPrint("Can't connect to proxy");
				return 408;
			}
		}
		catch (std::exception& ex)
		{
			LogPrint("Failed to download ", address, " : ", ex.what());
			return 408;
		}
	}
	
	url::url(const std::string& url_s)
	{
		portstr_ = "80";
		port_ = 80;
		user_ = "";
		pass_ = "";

		parse(url_s);
	}


	// code for parser tests
	//{
    //  i2p::util::http::url u_0("http://127.0.0.1:7070/asdasd?qqqqqqqqqqqq");
	//	i2p::util::http::url u_1("http://user:password@site.com:8080/asdasd?qqqqqqqqqqqqq");
	//	i2p::util::http::url u_2("http://user:password@site.com/asdasd?qqqqqqqqqqqqqq");
	//	i2p::util::http::url u_3("http://user:@site.com/asdasd?qqqqqqqqqqqqq");
	//	i2p::util::http::url u_4("http://user@site.com/asdasd?qqqqqqqqqqqq");
	//	i2p::util::http::url u_5("http://@site.com:800/asdasd?qqqqqqqqqqqq");
	//	i2p::util::http::url u_6("http://@site.com:err_port/asdasd?qqqqqqqqqqqq");
    //	i2p::util::http::url u_7("http://user:password@site.com:err_port/asdasd?qqqqqqqqqqqq");
	//}
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

		// parse user/password
		auto user_pass_i = find(host_.begin(), host_.end(), '@');
		if (user_pass_i != host_.end())
		{
			std::string user_pass = std::string(host_.begin(), user_pass_i);
			auto pass_i = find(user_pass.begin(), user_pass.end(), ':');
			if (pass_i != user_pass.end())
			{
				user_ = std::string(user_pass.begin(), pass_i);
				pass_ = std::string(pass_i + 1, user_pass.end());
			}
			else
				user_ = user_pass;

			host_.assign(user_pass_i + 1, host_.end());
		}

		// parse port
		auto port_i = find(host_.begin(), host_.end(), ':');
		if (port_i != host_.end())
		{
			portstr_ = std::string(port_i + 1, host_.end());
			host_.assign(host_.begin(), port_i);
			try{
				port_ = boost::lexical_cast<decltype(port_)>(portstr_);
			}
			catch (std::exception e) {
				port_ = 80;
			}
		}

		std::string::const_iterator query_i = find(path_i, url_s.end(), '?');
		path_.assign(path_i, query_i);
		if( query_i != url_s.end() )
			++query_i;
		query_.assign(query_i, url_s.end());
	}

	std::string urlDecode(const std::string& data)
	{
		std::string res(data);
		for (size_t pos = res.find('%'); pos != std::string::npos; pos = res.find('%',pos+1))
		{
			char c = strtol(res.substr(pos+1,2).c_str(), NULL, 16);
			res.replace(pos,3,1,c);
		}
		return res;
	}
} 

namespace net
{
	int GetMTU (const boost::asio::ip::address& localAddress)
	{
#if defined(__linux__) || defined(__FreeBSD_kernel__)	
		ifaddrs * ifaddr, * ifa = nullptr;
		if (getifaddrs(&ifaddr) == -1) 
		{
        	LogPrint (eLogError, "Can't excute getifaddrs");
            return 0;
        }
		int family = 0;
		// loook for interface matching local address	
		for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) 
		{
			if (!ifa->ifa_addr) continue;
        	family = ifa->ifa_addr->sa_family;
			if (family == AF_INET && localAddress.is_v4 ())
			{
				sockaddr_in * sa = (sockaddr_in *)ifa->ifa_addr;
				if (!memcmp (&sa->sin_addr, localAddress.to_v4 ().to_bytes ().data (), 4))
					break; // address matches
			}
			else if (family == AF_INET6 && localAddress.is_v6 ())
			{
				sockaddr_in6 * sa = (sockaddr_in6 *)ifa->ifa_addr;
				if (!memcmp (&sa->sin6_addr, localAddress.to_v6 ().to_bytes ().data (), 16))
					break; // address matches
			}
		}
		int mtu = 0;
		if (ifa && family) // interface found?
		{
			int fd = socket (family, SOCK_DGRAM, 0);
			if (fd > 0)
			{
				ifreq ifr;
				strncpy (ifr.ifr_name, ifa->ifa_name, IFNAMSIZ); // set interface for query
				if (ioctl (fd, SIOCGIFMTU, &ifr) >= 0)	
					mtu = ifr.ifr_mtu; // MTU
				else
					LogPrint (eLogError, "Failed to run ioctl");			
				close (fd);
			} 
			else
				LogPrint (eLogError, "Failed to create datagram socket");	
		}		
		else
			LogPrint (eLogWarning, "Interface for local address", localAddress.to_string (), " not found");

		freeifaddrs	(ifaddr);
		return mtu;
#elif defined(WIN32)

		int result = 576; // fallback MTU

		DWORD dwRetVal = 0;
		ULONG outBufLen = 0;
		PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
		PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
		PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;

#ifdef UNICODE
		string localAddress_temporary = localAddress.to_string();
		wstring localAddressUniversal (localAddress_temporary.begin(), localAddress_temporary.end());
#else
		std::string localAddressUniversal = localAddress.to_string();
#endif

		if (localAddress.is_v4())
		{
			struct sockaddr_in inputAddress;
			inet_pton(AF_INET, localAddressUniversal.c_str(), &(inputAddress.sin_addr));

			if (GetAdaptersAddresses (AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
				== ERROR_BUFFER_OVERFLOW)
			{
				FREE (pAddresses);
				pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC (outBufLen);
			}

			dwRetVal = GetAdaptersAddresses (AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
			if (dwRetVal == NO_ERROR)
			{
				pCurrAddresses = pAddresses;
				while (pCurrAddresses)
				{
					PIP_ADAPTER_UNICAST_ADDRESS firstUnicastAddress = pCurrAddresses->FirstUnicastAddress;

					pUnicast = pCurrAddresses->FirstUnicastAddress;
					if (pUnicast != nullptr)
					{
						for (int i = 0; pUnicast != nullptr; ++i)
						{
							LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
							struct sockaddr_in *localInterfaceAddress = (struct sockaddr_in*) lpAddr;
							if (localInterfaceAddress->sin_addr.S_un.S_addr == inputAddress.sin_addr.S_un.S_addr)
							{
								result = pAddresses->Mtu;
								FREE (pAddresses);
								pAddresses = nullptr;
								return result;
							}
							pUnicast = pUnicast->Next;
						}
					}
					else
					{
						LogPrint (eLogError, "GetMTU() has failed: not a unicast ipv4 address, this is not supported");
					}

					pCurrAddresses = pCurrAddresses->Next;
				}

		}
		else
		{
			LogPrint (eLogError, "GetMTU() has failed: enclosed GetAdaptersAddresses() call has failed");
		}

		}
		else if (localAddress.is_v6())
		{
			struct sockaddr_in6 inputAddress;
			inet_pton(AF_INET6, localAddressUniversal.c_str(), &(inputAddress.sin6_addr));

			if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen)
				== ERROR_BUFFER_OVERFLOW)
			{
				FREE (pAddresses);
				pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC (outBufLen);
			}

			dwRetVal = GetAdaptersAddresses (AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
			if (dwRetVal == NO_ERROR)
			{
				bool found_address = false;
				pCurrAddresses = pAddresses;
				while (pCurrAddresses)
				{
					PIP_ADAPTER_UNICAST_ADDRESS firstUnicastAddress = pCurrAddresses->FirstUnicastAddress;

					pUnicast = pCurrAddresses->FirstUnicastAddress;
					if (pUnicast != nullptr)
					{
						for (int i = 0; pUnicast != nullptr; ++i)
						{
							LPSOCKADDR lpAddr = pUnicast->Address.lpSockaddr;
							struct sockaddr_in6 *localInterfaceAddress = (struct sockaddr_in6*) lpAddr;

							for (int j = 0; j != 8; ++j)
							{
								if (localInterfaceAddress->sin6_addr.u.Word[j] != inputAddress.sin6_addr.u.Word[j])
								{
									break;
								}
								else
								{
									found_address = true;
								}
							}
							if (found_address)
							{
								result = pAddresses->Mtu;
								FREE (pAddresses);
								pAddresses = nullptr;
								return result;
							}
							pUnicast = pUnicast->Next;
						}
					}
					else
					{
						LogPrint (eLogError, "GetMTU() has failed: not a unicast ipv6 address, this is not supported");
					}

					pCurrAddresses = pCurrAddresses->Next;
				}

			}
			else
			{
				LogPrint (eLogError, "GetMTU() has failed: enclosed GetAdaptersAddresses() call has failed");
			}
		}
		else
		{
			LogPrint (eLogError, "GetMTU() has failed: address family is not supported");
		}

	FREE (pAddresses);
	pAddresses = nullptr;
	LogPrint(eLogError, "GetMTU() error: control flow should never reach this line");
	return result;
#endif
	}
} 

} // util
} // i2p
