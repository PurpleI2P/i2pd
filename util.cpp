#include <string>
#include <algorithm>
#include <cctype>
#include <functional>
#include <fstream>
#include <boost/asio.hpp>
#include "util.h"
#include "Log.h"

namespace i2p
{
namespace util
{
std::map<std::string, std::string> mapArgs;

void OptionParser(int argc, const char* const argv[])
{
	mapArgs.clear();
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
    	if (strKey[0] != '-')
    		break;

        mapArgs[strKey] = strValue;
    }
}

int GetIntArg(const std::string& strArg, int nDefault)
{
    if (mapArgs.count(strArg))
        return atoi(mapArgs[strArg].c_str());
    return nDefault;
}

const char* GetCharArg(const std::string& strArg, const std::string& nDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg].c_str();
    return nDefault.c_str();
}

namespace http
{
	std::string httpRequest(const std::string& address)
	{
		try
		{
			i2p::util::http::url u(address);
			boost::asio::ip::tcp::iostream site;
			site.expires_from_now (boost::posix_time::seconds(30));
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
