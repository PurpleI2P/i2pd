#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#define PAIRTYPE(t1, t2)    std::pair<t1, t2>

namespace i2p
{
namespace util
{
	namespace config
	{
		extern std::map<std::string, std::string> mapArgs;
		extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
		void OptionParser(int argc, const char* const argv[]);
		int GetArg(const std::string& strArg, int nDefault);
		std::string GetArg(const std::string& strArg, const std::string& strDefault);
		const char* GetCharArg(const std::string& strArg, const std::string& nDefault);
	}

	namespace filesystem
	{
		void SetAppName (const std::string& name);
		std::string GetAppName ();

		const boost::filesystem::path &GetDataDir();
		std::string GetFullPath (const std::string& filename);	
		boost::filesystem::path GetDefaultDataDir();
		boost::filesystem::path GetConfigFile();
		void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet,
                std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
		boost::filesystem::path GetCertificatesDir();
	}

	namespace http
	{
		const char ETAG[] = "ETag";
		const char IF_NONE_MATCH[] = "If-None-Match";
		const char IF_MODIFIED_SINCE[] = "If-Modified-Since";
		const char LAST_MODIFIED[] = "Last-Modified";
		const char TRANSFER_ENCODING[] = "Transfer-Encoding";

		std::string httpRequest(const std::string& address);
		void MergeChunkedResponse (std::istream& response, std::ostream& merged);
		int httpRequestViaI2pProxy(const std::string& address, std::string &content); // return http code
		
		struct url {
    			url(const std::string& url_s); // omitted copy, ==, accessors, ...
			private:
    			void parse(const std::string& url_s);
			public:
				std::string protocol_, host_, path_, query_;
				std::string portstr_;
				unsigned int port_;
				std::string user_;
				std::string pass_;
		};
	}

	namespace net
	{
		int GetMTU (const boost::asio::ip::address& localAddress);
	}
}
}


#endif
