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

        /**
         * Parses command line arguments, i.e. stores them in config::mapArgs.
         */
        void OptionParser(int argc, const char* const argv[]);

        /**
         * @return a command line argument from config::mapArgs as an int
         * @param nDefault the default value to be returned
         */
        int GetArg(const std::string& strArg, int nDefault);

        /**
         * @return a command line argument from config::mapArgs as a std::string
         * @param strDefault the default value to be returned
         */
        std::string GetArg(const std::string& strArg, const std::string& strDefault);

        /**
         * @return a command line argument from config::mapArgs as a C-style string
         * @param nDefault the default value to be returned
         */
        const char* GetCharArg(const std::string& strArg, const std::string& nDefault);
    }

    namespace filesystem
    {
        /**
         * Change the application name.
         */
        void SetAppName(const std::string& name);

        /**
         * @return the application name.
         */
        std::string GetAppName();

        /**
         * @return the path of the i2pd directory
         */
        const boost::filesystem::path& GetDataDir();

        /**
         * @return the full path of a file within the i2pd directory
         */
        std::string GetFullPath(const std::string& filename);

        /**
         * @return the path of the configuration file
         */
        boost::filesystem::path GetConfigFile();

        /**
         * @return the path of the tunnels configuration file
         */
        boost::filesystem::path GetTunnelsConfigFile();

        /**
         * @return the default directory for i2pd data
         */
        boost::filesystem::path GetDefaultDataDir();

        
        /**
         * Read a configuration file and store its contents in the given maps.
         */
        void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet,
                std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);

        /**
         * @return the path of the certificates directory
         */
        boost::filesystem::path GetCertificatesDir();
    }

    namespace http
    {
        const char ETAG[] = "ETag";
        const char IF_NONE_MATCH[] = "If-None-Match";
        const char IF_MODIFIED_SINCE[] = "If-Modified-Since";
        const char LAST_MODIFIED[] = "Last-Modified";
        const char TRANSFER_ENCODING[] = "Transfer-Encoding";

        /**
         * Perform an HTTP request.
         * @return the result of the request, or an empty string if it fails
         */
        std::string httpRequest(const std::string& address);

        /**
         * @return the content of the given HTTP stream without headers
         */
        std::string GetHttpContent(std::istream& response);

        /**
         * Merge chunks of a HTTP response into the gien std:ostream object.
         */
        void MergeChunkedResponse(std::istream& response, std::ostream& merged);

        /**
         * Send an HTTP request through the i2p proxy.
         * @return the HTTP status code 
         */
        int httpRequestViaI2pProxy(const std::string& address, std::string &content);


        /**
         * @return the decoded url
         */
        std::string urlDecode(const std::string& data);
        
        /**
         * Provides functionality for parsing URLs.
         */
        struct url {
            /**
             * Parse a url given as a string.
             */
            url(const std::string& url_s);
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
        /**
         * @return the maximum transmission unit, or 576 on failure
         */
        int GetMTU(const boost::asio::ip::address& localAddress);
    }
}
}


#endif
