#ifndef UTIL_H
#define UTIL_H

#define BOOST_NO_CXX11_SCOPED_ENUMS // Workaround for issue #272

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

        /**
         * @return true if the argument is set, false otherwise
         */
        bool HasArg(const std::string& strArg);
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
         * @return the default directory for webui data
         */
        boost::filesystem::path GetWebuiDataDir();
        
        /**
         * Read a configuration file and store its contents in the given maps.
         */
        void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet,
                std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);

        /**
         * @return the path of the certificates directory
         */
        boost::filesystem::path GetCertificatesDir();

        /**
         * Installs the webui files.
         * @throw std::runtime_error when installation fails
         */
        void InstallFiles();

        /**
         * Copies all files and directories in src to dest.
         * @warning overrides existing files
         */
        void CopyDir(const boost::filesystem::path& src, const boost::filesystem::path& dest);
    }

    namespace http
    {
        const char ETAG[] = "ETag";
        const char IF_NONE_MATCH[] = "If-None-Match";
        const char IF_MODIFIED_SINCE[] = "If-Modified-Since";
        const char LAST_MODIFIED[] = "Last-Modified";
        const char TRANSFER_ENCODING[] = "Transfer-Encoding";

	 /**
         * Header for HTTP/S requests.
         * @return a string of the complete header
         */
	std::string httpHeader(const std::string& path, const std::string& host, const std::string& version);

        /**
         * Perform an HTTPS request.
         * @return the result of the request, or an empty string if it fails
         */
        std::string httpsRequest(const std::string& address);

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
        class url {
	    /**
	     * The code for parse() was originally copied/pasted from
	     * https://stackoverflow.com/questions/2616011/easy-way-to-parse-a-url-in-c-cross-platform
	     *
	     * This function is a URI parser (not a URL parser) and is hack at best.
	     * See cpp-netlib for a better URI parsing implementation with Boost.
	     *
	     * Note: fragments are not parsed by this function (if they should
	     * ever be needed in the future).
	     *
             * @param string url
             */
            void parse(const std::string& url);
	public:
	     /**
             * Parse a URI given as a string.
             */
            url(const std::string& url);
        public:
            std::string m_protocol, m_host, m_path, m_query, m_portstr;
            unsigned int m_port;
            std::string m_user, m_pass;
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
