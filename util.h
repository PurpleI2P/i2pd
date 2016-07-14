#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#ifdef ANDROID
namespace std
{
template <typename T>
std::string to_string(T value)
{
   return boost::lexical_cast<std::string>(value);
}
}
#endif

namespace i2p
{
namespace util
{

	/**
		 wrapper arround boost::lexical_cast that "never" fails
	 */
	template <typename T>
	T lexical_cast(const std::string & str, const T fallback) {
		try {
			return boost::lexical_cast<T>(str);
		} catch ( ... ) {
			return fallback;
		}
	}
	
	namespace http
	{
		// in (lower case)
		const char ETAG[] = "etag"; // ETag
		const char LAST_MODIFIED[] = "last-modified"; // Last-Modified
		const char TRANSFER_ENCODING[] = "transfer-encoding"; // Transfer-Encoding
		const char CONTENT_ENCODING[] = "content-encoding"; // Content-Encoding
		// out
		const char IF_NONE_MATCH[] = "If-None-Match";
		const char IF_MODIFIED_SINCE[] = "If-Modified-Since";	
	
		std::string GetHttpContent (std::istream& response);
		void MergeChunkedResponse (std::istream& response, std::ostream& merged);
		std::string urlDecode(const std::string& data);
		
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
		const boost::asio::ip::address GetInterfaceAddress(const std::string & ifname, bool ipv6=false);
	}

	namespace config
	{
		/** get the host to use from out config, for use in RouterContext.cpp */
		std::string GetHost(bool ipv4=true, bool ipv6=true);
	}
}
}


#endif
