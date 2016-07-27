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

	namespace net
	{
		int GetMTU (const boost::asio::ip::address& localAddress);
		const boost::asio::ip::address GetInterfaceAddress(const std::string & ifname, bool ipv6=false);
	}
}
}

#endif
