#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>
#include <iostream>
#include <boost/asio.hpp>

#ifdef ANDROID
#include <boost/lexical_cast.hpp>
namespace std
{
template <typename T>
std::string to_string(T value)
{
   return boost::lexical_cast<std::string>(value);
}

inline int stoi(const std::string& str)
{
	return boost::lexical_cast<int>(str);
}
}
#endif

namespace i2p
{
namespace util
{
	namespace net
	{
		int GetMTU (const boost::asio::ip::address& localAddress);
		const boost::asio::ip::address GetInterfaceAddress(const std::string & ifname, bool ipv6=false);
	}
}
}

#endif
