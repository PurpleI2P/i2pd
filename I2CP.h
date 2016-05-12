#ifndef I2CP_H__
#define I2CP_H__

#include <string>
#include <boost/asio.hpp>

namespace i2p
{
namespace client
{
	class I2CPServer
	{
		public:

			I2CPServer (const std::string& interface, int port);
	};	
}
}

#endif

