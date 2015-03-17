#ifndef SOCKS_H__
#define SOCKS_H__

#include <memory>
#include <set>
#include <boost/asio.hpp>
#include <mutex>
#include "I2PService.h"

namespace i2p
{
namespace proxy
{
	class SOCKSServer: public i2p::client::TCPIPAcceptor
	{
		public:

			SOCKSServer(int port, std::shared_ptr<i2p::client::ClientDestination> localDestination = nullptr);
			~SOCKSServer() {};

		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(boost::asio::ip::tcp::socket * socket);
			const char* GetName() { return "SOCKS"; }
	};

	typedef SOCKSServer SOCKSProxy;
}
}


#endif
