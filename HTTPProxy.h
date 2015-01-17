#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

#include <memory>
#include <set>
#include <boost/asio.hpp>
#include <mutex>
#include "I2PService.h"

namespace i2p
{
namespace proxy
{
	class HTTPProxyServer: public i2p::client::TCPIPAcceptor
	{
		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(boost::asio::ip::tcp::socket * socket);
			const char* GetName() { return "HTTP Proxy"; }

		public:
			HTTPProxyServer(int port);
			~HTTPProxyServer() {}
	};

	typedef HTTPProxyServer HTTPProxy;
}
}

#endif