#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

namespace i2p {
namespace proxy {
	class HTTPProxy: public i2p::client::TCPIPAcceptor
	{
		public:

			HTTPProxy(const std::string& address, int port, std::shared_ptr<i2p::client::ClientDestination> localDestination = nullptr);
			~HTTPProxy() {};

		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			const char* GetName() { return "HTTP Proxy"; }
	};
} // http
} // i2p

#endif
