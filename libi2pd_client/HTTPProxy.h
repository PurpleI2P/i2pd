#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

namespace i2p {
namespace proxy {
	class HTTPProxy: public i2p::client::TCPIPAcceptor
	{
		public:
			HTTPProxy(const std::string& name, const std::string& address, int port, const std::string & outproxy, std::shared_ptr<i2p::client::ClientDestination> localDestination);
			HTTPProxy(const std::string& name, const std::string& address, int port, std::shared_ptr<i2p::client::ClientDestination> localDestination = nullptr) :
				HTTPProxy(name, address, port, "", localDestination) {} ;
			~HTTPProxy() {};

			std::string GetOutproxyURL() const { return m_OutproxyUrl; }

		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			const char* GetName() { return m_Name.c_str (); }

		private:
			std::string m_Name;
			std::string m_OutproxyUrl;
	};
} // http
} // i2p

#endif
