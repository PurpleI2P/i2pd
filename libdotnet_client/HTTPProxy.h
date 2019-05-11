#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

namespace dotnet {
namespace proxy {
	class HTTPProxy: public dotnet::client::TCPIPAcceptor
	{
		public:
			HTTPProxy(const std::string& name, const std::string& address, int port, const std::string & outproxy, bool addresshelper, std::shared_ptr<dotnet::client::ClientDestination> localDestination);
			HTTPProxy(const std::string& name, const std::string& address, int port, std::shared_ptr<dotnet::client::ClientDestination> localDestination = nullptr) :
				HTTPProxy(name, address, port, "", true, localDestination) {} ;
			~HTTPProxy() {};

			std::string GetOutproxyURL() const { return m_OutproxyUrl; }
			bool GetHelperSupport() { return m_Addresshelper; }

		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<dotnet::client::DotNetServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			const char* GetName() { return m_Name.c_str (); }

		private:
			std::string m_Name;
			std::string m_OutproxyUrl;
			bool m_Addresshelper;
	};
} // http
} // dotnet

#endif
