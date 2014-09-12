#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

#include <sstream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/array.hpp>

#include "HTTPServer.h"

namespace i2p
{
namespace proxy
{
	class HTTPProxyConnection : public i2p::util::HTTPConnection
	{
		public:
			HTTPProxyConnection (boost::asio::ip::tcp::socket * socket): HTTPConnection(socket) { };

		protected:
			void RunRequest();
			void parseHeaders(const std::string& h, std::vector<header>& hm);
			void ExtractRequest(request& r);
	};

	class HTTPProxy : public i2p::util::HTTPServer
	{
		public:
			HTTPProxy (int port): HTTPServer(port) {};

		private:
			void CreateConnection(boost::asio::ip::tcp::socket * m_NewSocket)
			{
				new HTTPProxyConnection(m_NewSocket);
			}
	};
}
}

#endif


