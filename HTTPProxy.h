#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

#include <memory>
#include <string>
#include <set>
#include <boost/asio.hpp>
#include <mutex>
#include <atomic>
#include "Identity.h"
#include "Streaming.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace proxy
{

	const size_t http_buffer_size = 8192;

	class HTTPProxyServer;
	class HTTPProxyHandler: public std::enable_shared_from_this<HTTPProxyHandler> {
		private:
			enum state {
				GET_METHOD,
				GET_HOSTNAME,
				GET_HTTPV,
				GET_HTTPVNL, //TODO: fallback to finding HOst: header if needed
				DONE
			};

			void EnterState(state nstate);
			bool HandleData(uint8_t *http_buff, std::size_t len);
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Done();
			void Terminate();
			void AsyncSockRead();
			void HTTPRequestFailed(/*std::string message*/);
			void ExtractRequest();
			bool ValidateHTTPRequest();
			bool CreateHTTPRequest(uint8_t *http_buff, std::size_t len);
			void SentHTTPFailed(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);

			uint8_t m_http_buff[http_buffer_size];
			HTTPProxyServer * m_parent;
			boost::asio::ip::tcp::socket * m_sock;
			std::string m_request; //Data left to be sent
			std::string m_url; //URL
			std::string m_method; //Method
			std::string m_version; //HTTP version
			std::string m_address; //Address
			std::string m_path; //Path
			int m_port; //Port
			std::atomic<bool> dead; //To avoid cleaning up multiple times
			state m_state;//Parsing state

		public:
			HTTPProxyHandler(HTTPProxyServer * parent, boost::asio::ip::tcp::socket * sock) : 
				m_parent(parent), m_sock(sock), dead(false)
				{ AsyncSockRead(); EnterState(GET_METHOD); }
			~HTTPProxyHandler() { Terminate(); }
	};

	class HTTPProxyServer: public i2p::client::I2PTunnel
	{
		private:
			std::set<std::shared_ptr<HTTPProxyHandler> > m_Handlers;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
			std::mutex m_HandlersMutex;

		private:

			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);

		public:
			HTTPProxyServer(int port) : I2PTunnel(nullptr),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
				m_Timer (GetService ()) {};
			~HTTPProxyServer() { Stop(); }

			void Start ();
			void Stop ();
			void AddHandler (std::shared_ptr<HTTPProxyHandler> handler);
			void RemoveHandler (std::shared_ptr<HTTPProxyHandler> handler);
			void ClearHandlers ();
	};

	typedef HTTPProxyServer HTTPProxy;
}
}

#endif