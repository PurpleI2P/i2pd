#include <cstring>
#include <cassert>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include "HTTPProxy.h"
#include "Identity.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"

namespace i2p
{
namespace proxy
{
	void HTTPProxyHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug,"--- HTTP Proxy async sock read");
		if(m_sock) {
			m_sock->async_receive(boost::asio::buffer(m_http_buff, http_buffer_size),
						std::bind(&HTTPProxyHandler::HandleSockRecv, this,
								std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError,"--- HTTP Proxy no socket for read");
		}
	}

	void HTTPProxyHandler::Done() {
		if (m_parent) m_parent->RemoveHandler (shared_from_this ());
	}

	void HTTPProxyHandler::Terminate() {
		if (dead.exchange(true)) return;
		if (m_sock) {
			LogPrint(eLogDebug,"--- HTTP Proxy close sock");
			m_sock->close();
			delete m_sock;
			m_sock = nullptr;
		}
		Done();
	}

	/* All hope is lost beyond this point */
	//TODO: handle this apropriately
	void HTTPProxyHandler::HTTPRequestFailed(/*HTTPProxyHandler::errTypes error*/)
	{
		std::string response = "HTTP/1.0 500 Internal Server Error\r\nContent-type: text/html\r\nContent-length: 0\r\n";
		boost::asio::async_write(*m_sock, boost::asio::buffer(response,response.size()),
					 std::bind(&HTTPProxyHandler::SentHTTPFailed, this, std::placeholders::_1));
	}

	void HTTPProxyHandler::EnterState(HTTPProxyHandler::state nstate) {
		m_state = nstate;
	}

	void HTTPProxyHandler::ExtractRequest()
	{
		LogPrint(eLogDebug,"--- HTTP Proxy method is: ", m_method, "\nRequest is: ", m_url);
		std::string server="";
		std::string port="80";
		boost::regex rHTTP("http://(.*?)(:(\\d+))?(/.*)");
		boost::smatch m;
		std::string path;
		if(boost::regex_search(m_url, m, rHTTP, boost::match_extra)) {
			server=m[1].str();
			if(m[2].str() != "") {
				port=m[3].str();
			}
			path=m[4].str();
		}
		LogPrint(eLogDebug,"--- HTTP Proxy server is: ",server, " port is: ", port, "\n path is: ",path);
		m_address = server;
		m_port = boost::lexical_cast<int>(port);
		m_path = path;
	}

	bool HTTPProxyHandler::ValidateHTTPRequest() {
		if ( m_version != "HTTP/1.0" && m_version != "HTTP/1.1" ) {
			LogPrint(eLogError,"--- HTTP Proxy unsupported version: ", m_version);
			HTTPRequestFailed(); //TODO: send right stuff
			return false;
		}
		return true;
	}

	bool HTTPProxyHandler::CreateHTTPRequest(uint8_t *http_buff, std::size_t len) {
		ExtractRequest(); //TODO: parse earlier
		if (!ValidateHTTPRequest()) return false;
		m_request = m_method;
		m_request.push_back(' ');
		m_request += m_path;
		m_request.push_back(' ');
		m_request += m_version;
		m_request.push_back('\r');
		m_request.push_back('\n');
		m_request.append("Connection: close\r\n");
		m_request.append(reinterpret_cast<const char *>(http_buff),len);
		return true;
	}

	bool HTTPProxyHandler::HandleData(uint8_t *http_buff, std::size_t len)
	{
		assert(len); // This should always be called with a least a byte left to parse
		while (len > 0) {
			//TODO: fallback to finding HOst: header if needed
			switch (m_state) {
				case GET_METHOD:
					switch (*http_buff) {
						case ' ': EnterState(GET_HOSTNAME); break;
						default: m_method.push_back(*http_buff); break;
					}
					break;
				case GET_HOSTNAME:
					switch (*http_buff) {
						case ' ': EnterState(GET_HTTPV); break;
						default: m_url.push_back(*http_buff); break;
					}
					break;
				case GET_HTTPV:
					switch (*http_buff) {
						case '\r': EnterState(GET_HTTPVNL); break;
						default: m_version.push_back(*http_buff); break;
					}
					break;
				case GET_HTTPVNL:
					switch (*http_buff) {
						case '\n': EnterState(DONE); break;
						default:
							LogPrint(eLogError,"--- HTTP Proxy rejected invalid request ending with: ", ((int)*http_buff));
							HTTPRequestFailed(); //TODO: add correct code
							return false;
					}
					break;
				default:
					LogPrint(eLogError,"--- HTTP Proxy invalid state: ", m_state);
					HTTPRequestFailed(); //TODO: add correct code 500
					return false;
			}
			http_buff++;
			len--;
			if (m_state == DONE)
				return CreateHTTPRequest(http_buff,len);
		}
		return true;
	}

	void HTTPProxyHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug,"--- HTTP Proxy sock recv: ", len);
		if(ecode) {
			LogPrint(eLogWarning," --- HTTP Proxy sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		if (HandleData(m_http_buff, len)) {
			if (m_state == DONE) {
				LogPrint(eLogInfo,"--- HTTP Proxy requested: ", m_url);
				m_parent->GetLocalDestination ()->CreateStream (
						std::bind (&HTTPProxyHandler::HandleStreamRequestComplete,
						this, std::placeholders::_1), m_address, m_port);
			} else {
				AsyncSockRead();
			}
		}

	}

	void HTTPProxyHandler::SentHTTPFailed(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			Terminate();
		} else {
			LogPrint (eLogError,"--- HTTP Proxy Closing socket after sending failure because: ", ecode.message ());
			Terminate();
		}
	}

	void HTTPProxyHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream) {
			if (dead.exchange(true)) return;
			LogPrint (eLogInfo,"--- HTTP Proxy New I2PTunnel connection");
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>((i2p::client::I2PTunnel *)m_parent, m_sock, stream);
			m_parent->AddConnection (connection);
			connection->I2PConnect (reinterpret_cast<const uint8_t*>(m_request.data()), m_request.size());
			Done();
		} else {
			LogPrint (eLogError,"--- HTTP Proxy Issue when creating the stream, check the previous warnings for more info.");
			HTTPRequestFailed(); // TODO: Send correct error message host unreachable
		}
	}

	void HTTPProxyServer::Start ()
	{
		m_Acceptor.listen ();
		Accept ();
	}

	void HTTPProxyServer::Stop ()
	{
		m_Acceptor.close();
		m_Timer.cancel ();
		ClearConnections ();
		ClearHandlers();
	}

	void HTTPProxyServer::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&HTTPProxyServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void  HTTPProxyServer::AddHandler (std::shared_ptr<HTTPProxyHandler> handler) {
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		m_Handlers.insert (handler);
	}

	void  HTTPProxyServer::RemoveHandler (std::shared_ptr<HTTPProxyHandler> handler)
	{
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		m_Handlers.erase (handler);
	}

	void  HTTPProxyServer::ClearHandlers ()
	{
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		m_Handlers.clear ();
	}

	void HTTPProxyServer::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			LogPrint(eLogDebug,"--- HTTP Proxy accepted");
			AddHandler(std::make_shared<HTTPProxyHandler> (this, socket));
			Accept();
		}
		else
		{
			LogPrint (eLogError,"--- HTTP Proxy Closing socket on accept because: ", ecode.message ());
			delete socket;
		}
	}

}
}
