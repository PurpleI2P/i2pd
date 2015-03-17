#include <cstring>
#include <cassert>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <string>
#include <atomic>
#include "HTTPProxy.h"
#include "util.h"
#include "Identity.h"
#include "Streaming.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace proxy
{
	static const size_t http_buffer_size = 8192;
	class HTTPProxyHandler: public i2p::client::I2PServiceHandler, public std::enable_shared_from_this<HTTPProxyHandler> 
	{
		private:
			enum state 
			{
				GET_METHOD,
				GET_HOSTNAME,
				GET_HTTPV,
				GET_HTTPVNL, //TODO: fallback to finding HOst: header if needed
				DONE
			};

			void EnterState(state nstate);
			bool HandleData(uint8_t *http_buff, std::size_t len);
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Terminate();
			void AsyncSockRead();
			void HTTPRequestFailed(/*std::string message*/);
			void ExtractRequest();
			bool ValidateHTTPRequest();
			void HandleJumpServices();
			bool CreateHTTPRequest(uint8_t *http_buff, std::size_t len);
			void SentHTTPFailed(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);

			uint8_t m_http_buff[http_buffer_size];
			boost::asio::ip::tcp::socket * m_sock;
			std::string m_request; //Data left to be sent
			std::string m_url; //URL
			std::string m_method; //Method
			std::string m_version; //HTTP version
			std::string m_address; //Address
			std::string m_path; //Path
			int m_port; //Port
			state m_state;//Parsing state

		public:

			HTTPProxyHandler(HTTPProxyServer * parent, boost::asio::ip::tcp::socket * sock) : 
				I2PServiceHandler(parent), m_sock(sock)
				{ EnterState(GET_METHOD); }
			~HTTPProxyHandler() { Terminate(); }
			void Handle () { AsyncSockRead(); }
	};

	void HTTPProxyHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug,"--- HTTP Proxy async sock read");
		if(m_sock) {
			m_sock->async_receive(boost::asio::buffer(m_http_buff, http_buffer_size),
						std::bind(&HTTPProxyHandler::HandleSockRecv, shared_from_this(),
								std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError,"--- HTTP Proxy no socket for read");
		}
	}

	void HTTPProxyHandler::Terminate() {
		if (Kill()) return;
		if (m_sock) {
			LogPrint(eLogDebug,"--- HTTP Proxy close sock");
			m_sock->close();
			delete m_sock;
			m_sock = nullptr;
		}
		Done(shared_from_this());
	}

	/* All hope is lost beyond this point */
	//TODO: handle this apropriately
	void HTTPProxyHandler::HTTPRequestFailed(/*HTTPProxyHandler::errTypes error*/)
	{
		std::string response = "HTTP/1.0 500 Internal Server Error\r\nContent-type: text/html\r\nContent-length: 0\r\n";
		boost::asio::async_write(*m_sock, boost::asio::buffer(response,response.size()),
					 std::bind(&HTTPProxyHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
	}

	void HTTPProxyHandler::EnterState(HTTPProxyHandler::state nstate) 
	{
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
		if(boost::regex_search(m_url, m, rHTTP, boost::match_extra)) 
		{
			server=m[1].str();
			if (m[2].str() != "")  port=m[3].str();
			path=m[4].str();
		}
		LogPrint(eLogDebug,"--- HTTP Proxy server is: ",server, " port is: ", port, "\n path is: ",path);
		m_address = server;
		m_port = boost::lexical_cast<int>(port);
		m_path = path;
	}

	bool HTTPProxyHandler::ValidateHTTPRequest() 
	{
		if ( m_version != "HTTP/1.0" && m_version != "HTTP/1.1" ) 
		{
			LogPrint(eLogError,"--- HTTP Proxy unsupported version: ", m_version);
			HTTPRequestFailed(); //TODO: send right stuff
			return false;
		}
		return true;
	}

	void HTTPProxyHandler::HandleJumpServices() 
	{
		static const char * helpermark1 = "?i2paddresshelper=";
		static const char * helpermark2 = "&i2paddresshelper=";
		size_t addressHelperPos1 = m_path.rfind (helpermark1);
		size_t addressHelperPos2 = m_path.rfind (helpermark2);
		size_t addressHelperPos;
		if (addressHelperPos1 == std::string::npos)
		{
			if (addressHelperPos2 == std::string::npos)
				return; //Not a jump service
			else
				addressHelperPos = addressHelperPos2;
		}
		else
		{
			if (addressHelperPos2 == std::string::npos)
				addressHelperPos = addressHelperPos1;
			else if ( addressHelperPos1 > addressHelperPos2 )
				addressHelperPos = addressHelperPos1;
			else
				addressHelperPos = addressHelperPos2;
		}
		auto base64 = m_path.substr (addressHelperPos + strlen(helpermark1));
		base64 = i2p::util::http::urlDecode(base64); //Some of the symbols may be urlencoded
		LogPrint (eLogDebug,"Jump service for ", m_address, " found at ", base64, ". Inserting to address book");
		//TODO: this is very dangerous and broken. We should ask the user before doing anything see http://pastethis.i2p/raw/pn5fL4YNJL7OSWj3Sc6N/
		//TODO: we could redirect the user again to avoid dirtiness in the browser
		i2p::client::context.GetAddressBook ().InsertAddress (m_address, base64);
		m_path.erase(addressHelperPos);
	}

	bool HTTPProxyHandler::CreateHTTPRequest(uint8_t *http_buff, std::size_t len) 
	{
		ExtractRequest(); //TODO: parse earlier
		if (!ValidateHTTPRequest()) return false;
		HandleJumpServices();
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
		while (len > 0) 
		{
			//TODO: fallback to finding HOst: header if needed
			switch (m_state) 
			{
				case GET_METHOD:
					switch (*http_buff) 
					{
						case ' ': EnterState(GET_HOSTNAME); break;
						default: m_method.push_back(*http_buff); break;
					}
				break;
				case GET_HOSTNAME:
					switch (*http_buff) 
					{
						case ' ': EnterState(GET_HTTPV); break;
						default: m_url.push_back(*http_buff); break;
					}
				break;
				case GET_HTTPV:
					switch (*http_buff) 
					{
						case '\r': EnterState(GET_HTTPVNL); break;
						default: m_version.push_back(*http_buff); break;
					}
				break;
				case GET_HTTPVNL:
					switch (*http_buff) 
					{
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
		if(ecode) 
		{
			LogPrint(eLogWarning," --- HTTP Proxy sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		if (HandleData(m_http_buff, len)) 
		{
			if (m_state == DONE) 
			{
				LogPrint(eLogInfo,"--- HTTP Proxy requested: ", m_url);
				GetOwner()->CreateStream (std::bind (&HTTPProxyHandler::HandleStreamRequestComplete,
						shared_from_this(), std::placeholders::_1), m_address, m_port);
			} 
			else 
				AsyncSockRead();
		}

	}

	void HTTPProxyHandler::SentHTTPFailed(const boost::system::error_code & ecode)
	{
		if (!ecode)
			Terminate();
		else 
		{
			LogPrint (eLogError,"--- HTTP Proxy Closing socket after sending failure because: ", ecode.message ());
			Terminate();
		}
	}

	void HTTPProxyHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream) 
		{
			if (Kill()) return;
			LogPrint (eLogInfo,"--- HTTP Proxy New I2PTunnel connection");
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>(GetOwner(), m_sock, stream);
			GetOwner()->AddHandler (connection);
			connection->I2PConnect (reinterpret_cast<const uint8_t*>(m_request.data()), m_request.size());
			Done(shared_from_this());
		} 
		else 
		{
			LogPrint (eLogError,"--- HTTP Proxy Issue when creating the stream, check the previous warnings for more info.");
			HTTPRequestFailed(); // TODO: Send correct error message host unreachable
		}
	}

	HTTPProxyServer::HTTPProxyServer(int port, std::shared_ptr<i2p::client::ClientDestination> localDestination): 
		TCPIPAcceptor(port, localDestination ? localDestination : i2p::client::context.GetSharedLocalDestination ()) 
	{
	}
	
	std::shared_ptr<i2p::client::I2PServiceHandler> HTTPProxyServer::CreateHandler(boost::asio::ip::tcp::socket * socket)
	{
		return std::make_shared<HTTPProxyHandler> (this, socket);
	}

}
}
