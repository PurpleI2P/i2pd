#include <cstring>
#include <cassert>
#include <string>
#include <atomic>
#include <memory>
#include <set>
#include <boost/asio.hpp>
#include <mutex>

#include "I2PService.h"
#include "Destination.h"
#include "HTTPProxy.h"
#include "util.h"
#include "Identity.h"
#include "Streaming.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"
#include "I2PTunnel.h"
#include "Config.h"
#include "HTTP.h"

namespace i2p {
namespace proxy {
	bool str_rmatch(std::string & str, const char *suffix) {
		auto pos = str.rfind (suffix);
		if (pos == std::string::npos)
			return false; /* not found */
		if (str.length() == (pos + std::strlen(suffix)))
			return true; /* match */
		return false;
	}

	static const size_t http_buffer_size = 8192;
	class HTTPReqHandler: public i2p::client::I2PServiceHandler, public std::enable_shared_from_this<HTTPReqHandler>
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
			void HTTPRequestFailed(const char *message);
			void RedirectToJumpService(std::string & host);
			bool ValidateHTTPRequest();
			bool ExtractAddressHelper(i2p::http::URL & url, std::string & b64);
			bool CreateHTTPRequest(uint8_t *http_buff, std::size_t len);
			void SentHTTPFailed(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);

			uint8_t m_http_buff[http_buffer_size];
			std::shared_ptr<boost::asio::ip::tcp::socket> m_sock;
			std::string m_request; //Data left to be sent
			std::string m_url; //URL
			std::string m_method; //Method
			std::string m_version; //HTTP version
			std::string m_address; //Address
			std::string m_path; //Path
			int m_port; //Port
			state m_state;//Parsing state

		public:

			HTTPReqHandler(HTTPProxy * parent, std::shared_ptr<boost::asio::ip::tcp::socket> sock) :
				I2PServiceHandler(parent), m_sock(sock)
				{ EnterState(GET_METHOD); }
			~HTTPReqHandler() { Terminate(); }
			void Handle () { AsyncSockRead(); }
	};

	void HTTPReqHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug, "HTTPProxy: async sock read");
		if (!m_sock) {
			LogPrint(eLogError, "HTTPProxy: no socket for read");
			return;
		}
		m_sock->async_receive(boost::asio::buffer(m_http_buff, http_buffer_size),
					std::bind(&HTTPReqHandler::HandleSockRecv, shared_from_this(),
							std::placeholders::_1, std::placeholders::_2));
	}

	void HTTPReqHandler::Terminate() {
		if (Kill()) return;
		if (m_sock) 
		{
			LogPrint(eLogDebug, "HTTPProxy: close sock");
			m_sock->close();
			m_sock = nullptr;
		}
		Done(shared_from_this());
	}

	/* All hope is lost beyond this point */
	//TODO: handle this apropriately
	void HTTPReqHandler::HTTPRequestFailed(const char *message)
	{
		i2p::http::HTTPRes res;
		res.code = 500;
		res.add_header("Content-Type", "text/plain");
		res.add_header("Connection", "close");
		res.body = message;
		res.body += "\r\n";
		std::string response = res.to_string();
		boost::asio::async_write(*m_sock, boost::asio::buffer(response),
					 std::bind(&HTTPReqHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
	}

	void HTTPReqHandler::RedirectToJumpService(std::string & host)
	{
		i2p::http::HTTPRes res;
		i2p::http::URL url;

		/* TODO: don't redirect to webconsole, it's not always work, handle jumpservices here */
		i2p::config::GetOption("http.address", url.host);
		i2p::config::GetOption("http.port",    url.port);
		url.schema = "http";
		url.path  = "/";
		url.query = "page=jumpservices&address=";
		url.query += host;

		res.code = 302; /* redirect */
		res.add_header("Location", url.to_string().c_str());
		res.add_header("Connection", "close");

		std::string response = res.to_string();
		boost::asio::async_write(*m_sock, boost::asio::buffer(response),
					 std::bind(&HTTPReqHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
	}

	void HTTPReqHandler::EnterState(HTTPReqHandler::state nstate)
	{
		m_state = nstate;
	}

	bool HTTPReqHandler::ValidateHTTPRequest()
	{
		if ( m_version != "HTTP/1.0" && m_version != "HTTP/1.1" ) 
		{
			LogPrint(eLogError, "HTTPProxy: unsupported version: ", m_version);
			HTTPRequestFailed("unsupported HTTP version");
			return false;
		}
		return true;
	}

	bool HTTPReqHandler::ExtractAddressHelper(i2p::http::URL & url, std::string & b64)
	{
		const char *param = "i2paddresshelper=";
		std::size_t pos = url.query.find(param);
		std::size_t len = std::strlen(param);
		std::map<std::string, std::string> params;

		if (pos == std::string::npos)
			return false; /* not found */
		if (!url.parse_query(params))
			return false;

		std::string value = params["i2paddresshelper"];
		len += value.length();
		b64 = i2p::http::UrlDecode(value);
		url.query.replace(pos, len, "");
		return true;
	}

	bool HTTPReqHandler::CreateHTTPRequest(uint8_t *http_buff, std::size_t len)
	{
		std::string b64;
		i2p::http::URL url;
		url.parse(m_url);
		m_address = url.host; /* < compatibility */
		m_port    = url.port; /* < compatibility */
		if (!m_port) {
			m_port = (url.schema == "https") ? 443 : 80;
		}
		url.schema = "";
		url.host   = "";
		m_path    = url.to_string(); /* < compatibility */
		if (!ValidateHTTPRequest()) return false;

		/* TODO: notify user */
		if (ExtractAddressHelper(url, b64)) {
			i2p::client::context.GetAddressBook ().InsertAddress (url.host, b64);
			LogPrint (eLogInfo, "HTTPProxy: added b64 from addresshelper for ", url.host, " to address book");
		}

		i2p::data::IdentHash identHash;
		if (str_rmatch(m_address, ".i2p"))
		{
			if (!i2p::client::context.GetAddressBook ().GetIdentHash (m_address, identHash)){
				RedirectToJumpService(m_address);
				return false;
			}
		}

		m_request = m_method;
		m_request.push_back(' ');
		m_request += m_path;
		m_request.push_back(' ');
		m_request += m_version;
		m_request.push_back('\r');
		m_request.push_back('\n');
		m_request.append("Connection: close\r\n");
		// TODO: temporary shortcut. Must be implemented properly
		uint8_t * eol = nullptr;
		bool isEndOfHeader = false;
		while (!isEndOfHeader && len && (eol = (uint8_t *)memchr (http_buff, '\r', len)))
		{
			if (eol)
			{
				*eol = 0; eol++;			
				if (strncmp ((const char *)http_buff, "Referer", 7) && strncmp ((const char *)http_buff, "Connection", 10)) // strip out referer and connection
				{
					if (!strncmp ((const char *)http_buff, "User-Agent", 10)) // replace UserAgent
						m_request.append("User-Agent: MYOB/6.66 (AN/ON)");
					else
						m_request.append ((const char *)http_buff);
					m_request.append ("\r\n");
				}
				isEndOfHeader = !http_buff[0];
				auto l = eol - http_buff;
				http_buff = eol;
				len -= l;
				if (len > 0) // \r
				{
					http_buff++;
					len--;
				}	
			}
		}	
		m_request.append(reinterpret_cast<const char *>(http_buff),len);	
		return true;
	}

	bool HTTPReqHandler::HandleData(uint8_t *http_buff, std::size_t len)
	{
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
							LogPrint(eLogError, "HTTPProxy: rejected invalid request ending with: ", ((int)*http_buff));
							HTTPRequestFailed("rejected invalid request");
							return false;
					}
				break;
				default:
					LogPrint(eLogError, "HTTPProxy: invalid state: ", m_state);
					HTTPRequestFailed("invalid parser state");
					return false;
			}
			http_buff++;
			len--;
			if (m_state == DONE)
				return CreateHTTPRequest(http_buff,len);
		}
		return true;
	}

	void HTTPReqHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug, "HTTPProxy: sock recv: ", len, " bytes");
		if(ecode) 
		{
			LogPrint(eLogWarning, "HTTPProxy: sock recv got error: ", ecode);
			Terminate();
			return;
		}

		if (HandleData(m_http_buff, len)) 
		{
			if (m_state == DONE) 
			{
				LogPrint(eLogDebug, "HTTPProxy: requested: ", m_url);
				GetOwner()->CreateStream (std::bind (&HTTPReqHandler::HandleStreamRequestComplete,
						shared_from_this(), std::placeholders::_1), m_address, m_port);
			} 
			else 
				AsyncSockRead();
		}
	}

	void HTTPReqHandler::SentHTTPFailed(const boost::system::error_code & ecode)
	{
		if (ecode)
			LogPrint (eLogError, "HTTPProxy: Closing socket after sending failure because: ", ecode.message ());
		Terminate();
	}

	void HTTPReqHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (!stream) {
			LogPrint (eLogError, "HTTPProxy: error when creating the stream, check the previous warnings for more info");
			HTTPRequestFailed("error when creating the stream, check logs");
			return;
		}
		if (Kill())
			return;
		LogPrint (eLogDebug, "HTTPProxy: New I2PTunnel connection");
		auto connection = std::make_shared<i2p::client::I2PTunnelConnection>(GetOwner(), m_sock, stream);
		GetOwner()->AddHandler (connection);
		connection->I2PConnect (reinterpret_cast<const uint8_t*>(m_request.data()), m_request.size());
		Done (shared_from_this());
	}

	HTTPProxy::HTTPProxy(const std::string& address, int port, std::shared_ptr<i2p::client::ClientDestination> localDestination):
		TCPIPAcceptor(address, port, localDestination ? localDestination : i2p::client::context.GetSharedLocalDestination ()) 
	{
	}
	
	std::shared_ptr<i2p::client::I2PServiceHandler> HTTPProxy::CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		return std::make_shared<HTTPReqHandler> (this, socket);
	}
} // http
} // i2p
