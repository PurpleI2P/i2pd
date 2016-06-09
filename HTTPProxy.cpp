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

	class HTTPReqHandler: public i2p::client::I2PServiceHandler, public std::enable_shared_from_this<HTTPReqHandler> 
	{
		private:

			bool HandleRequest(std::size_t len);
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Terminate();
			void AsyncSockRead();
			void HTTPRequestFailed(const char *message);
			void RedirectToJumpService(std::string & host);
			bool ExtractAddressHelper(i2p::http::URL & url, std::string & b64);
			void SanitizeHTTPRequest(i2p::http::HTTPReq & req);
			void SentHTTPFailed(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);

			std::shared_ptr<boost::asio::ip::tcp::socket> m_sock;
			std::vector<unsigned char> m_recv_buf; /* as "downstream recieve buffer", from client to me */
			std::vector<unsigned char> m_send_buf; /* as "upstream send buffer", from me to remote host */

		public:

			HTTPReqHandler(HTTPProxy * parent, std::shared_ptr<boost::asio::ip::tcp::socket> sock) : 
				I2PServiceHandler(parent), m_sock(sock), m_recv_buf(8192), m_send_buf(0) {};
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
		m_sock->async_receive(boost::asio::buffer(m_recv_buf),
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

	void HTTPReqHandler::HTTPRequestFailed(const char *message)
	{
		i2p::http::HTTPRes res;
		res.code = 500;
		res.add_header("Content-Type", "text/plain");
		res.add_header("Connection", "close");
		res.body = message;
		res.body += "\r\n";
		std::string response = res.to_string();
		boost::asio::async_write(*m_sock, boost::asio::buffer(response, response.size()),
					 std::bind(&HTTPReqHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
	}

	void HTTPReqHandler::RedirectToJumpService(std::string & host)
	{
		i2p::http::HTTPRes res;
		i2p::http::URL url;

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
		boost::asio::async_write(*m_sock, boost::asio::buffer(response, response.length()),
					 std::bind(&HTTPReqHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
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

	void HTTPReqHandler::SanitizeHTTPRequest(i2p::http::HTTPReq & req)
	{
		req.del_header("Referer");
		req.del_header("Via");
		req.del_header("Forwarded");
		std::vector<std::string> toErase;
		for (auto it : req.headers) {
			if (it.first.compare(0, 12, "X-Forwarded-")) {
				toErase.push_back(it.first);
			} else if (it.first.compare(0, 6, "Proxy-")) {
				toErase.push_back(it.first);
			} else {
				/* allow this header */
			}
		}
		for (auto header : toErase) {
			req.headers.erase(header);
		}
		/* replace headers */
		req.add_header("Connection", "close", true); /* keep-alive conns not supported yet */
		req.add_header("User-Agent", "MYOB/6.66 (AN/ON)", true); /* privacy */
	}

	/**
	 * @param len length of data in m_recv_buf
	 * @return true on processed request or false if more data needed
	 */
	bool HTTPReqHandler::HandleRequest(std::size_t len)
	{
		i2p::http::HTTPReq req;
		i2p::http::URL url;
		std::string b64;

		int req_len = 0;

		req_len = req.parse((const char *) m_recv_buf.data(), len);
		if (req_len == 0)
			return false; /* need more data */
		if (req_len < 0) {
			LogPrint(eLogError, "HTTPProxy: unable to parse request");
			HTTPRequestFailed("invalid request");
			return true; /* parse error */
		}

		/* parsing success, now let's look inside request */
		LogPrint(eLogDebug, "HTTPProxy: requested: ", req.uri);
		url.parse(req.uri);

		if (ExtractAddressHelper(url, b64)) {
			i2p::client::context.GetAddressBook ().InsertAddress (url.host, b64);
			std::string message = "added b64 from addresshelper for " + url.host + " to address book";
			LogPrint (eLogInfo, "HTTPProxy: ", message);
			message += ", please reload page";
			HTTPRequestFailed(message.c_str());
			return true; /* request processed */
		}

		i2p::data::IdentHash identHash;
		if (str_rmatch(url.host, ".i2p")) {
			if (!i2p::client::context.GetAddressBook ().GetIdentHash (url.host, identHash)) {
				RedirectToJumpService(url.host);
				return true; /* request processed */
			}
		/* TODO: outproxy handler here */
		} else {
			std::string message = "Host " + url.host + " not inside i2p network, but outproxy support still missing";
			HTTPRequestFailed(message.c_str());
			LogPrint (eLogWarning, "HTTPProxy: ", message);
			return true;
		}
		SanitizeHTTPRequest(req);

		std::string dest_host = url.host;
		uint16_t    dest_port = url.port;
		/* set proper 'Host' header in upstream request */
		auto h = req.headers.find("Host");
		if (dest_host != "") {
			/* absolute url, replace 'Host' header */
			std::string h = dest_host;
			if (dest_port != 0 && dest_port != 80)
				h += ":" + std::to_string(dest_port);
			req.add_header("Host", h, true);
		} else if (h != req.headers.end()) {
			/* relative url and 'Host' header provided. transparent proxy mode? */
			i2p::http::URL u;
			std::string t = "http://" + h->second;
			u.parse(t);
			dest_host = u.host;
			dest_port = u.port;
		} else {
			/* relative url and missing 'Host' header */
			std::string message = "Can't detect destination host from request";
			HTTPRequestFailed(message.c_str());
			return true;
		}
		if (!dest_port) dest_port = 80; /* always set port for CreateStream() */ //TODO: 443 for https
		/* make relative url */
		url.schema = "";
		url.host   = "";
		req.uri = url.to_string();

		/* drop original request from input buffer */
		m_recv_buf.erase(m_recv_buf.begin(), m_recv_buf.begin() + req_len);

		/* build new buffer from modified request and data from original request */
		std::string request = req.to_string();
		m_send_buf.assign(request.begin(), request.end());
		m_send_buf.insert(m_send_buf.end(), m_recv_buf.begin(), m_recv_buf.end());

		/* connect to destination */
		GetOwner()->CreateStream (std::bind (&HTTPReqHandler::HandleStreamRequestComplete,
			shared_from_this(), std::placeholders::_1), dest_host, dest_port);

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

		if (HandleRequest(len)) {
			m_recv_buf.clear();
			return; /* request processed */
		}
		AsyncSockRead();
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
		connection->I2PConnect (m_send_buf.data(), m_send_buf.size());
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
