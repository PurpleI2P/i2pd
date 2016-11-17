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
	std::map<std::string, std::string> jumpservices = {
		{ "inr.i2p",    "http://joajgazyztfssty4w2on5oaqksz6tqoxbduy553y34mf4byv6gpq.b32.i2p/search/?q=" },
		{ "stats.i2p",  "http://7tbay5p4kzeekxvyvbf6v7eauazemsnnl2aoyqhg5jzpr5eke7tq.b32.i2p/cgi-bin/jump.cgi?a=" },
	};

	static const char *pageHead =
		"<head>\r\n"
		"  <title>I2Pd HTTP proxy</title>\r\n"
		"  <style type=\"text/css\">\r\n"
		"    body { font: 100%/1.5em sans-serif; margin: 0; padding: 1.5em; background: #FAFAFA; color: #103456; }\r\n"
		"    .header { font-size: 2.5em; text-align: center; margin: 1.5em 0; color: #894C84; }\r\n"
		"  </style>\r\n"
		"</head>\r\n"
	;

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

			bool HandleRequest();
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Terminate();
			void AsyncSockRead();
			bool ExtractAddressHelper(i2p::http::URL & url, std::string & b64);
			void SanitizeHTTPRequest(i2p::http::HTTPReq & req);
			void SentHTTPFailed(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
			/* error helpers */
			void GenericProxyError(const char *title, const char *description);
			void GenericProxyInfo(const char *title, const char *description);
			void HostNotFound(std::string & host);
			void SendProxyError(std::string & content);

			uint8_t m_recv_chunk[8192];
			std::string m_recv_buf; // from client
			std::string m_send_buf; // to upstream
			std::shared_ptr<boost::asio::ip::tcp::socket> m_sock;

		public:

			HTTPReqHandler(HTTPProxy * parent, std::shared_ptr<boost::asio::ip::tcp::socket> sock) :
				I2PServiceHandler(parent), m_sock(sock) {}
			~HTTPReqHandler() { Terminate(); }
			void Handle () { AsyncSockRead(); } /* overload */
	};

	void HTTPReqHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug, "HTTPProxy: async sock read");
		if (!m_sock) {
			LogPrint(eLogError, "HTTPProxy: no socket for read");
			return;
		}
		m_sock->async_read_some(boost::asio::buffer(m_recv_chunk, sizeof(m_recv_chunk)),
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

	void HTTPReqHandler::GenericProxyError(const char *title, const char *description) {
		std::stringstream ss;
		ss << "<h1>Proxy error: " << title << "</h1>\r\n";
		ss << "<p>" << description << "</p>\r\n";
		std::string content = ss.str();
		SendProxyError(content);
	}

	void HTTPReqHandler::GenericProxyInfo(const char *title, const char *description) {
		std::stringstream ss;
		ss << "<h1>Proxy info: " << title << "</h1>\r\n";
		ss << "<p>" << description << "</p>\r\n";
		std::string content = ss.str();
		SendProxyError(content);
	}

	void HTTPReqHandler::HostNotFound(std::string & host) {
		std::stringstream ss;
		ss << "<h1>Proxy error: Host not found</h1>\r\n"
		   << "<p>Remote host not found in router's addressbook</p>\r\n"
		   << "<p>You may try to find this host on jumpservices below:</p>\r\n"
		   << "<ul>\r\n";
		for (const auto& js : jumpservices) {
			ss << "  <li><a href=\"" << js.second << host << "\">" << js.first << "</a></li>\r\n";
		}
		ss << "</ul>\r\n";
		std::string content = ss.str();
		SendProxyError(content);
	}

	void HTTPReqHandler::SendProxyError(std::string & content)
	{
		i2p::http::HTTPRes res;
		res.code = 500;
		res.add_header("Content-Type", "text/html; charset=UTF-8");
		res.add_header("Connection", "close");
		std::stringstream ss;
		ss << "<html>\r\n" << pageHead
		   << "<body>" << content << "</body>\r\n"
		   << "</html>\r\n";
		res.body = ss.str();
		std::string response = res.to_string();
		boost::asio::async_write(*m_sock, boost::asio::buffer(response),
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
		/* drop common headers */
		req.del_header("Referer");
		req.del_header("Via");
		req.del_header("Forwarded");
		/* drop proxy-disclosing headers */
		std::vector<std::string> toErase;
		for (const auto& it : req.headers) {
			if (it.first.compare(0, 12, "X-Forwarded-") == 0) {
				toErase.push_back(it.first);
			} else if (it.first.compare(0, 6, "Proxy-") == 0) {
				toErase.push_back(it.first);
			} else {
				/* allow */
			}
		}
		for (const auto& header : toErase) {
			req.headers.erase(header);
		}
		/* replace headers */
		req.add_header("Connection", "close", true); /* keep-alive conns not supported yet */
		req.add_header("User-Agent", "MYOB/6.66 (AN/ON)", true); /* privacy */
	}

	/**
	 * @brief Try to parse request from @a m_recv_buf
	 *   If parsing success, rebuild request and store to @a m_send_buf
	 * with remaining data tail
	 * @return true on processed request or false if more data needed
	 */
	bool HTTPReqHandler::HandleRequest()
	{
		i2p::http::HTTPReq req;
		i2p::http::URL url;
		std::string b64;
		int req_len = 0;

		req_len = req.parse(m_recv_buf);

		if (req_len == 0)
			return false; /* need more data */

		if (req_len < 0) {
			LogPrint(eLogError, "HTTPProxy: unable to parse request");
			GenericProxyError("Invalid request", "Proxy unable to parse your request");
			return true; /* parse error */
		}

		/* parsing success, now let's look inside request */
		LogPrint(eLogDebug, "HTTPProxy: requested: ", req.uri);
		url.parse(req.uri);

		if (ExtractAddressHelper(url, b64)) {
			i2p::client::context.GetAddressBook ().InsertAddress (url.host, b64);
			LogPrint (eLogInfo, "HTTPProxy: added b64 from addresshelper for ", url.host);
			std::string full_url = url.to_string();
			std::stringstream ss;
			ss << "Host " << url.host << " added to router's addressbook from helper. "
			   << "Click <a href=\"" << full_url << "\">here</a> to proceed.";
			GenericProxyInfo("Addresshelper found", ss.str().c_str());
			return true; /* request processed */
		}

		SanitizeHTTPRequest(req);

		std::string dest_host = url.host;
		uint16_t    dest_port = url.port;
		/* always set port, even if missing in request */
		if (!dest_port) {
			dest_port = (url.schema == "https") ? 443 : 80;
		}
		/* detect dest_host, set proper 'Host' header in upstream request */
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
			GenericProxyError("Invalid request", "Can't detect destination host from request");
			return true;
		}

		/* check dest_host really exists and inside I2P network */
		i2p::data::IdentHash identHash;
		if (str_rmatch(dest_host, ".i2p")) {
			if (!i2p::client::context.GetAddressBook ().GetIdentHash (dest_host, identHash)) {
				HostNotFound(dest_host);
				return true; /* request processed */
			}
			/* TODO: outproxy handler here */
		} else {
			LogPrint (eLogWarning, "HTTPProxy: outproxy failure for ", dest_host, ": not implemented yet");
			std::string message = "Host" + dest_host + "not inside I2P network, but outproxy support not implemented yet";
			GenericProxyError("Outproxy failure", message.c_str());
			return true;
		}

		/* make relative url */
		url.schema = "";
		url.host   = "";
		req.uri = url.to_string();

		/* drop original request from recv buffer */
		m_recv_buf.erase(0, req_len);
		/* build new buffer from modified request and data from original request */
		m_send_buf = req.to_string();
		m_send_buf.append(m_recv_buf);
		/* connect to destination */
		LogPrint(eLogDebug, "HTTPProxy: connecting to host ", dest_host, ":", dest_port);
		GetOwner()->CreateStream (std::bind (&HTTPReqHandler::HandleStreamRequestComplete,
			shared_from_this(), std::placeholders::_1), dest_host, dest_port);
		return true;
	}

	/* will be called after some data received from client */
	void HTTPReqHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug, "HTTPProxy: sock recv: ", len, " bytes, recv buf: ", m_recv_buf.length(), ", send buf: ", m_send_buf.length());
		if(ecode) 
		{
			LogPrint(eLogWarning, "HTTPProxy: sock recv got error: ", ecode);
			Terminate();
			return;
		}

		m_recv_buf.append(reinterpret_cast<const char *>(m_recv_chunk), len);
		if (HandleRequest()) {
			m_recv_buf.clear();
			return;
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
			GenericProxyError("Host is down", "Can't create connection to requested host, it may be down");
			return;
		}
		if (Kill())
			return;
		LogPrint (eLogDebug, "HTTPProxy: Created new I2PTunnel stream, sSID=", stream->GetSendStreamID(), ", rSID=", stream->GetRecvStreamID());
		auto connection = std::make_shared<i2p::client::I2PTunnelConnection>(GetOwner(), m_sock, stream);
		GetOwner()->AddHandler (connection);
		connection->I2PConnect (reinterpret_cast<const uint8_t*>(m_send_buf.data()), m_send_buf.length());
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
