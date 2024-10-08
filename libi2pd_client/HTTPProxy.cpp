/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstring>
#include <cassert>
#include <string>
#include <string_view>
#include <atomic>
#include <memory>
#include <set>
#include <boost/asio.hpp>
#include <boost/algorithm/string/predicate.hpp>
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
#include "I18N.h"
#include "Socks5.h"

namespace i2p {
namespace proxy {
	static const std::vector<std::string> jumporder = {
		"reg.i2p",
		"stats.i2p",
		"identiguy.i2p",
		"notbob.i2p"
	};

	static const std::map<std::string, std::string> jumpservices = {
		{ "reg.i2p",       "http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/jump/" },
		{ "identiguy.i2p", "http://3mzmrus2oron5fxptw7hw2puho3bnqmw2hqy7nw64dsrrjwdilva.b32.i2p/cgi-bin/query?hostname=" },
		{ "stats.i2p",     "http://7tbay5p4kzeekxvyvbf6v7eauazemsnnl2aoyqhg5jzpr5eke7tq.b32.i2p/cgi-bin/jump.cgi?a=" },
		{ "notbob.i2p",    "http://nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p/cgi-bin/jump.cgi?q=" }
	};

	static const char *pageHead =
		"<head>\r\n"
		"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n"
		"  <title>I2Pd HTTP proxy</title>\r\n"
		"  <style type=\"text/css\">\r\n"
		"    body { font: 100%/1.5em sans-serif; margin: 0; padding: 1.5em; background: #FAFAFA; color: #103456; }\r\n"
		"    h1 { font-size: 1.7em; color: #894C84; }\r\n"
		"    @media screen and (max-width: 980px) { h1 { font-size: 1.7em; text-align: center; color: #894C84; }}\r\n"
		"  </style>\r\n"
		"</head>\r\n"
	;

	static bool str_rmatch(std::string & str, const char *suffix) 
	{
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
			static bool ExtractAddressHelper(i2p::http::URL& url, std::string& jump, bool& confirm);
			static bool VerifyAddressHelper (std::string_view jump);
			void SanitizeHTTPRequest(i2p::http::HTTPReq& req);
			void SentHTTPFailed(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
			/* error helpers */
			void GenericProxyError(const std::string& title, const std::string& description);
			void GenericProxyInfo(const std::string& title, const std::string& description);
			void HostNotFound(const std::string& host);
			void SendProxyError(const std::string& content);
			void SendRedirect(const std::string& address);

			void ForwardToUpstreamProxy();
			void HandleUpstreamHTTPProxyConnect(const boost::system::error_code & ec);
			void HandleUpstreamSocksProxyConnect(const boost::system::error_code & ec);
			void HTTPConnect(const std::string & host, uint16_t port);
			void HandleHTTPConnectStreamRequestComplete(std::shared_ptr<i2p::stream::Stream> stream);

			typedef std::function<void(boost::asio::ip::tcp::endpoint)> ProxyResolvedHandler;

			void HandleUpstreamProxyResolved(const boost::system::error_code & ecode, boost::asio::ip::tcp::resolver::iterator itr, ProxyResolvedHandler handler);

			void SocksProxySuccess();
			void HandoverToUpstreamProxy();

			uint8_t m_recv_chunk[8192];
			std::string m_recv_buf; // from client
			std::string m_send_buf; // to upstream
			std::shared_ptr<boost::asio::ip::tcp::socket> m_sock;
			std::shared_ptr<boost::asio::ip::tcp::socket> m_proxysock;
			boost::asio::ip::tcp::resolver m_proxy_resolver;
			std::string m_OutproxyUrl, m_Response;
			bool m_Addresshelper, m_SendUserAgent;
			i2p::http::URL m_ProxyURL;
			i2p::http::URL m_RequestURL;
			int m_req_len;
			i2p::http::URL m_ClientRequestURL;
			i2p::http::HTTPReq m_ClientRequest;
			i2p::http::HTTPRes m_ClientResponse;
			std::stringstream m_ClientRequestBuffer;

		public:

			HTTPReqHandler(HTTPProxy * parent, std::shared_ptr<boost::asio::ip::tcp::socket> sock) :
				I2PServiceHandler(parent), m_sock(sock),
				m_proxysock(std::make_shared<boost::asio::ip::tcp::socket>(parent->GetService())),
				m_proxy_resolver(parent->GetService()),
				m_OutproxyUrl(parent->GetOutproxyURL()),
				m_Addresshelper(parent->GetHelperSupport()),
				m_SendUserAgent (parent->GetSendUserAgent ()) {}
			~HTTPReqHandler() { Terminate(); }
			void Handle () { AsyncSockRead(); } /* overload */
	};

	void HTTPReqHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug, "HTTPProxy: Async sock read");
		if (!m_sock) {
			LogPrint(eLogError, "HTTPProxy: No socket for read");
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
			LogPrint(eLogDebug, "HTTPProxy: Close sock");
			m_sock->close();
			m_sock = nullptr;
		}
		if(m_proxysock)
		{
			LogPrint(eLogDebug, "HTTPProxy: Close proxysock");
			if(m_proxysock->is_open())
				m_proxysock->close();
			m_proxysock = nullptr;
		}
		Done(shared_from_this());
	}

	void HTTPReqHandler::GenericProxyError(const std::string& title, const std::string& description) {
		std::stringstream ss;
		ss << "<h1>" << tr("Proxy error") << ": " << title << "</h1>\r\n";
		ss << "<p>" << description << "</p>\r\n";
		std::string content = ss.str();
		SendProxyError(content);
	}

	void HTTPReqHandler::GenericProxyInfo(const std::string& title, const std::string& description) {
		std::stringstream ss;
		ss << "<h1>" << tr("Proxy info") << ": " << title << "</h1>\r\n";
		ss << "<p>" << description << "</p>\r\n";
		std::string content = ss.str();
		SendProxyError(content);
	}

	void HTTPReqHandler::HostNotFound(const std::string& host) 
	{
		std::stringstream ss;
		ss << "<h1>" << tr("Proxy error: Host not found") << "</h1>\r\n"
		   << "<p>" << tr("Remote host not found in router's addressbook") << "</p>\r\n"
		   << "<p>" << tr("You may try to find this host on jump services below") << ":</p>\r\n"
		   << "<ul>\r\n";
		for (const auto& jump : jumporder)
		{
			auto js = jumpservices.find (jump);
			if (js != jumpservices.end())
				ss << "  <li><a href=\"" << js->second << host << "\">" << js->first << "</a></li>\r\n";
		}
		ss << "</ul>\r\n";
		std::string content = ss.str();
		SendProxyError(content);
	}

	void HTTPReqHandler::SendProxyError(const std::string& content)
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
		m_Response = res.to_string();
		boost::asio::async_write(*m_sock, boost::asio::buffer(m_Response), boost::asio::transfer_all(),
			std::bind(&HTTPReqHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
	}

	void HTTPReqHandler::SendRedirect(const std::string& address)
	{
		i2p::http::HTTPRes res;
		res.code = 302;
		res.add_header("Location", address);
		res.add_header("Connection", "close");
		m_Response = res.to_string();
		boost::asio::async_write(*m_sock, boost::asio::buffer(m_Response), boost::asio::transfer_all(),
			std::bind(&HTTPReqHandler::SentHTTPFailed, shared_from_this(), std::placeholders::_1));
	}

	bool HTTPReqHandler::ExtractAddressHelper(i2p::http::URL& url, std::string& jump, bool& confirm)
	{
		confirm = false;
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
		jump = i2p::http::UrlDecode(value);
		if (!VerifyAddressHelper (jump))
		{
			LogPrint (eLogError, "HTTPProxy: Malformed jump link ", jump);
			return false;
		}	
		
		// if we need update exists, request formed with update param
		if (params["update"] == "true")
		{
			len += std::strlen("&update=true");
			confirm = true;
		}

		// if helper is not only one query option and it placed after user's query
		if (pos != 0 && url.query[pos-1] == '&')
		{
			pos--;
			len++;
		}
		// if helper is not only one query option and it placed before user's query
		else if (pos == 0 && url.query.length () > len && url.query[len] == '&')
		{
			// we don't touch the '?' but remove the trailing '&'
			len++;
		}
		else
		{
			// there is no more query options, resetting hasquery flag
			url.hasquery = false;
		}

		// reset hasquery flag and remove addresshelper from URL
		url.query.replace(pos, len, "");
		return true;
	}

	bool HTTPReqHandler::VerifyAddressHelper (std::string_view jump)
	{
		auto pos = jump.find(".b32.i2p");
		if (pos != std::string::npos)
		{
			auto b32 = jump.substr (0, pos);
			for (auto& ch: b32)
				if (!i2p::data::IsBase32(ch)) return false;
			return true;
		}
		else
		{
			bool padding = false;
			for (auto& ch: jump)
			{
				if (ch == '=')
					padding = true;
				else
				{
					if (padding) return false; // other chars after padding
					if (!i2p::data::IsBase64(ch)) return false;
				}	
			}	
			return true;
		}	
		return false;
	}	
	
	void HTTPReqHandler::SanitizeHTTPRequest(i2p::http::HTTPReq& req)
	{
		/* drop common headers */
		req.RemoveHeader("Via");
		req.RemoveHeader("From");
		req.RemoveHeader("Forwarded");
		req.RemoveHeader("DNT"); // Useless DoNotTrack flag
		req.RemoveHeader("Accept", "Accept-Encoding"); // Accept*, but Accept-Encoding
		/* drop proxy-disclosing headers */
		req.RemoveHeader("X-Forwarded");
		req.RemoveHeader("Proxy-"); // Proxy-*
		/* replace headers */
		if (!m_SendUserAgent)
			req.UpdateHeader("User-Agent", "MYOB/6.66 (AN/ON)");

		/**
		 * i2pd PR #1816:
		 * Android Webview send this with the value set to the application ID, so we drop it,
		 * but only if it does not belong to an AJAX request (*HttpRequest, like XMLHttpRequest).
		 */
		if(req.GetHeader("X-Requested-With") != "") {
			auto h = req.GetHeader ("X-Requested-With");
			auto x = h.find("HttpRequest");
			if (x == std::string::npos) // not found
				req.RemoveHeader("X-Requested-With");
		}

		/**
		 * according to i2p ticket #1862:
		 * leave Referer if requested URL with same schema, host and port,
		 * otherwise, drop it.
		 */
		if(req.GetHeader("Referer") != "") {
			i2p::http::URL reqURL; reqURL.parse(req.uri);
			i2p::http::URL refURL; refURL.parse(req.GetHeader("Referer"));
			if(!boost::iequals(reqURL.schema, refURL.schema) || !boost::iequals(reqURL.host, refURL.host) || reqURL.port != refURL.port)
				req.RemoveHeader("Referer");
		}

		/* add headers */
		/* close connection, if not Connection: (U|u)pgrade (for websocket) */
		auto h = req.GetHeader ("Connection");
		auto x = h.find("pgrade");
		if (!(x != std::string::npos && std::tolower(h[x - 1]) == 'u'))
			req.UpdateHeader("Connection", "close");
	}

	/**
	 * @brief Try to parse request from @a m_recv_buf
	 *   If parsing success, rebuild request and store to @a m_send_buf
	 * with remaining data tail
	 * @return true on processed request or false if more data needed
	 */
	bool HTTPReqHandler::HandleRequest()
	{
		m_req_len = m_ClientRequest.parse(m_recv_buf);

		if (m_req_len == 0)
			return false; /* need more data */

		if (m_req_len < 0) {
			LogPrint(eLogError, "HTTPProxy: Unable to parse request");
			GenericProxyError(tr("Invalid request"), tr("Proxy unable to parse your request"));
			return true; /* parse error */
		}

		/* parsing success, now let's look inside request */
		LogPrint(eLogDebug, "HTTPProxy: Requested: ", m_ClientRequest.uri);
		m_RequestURL.parse(m_ClientRequest.uri);
		bool m_Confirm;

		std::string jump;
		if (ExtractAddressHelper(m_RequestURL, jump, m_Confirm))
		{
			if (!m_Addresshelper || !i2p::client::context.GetAddressBook ().IsEnabled ())
			{
				LogPrint(eLogWarning, "HTTPProxy: Addresshelper request rejected");
				GenericProxyError(tr("Invalid request"), tr("Addresshelper is not supported"));
				return true;
			}

			if (i2p::client::context.GetAddressBook ().RecordExists (m_RequestURL.host, jump))
			{
				std::string full_url = m_RequestURL.to_string();
				SendRedirect(full_url);
				return true;
			}
			else if (!i2p::client::context.GetAddressBook ().FindAddress (m_RequestURL.host) || m_Confirm)
			{
				const std::string referer_raw = m_ClientRequest.GetHeader("Referer");
				i2p::http::URL referer_url;
				if (!referer_raw.empty ())
				{
					referer_url.parse (referer_raw);
				}
				if (m_RequestURL.host != referer_url.host)
				{
					if (m_Confirm) // Attempt to forced overwriting by link with "&update=true" from harmful URL
					{
						LogPrint (eLogWarning, "HTTPProxy: Address update from addresshelper rejected for ", m_RequestURL.host, " (referer is ", m_RequestURL.host.empty() ? "empty" : "harmful", ")");
						std::string full_url = m_RequestURL.to_string();
						std::stringstream ss;
						ss << tr("Host %s is <font color=red>already in router's addressbook</font>. <b>Be careful: source of this URL may be harmful!</b> Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.",
							m_RequestURL.host.c_str(), full_url.c_str(), (full_url.find('?') != std::string::npos ? "&i2paddresshelper=" : "?i2paddresshelper="), jump.c_str());
						GenericProxyInfo(tr("Addresshelper forced update rejected"), ss.str());
					}
					else // Preventing unauthorized additions to the address book
					{
						LogPrint (eLogDebug, "HTTPProxy: Adding address from addresshelper for ", m_RequestURL.host, " (generate refer-base page)");
						std::string full_url = m_RequestURL.to_string();
						std::stringstream ss;
						ss << tr("To add host <b>%s</b> in router's addressbook, click here: <a href=\"%s%s%s\">Continue</a>.",
							m_RequestURL.host.c_str(), full_url.c_str(), (full_url.find('?') != std::string::npos ? "&i2paddresshelper=" : "?i2paddresshelper="), jump.c_str());
						GenericProxyInfo(tr("Addresshelper request"), ss.str());
					}
					return true; /* request processed */
				}

				i2p::client::context.GetAddressBook ().InsertAddress (m_RequestURL.host, jump);
				LogPrint (eLogInfo, "HTTPProxy: Added address from addresshelper for ", m_RequestURL.host);
				std::string full_url = m_RequestURL.to_string();
				std::stringstream ss;
				ss << tr("Host %s added to router's addressbook from helper. Click here to proceed: <a href=\"%s\">Continue</a>.",
					m_RequestURL.host.c_str(), full_url.c_str());
				GenericProxyInfo(tr("Addresshelper adding"), ss.str());
				return true; /* request processed */
			}
			else
			{
				std::string full_url = m_RequestURL.to_string();
				std::stringstream ss;
				ss << tr("Host %s is <font color=red>already in router's addressbook</font>. Click here to update record: <a href=\"%s%s%s&update=true\">Continue</a>.",
					m_RequestURL.host.c_str(), full_url.c_str(), (full_url.find('?') != std::string::npos ? "&i2paddresshelper=" : "?i2paddresshelper="), jump.c_str());
				GenericProxyInfo(tr("Addresshelper update"), ss.str());
				return true; /* request processed */
			}
		}
		std::string dest_host;
		uint16_t    dest_port;
		bool useConnect = false;
		if(m_ClientRequest.method == "CONNECT")
		{
			const std::string& uri = m_ClientRequest.uri;
			auto pos = uri.find(":");
			if(pos == std::string::npos || pos == uri.size() - 1)
			{
				GenericProxyError(tr("Invalid request"), tr("Invalid request URI"));
				return true;
			}
			else
			{
				useConnect = true;
				dest_port = std::stoi(uri.substr(pos+1));
				dest_host = uri.substr(0, pos);
			}
		}
		else
		{
			SanitizeHTTPRequest(m_ClientRequest);

			dest_host = m_RequestURL.host;
			dest_port = m_RequestURL.port;
			/* always set port, even if missing in request */
			if (!dest_port)
				dest_port = (m_RequestURL.schema == "https") ? 443 : 80;
			/* detect dest_host, set proper 'Host' header in upstream request */
			if (dest_host != "")
			{
				/* absolute url, replace 'Host' header */
				std::string h = dest_host;
				if (dest_port != 0 && dest_port != 80)
					h += ":" + std::to_string(dest_port);
				m_ClientRequest.UpdateHeader("Host", h);
			}
			else
			{
				auto h = m_ClientRequest.GetHeader ("Host");
				if (h.length () > 0)
				{
					/* relative url and 'Host' header provided. transparent proxy mode? */
					i2p::http::URL u;
					std::string t = "http://" + h;
					u.parse(t);
					dest_host = u.host;
					dest_port = u.port;
				}
				else
				{
					/* relative url and missing 'Host' header */
					GenericProxyError(tr("Invalid request"), tr("Can't detect destination host from request"));
					return true;
				}
			}
		}
		/* check dest_host really exists and inside I2P network */
		if (str_rmatch(dest_host, ".i2p")) {
			if (!i2p::client::context.GetAddressBook ().GetAddress (dest_host)) {
				HostNotFound(dest_host);
				return true; /* request processed */
			}
		} else {
			if(m_OutproxyUrl.size()) {
				LogPrint (eLogDebug, "HTTPProxy: Using outproxy ", m_OutproxyUrl);
				if(m_ProxyURL.parse(m_OutproxyUrl))
					ForwardToUpstreamProxy();
				else
					GenericProxyError(tr("Outproxy failure"), tr("Bad outproxy settings"));
			} else {
				LogPrint (eLogWarning, "HTTPProxy: Outproxy failure for ", dest_host, ": no outproxy enabled");
				std::stringstream ss; ss << tr("Host %s is not inside I2P network, but outproxy is not enabled", dest_host.c_str());
				GenericProxyError(tr("Outproxy failure"), ss.str());
			}
			return true;
		}
		if(useConnect)
		{
			HTTPConnect(dest_host, dest_port);
			return true;
		}

		/* make relative url */
		m_RequestURL.schema = "";
		m_RequestURL.host   = "";
		m_ClientRequest.uri = m_RequestURL.to_string();

		/* drop original request from recv buffer */
		m_recv_buf.erase(0, m_req_len);
		/* build new buffer from modified request and data from original request */
		m_send_buf = m_ClientRequest.to_string();
		m_send_buf.append(m_recv_buf);
		/* connect to destination */
		LogPrint(eLogDebug, "HTTPProxy: Connecting to host ", dest_host, ":", dest_port);
		GetOwner()->CreateStream (std::bind (&HTTPReqHandler::HandleStreamRequestComplete,
			shared_from_this(), std::placeholders::_1), dest_host, dest_port);
		return true;
	}

	void HTTPReqHandler::ForwardToUpstreamProxy()
	{
		LogPrint(eLogDebug, "HTTPProxy: Forwarded to upstream");

		/* build http request */
		m_ClientRequestURL = m_RequestURL;
		LogPrint(eLogDebug, "HTTPProxy: ", m_ClientRequestURL.host);
		m_ClientRequestURL.schema = "";
		m_ClientRequestURL.host   = "";
		std::string origURI = m_ClientRequest.uri; // TODO: what do we need to change uri for?
		m_ClientRequest.uri = m_ClientRequestURL.to_string();

		/* update User-Agent to ESR version of Firefox, same as Tor Browser below version 13, for non-HTTPS connections */
		if(m_ClientRequest.method != "CONNECT" && !m_SendUserAgent)
			m_ClientRequest.UpdateHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0");

		m_ClientRequest.write(m_ClientRequestBuffer);
		m_ClientRequestBuffer << m_recv_buf.substr(m_req_len);

		/* assume http if empty schema */
		if (m_ProxyURL.schema == "" || m_ProxyURL.schema == "http")
		{
			/* handle upstream http proxy */
			if (!m_ProxyURL.port) m_ProxyURL.port = 80;
			if (m_ProxyURL.is_i2p())
			{
				m_ClientRequest.uri = origURI;
				auto auth = i2p::http::CreateBasicAuthorizationString (m_ProxyURL.user, m_ProxyURL.pass);
				if (!auth.empty ())
				{
					/* remove existing authorization if any */
					m_ClientRequest.RemoveHeader("Proxy-");
					/* add own http proxy authorization */
					m_ClientRequest.AddHeader("Proxy-Authorization", auth);
				}
				m_send_buf = m_ClientRequest.to_string();
				m_recv_buf.erase(0, m_req_len);
				m_send_buf.append(m_recv_buf);
				GetOwner()->CreateStream (std::bind (&HTTPReqHandler::HandleStreamRequestComplete,
					shared_from_this(), std::placeholders::_1), m_ProxyURL.host, m_ProxyURL.port);
			}
			else
			{
				boost::asio::ip::tcp::resolver::query q(m_ProxyURL.host, std::to_string(m_ProxyURL.port));
				m_proxy_resolver.async_resolve(q, std::bind(&HTTPReqHandler::HandleUpstreamProxyResolved, this, std::placeholders::_1, std::placeholders::_2, [&](boost::asio::ip::tcp::endpoint ep) {
					m_proxysock->async_connect(ep, std::bind(&HTTPReqHandler::HandleUpstreamHTTPProxyConnect, this, std::placeholders::_1));
				}));
			}
		}
		else if (m_ProxyURL.schema == "socks")
		{
			/* handle upstream socks proxy */
			if (!m_ProxyURL.port) m_ProxyURL.port = 9050; // default to tor default if not specified
			boost::asio::ip::tcp::resolver::query q(m_ProxyURL.host, std::to_string(m_ProxyURL.port));
			m_proxy_resolver.async_resolve(q, std::bind(&HTTPReqHandler::HandleUpstreamProxyResolved, this, std::placeholders::_1, std::placeholders::_2, [&](boost::asio::ip::tcp::endpoint ep) {
				m_proxysock->async_connect(ep, std::bind(&HTTPReqHandler::HandleUpstreamSocksProxyConnect, this, std::placeholders::_1));
			}));
		}
		else
		{
			/* unknown type, complain */
			GenericProxyError(tr("Unknown outproxy URL"), m_ProxyURL.to_string());
		}
	}

	void HTTPReqHandler::HandleUpstreamProxyResolved(const boost::system::error_code & ec, boost::asio::ip::tcp::resolver::iterator it, ProxyResolvedHandler handler)
	{
		if(ec) GenericProxyError(tr("Cannot resolve upstream proxy"), ec.message());
		else handler(*it);
	}

	void HTTPReqHandler::HandleUpstreamSocksProxyConnect(const boost::system::error_code & ec)
	{
		if(!ec) 
		{
			if(m_RequestURL.host.size() > 255) 
			{
				GenericProxyError(tr("Hostname is too long"), m_RequestURL.host);
				return;
			}
			uint16_t port = m_RequestURL.port;
			if(!port) port = 80;
			LogPrint(eLogDebug, "HTTPProxy: Connected to SOCKS upstream");
			std::string host = m_RequestURL.host;
			auto s = shared_from_this ();
			i2p::transport::Socks5Handshake (*m_proxysock, std::make_pair(host, port),
				[s](const boost::system::error_code& ec)
			    {
					if (!ec)
						s->SocksProxySuccess();
					else
						s->GenericProxyError(tr("SOCKS proxy error"), ec.message ());	
				});
			
		} 
		else 
			GenericProxyError(tr("Cannot connect to upstream SOCKS proxy"), ec.message());
	}

	void HTTPReqHandler::HandoverToUpstreamProxy()
	{
		LogPrint(eLogDebug, "HTTPProxy: Handover to SOCKS proxy");
		auto connection = CreateSocketsPipe (GetOwner(), m_proxysock, m_sock);
		m_sock = nullptr;
		m_proxysock = nullptr;
		GetOwner()->AddHandler(connection);
		connection->Start();
		Terminate();
	}

	void HTTPReqHandler::HTTPConnect(const std::string & host, uint16_t port)
	{
		LogPrint(eLogDebug, "HTTPProxy: CONNECT ",host, ":", port);
		std::string hostname(host);
		if(str_rmatch(hostname, ".i2p"))
			GetOwner()->CreateStream (std::bind (&HTTPReqHandler::HandleHTTPConnectStreamRequestComplete,
				shared_from_this(), std::placeholders::_1), host, port);
		else
			ForwardToUpstreamProxy();
	}

	void HTTPReqHandler::HandleHTTPConnectStreamRequestComplete(std::shared_ptr<i2p::stream::Stream> stream)
	{
		if(stream)
		{
			m_ClientResponse.code = 200;
			m_ClientResponse.status = "OK";
			m_send_buf = m_ClientResponse.to_string();
			m_sock->send(boost::asio::buffer(m_send_buf));
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>(GetOwner(), m_sock, stream);
			GetOwner()->AddHandler(connection);
			connection->I2PConnect();
			m_sock = nullptr;
			Terminate();
		}
		else
		{
			GenericProxyError(tr("CONNECT error"), tr("Failed to connect"));
		}
	}

	void HTTPReqHandler::SocksProxySuccess()
	{
		if(m_ClientRequest.method == "CONNECT") {
			m_ClientResponse.code = 200;
			m_send_buf = m_ClientResponse.to_string();
			boost::asio::async_write(*m_sock, boost::asio::buffer(m_send_buf), boost::asio::transfer_all(), [&] (const boost::system::error_code & ec, std::size_t transferred)
				{
					if(ec) GenericProxyError(tr("SOCKS proxy error"), ec.message());
					else HandoverToUpstreamProxy();
				});
		} else {
			m_send_buf = m_ClientRequestBuffer.str();
			LogPrint(eLogDebug, "HTTPProxy: Send ", m_send_buf.size(), " bytes");
			boost::asio::async_write(*m_proxysock, boost::asio::buffer(m_send_buf), boost::asio::transfer_all(), [&](const boost::system::error_code & ec, std::size_t transferred)
				{
					if(ec) GenericProxyError(tr("Failed to send request to upstream"), ec.message());
					else HandoverToUpstreamProxy();
				});
		}
	}

	void HTTPReqHandler::HandleUpstreamHTTPProxyConnect(const boost::system::error_code & ec)
	{
		if(!ec) {
			LogPrint(eLogDebug, "HTTPProxy: Connected to http upstream");
			GenericProxyError(tr("Cannot connect"), tr("HTTP out proxy not implemented"));
		} else GenericProxyError(tr("Cannot connect to upstream HTTP proxy"), ec.message());
	}

	/* will be called after some data received from client */
	void HTTPReqHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug, "HTTPProxy: Sock recv: ", len, " bytes, recv buf: ", m_recv_buf.length(), ", send buf: ", m_send_buf.length());
		if(ecode)
		{
			LogPrint(eLogWarning, "HTTPProxy: Sock recv got error: ", ecode);
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
			LogPrint (eLogError, "HTTPProxy: Error when creating the stream, check the previous warnings for more info");
			GenericProxyError(tr("Host is down"), tr("Can't create connection to requested host, it may be down. Please try again later."));
			return;
		}
		if (Kill())
			return;
		LogPrint (eLogDebug, "HTTPProxy: Created new I2PTunnel stream, sSID=", stream->GetSendStreamID(), ", rSID=", stream->GetRecvStreamID());
		auto connection = std::make_shared<i2p::client::I2PClientTunnelConnectionHTTP>(GetOwner(), m_sock, stream);
		GetOwner()->AddHandler (connection);
		connection->I2PConnect (reinterpret_cast<const uint8_t*>(m_send_buf.data()), m_send_buf.length());
		Done (shared_from_this());
	}

	HTTPProxy::HTTPProxy(const std::string& name, const std::string& address, uint16_t port, 
	    const std::string & outproxy, bool addresshelper, bool senduseragent, std::shared_ptr<i2p::client::ClientDestination> localDestination):
		TCPIPAcceptor (address, port, localDestination ? localDestination : i2p::client::context.GetSharedLocalDestination ()),
		m_Name (name), m_OutproxyUrl (outproxy), m_Addresshelper (addresshelper), m_SendUserAgent (senduseragent)
	{
	}

	std::shared_ptr<i2p::client::I2PServiceHandler> HTTPProxy::CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		return std::make_shared<HTTPReqHandler> (this, socket);
	}
} // http
} // i2p
