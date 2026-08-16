/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <boost/version.hpp>
#if BOOST_VERSION >= 107800 // boost::json since 1.75, we allow since 1.78
#include <boost/json.hpp>
#define JSON_SUPPORTED
#endif
#include <boost/algorithm/hex.hpp>
#include "Log.h"
#include "Torrents.h"
#include "TorrentsRPC.h"

namespace i2p
{
namespace torrents
{
#ifdef JSON_SUPPORTED

	enum JSONRPCErrorCode
	{
		eMethodNotFound = -32601,
		eInvalidParam = -32602,
		eParseError = -32700
	};

	class JSONRPCHandler
	{
		public:

			JSONRPCHandler (std::shared_ptr<TorrentsTunnel> tunnel): m_Tunnel (tunnel) {};

			std::string HandleRequest (std::string_view request);

		private:

			std::string SuccessResponse (boost::json::object&& arguments);
			std::string ErrorResponse (JSONRPCErrorCode errorCode, int64_t id, std::string_view message);

			std::string HandleTorrrentAdd (boost::json::object&& jsonRequest);

		private:

			std::shared_ptr<TorrentsTunnel> m_Tunnel;
	};

	std::string JSONRPCHandler::SuccessResponse (boost::json::object&& arguments)
	{
		boost::json::object response;
		response["result"] = "success";
		response["arguments"] = arguments;
		return boost::json::serialize(response);
	}

	std::string JSONRPCHandler::ErrorResponse (JSONRPCErrorCode errorCode, int64_t id, std::string_view message)
	{
		boost::json::object response;
		response["jsonrpc"] = "2.0";
		if (id) response["id"] = id;
		boost::json::object error;
		error["code"] = errorCode;
		error["message"] = message;
		response["error"] = error;
		return boost::json::serialize(response);
	}

	std::string JSONRPCHandler::HandleRequest (std::string_view request)
	{
		try
		{
			auto jsonRequest = boost::json::parse (request).as_object ();
			auto method = jsonRequest.at ("method").as_string ();
			if (method == "torrent-add")
				return HandleTorrrentAdd (std::move (jsonRequest));
			else
			{
				LogPrint (eLogInfo, "TorrentsRPC: Method not found ", method);
				int64_t tag = jsonRequest.at ("tag").as_int64 ();
				return ErrorResponse (eMethodNotFound, tag, "Method not found");
			}
		}
		catch (const std::exception& ex)
		{
			LogPrint (eLogInfo, "TorrentsRPC: Failed to parse JSON: ", ex.what ());
			return ErrorResponse (eParseError, 0, "Parse error");
		}
		return "";
	}

	std::string JSONRPCHandler::HandleTorrrentAdd (boost::json::object&& jsonRequest)
	{
		auto arguments = jsonRequest.at ("arguments").as_object ();
		auto b64torrent = arguments.at ("metainfo").as_string ();
		std::string torrentFileContent;
		torrentFileContent.resize (boost::beast::detail::base64::decoded_size (b64torrent.size ()));
		boost::beast::detail::base64::decode (torrentFileContent.data (), b64torrent.data (), b64torrent.size ());
		auto [torrent, added] = m_Tunnel->AddTorrent (torrentFileContent);

		boost::json::object response, torrentInfo;
		std::string hexHash;
		if (torrent)
		{
			boost::algorithm::hex (torrent->GetInfoHash ().begin(), torrent->GetInfoHash ().end(), std::back_inserter(hexHash));
			torrentInfo["id"] = 1; // TODO:
			torrentInfo["hashString"] = hexHash;
			torrentInfo["name"] = torrent->GetName ();
		}
		if (added)
		{
			response["torrent-added"] = torrentInfo;
			LogPrint (eLogDebug, "TorrentsRPC: torrent added ", torrentInfo["name"].as_string ());
		}
		else
		{
			response["torrent-duplicate"] = torrentInfo;
			LogPrint (eLogDebug, "TorrentsRPC: duplicate torrent ", torrentInfo["name"].as_string ());
		}
		return SuccessResponse (std::move (response));
	}

#endif

	TorrentsRPCSession::TorrentsRPCSession (TorrentsRPCServer& server, boost::asio::ip::tcp::socket&& s):
		m_Server (server), m_Socket (std::move (s))
	{
	}

	void TorrentsRPCSession::ReceiveRequest ()
	{
		boost::beast::http::async_read (m_Socket, m_ReceiveBuffer, m_Request,
			boost::beast::bind_front_handler (&TorrentsRPCSession::HandleRequest, shared_from_this()));
	}

	void TorrentsRPCSession::HandleRequest (const boost::system::error_code& ecode, size_t bytes_transferred)
	{
		if (!ecode)
		{
			if (m_Request.method() == boost::beast::http::verb::post)
			{
				auto path = m_Request.target ();
				auto tunnel = m_Server.GetTunnel ( {path.data (), path.size ()}); // boost::beast::string_view to std::string_view
				if (tunnel)
				{
					if (m_Request[boost::beast::http::field::content_type] == "application/json" ||
						m_Request[boost::beast::http::field::content_type] == "application/x-www-form-urlencoded")
					{
#ifdef JSON_SUPPORTED
						JSONRPCHandler jsonHandler (tunnel);
						auto response = jsonHandler.HandleRequest (m_Request.body ());
						if (!response.empty ())
							SendResponse (boost::beast::http::status::ok, response);
#else
						SendResponse (boost::beast::http::status::not_implemented, std::string ("Your boost version ") + BOOST_LIB_VERSION + " is too old");
#endif
					}
					else
						SendResponse (boost::beast::http::status::no_content);
				}
				else
					SendResponse (boost::beast::http::status::not_found);
			}
			else
				SendResponse (boost::beast::http::status::method_not_allowed);
		}
	}

	void TorrentsRPCSession::SendResponse (boost::beast::http::status result, std::string_view data)
	{
		m_Response.version (11); // HTTP/1.1
		m_Response.result (result);
		m_Response.set (boost::beast::http::field::server, "i2pd torents RPC");
		m_Response.set(boost::beast::http::field::content_type, (result == boost::beast::http::status::ok) ? "application/json" : "text/plain");
		m_Response.body () = data;
		m_Response.prepare_payload ();
		boost::beast::http::async_write (m_Socket, m_Response,
			[s = shared_from_this ()](const boost::system::error_code& ecode, size_t bytes_transferred)
			{
				if (ecode)
					LogPrint (eLogWarning, "TorrentsRPC: Failed to send response: ", ecode.message ());
			});
	}

	TorrentsRPCServer::TorrentsRPCServer (uint16_t port):
		RunnableServiceWithWork ("TRPC"),  m_Acceptor (GetService (),
			boost::asio::ip::tcp::endpoint (boost::asio::ip::make_address ("127.0.0.1"), port))
	{
	}

	void TorrentsRPCServer::Start ()
	{
		if (!IsRunning ())
		{
			StartIOService ();
			Accept ();
		}
	}

	void TorrentsRPCServer::Stop ()
	{
		if (IsRunning ())
		{
			m_Acceptor.cancel ();
			StopIOService ();
		}
	}

	void TorrentsRPCServer::AddTunnel (std::string_view path, std::shared_ptr<TorrentsTunnel> tunnel)
	{
		std::string rpcPath ("/");
		if (!path.empty ())
			rpcPath += std::string (path) + "/";
		rpcPath += "rpc/";
		m_Tunnels.emplace (rpcPath, tunnel);
	}

	std::shared_ptr<TorrentsTunnel> TorrentsRPCServer::GetTunnel (std::string_view path) const
	{
		auto it = m_Tunnels.find (path);
		if (it != m_Tunnels.end ())
			return it->second.lock ();
		return nullptr;
	}

	void TorrentsRPCServer::Accept ()
	{
		m_Acceptor.async_accept (boost::asio::make_strand (GetService ()),
			[this](const boost::system::error_code& ecode, boost::asio::ip::tcp::socket socket)
			{
				if (!ecode)
				{
					LogPrint (eLogDebug, "TorrentsRPC: Accepted incoming request");
					auto session = std::make_shared<TorrentsRPCSession>(*this, std::move(socket));
					session->ReceiveRequest ();
					Accept ();
				}
			});
	}
}
}
