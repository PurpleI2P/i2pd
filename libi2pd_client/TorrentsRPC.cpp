/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <boost/version.hpp>
#if BOOST_VERSION >= 108100 // boost::json since 1.75, we allow it since 1.81 due to std::string_view compatibility
#include <boost/json.hpp>
#define JSON_SUPPORTED
#endif
#include <boost/algorithm/hex.hpp>
#include <vector>
#include <functional>
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

			std::string SuccessResponse (int64_t id, boost::json::object&& arguments);
			std::string ResultResponse (int64_t id, boost::json::object&& result);
			std::string ErrorResponse (JSONRPCErrorCode errorCode, int64_t id, std::string_view message);
			int64_t GetTag (boost::json::object& jsonRequest) const;
			std::string GetNewFieldName (std::string_view fieldName) const;
			static boost::json::value GetFieldValue (std::string_view field, std::shared_ptr<Torrent> torrent);
			boost::json::array GetPeers (std::shared_ptr<Torrent> torrent);
			static std::string_view RecognizeClientByPeerID (std::string_view peerID);

			std::string HandleTorrrentAdd (boost::json::object&& jsonRequest);
			std::string HandleTorrrentRemove (boost::json::object&& jsonRequest);
			std::string HandleTorrrentGet (boost::json::object&& jsonRequest);

		private:

			std::shared_ptr<TorrentsTunnel> m_Tunnel;
	};

	std::string JSONRPCHandler::SuccessResponse (int64_t id, boost::json::object&& arguments)
	{
		boost::json::object response;
		response["result"] = "success";
		response["arguments"] = arguments;
		if (id) response["id"] = id;
		return boost::json::serialize(response);
	}

	std::string JSONRPCHandler::ResultResponse (int64_t id, boost::json::object&& result)
	{
		boost::json::object response;
		response["jsonrpc"] = "2.0";
		response["result"] = result;
		if (id) response["id"] = id;
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

	int64_t JSONRPCHandler::GetTag (boost::json::object& jsonRequest) const
	{
		if (jsonRequest.contains ("tag"))
			return jsonRequest.at ("tag").as_int64 ();
		return 0;
	}

	std::string JSONRPCHandler::GetNewFieldName (std::string_view fieldName) const
	{
		std::string newFieldName;
		newFieldName.reserve (fieldName.length ());
		for (auto it: fieldName)
			if (std::isupper (it))
			{
				newFieldName.push_back ('_');
				newFieldName.push_back (std::tolower (it));
			}
			else
				newFieldName.push_back (it);
		return newFieldName;
	}

	std::string JSONRPCHandler::HandleRequest (std::string_view request)
	{
		try
		{
			auto jsonRequest = boost::json::parse (request).as_object ();
			auto method = jsonRequest.at ("method").as_string ();
			if (method == "torrent-add")
				return HandleTorrrentAdd (std::move (jsonRequest));
			else if (method == "torrent-remove")
				return HandleTorrrentRemove (std::move (jsonRequest));
			else if (method == "torrent-get")
				return HandleTorrrentGet (std::move (jsonRequest));
			else
			{
				LogPrint (eLogInfo, "TorrentsRPC: Method not found ", method);
				return ErrorResponse (eMethodNotFound, jsonRequest.at ("tag").as_int64 (), "Method not found");
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
		auto [torrent, id] = m_Tunnel->AddTorrent (torrentFileContent);

		boost::json::object response, torrentInfo;
		if (torrent)
		{
			std::string hexHash;
			boost::algorithm::hex (torrent->GetInfoHash ().begin(), torrent->GetInfoHash ().end(), std::back_inserter(hexHash));
			torrentInfo["id"] = id;
			torrentInfo["hashString"] = hexHash;
			torrentInfo["name"] = torrent->GetName ();
		}
		if (id)
		{
			response["torrent-added"] = torrentInfo;
			LogPrint (eLogDebug, "TorrentsRPC: torrent added ", torrentInfo["name"].as_string ());
		}
		else
		{
			response["torrent-duplicate"] = torrentInfo;
			LogPrint (eLogDebug, "TorrentsRPC: duplicate torrent ", torrentInfo["name"].as_string ());
		}
		return SuccessResponse (GetTag (jsonRequest), std::move (response));
	}

	std::string JSONRPCHandler::HandleTorrrentRemove (boost::json::object&& jsonRequest)
	{
		auto arguments = jsonRequest.at ("arguments").as_object ();
		bool deleteFiles = false;
		if (arguments.contains ("delete-local-data"))
			deleteFiles = arguments.at ("delete-local-data").as_bool ();
		std::vector<int> torrentIds;
		if (arguments.contains ("ids"))
		{
			auto ids = arguments.at ("ids");
			if (ids.is_array ())
				for (const auto& it: ids.as_array ())
					torrentIds.push_back (it.as_int64 ());
			else
				torrentIds.push_back (ids.as_int64 ());
		}
		for (auto id: torrentIds)
 			m_Tunnel->RemoveTorrent (id, deleteFiles);
		boost::json::object response; // always empty
		return SuccessResponse (GetTag (jsonRequest), std::move (response));
	}

	std::string JSONRPCHandler::HandleTorrrentGet (boost::json::object&& jsonRequest)
	{
		auto arguments = jsonRequest.at ("arguments").as_object ();
		std::vector<int> torrentIds;
		bool torrentsRequested = arguments.contains ("ids");
		if (torrentsRequested)
		{
			auto ids = arguments.at ("ids");
			if (ids.is_array ())
				for (const auto& it: ids.as_array ())
					torrentIds.push_back (it.as_int64 ());
			else
				torrentIds.push_back (ids.as_int64 ());
		}
		else
			torrentIds = m_Tunnel->GetTorrentIDs ();
		auto fields = arguments.at ("fields").as_array ();

		boost::json::object response;
		boost::json::array torrents;
		for (auto id: torrentIds)
		{
			auto torrent = m_Tunnel->FindTorrentByID (id);
			if (torrent)
			{
				boost::json::object t;
				t["id"] = id;
				for (const auto& field: fields)
				{
					if (field == "id")
						continue;
					else if (field == "peers")
						t["peers"] = GetPeers (torrent);
					else
					{
						auto fieldValue = GetFieldValue (field.as_string (), torrent);
						if (!fieldValue.is_null ())
							t[GetNewFieldName (field.as_string ())] = fieldValue;
					}
				}
				torrents.push_back (t);
			}
		}
		response["torrents"] = torrents;
		return ResultResponse (GetTag (jsonRequest), std::move (response));
	}

	boost::json::value JSONRPCHandler::GetFieldValue (std::string_view field, std::shared_ptr<Torrent> torrent)
	{
		const static std::map<std::string_view, std::function<boost::json::value (std::shared_ptr<Torrent>)> > fields =
		{
			{ "name", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetName ()); } },
			{ "status", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetStatus ()); } },
			{ "isFinished", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->IsComplete ()); } },
			{ "sizeWhenDone", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetLength ()); } },
			{ "leftUntilDone", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetLeft ()); } },
			{ "rateDownload", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetDownloadRate ()); } },
			{ "rateUpload", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetUploadRate ()); } },
			{ "peersGettingFromUs", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetNumUploadingToPeers ()); } },
			{ "peersSendingToUs", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetNumDownloadingFromPeers ()); } },
			{ "pieceCount", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetNumPieces ()); } },
			{ "pieceSize", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetPieceLength ()); } },
			{ "totalSize", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(torrent->GetLength ()); } },
			{ "hashString", [](std::shared_ptr<Torrent> torrent)
				{
					std::string hexHash;
					boost::algorithm::hex (torrent->GetInfoHash ().begin(), torrent->GetInfoHash ().end(), std::back_inserter(hexHash));
					return boost::json::value(hexHash);
				}
			},
			{ "pieces", [](std::shared_ptr<Torrent> torrent)
				{
					auto [bitfield, empry] = torrent->CreateBitfield ();
					std::string b64pieces;
					b64pieces.resize (boost::beast::detail::base64::encoded_size (bitfield.size()));
					boost::beast::detail::base64::encode (b64pieces.data (), bitfield.data(), bitfield.size());
					return boost::json::value(b64pieces);
				}
			},
			{ "error", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(0); } }, // no error
			{ "eta", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(600); } }, // TODO:
			{ "uploadRatio", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(1); } } // TODO:
		};
		if (torrent)
		{
			auto it = fields.find (field);
			if (it != fields.end ())
				return it->second (torrent);
		}
		return boost::json::value ();
	}

	boost::json::array JSONRPCHandler::GetPeers (std::shared_ptr<Torrent> torrent)
	{
		boost::json::array peers;
		std::list<std::shared_ptr<PeerConnection> > conns;
		boost::asio::post (m_Tunnel->GetService (),
			boost::asio::use_future ([tunnel = m_Tunnel, torrent, &conns]()
			{
				conns = tunnel->GetTorrentConnections (torrent);
			})).wait ();
		for (const auto& it: conns)
		{
			boost::json::object peer;
			auto stream = it->GetStream ();
			peer["address"] = stream ? stream->GetRemoteIdentity ()->GetIdentHash ().ToBase64 ().substr (0,4) : "";
			peer["port"] = TORRENT_PORT;
			peer["client_name"] = RecognizeClientByPeerID (it->GetRemotePeerID ());
			peer["is_dowloading_from"] = it->IsDownloading ();
			peer["is_uploading_to"] = it->IsUploading ();
			peer["rate_to_client"] = it->GetDownloadRate ();
			peer["rate_to_peer"] = it->GetUploadRate ();
			peer["is_incoming"] = stream ? stream->IsIncoming () : false;
			peer["client_is_choked"] = it->IsChoked ();
			peer["peer_is_choked"] = it->IsRemoteChoked ();
			peer["client_is_intersted"] = it->IsInterested ();
			peer["peer_is_interested"] = it->IsRemoteInterested ();
			peer["flag_str"] = "TE"; // TODO:
			peer["progress"] = 0.5; // TODO:
			peers.push_back (peer);
		}
		return peers;
	}

	std::string_view JSONRPCHandler::RecognizeClientByPeerID (std::string_view peerID)
	{
		const static std::map<std::string_view, std::string_view> twoChars =
		{
			{ "qB", "qBittorrent" },
			{ "XD", "XD"},
			{ "BI", "BiglyBT" },
			{ "AZ", "Vuze" },
			{ "LT", "libtorrent" }
		};

		if (peerID.substr (0, 6) == "-I2PD-")
			return "i2pd";
		if (peerID[0] == '-')
		{
			auto it = twoChars.find (peerID.substr (1,2));
			if (it != twoChars.end ())
				return it->second;
		}
		if (peerID.substr (0, 12) == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x03\x03")
			return "I2PSnark";
		return "Unknown";
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
		m_Response.set(boost::beast::http::field::content_type, (result == boost::beast::http::status::ok) ? "application/json; charset=UTF-8" : "text/plain");
		m_Response.body () = data;
		m_Response.prepare_payload ();
		boost::beast::http::async_write (m_Socket, m_Response,
			[s = shared_from_this ()](const boost::system::error_code& ecode, size_t bytes_transferred)
			{
				if (ecode)
					LogPrint (eLogWarning, "TorrentsRPC: Failed to send response: ", ecode.message ());
			});
	}

	TorrentsRPCServer::TorrentsRPCServer (std::string_view address, uint16_t port):
		RunnableServiceWithWork ("TRPC"),  m_Acceptor (GetService (),
			boost::asio::ip::tcp::endpoint (boost::asio::ip::make_address (address), port))
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
