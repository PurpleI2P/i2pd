/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <boost/version.hpp>
#if !defined(ANDROID) && (BOOST_VERSION >= 108100) // boost::json since 1.75, we allow it since 1.81 due to std::string_view compatibility
#include <boost/json.hpp>
#define JSON_SUPPORTED
#endif
#include <boost/algorithm/hex.hpp>
#include <vector>
#include <array>
#include <functional>
#include "Log.h"
#include "HTTP.h"
#include "Timestamp.h"
#include "Torrents.h"
#include "TorrentsTunnel.h"
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
			static int64_t GetTag (boost::json::object& jsonRequest);
			static std::vector<int> GetTorrentIds (boost::json::object& arguments);
			static boost::json::value GetFieldValue (std::string_view field, std::shared_ptr<Torrent> torrent);
			boost::json::array GetPeers (std::shared_ptr<Torrent> torrent) const;
			boost::json::array GetTrackers (std::shared_ptr<Torrent> torrent) const;
			boost::json::array GetTrackerStats (std::shared_ptr<Torrent> torrent) const;
			boost::json::array GetFiles (std::shared_ptr<Torrent> torrent) const;
			static std::string_view RecognizeClientByPeerID (const PeerConnection::PeerID& peerID);

			std::string HandleTorrentAdd (boost::json::object&& jsonRequest);
			std::string HandleTorrentRemove (boost::json::object&& jsonRequest);
			std::string HandleTorrentGet (boost::json::object&& jsonRequest);
			std::string HandleTorrentStop (boost::json::object&& jsonRequest);
			std::string HandleTorrentStart (boost::json::object&& jsonRequest);
			std::string HandleSessionGet (boost::json::object&& jsonRequest); // for transmission-rpc library
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

	int64_t JSONRPCHandler::GetTag (boost::json::object& jsonRequest)
	{
		if (jsonRequest.contains ("tag"))
			return jsonRequest.at ("tag").as_int64 ();
		return 0;
	}

	std::vector<int> JSONRPCHandler::GetTorrentIds (boost::json::object& arguments)
	{
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
		return torrentIds;;
	}

	std::string JSONRPCHandler::HandleRequest (std::string_view request)
	{
		try
		{
			auto jsonRequest = boost::json::parse (request).as_object ();
			auto method = jsonRequest.at ("method").as_string ();
			if (method == "torrent-add")
				return HandleTorrentAdd (std::move (jsonRequest));
			else if (method == "torrent-remove")
				return HandleTorrentRemove (std::move (jsonRequest));
			else if (method == "torrent-get")
				return HandleTorrentGet (std::move (jsonRequest));
			else if (method == "torrent-stop")
				return HandleTorrentStop (std::move (jsonRequest));
			else if (method == "torrent-start")
				return HandleTorrentStart (std::move (jsonRequest));
			else if (method == "session-get")
				return HandleSessionGet (std::move (jsonRequest));
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

	std::string JSONRPCHandler::HandleSessionGet (boost::json::object&& jsonRequest)
	{
		boost::json::object response, arguments;
		response["result"] = "success";
		response["version"] = "4.0.0";
		response["rpc-version"] = 17;
		arguments["version"] = "4.0.0";
		response["arguments"] = arguments;
		response["tag"] = 0;
		return SuccessResponse (GetTag (jsonRequest), std::move (response));
	}

	std::string JSONRPCHandler::HandleTorrentAdd (boost::json::object&& jsonRequest)
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

	std::string JSONRPCHandler::HandleTorrentRemove (boost::json::object&& jsonRequest)
	{
		auto arguments = jsonRequest.at ("arguments").as_object ();
		bool deleteFiles = false;
		if (arguments.contains ("delete-local-data"))
			deleteFiles = arguments.at ("delete-local-data").as_bool ();
		for (auto id: GetTorrentIds (arguments))
 			m_Tunnel->RemoveTorrent (id, deleteFiles);
		boost::json::object response; // always empty
		return SuccessResponse (GetTag (jsonRequest), std::move (response));
	}

	std::string JSONRPCHandler::HandleTorrentGet (boost::json::object&& jsonRequest)
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
		response["jsonrpc"] = "2.0";
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
					else if (field == "trackers")
						t["trackers"] = GetTrackers (torrent);
					else if (field == "trackerStats")
						t["trackerStats"] = GetTrackerStats (torrent);
					else if (field == "files")
						t["files"] = GetFiles (torrent);
					else
					{
						auto fieldValue = GetFieldValue (field.as_string (), torrent);
						if (!fieldValue.is_null ())
							t[field.as_string ()] = fieldValue;
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
			{ "percentDone", [](std::shared_ptr<Torrent> torrent)
				{
					 if (!torrent->GetLength ()) return boost::json::value (1.0);
					 return boost::json::value ((float)(torrent->GetLength () - torrent->GetLeft ())/(float)torrent->GetLength ());
				}
			},
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
			{ "wanted", [](std::shared_ptr<Torrent> torrent)
				{
					boost::json::array wanted;
					size_t numFiles = torrent->GetFiles ().size ();
					if (!numFiles) numFiles = 1;
					wanted.resize (numFiles);
					std::fill (wanted.begin(), wanted.end(), 1);
					return wanted;
				}
			},
			{ "priorities", [](std::shared_ptr<Torrent> torrent)
				{
					boost::json::array priorities;
					size_t numFiles = torrent->GetFiles ().size ();
					if (!numFiles) numFiles = 1;
					priorities.resize (numFiles);
					std::fill (priorities.begin(), priorities.end(), 0);
					return priorities;
				}
			},
			{ "error", [](std::shared_ptr<Torrent> torrent) { return boost::json::value(0); } }, // no error
			{ "eta", [](std::shared_ptr<Torrent> torrent)
				{
					auto downloadRate = torrent->GetDownloadRate ();
					return boost::json::value (downloadRate ? torrent->GetLeft ()/downloadRate : -2);
				}
			},
			{ "uploadRatio", [](std::shared_ptr<Torrent> torrent)
				{
					float ratio = torrent->GetDownloaded () ? ((float)torrent->GetUploaded ())/((float)torrent->GetDownloaded ()) : 100.0;
					return boost::json::value (ratio);
				}
			}
		};
		if (torrent)
		{
			auto it = fields.find (field);
			if (it != fields.end ())
				return it->second (torrent);
		}
		return boost::json::value ();
	}

	boost::json::array JSONRPCHandler::GetPeers (std::shared_ptr<Torrent> torrent) const
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
			if (it->IsEstablished ())
			{
				boost::json::object peer;
				std::string flags;
				auto stream = it->GetStream ();
				bool isIncoming = stream ? stream->IsIncoming () : false;
				if (isIncoming) flags.push_back ('I');
				auto identHashStr = stream ? stream->GetRemoteIdentity ()->GetIdentHash ().ToBase64 () : "";
				peer["address"] = identHashStr.substr (0, 4);
				peer["port"] = TORRENT_PORT;
				peer["identHash"] = identHashStr;
				peer["clientName"] = it->GetRemoteName ().empty () ? RecognizeClientByPeerID (it->GetRemotePeerID ()) : it->GetRemoteName ();
				peer["isDowloadingFrom"] = it->IsDownloading ();
				peer["isUploading_to"] = it->IsUploading ();
				peer["rateToClient"] = it->GetDownloadRate ();
				peer["rateToPeer"] = it->GetUploadRate ();
				peer["isIncoming"] = isIncoming;
				peer["clientIsChoked"] = it->IsChoked ();
				peer["peerIsChoked"] = it->IsRemoteChoked ();
				peer["clientIsIntersted"] = it->IsInterested ();
				peer["peerIsInterested"] = it->IsRemoteInterested ();
				peer["flagStr"] = flags;
				peer["progress"] = torrent->GetLength () ? ((float)it->GetDownloaded ())/(float)(torrent->GetLength ()) : 1.0;
				peers.push_back (peer);
			}
		}
		return peers;
	}

	boost::json::array JSONRPCHandler::GetTrackers (std::shared_ptr<Torrent> torrent) const
	{
		boost::json::array trackers;
		for (size_t i = 0; i < m_Tunnel->GetNumTrackers (); i++)
		{
			boost::json::object tracker;
			tracker["id"] = i;
			tracker["announce"] = m_Tunnel->GetTrackerAnnounce (i);
			tracker["tier"] = 0;
			trackers.push_back (tracker);
		}
		return trackers;
	}

	boost::json::array JSONRPCHandler::GetTrackerStats (std::shared_ptr<Torrent> torrent) const
	{
		boost::json::array trackers;
		for (size_t i = 0; i < m_Tunnel->GetNumTrackers (); i++)
		{
			boost::json::object tracker;
			tracker["id"] = i;
			tracker["announce"] = m_Tunnel->GetTrackerAnnounce (i);
			i2p::http::URL announceURL;
			announceURL.parse (m_Tunnel->GetTrackerAnnounce (i));
			tracker["host"]= announceURL.host;
			tracker["announceState"] = 1;
			tracker["scrapeState"] = 0;
			tracker["hasAnnounced"] = true; // TODO:
            tracker["hasScraped"] = false;
            tracker["isBackup"] = false;
			tracker["downloadCount"] = -1;
			tracker["tier"] = 0;
			tracker["seederCount"] = torrent->GetNumSeeders (i);
			tracker["leecherCount"] = torrent->GetNumLeechers (i);
			tracker["lastAnnouncePeerCount"] = torrent->GetNumPeers (i);
			auto trackerError = torrent->GetTrackerError (i);
			if (trackerError.empty ())
			{
				tracker["lastAnnounceResult"] = "Success";
				tracker["lastAnnounceSucceeded"] = true;
			}
			else
			{
				tracker["lastAnnounceResult"] = trackerError;
				tracker["lastAnnounceSucceeded"] = false;
			}
			tracker["lastAnnounceTimedOut"] = false; // TODO:
			tracker["nextAnnounceTime"] = (torrent->GetNextTrackerRequestTime (i) -
				i2p::util::GetMonotonicMilliseconds () + i2p::util::GetMillisecondsSinceEpoch ())/1000;
			tracker["lastAnnounceTime"] = torrent->GetLastTrackerUpdateTime (i);
			tracker["lastAnnounceStartTime"] = torrent->GetLastTrackerUpdateTime (i); // TODO:
			tracker["lastScrapeTime"] = 0;
			tracker["lastScrapeStartTime"] = 0;
			tracker["nextScrapeTime"] = 0;
			tracker["lastScrapeResult"]= "";
			tracker["lastScrapeTimedOut"]= false;
			tracker["lastScrapeSucceeded"]= true;
			trackers.push_back (tracker);
		}
		return trackers;
	}

	boost::json::array JSONRPCHandler::GetFiles (std::shared_ptr<Torrent> torrent) const
	{
		boost::json::array files;
		const auto& torrentFiles = torrent->GetFiles ();
		if (torrentFiles.empty ())
		{
			boost::json::object file;
			file["name"] = torrent->GetName ();
			file["length"] = torrent->GetLength ();
			file["bytesCompleted"] = torrent->GetLength () - torrent->GetLeft ();
			files.push_back (file);
		}
		else
		{
			const auto& torrentsDir = m_Tunnel->GetTorrentsDir ();
			auto filesCompleted = torrent->GetFilesCompleted ();
			size_t ind = 0;
			for (const auto& [filePath, fileSize]: torrentFiles)
			{
				boost::json::object file;
				file["name"] = std::filesystem::relative (filePath, torrentsDir).string ();
				file["length"] = fileSize;
				file["bytesCompleted"] = (ind < filesCompleted.size ()) ? filesCompleted[ind] : 0;
				files.push_back (file);
				ind++;
			}
		}
		return files;
	}

	std::string_view JSONRPCHandler::RecognizeClientByPeerID (const PeerConnection::PeerID& peerID)
	{
		static constexpr std::array<uint8_t,12> i2psnark { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03 };
		static const std::map<std::string_view, std::string_view> twoChars =
		{
			{ "qB", "qBittorrent" },
			{ "XD", "XD"},
			{ "BI", "BiglyBT" },
			{ "AZ", "Vuze" },
			{ "LT", "libtorrent" }
		};

		if (peerID.size () >= i2psnark.size () && !memcmp (peerID.data (), i2psnark.data (), i2psnark.size ()))
			return "I2PSnark";

		std::string_view peerIDStr ((const char *)peerID.data (), peerID.size ());
		if (peerIDStr.substr (0, 6) == "-I2PD-")
			return "i2pd";
		if (peerIDStr[0] == '-')
		{
			auto it = twoChars.find (peerIDStr.substr (1,2));
			if (it != twoChars.end ())
				return it->second;
		}

		return "Unknown";
	}

	std::string JSONRPCHandler::HandleTorrentStop (boost::json::object&& jsonRequest)
	{
		auto arguments = jsonRequest.at ("arguments").as_object ();
		for (auto id: GetTorrentIds (arguments))
 			m_Tunnel->StopTorrent (id);
		boost::json::object response; // always empty
		return SuccessResponse (GetTag (jsonRequest), std::move (response));
	}

	std::string JSONRPCHandler::HandleTorrentStart (boost::json::object&& jsonRequest)
	{
		auto arguments = jsonRequest.at ("arguments").as_object ();
		for (auto id: GetTorrentIds (arguments))
 			m_Tunnel->StartTorrent (id);
		boost::json::object response; // always empty
		return SuccessResponse (GetTag (jsonRequest), std::move (response));
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
#ifdef JSON_SUPPORTED
			if (m_Request.method() == boost::beast::http::verb::post)
			{
				auto path = m_Request.target ();
				auto tunnel = m_Server.GetTunnel ( {path.data (), path.size ()}); // boost::beast::string_view to std::string_view
				if (tunnel)
				{
					static constexpr std::string_view appjson { "application/json" };
#if __cplusplus >= 202002L // C++20
					if (m_Request[boost::beast::http::field::content_type].starts_with (appjson) || // starts with
#else
					if (m_Request[boost::beast::http::field::content_type].substr (0, appjson.size ()) == appjson || // starts with
#endif
						m_Request[boost::beast::http::field::content_type] == "application/x-www-form-urlencoded")
					{

						JSONRPCHandler jsonHandler (tunnel);
						auto response = jsonHandler.HandleRequest (m_Request.body ());
						if (!response.empty ())
							SendResponse (boost::beast::http::status::ok, response);
					}
					else
						SendResponse (boost::beast::http::status::no_content);
				}
				else
				{
					LogPrint(eLogDebug, "TorrentRPC ", path, " not found ", tunnel);
					SendResponse (boost::beast::http::status::not_found);
				}
			}
			else if (m_Request.method() == boost::beast::http::verb::options)
				SendResponse (boost::beast::http::status::no_content, "", true);
			else
				SendResponse (boost::beast::http::status::method_not_allowed);
#else
			SendResponse (boost::beast::http::status::not_implemented, std::string ("Your boost version ") + BOOST_LIB_VERSION + " is too old");
#endif
		}
	}

	void TorrentsRPCSession::SendResponse (boost::beast::http::status result, std::string_view data, bool isOptions)
	{
		m_Response.version (11); // HTTP/1.1
		m_Response.result (result);
		m_Response.set (boost::beast::http::field::server, "i2pd torents RPC");
		m_Response.set (boost::beast::http::field::access_control_allow_origin, "*");
		m_Response.set (boost::beast::http::field::access_control_allow_headers, "Content-Type, Authorization");
		if (isOptions)
			m_Response.set (boost::beast::http::field::access_control_allow_methods, "GET, POST, OPTIONS");
		else
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
		// insert both pathes rpc and rpc/
		rpcPath += "rpc";
		m_Tunnels.emplace (rpcPath, tunnel);
		rpcPath += "/";
		m_Tunnels.emplace (rpcPath, tunnel);
	}

	std::pair<boost::asio::ip::tcp::endpoint, std::string> TorrentsRPCServer::GetTunnelEndpoint (std::shared_ptr<TorrentsTunnel> tunnel) const
	{
		for (const auto& [path, weakTunnel] : m_Tunnels)
		{
			if (auto t = weakTunnel.lock(); t == tunnel)
			{
				return { m_Acceptor.local_endpoint(), path };
			}
		}
		return {};
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
