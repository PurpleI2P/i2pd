/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "Log.h"
#include "Timestamp.h"
#include "I2PEndian.h"
#include "HTTP.h"
#include "AddressBook.h"
#include "ClientContext.h"
#include "TorrentsTunnel.h"

namespace i2p
{
namespace torrents
{
	TorrentsTunnel::TorrentsTunnel (std::string_view name, std::shared_ptr<i2p::client::ClientDestination> localDestination,
		std::string_view torrentsDir, std::string_view trackers):
		i2p::client::I2PService (localDestination), m_Name (name), m_PeerID ("-I2PD-"),
		m_TorrentsDir (torrentsDir), m_TrackerRequestsCheckTimer (GetService ()),
		m_KeepAliveCheckTimer (GetService ()), m_ReconnectCheckTimer (GetService ()),
		m_TorrentsStatusUpdateTimer (GetService ())
	{
		if (localDestination)
			m_PeerID += localDestination->GetIdentHash ().ToBase64 ();
		m_PeerID.resize (20, '0');
		if (!trackers.empty ())
			boost::split(m_Trackers, trackers, boost::is_any_of(","), boost::token_compress_on);
	}

	void TorrentsTunnel::Start ()
	{
		i2p::client::I2PService::Start ();
		m_DiskIOService.Start ();

		auto dgramDest = GetLocalDestination ()->CreateDatagramDestination (false, i2p::datagram::eDatagramV3);
		if (dgramDest)
			dgramDest->SetRawReceiver (std::bind (&TorrentsTunnel::HandleRecvFromI2PRaw,
				std::static_pointer_cast<TorrentsTunnel>(shared_from_this ()),
				std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));

		Accept ();

		if (!m_TorrentsDir.empty() && std::filesystem::exists (m_TorrentsDir) &&
			std::filesystem::is_directory (m_TorrentsDir))
		{
			for (const auto& it: std::filesystem::directory_iterator (m_TorrentsDir))
				if (std::filesystem::is_regular_file (it.status()) && it.path ().extension () == ".torrent")
					ReadTorrentFile (it.path ());
        }

		ScheduleTrackerRequestsCheck ();
		ScheduleKeepAliveCheck ();
		ScheduleStatusUpdate ();
	}

	void TorrentsTunnel::Stop ()
	{
		auto localDestination = GetLocalDestination ();
		if (localDestination)
		{
			localDestination->StopAcceptingStreams ();
			auto dgramDest = localDestination->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->ResetRawReceiver ();
		}
		m_TrackerRequestsCheckTimer.cancel ();
		m_KeepAliveCheckTimer.cancel ();
		m_ReconnectCheckTimer.cancel ();
		m_TorrentsStatusUpdateTimer.cancel ();
		m_Torrents.clear ();
		for (auto it: m_Torrents)
		{
			auto fullPath = it.second->GetFullPath (); fullPath += ".resume";
			boost::asio::post (m_DiskIOService.GetService (),  [torrent = it.second, fullPath]()
				{
					torrent->SaveTorrentResumeFile (fullPath);
				});
		}
		m_DiskIOService.Stop ();
		i2p::client::I2PService::Stop ();
	}

	void TorrentsTunnel::ReadTorrentFile (const std::filesystem::path& torrentFilePath)
	{
		std::shared_ptr<Torrent> torrent;
 		std::ifstream s(torrentFilePath, std::ifstream::binary);
		if (s)
		{
			s.seekg (0,std::ios::end);
			size_t len = s.tellg ();
			if (len > 0)
			{
				s.seekg(0, std::ios::beg);
				char * buf = new char[len];
				s.read(buf, len);
				torrent = std::make_shared<Torrent>(std::string_view{buf, len});
				delete[] buf;
			}
			else
				LogPrint (eLogError, "TorrentsTunnel: Empty file ", torrentFilePath);
		}
		else
			LogPrint (eLogError, "TorrentsTunnel: Can't open file ", torrentFilePath);

		if (torrent && !torrent->IsValid ())
		{
			// a torrent whose parsing stopped, an unsafe name among the rest, must
			// not be used even in part: it would leave stray files behind
			LogPrint (eLogError, "TorrentsTunnel: Invalid torrent file ", torrentFilePath, ". Skipped");
			torrent = nullptr;
		}
		if (torrent)
		{
			torrent->SetFullPath (m_TorrentsDir/std::filesystem::path (torrent->GetName ()));
			InitTorrentFiles (torrent);
			InsertTorrent (torrent);
		}
	}

	void TorrentsTunnel::InitTorrentFiles (std::shared_ptr<Torrent> torrent)
	{
		if (!torrent) return;
		if (torrent->GetFiles ().empty ())
		{
			if (std::filesystem::exists (torrent->GetFullPath ()))
				torrent->SetComplete ();
			else
			{
				auto partFilePath = torrent->GetFullPath (); partFilePath += ".part";
				if (!std::filesystem::exists (partFilePath))
					CreateAndReserveFile (partFilePath, torrent->GetLength ());
			}
		}
		else
		{
			bool completed = true;
			for (auto& [filePath, fileLength]: torrent->GetFiles ())
			{
				filePath = torrent->GetFullPath ()/filePath;
				if (!std::filesystem::exists (filePath))
				{
					auto partFilePath = filePath; partFilePath += ".part";
					if (!std::filesystem::exists (partFilePath))
						CreateAndReserveFile (partFilePath, fileLength);
					completed = false;
				}
			}
			if (completed) torrent->SetComplete ();
		}
		auto resumeFilePath = torrent->GetFullPath (); resumeFilePath += ".resume";
		if (std::filesystem::exists (resumeFilePath))
		{
			if (!torrent->IsComplete ())
			{
				std::ifstream rs(resumeFilePath, std::ifstream::binary);
				if (rs)
				{
					rs.seekg (0,std::ios::end);
					size_t l = rs.tellg ();
					if (l > 0)
					{
						rs.seekg(0, std::ios::beg);
						std::vector<uint8_t> bitfield(l);
						rs.read((char *)bitfield.data (), l);
						if (torrent->ApplyBitfield (bitfield))
							CompleteTorrent (torrent);
					}
				}
			}
			else
				std::filesystem::remove (resumeFilePath);
		}
	}

	bool TorrentsTunnel::CreateAndReserveFile (const std::filesystem::path& filePath, size_t reserve)
	{
		if (std::filesystem::exists (filePath)) return false;
		auto subdirs = filePath.parent_path ();
		if (!subdirs.empty ())
		{
			// try to create all subdirs
			try
			{
				std::filesystem::create_directories (subdirs);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "TorrentsTunnel: Can't create subdirs ", subdirs, " : ", ex.what());
				return false;
			}
		}
		// create file
		std::ofstream f(filePath, std::ios::binary);
		if (!f) return false;
		f.close ();
		if (reserve > 0)
		{
			// resize
			try
			{
				std::filesystem::resize_file (filePath, reserve);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "TorrentsTunnel: Can't resize file ", filePath, " to ", reserve, " : ", ex.what());
				return false;
			}
		}
		return true;
	}

	void TorrentsTunnel::CompleteTorrent (std::shared_ptr<Torrent> torrent)
	{
		boost::asio::post (GetDiskIOService (), [this, torrent]()
		{
			bool completed = false;
			if (torrent->GetFiles ().empty ())
			{
				auto partFilePath = torrent->GetFullPath ();  partFilePath += ".part";
				std::error_code ec;
				std::filesystem::rename (partFilePath, torrent->GetFullPath (), ec);
				if (!ec)
					completed = true;
				else
					LogPrint (eLogError, "TorrentsTunnel: Can't rename ", partFilePath);
			}
			else
			{
				completed = true;
				for (const auto& [filePath, fileSize]: torrent->GetFiles ())
				{
					auto partFilePath = filePath; partFilePath += ".part";
					std::error_code ec;
					std::filesystem::rename (partFilePath, filePath, ec);
					if (ec)
					{
						completed = false;
						LogPrint (eLogError, "TorrentsTunnel: Can't rename ", partFilePath);
					}
				}
			}
			if (completed)
			{
				torrent->SetComplete ();
				auto resumeFilePath = torrent->GetFullPath (); resumeFilePath += ".resume";
				if (!std::filesystem::remove (resumeFilePath))
					LogPrint (eLogError, "TorrentsTunnel: Can't delete resume file ", resumeFilePath);
				LogPrint (eLogInfo, "TorrentsTunnel: Download complete ", torrent->GetFullPath ());

				boost::asio::post (GetService (), [this, torrent]()
					{
						// inform trackers that we are done
						RequestTorrentTrackers (torrent, eTrackerAnnounceEventCompleted);
						// close connections with seeds and reset stats for remaining
						auto conns = GetTorrentConnections (torrent);
						for (auto it: conns)
						{
							if (it->GetRemoteBitfield ().all ()) // seed
								it->Close ();
							else
								it->ResetStats ();
						}
					});
			}
		});
	}

	std::shared_ptr<Torrent> TorrentsTunnel::FindTorrent (const Torrent::InfoHash& infoHash) const
	{
		std::lock_guard<std::mutex> l(m_TorrentsMutex);
		auto it = m_Torrents.find (infoHash);
		if (it != m_Torrents.end ())
			return it->second;
		return nullptr;
	}

	std::shared_ptr<Torrent> TorrentsTunnel::FindTorrentByID (int id) const
	{
		std::lock_guard<std::mutex> l(m_TorrentsMutex);
		auto it = m_TorrentsByID.find (id);
		if (it != m_TorrentsByID.end ())
			return it->second.lock ();
		return nullptr;
	}

	std::vector<int> TorrentsTunnel::GetTorrentIDs () const
	{
		std::vector<int> ids;
		std::lock_guard<std::mutex> l(m_TorrentsMutex);
		for (const auto& it: m_TorrentsByID)
			if (!it.second.expired ()) ids.push_back (it.first);
		return ids;
	}

	std::pair<std::shared_ptr<Torrent>, int> TorrentsTunnel::AddTorrent (std::string_view torrentFileContent)
	{
		auto torrent = std::make_shared<Torrent> (torrentFileContent);
		if (m_Torrents.find (torrent->GetInfoHash ()) == m_Torrents.end ())
		{
			torrent->SetFullPath (m_TorrentsDir/std::filesystem::path (torrent->GetName ()));
			{
				auto torrentFilePath = torrent->GetFullPath ();  torrentFilePath += ".torrent";
				std::ofstream f(torrentFilePath, std::ofstream::binary);
				if (f)
					f.write (torrentFileContent.data (), torrentFileContent.size ());
				else
					return { torrent, 0 };
			}
			InitTorrentFiles (torrent);
			return { torrent, InsertTorrent (torrent) };
		}
		return { torrent, 0 };
	}

	int TorrentsTunnel::InsertTorrent (std::shared_ptr<Torrent> torrent)
	{
		if (!torrent) return 0;
		std::lock_guard<std::mutex> l(m_TorrentsMutex);
		if (m_Torrents.emplace (torrent->GetInfoHash (), torrent).second)
		{
			int id = 1;
			if (!m_TorrentsByID.empty ())
				id = m_TorrentsByID.rbegin ()->first + 1;
			m_TorrentsByID.emplace (id, torrent);
			return id;
 		}
		return 0;
	}

	bool TorrentsTunnel::RemoveTorrent (int id, bool deleteFiles)
	{
		std::shared_ptr<Torrent> torrent;
		{
			std::lock_guard<std::mutex> l(m_TorrentsMutex);
			auto it = m_TorrentsByID.find (id);
			if (it == m_TorrentsByID.end ()) return false;
			torrent = it->second.lock ();
			m_TorrentsByID.erase (it);
			if (!torrent) return false;
			m_Torrents.erase (torrent->GetInfoHash ());
		}
		boost::asio::post (GetService (), [this, torrent, deleteFiles]()
			{
				RemoveTorrent (torrent, deleteFiles);
			});
		return true;
	}

	void TorrentsTunnel::RemoveTorrent (std::shared_ptr<Torrent> torrent, bool deleteFiles)
	{
		if (!torrent) return;
		StopTorrent (torrent);
		if (deleteFiles)
			boost::asio::post (GetDiskIOService (), [torrent]()
				{
					auto fullPath = torrent->GetFullPath ();
					auto torrentFilePath = fullPath; torrentFilePath += ".torrent";
					std::error_code ec;
					std::filesystem::remove (torrentFilePath, ec);
					if (ec)
						LogPrint (eLogError, "TorrentsTunnel: Can't delete ", torrentFilePath);
					auto resumeFilePath = fullPath; resumeFilePath += ".resume";
					if (std::filesystem::exists (resumeFilePath))
					{
						std::filesystem::remove (resumeFilePath, ec);
						if (ec)
							LogPrint (eLogError, "TorrentsTunnel: Can't delete ", resumeFilePath);
					}
					if (torrent->IsComplete () || !torrent->GetFiles ().empty ())
					{
						std::filesystem::remove_all (fullPath, ec);
						if (ec)
							LogPrint (eLogError, "TorrentsTunnel: Can't delete ", fullPath);
					}
					else
					{
						auto partFilePath = fullPath; partFilePath += ".part";
						std::filesystem::remove (partFilePath, ec);
						if (ec)
							LogPrint (eLogError, "TorrentsTunnel: Can't delete ", partFilePath);
					}
				});
	}

	bool TorrentsTunnel::StopTorrent (int id)
	{
		std::shared_ptr<Torrent> torrent;
		{
			std::lock_guard<std::mutex> l(m_TorrentsMutex);
			auto it = m_TorrentsByID.find (id);
			if (it == m_TorrentsByID.end ()) return false;
			torrent = it->second.lock ();
			if (!torrent) return false;
		}
		boost::asio::post (GetService (), [this, torrent]()
			{
				StopTorrent (torrent);
			});
		return true;
	}

	void TorrentsTunnel::StopTorrent (std::shared_ptr<Torrent> torrent)
	{
		if (!torrent) return;
		torrent->SetStopped (true);
		// inform trackers that we stopped
		RequestTorrentTrackers (torrent, eTrackerAnnounceEventStopped);
		// close connections
		auto connections = GetTorrentConnections (torrent);
		for (auto it: connections)
			it->Close ();
	}

	bool TorrentsTunnel::StartTorrent (int id)
	{
		std::shared_ptr<Torrent> torrent;
		{
			std::lock_guard<std::mutex> l(m_TorrentsMutex);
			auto it = m_TorrentsByID.find (id);
			if (it == m_TorrentsByID.end ()) return false;
			torrent = it->second.lock ();
			if (!torrent) return false;
		}
		boost::asio::post (GetService (), [this, torrent]()
			{
				torrent->SetStopped (false);
				// inform trackers that we started
				RequestTorrentTrackers (torrent, eTrackerAnnounceEventStarted);
			});
		return true;
	}

	void TorrentsTunnel::Accept ()
	{
		auto localDestination = GetLocalDestination ();
		if (localDestination)
		{
			if (!localDestination->IsAcceptingStreams ()) // set it as default if not set yet
				localDestination->AcceptStreams ([this](std::shared_ptr<i2p::stream::Stream> stream)
					{
						if (stream)
						{
							auto conn = std::make_shared<PeerConnection> (shared_from_this (), stream);
							AddHandler (conn);
							conn->ReceiveHandshake ();
						}
					});
		}
		else
			LogPrint (eLogError, "TorrentsTunnel: Local destination not set");
	}

	void TorrentsTunnel::RequestTorrentTrackers (std::shared_ptr<Torrent> torrent, TrackerAnnounceEvent event)
	{
		if (!m_Trackers.empty ())
			for (size_t i = 0; i < m_Trackers.size (); i++)
				RequestTracker (i, torrent, event);
		else
			RequestTracker (0, torrent, event); // from announce
	}

	void TorrentsTunnel::RequestTracker (size_t trackerID, std::shared_ptr<Torrent> torrent, TrackerAnnounceEvent event)
	{
		if (!torrent) return;
		i2p::http::URL reqURL;
		if (trackerID < m_Trackers.size())
			reqURL.parse (m_Trackers[trackerID]);
		else
			reqURL.parse (torrent->GetAnnounce ());
#if __cplusplus >= 202002L // C++20
		if (!reqURL.host.ends_with (".i2p"))
#else
		if (reqURL.host.find(".i2p") == reqURL.host.npos)
#endif
		{
			LogPrint (eLogWarning, "TorrentsTunnel: Non-I2P address ", reqURL.host, " for torrent ", torrent->GetName ());
			return;
		}
		if (reqURL.schema == "udp")
		{
			ConnectToDatagramTracker (torrent, trackerID, reqURL.host, reqURL.port, event);
			return;
		}
		std::map<std::string, std::string> params;
		params.emplace ("info_hash", torrent->GetHexStringInfoHash ());
		params.emplace ("peer_id", m_PeerID);
		params.emplace ("ip", GetLocalDestination ()->GetIdentity ()->ToBase64 () + ".i2p");
		params.emplace ("port", std::to_string (TORRENT_PORT)); // 6881
		params.emplace ("compact", "1");
		params.emplace ("uploaded", std::to_string (torrent->GetUploaded ()));
		params.emplace ("downloaded", std::to_string (torrent->GetLength () - torrent->GetLeft ()));
		params.emplace ("left", std::to_string (torrent->GetLeft ()));
		int numWant = 0;
		if (!torrent->IsComplete () && (event == eTrackerAnnounceEventNone || event == eTrackerAnnounceEventStarted))
			numWant = TRACKER_MAX_NUM_WANT;
		params.emplace ("numwant", std::to_string (numWant));
		if (event != eTrackerAnnounceEventNone)
			params.emplace ("event", TrackerAnnounceEventStr[event]);
		reqURL.create_query (params);

		auto req = std::make_shared<boost::beast::http::request<boost::beast::http::string_body> >(boost::beast::http::verb::get, reqURL.to_string (true), 11); // HTTP 1.1
		req->set (boost::beast::http::field::host, reqURL.host);
		req->set (boost::beast::http::field::user_agent, "I2PSocketEepGet");
		req->keep_alive (false); // Connection: close
		CreateStream ([this, req, torrent, trackerID](std::shared_ptr<i2p::stream::Stream> stream)
			{
				if (stream)
				{
					auto httpStream = std::make_shared<i2p::client::BoostAsyncStream>(stream);
					boost::beast::http::async_write (*httpStream, *req,
						std::bind (&TorrentsTunnel::TrackerRequestSent, this, std::placeholders::_1,
							std::placeholders::_2, httpStream, torrent, req, trackerID));
				}
			}, reqURL.host, reqURL.port);
	}

	void TorrentsTunnel::TrackerRequestSent (const boost::beast::error_code& ecode, size_t bytes_transferred,
		std::shared_ptr<i2p::client::BoostAsyncStream> httpStream, std::shared_ptr<Torrent> torrent,
		std::shared_ptr<boost::beast::http::request<boost::beast::http::string_body> > req, size_t trackerID)
	{
		if (!ecode)
		{
			// receive
			auto buf = std::make_shared<boost::beast::flat_buffer> ();
			auto res = std::make_shared<boost::beast::http::response<boost::beast::http::string_body> >();
			boost::beast::http::async_read (*httpStream, *buf, *res,
				[this, httpStream, torrent, buf, res, trackerID](const boost::beast::error_code& ecode, size_t bytes_transferred)
				{
					httpStream->GetStream ()->AsyncClose ();
					if (!ecode)
					{
						if (res->result () == boost::beast::http::status::ok)
						{
							torrent->ParseTrackerResponse (trackerID, res->body ());
							ConnectToPeers (torrent);
							ScheduleReconnectCheck ();
						}
						else
							LogPrint (eLogWarning, "TorrentsTunnel: Tracker ", trackerID, " response code ", res->result_int());
					}
				});
		}
	}

	void TorrentsTunnel::ConnectToPeer (std::shared_ptr<Torrent> torrent, const i2p::data::IdentHash& peer)
	{
		if (!torrent) return;
		LogPrint (eLogDebug, "TorrentsTunnel: Connecting to peer ", peer.ToBase32 () + ".b32.i2p");
		if (peer == GetLocalDestination ()->GetIdentHash ())
		{
			LogPrint (eLogInfo, "TorrentsTunnel: Can't connect to self");
			return;
		}
		CreateStream ([this, torrent, peer](std::shared_ptr<i2p::stream::Stream> stream)
			{
				if (stream)
				{
					LogPrint (eLogDebug, "TorrentsTunnel: Connected to peer ", peer.ToBase32 () + ".b32.i2p");
					auto connection = std::make_shared<PeerConnection>(shared_from_this (), stream, torrent);
					AddHandler (connection);
					connection->Connect ();
				}
				else
					LogPrint (eLogInfo, "TorrentsTunnel: Can't connect to peer ", peer.ToBase32 () + ".b32.i2p");
			}, std::make_shared<i2p::client::Address>(peer), TORRENT_PORT);
	}

	size_t TorrentsTunnel::ConnectToPeers (std::shared_ptr<Torrent> torrent)
	{
		if (!torrent) return 0;
		auto peersToConnect = GetNonConnectedPeers (torrent);
		if (!peersToConnect.empty ())
		{
			for (const auto& it: peersToConnect)
				ConnectToPeer (torrent, it);
		}
		return peersToConnect.size ();
	}

	void TorrentsTunnel::ScheduleTrackerRequestsCheck ()
	{
		m_TrackerRequestsCheckTimer.expires_after (std::chrono::milliseconds(TRACKER_REQUESTS_CHECK_TIMEOUT));
		m_TrackerRequestsCheckTimer.async_wait (std::bind (&TorrentsTunnel::HandleTrackerRequestsCheckTimer,
			this, std::placeholders::_1));
	}

	void TorrentsTunnel::HandleTrackerRequestsCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetMonotonicMilliseconds ();
			if (!m_DatragramTrackerTransactions.empty ())
			{
				// cleanup  expired transactions
				auto it = m_DatragramTrackerTransactions.begin ();
				while (it != m_DatragramTrackerTransactions.end ())
				{
					if (ts > (std::get<5>(it->second) + DATAGRAM_TRACKER_TRANSACTION_TIMEOUT)*1000LL)
						it = m_DatragramTrackerTransactions.erase (it);
					else
						it++;
				}
			}
			for (auto it: m_Torrents)
			{
				if (!it.second->IsStopped ())
				{
					for (size_t i = 0; i < m_Trackers.size (); i++)
					{
						if (!it.second->GetNextTrackerRequestTime (i)) // first time
						{
							auto initialInterval = GetLocalDestination ()->GetRng()() % TRACKER_INITIAL_REQUEST_INTERVAL_VARIANCE;
							if (initialInterval <= TRACKER_REQUESTS_CHECK_TIMEOUT) initialInterval = 0; // request immeditely
							it.second->SetNextTrackerRequestTime (i, ts + initialInterval);
						}
						if (ts >= it.second->GetNextTrackerRequestTime (i))
						{
							auto nextInterval = it.second->GetInterval (i) + GetLocalDestination ()->GetRng()() % TRACKER_REQUESTS_INTERVAL_VARIANCE;
							it.second->SetNextTrackerRequestTime (i, ts + nextInterval);
							RequestTracker (i, it.second, eTrackerAnnounceEventNone);
						}
					}
				}
			}
			ScheduleTrackerRequestsCheck ();
		}
	}

	void TorrentsTunnel::ScheduleKeepAliveCheck ()
	{
		m_KeepAliveCheckTimer.expires_after (std::chrono::seconds(PEER_KEEP_ALIVE_CHECK_INTERVAL));
		m_KeepAliveCheckTimer.async_wait (std::bind (&TorrentsTunnel::HandleKeepAliveCheckTimer,
			this, std::placeholders::_1));
	}

	void TorrentsTunnel::HandleKeepAliveCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetMonotonicSeconds ();
			IterateHandlers ([ts](std::shared_ptr<i2p::client::I2PServiceHandler> handler)
				{
					if (handler)
						std::static_pointer_cast<PeerConnection>(handler)->CheckKeepAlive (ts);
				});
			ScheduleKeepAliveCheck ();
		}
	}

	void TorrentsTunnel::ScheduleReconnectCheck ()
	{
		m_ReconnectCheckTimer.cancel ();
		m_ReconnectCheckTimer.expires_after (std::chrono::seconds(RECONNECT_CHECK_INTERVAL));
		m_ReconnectCheckTimer.async_wait (std::bind (&TorrentsTunnel::HandleReconnectCheckTimer,
			this, std::placeholders::_1));
	}

	void TorrentsTunnel::HandleReconnectCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			for (auto it: m_Torrents)
			{
				if (!it.second->IsComplete () && !it.second->IsStopped ())
				{
					auto numPeers = ConnectToPeers (it.second);
					if (numPeers)
						LogPrint (eLogDebug, "TorrentsTunnel: Reconnecting to ", numPeers, " peers");
				}
			}
			ScheduleReconnectCheck ();
		}
	}

	void TorrentsTunnel::ScheduleStatusUpdate ()
	{
		m_TorrentsStatusUpdateTimer.cancel ();
		m_TorrentsStatusUpdateTimer.expires_after (std::chrono::seconds(TORRENTS_STATUS_UPDATE_INTERVAL));
		m_TorrentsStatusUpdateTimer.async_wait (std::bind (&TorrentsTunnel::HandleTorrentsStatusUpdateTimer,
			this, std::placeholders::_1));
	}

	void TorrentsTunnel::HandleTorrentsStatusUpdateTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetMonotonicSeconds ();
			for (auto it: m_Torrents)
			{
				if (!it.second->IsComplete () &&!it.second->IsStopped ())
				{
					if (it.second->UpdateStatus (ts))
						CompleteTorrent (it.second);
					else
						UpdatePeersPerPiece (it.second);
				}
			}
			UpdateStats ();
			ScheduleStatusUpdate ();
		}
	}

	std::list<std::shared_ptr<PeerConnection> > TorrentsTunnel::GetTorrentConnections (std::shared_ptr<Torrent> torrent)
	{
		std::list<std::shared_ptr<PeerConnection> > ret;
		if (torrent)
		{
			IterateHandlers ([&ret, torrent](std::shared_ptr<i2p::client::I2PServiceHandler> handler)
				{
					if (handler)
					{
						auto conn = std::static_pointer_cast<PeerConnection>(handler);
						if (conn->GetTorrent () == torrent && conn->GetStream ())
							ret.emplace_back (conn);
					}
				});
		}
		return ret;
	}

	std::unordered_set<i2p::data::IdentHash> TorrentsTunnel::GetNonConnectedPeers (std::shared_ptr<Torrent> torrent)
	{
		std::unordered_set<i2p::data::IdentHash> ret;
		if (torrent)
		{
			ret = torrent->GetPeers ();
			if(!ret.empty ())
			{
				IterateHandlers ([&ret, torrent](std::shared_ptr<i2p::client::I2PServiceHandler> handler)
					{
						if (handler)
						{
							auto conn = std::static_pointer_cast<PeerConnection>(handler);
							if (conn->GetTorrent () == torrent && conn->GetStream ())
							{
								auto ident = conn->GetStream ()->GetRemoteIdentity ();
								if (ident)
									ret.erase (ident->GetIdentHash ());
							}
						}
					});
			}
		}
		return ret;
	}

	void TorrentsTunnel::UpdatePeersPerPiece (std::shared_ptr<Torrent> torrent)
	{
		if (!torrent) return;
		torrent->StartCountingPeers ();
		IterateHandlers ([torrent](std::shared_ptr<i2p::client::I2PServiceHandler> handler)
			{
				if (handler)
				{
					auto conn = std::static_pointer_cast<PeerConnection>(handler);
					if (conn->GetTorrent () == torrent)
						torrent->ApplyPeerRemoteBitfield (conn->GetRemoteBitfield ());
				}
			});
	}

	void TorrentsTunnel::UpdateStats ()
	{
		for (auto it: m_Torrents)
			it.second->ResetStats ();
		IterateHandlers ([](std::shared_ptr<i2p::client::I2PServiceHandler> handler) mutable
			{
				if (handler)
				{
					auto conn = std::static_pointer_cast<PeerConnection>(handler);
					auto torrent = conn->GetTorrent ();
					if (torrent)
					{
						torrent->SetDownloadRate (torrent->GetDownloadRate () + conn->GetDownloadRate ());
						torrent->SetUploadRate (torrent->GetUploadRate () + conn->GetUploadRate ());
						if (conn->IsDownloading ())
							torrent->SetNumDownloadingFromPeers (torrent->GetNumDownloadingFromPeers () + 1);
						if (conn->IsUploading ())
							torrent->SetNumUploadingToPeers (torrent->GetNumUploadingToPeers () + 1);
					}
				}
			});
	}

	void TorrentsTunnel::HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		// response from tracker
		if (len < 8) return;
		uint32_t action = bufbe32toh (buf);
		switch (action)
		{
			case eDatagramTrackerActionConnect:
				HandleConnectResponse (buf + 4, len - 4);
			break;
			case eDatagramTrackerActionAnnounce:
				HandleAnnounceResponse (buf + 4, len - 4);
			break;
			case eDatagramTrackerActionError:
				HandleErrorResponse (buf + 4, len - 4);
			break;
			default:
				LogPrint (eLogInfo, "TorrentsTunnel: Unexpected action ", action, " from tracker");
		}
	}

	void TorrentsTunnel::HandleErrorResponse (const uint8_t * buf, size_t len)
	{
		uint32_t transactionID = bufbe32toh (buf);
		LogPrint (eLogDebug, "TorrentsTunnel: Datagram tracker action error response ", transactionID);
		m_DatragramTrackerTransactions.erase (transactionID);
		LogPrint (eLogInfo, "TorrentsTunnel: Datagram tracker error response: ", std::string_view ((const char *)(buf + 4), len - 4));
	}

	void TorrentsTunnel::ConnectToDatagramTracker (std::shared_ptr<Torrent> torrent,
		size_t trackerID, std::string_view dest, uint16_t port, TrackerAnnounceEvent event)
	{
		LogPrint (eLogDebug, "TorrentsTunnel: Connecting to datagram tracker ", dest, ":", port);
		auto address = i2p::client::context.GetAddressBook ().GetAddress (dest);
		if (address && address->IsIdentHash ())
		{
			auto localDestination = GetLocalDestination ();
			auto dgramDest = localDestination->GetDatagramDestination ();
			if (dgramDest)
			{
				uint8_t connectRequest[16];
				htobe64buf (connectRequest, 0x41727101980); // protocol_id
				htobe32buf (connectRequest + 8, eDatagramTrackerActionConnect); // action
				uint32_t transactionID = localDestination->GetRng()();
				htobe32buf (connectRequest + 12, transactionID); // transactionID
				uint16_t fromPort = localDestination->GetRng()() % 1000 + 6000;
				auto session = dgramDest->GetSession (address->identHash);
				if (session)
				{
					m_DatragramTrackerTransactions.emplace (transactionID, std::make_tuple (torrent,
						trackerID, address->identHash, port, fromPort, i2p::util::GetMonotonicSeconds (), event));
					session->SetVersion (i2p::datagram::eDatagramV2); // send datagram2
					dgramDest->SendDatagram (session, connectRequest, 16, fromPort, port);
				}
				else
					LogPrint (eLogInfo, "TorrentsTunnel: Can't obtain datagram session to ", dest);
			}
			else
				LogPrint (eLogError, "TorrentsTunnel: Datagram destination is not avaliable");
		}
		else
			LogPrint (eLogInfo, "TorrentsTunnel: Tracker not found: ", dest);
	}

	void TorrentsTunnel::HandleConnectResponse (const uint8_t * buf, size_t len)
	{
		if (len < 12)
		{
			LogPrint (eLogInfo, "TorrentsTunnel: Unexpected connect response length ", len + 4);
			return;
		}
		uint32_t transactionID = bufbe32toh (buf);
		LogPrint (eLogDebug, "TorrentsTunnel: Datagram tracker action connect response ", transactionID);
		auto it = m_DatragramTrackerTransactions.find (transactionID);
		if (it == m_DatragramTrackerTransactions.end ())
		{
			LogPrint (eLogInfo, "TorrentsTunnel: Datagram tracker transaction ", transactionID, " not found");
			return;
		}
		uint64_t connectionID = bufbe64toh (buf + 4);
		auto [torrent, trackerID, ident, port, fromPort, ts, event] = it->second;
		if (!torrent.expired ())
			SendAnnounceToDatagramTracker (transactionID, connectionID, torrent.lock (), ident, port, fromPort, event);
		else
			m_DatragramTrackerTransactions.erase (it);
	}

	void TorrentsTunnel::SendAnnounceToDatagramTracker (uint32_t transactionID,
		uint64_t connectionID, std::shared_ptr<Torrent> torrent, const i2p::data::IdentHash& ident,
		uint16_t port, uint16_t fromPort, TrackerAnnounceEvent event)
	{
		auto localDestination = GetLocalDestination ();
		auto dgramDest = localDestination->GetDatagramDestination ();
		if (dgramDest)
		{
			uint8_t announce[98];
			htobe64buf (announce, connectionID); // connection_id
			htobe32buf (announce + 8, eDatagramTrackerActionAnnounce); // action
			htobe32buf (announce + 12, transactionID); // transaction_id
			memcpy (announce + 16, torrent->GetInfoHash ().data (), 20); // info_hash
			memcpy (announce + 36, m_PeerID.data (), 20); // peer_id
			auto left = torrent->GetLeft ();
			htobe64buf (announce + 56, torrent->GetLength () - left); // downloaded
			htobe64buf (announce + 64, left); // left
			htobe64buf (announce + 72, torrent->GetUploaded ()); // uploaded
			htobe32buf (announce + 80, event); // event
			htobe32buf (announce + 84, 0); // IP address 0:not used
			htobe32buf (announce + 88, 0); // key, ignored
			int numWant = 0;
			if (!torrent->IsComplete () && (event == eTrackerAnnounceEventNone || event == eTrackerAnnounceEventStarted))
				numWant = TRACKER_MAX_NUM_WANT;
			htobe32buf (announce + 92, numWant); // num_want
			htobe16buf (announce + 96, fromPort); // from port
			auto session = dgramDest->GetSession (ident);
			if (session)
			{
				session->SetVersion (i2p::datagram::eDatagramV3); // send datagram3
				dgramDest->SendDatagram (session, announce, 98, fromPort, port);
			}
			else
				LogPrint (eLogInfo, "TorrentsTunnel: Can't obtain datagram session");
		}
	}

	void TorrentsTunnel::HandleAnnounceResponse (const uint8_t * buf, size_t len)
	{
		if (len < 16)
		{
			LogPrint (eLogInfo, "TorrentsTunnel: Unexpected announce response length ", len + 4);
			return;
		}
		uint32_t transactionID = bufbe32toh (buf);
		LogPrint (eLogDebug, "TorrentsTunnel: Datagram tracker action announce response ", transactionID);
		auto it = m_DatragramTrackerTransactions.find (transactionID);
		if (it == m_DatragramTrackerTransactions.end ())
		{
			LogPrint (eLogInfo, "TorrentsTunnel: Datagram tracker transaction ", transactionID, " not found");
			return;
		}
		auto [torrent, trackerID, ident, port, fromPort, ts, event] = it->second;
		if (!torrent.expired ())
		{
			uint32_t interval = bufbe32toh (buf + 4);
			uint32_t leechers = bufbe32toh (buf + 8);
			uint32_t seeders = bufbe32toh (buf + 12);
			torrent.lock ()->HandleDatagramTrackerResponse (trackerID, interval, buf + 16, len - 16, seeders, leechers);
		}
		m_DatragramTrackerTransactions.erase (it);
	}
}
}
