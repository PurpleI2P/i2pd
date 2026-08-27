/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TORRENTS_TUNNEL_H__
#define TORRENTS_TUNNEL_H__

#include <string>
#include <string_view>
#include <memory>
#include <filesystem>
#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "I2PService.h"
#include "util.h"
#include "BoostStream.h"
#include "Torrents.h"

namespace i2p
{
namespace torrents
{
	constexpr int TRACKER_RESPONSE_TIMEOUT = 8; // in seconds
	constexpr int DATAGRAM_TRACKER_TRANSACTION_TIMEOUT = 60; // in seconds
	constexpr int TRACKER_REQUESTS_CHECK_TIMEOUT = 1900; // in milliseconds
	constexpr int RECONNECT_CHECK_INTERVAL = 70; // in seconds
	constexpr int TRACKER_REQUESTS_INTERVAL_VARIANCE = 3000; // in milliseconds
	constexpr int PEER_KEEP_ALIVE_CHECK_INTERVAL = 15; // in seconds
	constexpr int TORRENTS_STATUS_UPDATE_INTERVAL = 25; // in seconds

	enum DatagramTrackerAction
	{
		eDatagramTrackerActionConnect = 0,
		eDatagramTrackerActionAnnounce = 1,
		eDatagramTrackerActionError = 3
	};

	enum TrackerAnnounceEvent
	{
		eTrackerAnnounceEventNone = 0,
		eTrackerAnnounceEventCompleted = 1,
		eTrackerAnnounceEventStarted = 2,
		eTrackerAnnounceEventStopped = 3
	};

	class TorrentsTunnel final: public i2p::client::I2PService
	{
		private:

			class DiskIOService: private i2p::util::RunnableServiceWithWork
			{
				public:

					DiskIOService (): RunnableServiceWithWork ("TDiskIO") {}
					auto& GetService () { return GetIOService (); }
					void Start () { StartIOService (); }
					void Stop () { StopWorkAndFinishTasks (); }
			};

		public:

			TorrentsTunnel (std::string_view name, std::shared_ptr<i2p::client::ClientDestination> localDestination,
				std::string_view torrentsDir, std::string_view trackers = "");

			void Start () override;
			void Stop () override;
			auto& GetDiskIOService () { return m_DiskIOService.GetService (); };

			const std::string& GetPeerID () const { return m_PeerID; }
			const std::vector<std::string>& GetTrackers () const { return m_Trackers; }
			std::shared_ptr<Torrent> FindTorrent (const Torrent::InfoHash& infoHash) const;
			std::shared_ptr<Torrent> FindTorrentByID (int id) const;
			std::vector<int> GetTorrentIDs () const;
			std::pair<std::shared_ptr<Torrent>, int> AddTorrent (std::string_view torrentFileContent); // (tunnel, id)
			bool RemoveTorrent (int id, bool deleteFiles);
			std::list<std::shared_ptr<PeerConnection> > GetTorrentConnections (std::shared_ptr<Torrent> torrent);

			const char* GetName() const override { return m_Name.c_str (); }

		private:


			void Accept ();
			void ReadTorrentFile (const std::filesystem::path& torrentFilePath);
			void InitTorrentFiles (std::shared_ptr<Torrent> torrent);
			int InsertTorrent (std::shared_ptr<Torrent> torrent); // returns id > 0 if success and 0 if failed
			void RemoveTorrent (std::shared_ptr<Torrent> torrent, bool deleteFiles);
			bool CreateAndReserveFile (const std::filesystem::path& filePath, size_t reserve);
			void CompleteTorrent (std::shared_ptr<Torrent> torrent);
			void RequestTracker (size_t trackerID, std::shared_ptr<Torrent> torrent, std::string_view event = "");
			void RequestTorrentTrackers (std::shared_ptr<Torrent> torrent, std::string_view event = "");
			void TrackerRequestSent (const boost::beast::error_code& ecode, size_t bytes_transferred,
				std::shared_ptr<i2p::client::BoostAsyncStream> httpStream, std::shared_ptr<Torrent> torrent,
				std::shared_ptr<boost::beast::http::request<boost::beast::http::string_body> > req, size_t trackerID);

			void ScheduleTrackerRequestsCheck ();
			void HandleTrackerRequestsCheckTimer (const boost::system::error_code& ecode);

			void ScheduleKeepAliveCheck ();
			void HandleKeepAliveCheckTimer (const boost::system::error_code& ecode);

			void ScheduleReconnectCheck ();
			void HandleReconnectCheckTimer (const boost::system::error_code& ecode);

			void ScheduleStatusUpdate ();
			void HandleTorrentsStatusUpdateTimer (const boost::system::error_code& ecode);

			std::unordered_set<i2p::data::IdentHash> GetNonConnectedPeers (std::shared_ptr<Torrent> torrent);
			void ConnectToPeer (std::shared_ptr<Torrent> torrent, const i2p::data::IdentHash& peer);
			size_t ConnectToPeers (std::shared_ptr<Torrent> torrent);
			void UpdatePeersPerPiece (std::shared_ptr<Torrent> torrent);
			void UpdateStats ();

			void HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			void ConnectToDatagramTracker (std::shared_ptr<Torrent> torrent, size_t trackerID,
				std::string_view dest, uint16_t port, TrackerAnnounceEvent event);
			void HandleConnectResponse (const uint8_t * buf, size_t len);
			void HandleErrorResponse (const uint8_t * buf, size_t len);
			void HandleAnnounceResponse (const uint8_t * buf, size_t len);
			void SendAnnounceToDatagramTracker (uint32_t transactionID, uint64_t connectionID,
				std::shared_ptr<Torrent> torrent, const i2p::data::IdentHash& ident,
				uint16_t port, uint16_t fromPort, TrackerAnnounceEvent event);

		private:

			std::string m_Name, m_PeerID; // 20 characters
			std::filesystem::path m_TorrentsDir;
			std::vector<std::string> m_Trackers;
			std::map<Torrent::InfoHash, std::shared_ptr<Torrent> > m_Torrents;
			std::map<int, std::weak_ptr<Torrent> > m_TorrentsByID;
			mutable std::mutex m_TorrentsMutex;
			boost::asio::steady_timer m_TrackerRequestsCheckTimer, m_KeepAliveCheckTimer,
				m_ReconnectCheckTimer, m_TorrentsStatusUpdateTimer;
			DiskIOService m_DiskIOService;
			std::unordered_map<uint32_t, std::tuple<std::weak_ptr<Torrent>, size_t, i2p::data::IdentHash,
				uint16_t, uint16_t, uint64_t, TrackerAnnounceEvent> > m_DatragramTrackerTransactions;
			// transactionID->(torrent, trackerID, ident, port, fromPort, ts in monotonic seconds, event)
	};

}
}

#endif
