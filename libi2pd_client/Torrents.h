/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TORRENTS_H__
#define TORRENTS_H__

#include <inttypes.h>
#include <openssl/sha.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/dynamic_bitset.hpp>
#include <memory>
#include <vector>
#include <array>
#include <list>
#include <map>
#include <string>
#include <string_view>
#include <random>
#include "Streaming.h"
#include "HTTP.h"
#include "I2PService.h"
#include "AddressBook.h"
#include "BoostStream.h"

namespace i2p
{
namespace torrents
{
	constexpr size_t REQUEST_BLOCK_SIZE = 16384;
	constexpr int TRACKER_RESPONSE_TIMEOUT = 8; // in seconds
	constexpr int TRACKER_REQUESTS_CHECK_TIMEOUT = 1900; // in milliseconds
	constexpr int MIN_TRACKER_REQUESTS_INTERVAL = 15000; // in milliseconds
	constexpr int TRACKER_REQUESTS_INTERVAL_VARIANCE = 3000; // in milliseconds
	constexpr size_t PEER_CONNECTION_RECEIVE_BUFFER_SIZE = 65535;
	constexpr int PEER_CONNECTION_MAX_IDLE = 3600; // in seconds
	constexpr int PEER_KEEP_ALIVE_INTERVAL = 120; // in seconds
	constexpr int PEER_KEEP_ALIVE_CHECK_TIMEOUT = 15; // in seconds

	constexpr size_t HANDSHAKE_MSG_LENGTH = 68;
	constexpr size_t REQUEST_MSG_PAYLOAD_LENGTH = 12;
	enum MessageType
	{
		eMessageTypeBitfield = 5,
		eMessageTypeRequest = 6,
		eMessageTypePiece = 7,
		eMessageTypeHaveAll = 14,
		eMessageTypeHaveNone = 15
	};

	class PeerConnection;
	class Piece final
	{
		public:

			Piece (size_t size, const uint8_t * hash);
			~Piece ();

			bool IsComplete () const { return m_Blocks.all (); }
			bool VerifyHash () const;

			void BlockReceived (const uint8_t * block, size_t len, size_t offset);
			void Dump (const std::string& fullPath, size_t offset);
			void Load (const std::string& fullPath, size_t offset);
			const uint8_t * GetData () const { return m_Data; }
			size_t GetSize () const { return m_Size; }
			std::pair<size_t, size_t> GetAvailableBuffer (size_t offset, size_t len) const; // return (offset, len) of available data

			void AddConnection (std::shared_ptr<PeerConnection> connection);
			void RemoveConnection (std::shared_ptr<PeerConnection> connection);

		private:

			bool IsAvailable (int block) const;
			size_t GetNumBlocks (size_t len) const;

		private:

			size_t m_Size;
			uint8_t * m_Data, m_Hash[SHA_DIGEST_LENGTH];
			boost::dynamic_bitset<> m_Blocks;
			std::list<std::weak_ptr<PeerConnection> > m_Connections; // for incomplete pieces only
	};

	class Torrent final
	{
		public:

			using InfoHash = std::array<uint8_t, 20>;

			Torrent (std::string_view buf);
			void ParseTrackerResponse (std::string_view buf);

			const std::string& GetAnnounce () const { return m_Announce; }
			const std::string& GetName () const { return m_Name; }
			size_t GetLength () const { return m_Length; }
			size_t GetPieceLength () const { return m_PieceLength; }
			int GetInterval () const { return m_Interval; }
			const InfoHash& GetInfoHash () const { return m_InfoHash; }
			std::string GetHexStringInfoHash () const; // in url format
			size_t GetNumPieces () const { return m_Pieces.size (); }
			Piece& GetPiece (int index) { return m_Pieces[index]; }
			std::vector<uint8_t> CreateBitfield () const;

			uint64_t GetNextTrackerRequestTime () const { return m_NextTrackerRequestTime; }
			void SetNextTrackerRequestTime (uint64_t ts) { m_NextTrackerRequestTime = ts; }

		private:

			size_t ParsePieces (std::string_view buf);
			size_t ParseInfo (std::string_view buf);
			size_t ParsePeers (std::string_view buf);

		private:

			std::string m_Name, m_Announce;
			size_t m_Length, m_PieceLength;
			int m_Interval; // in miiliseconds
			uint64_t m_NextTrackerRequestTime; // monotonic millicesonds
			InfoHash m_InfoHash; // SHA1
			std::vector<Piece> m_Pieces;
			std::list<std::shared_ptr<const i2p::client::Address> > m_Peers;
	};

	class TorrentsTunnel;
	class PeerConnection: public i2p::client::I2PServiceHandler, public std::enable_shared_from_this<PeerConnection>
	{
		public:

			PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream); // incoming
			PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream,
				std::shared_ptr<Torrent> torrent); // outgoing
			~PeerConnection ();

			void Connect ();
			void ReceiveHandshake ();
			void CheckKeepAlive (uint64_t ts);

			void RequestPiece (uint32_t index);

		private:

			void Terminate ();
			TorrentsTunnel * GetTorrentsTunnel () const;

			void WriteToStream (const uint8_t * buf, size_t len);
			void StreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, size_t bytes_transferred);
			void HandleReceived ();
			size_t HandleNextMsg (size_t offset);

			size_t HandleHandshakeMsg ();
			void SendHandshakeMsg ();

			void HandleBitfieldMsg (const uint8_t * buf, size_t len);
			void SendBitfieldMsg (const uint8_t * bitfield, size_t bitfieldLen);
			void HandleHaveAllMsg ();
			void HandleHaveNoneMsg ();
			void HandlePieceMsg (const uint8_t * buf, size_t len);
			void SendPieceMsg (uint32_t index, uint32_t offset, const uint8_t * data, size_t len);
			void HandleRequestMsg (const uint8_t * buf, size_t len);

		private:

			std::shared_ptr<i2p::stream::Stream> m_Stream;
			uint8_t m_ReceiveBuffer[PEER_CONNECTION_RECEIVE_BUFFER_SIZE];
			size_t m_ReceiveBufferOffset;
			std::shared_ptr<Torrent> m_Torrent;
			std::string m_RemotePeerID;
			boost::dynamic_bitset<> m_RemoteBitfield;
			bool m_IsHandshakeSent, m_IsEstablished;
			uint64_t m_LastReceiveTime, m_LastSendTime; // monotonic seconds
	};

	class TorrentsTunnel: public i2p::client::I2PService
	{
		public:

			TorrentsTunnel (std::shared_ptr<i2p::client::ClientDestination> localDestination,
				std::string_view torrentsDir, std::string_view trackers = "");

			void Start () override;
			void Stop () override;

			const std::string& GetPeerID () const { return m_PeerID; }
			std::string GetTorrentFilePath (const std::string& filename) const;
			std::shared_ptr<Torrent> FindTorrent (const Torrent::InfoHash& infoHash) const;
			void ConnectToPeer (std::shared_ptr<Torrent> torrent, std::shared_ptr<const i2p::client::Address> peer);

			const char* GetName() const override { return "Torrents"; }

		private:

			void Accept ();

			void ReadTorrentFile (const std::string& path);
			void SaveTorrentResumeFile (std::shared_ptr<const Torrent> torrent);

			void RequestTracker (std::shared_ptr<Torrent> torrent);
			void TrackerRequestSent (const boost::beast::error_code& ecode, size_t bytes_transferred,
				std::shared_ptr<i2p::client::BoostAsyncStream> httpStream, std::shared_ptr<Torrent> torrent,
				std::shared_ptr<boost::beast::http::request<boost::beast::http::string_body> > req);

			void ScheduleTrackerRequestsCheck ();
			void HandleTrackerRequestsCheckTimer (const boost::system::error_code& ecode);

			void ScheduleKeepAliveCheck ();
			void HandleKeepAliveCheckTimer (const boost::system::error_code& ecode);

		private:

			std::string m_TorrentsDir, m_PeerID; // 20 characters
			std::vector<std::string> m_Trackers;
			std::map<Torrent::InfoHash, std::shared_ptr<Torrent> > m_Torrents;
			std::mt19937 m_Rng;
			boost::asio::steady_timer m_TrackerRequestsCheckTimer, m_KeepAliveCheckTimer;
	};
}
}
#endif
