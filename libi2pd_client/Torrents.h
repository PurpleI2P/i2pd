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
#include <tuple>
#include "util.h"
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
	constexpr uint16_t TORRENT_PORT = 6881; //  not used by required by protocol
	constexpr int TRACKER_RESPONSE_TIMEOUT = 8; // in seconds
	constexpr int TRACKER_REQUESTS_CHECK_TIMEOUT = 1900; // in milliseconds
	constexpr int RECONNECT_CHECK_INTERVAL = 70; // in seconds
	constexpr int MIN_TRACKER_REQUESTS_INTERVAL = 15000; // in milliseconds
	constexpr int TRACKER_REQUESTS_INTERVAL_VARIANCE = 3000; // in milliseconds
	constexpr size_t PEER_CONNECTION_RECEIVE_BUFFER_SIZE = 65535;
	constexpr int PEER_CONNECTION_MAX_IDLE = 3600; // in seconds
	constexpr int PEER_KEEP_ALIVE_TIMEOUT = 120; // in seconds
	constexpr int PEER_KEEP_SEND_INTERVAL = 95; // in seconds
	constexpr int PEER_KEEP_ALIVE_CHECK_INTERVAL = 15; // in seconds
	constexpr size_t MAX_NUM_REQUESTS = 8;
	constexpr size_t MAX_NUM_PIECES = 6;
	constexpr int PIECE_INACTIVITY_TIMEOUT = 60; // in seconds
	constexpr int TORRENTS_STATUS_UPDATE_INTERVAL = 25; // in seconds

	constexpr size_t HANDSHAKE_MSG_LENGTH = 68;
	constexpr size_t INTERESTED_MSG_LENGTH = 5;
	constexpr size_t NOTINTERESTED_MSG_LENGTH = 5;
	constexpr size_t UNCHOKE_MSG_LENGTH = 5;
	constexpr size_t REQUEST_MSG_PAYLOAD_LENGTH = 12;
	constexpr size_t HAVE_MSG_PAYLOAD_LENGTH = 4;

	enum MessageType
	{
		eMessageTypeChoke = 0,
		eMessageTypeUnchoke = 1,
		eMessageTypeInterested = 2,
		eMessageTypeNotInterested = 3,
		eMessageTypeHave = 4,
		eMessageTypeBitfield = 5,
		eMessageTypeRequest = 6,
		eMessageTypePiece = 7,
		eMessageTypeHaveAll = 14,
		eMessageTypeHaveNone = 15
	};

	class PeerConnection;
	class Piece final
	{
		enum class BlockStatus
		{
			Missing,
			Available,
			Requested
		};

		public:

			Piece (size_t size, const uint8_t * hash);
			Piece (Piece&& ) = default;
			~Piece ();

			bool IsComplete () const { return !m_Blocks; }
			void Complete () { m_Blocks = nullptr; }
			bool VerifyHash () const;
			void SetIsSending (bool isSending);
			uint64_t GetLastActivityTimestamp () const { return m_LastActivityTimestamp; }
			bool IsRequested () const { return m_IsRequested; }
			size_t GetNumPeers () const { return m_NumPeers; }
			void SetNumPeers (size_t numPeers) { m_NumPeers = numPeers; }

			void BlockReceived (const uint8_t * block, size_t len, size_t offset);
			void Dump (const std::string& fullPath, size_t offset);
			bool Load (const std::string& fullPath, size_t offset);
			const uint8_t * GetData () const { return m_Data; }
			size_t GetSize () const { return m_Size; }
			bool HasBlock (size_t offset) const;
			std::pair<size_t, size_t> GetNextBlockToRequest (); // return (offset, len) of next buffer, len = 0 if no next buffer
			void ClearAllRequests ();
			void InvalidateAllBlocks ();
			void Reset ();

		private:

			bool IsAvailable (int block) const;
			size_t GetNumBlocks (size_t len) const;

		private:

			size_t m_Size;
			uint8_t * m_Data, m_Hash[SHA_DIGEST_LENGTH];
			std::unique_ptr<std::vector<BlockStatus> > m_Blocks;
			bool m_IsSending, m_IsRequested;
			uint64_t m_LastActivityTimestamp; // monotonic seconds
			size_t m_NumPeers; // where this piece is available
	};

	class Torrent final
	{
		public:

			using InfoHash = std::array<uint8_t, 20>;

			Torrent (std::string_view buf);
			void ParseTrackerResponse (std::string_view buf);

			bool IsComplete () const { return m_IsComplete; }
			void SetComplete ();

			const std::string& GetAnnounce () const { return m_Announce; }
			const std::string& GetName () const { return m_Name; }
			const std::list<std::pair<std::string, size_t> >& GetFiles () const { return m_Files; }
			size_t GetLength () const { return m_Length; }
			size_t GetPieceLength () const { return m_PieceLength; }
			int GetInterval () const { return m_Interval; }
			const InfoHash& GetInfoHash () const { return m_InfoHash; }
			std::string GetHexStringInfoHash () const; // in url format
			size_t GetNumPieces () const { return m_Pieces.size (); }
			Piece& GetPiece (int index) { return m_Pieces[index]; }
			std::pair<std::vector<uint8_t>, bool> CreateBitfield () const; // (bitfield, empty)
			bool ApplyBitfield (const std::vector<uint8_t>& bitfield); // return true if complete
			const std::unordered_set<i2p::data::IdentHash>&  GetPeers () const { return m_Peers; }
			std::tuple<uint32_t, uint32_t, uint32_t> GetNextBlockToRequest (std::shared_ptr<PeerConnection> conn); // return (index, offset, len)
			bool UpdateStatus (uint64_t ts); // return true if complete

			uint64_t GetNextTrackerRequestTime () const { return m_NextTrackerRequestTime; }
			void SetNextTrackerRequestTime (uint64_t ts) { m_NextTrackerRequestTime = ts; }

			void SaveTorrentResumeFile (const std::string& fullPath);

			void StartCountingPeers ();
			void ApplyPeerRemoteBitfield (const boost::dynamic_bitset<>& peerRemoteBitfield);

		private:

			size_t ParsePieces (std::string_view buf);
			size_t ParseInfo (std::string_view buf);
			size_t ParsePeers (std::string_view buf);
			size_t ParseFiles (std::string_view buf);

		private:

			std::string m_Name, m_Announce;
			size_t m_Length, m_PieceLength;
			int m_Interval; // in miiliseconds
			uint64_t m_NextTrackerRequestTime; // monotonic millicesonds
			InfoHash m_InfoHash; // SHA1
			std::vector<Piece> m_Pieces;
			std::unordered_set<i2p::data::IdentHash> m_Peers;
			bool m_IsComplete;
			std::list<std::pair<std::string, size_t> > m_Files; // list of (path, length)
	};

	class TorrentsTunnel;
	class PeerConnection: public i2p::client::I2PServiceHandler, public std::enable_shared_from_this<PeerConnection>
	{
		struct RequestedBlock
		{
			uint32_t index, offset, length;
			RequestedBlock (uint32_t i, uint32_t o, uint32_t l): index(i), offset(o), length (l) {}
			RequestedBlock(const RequestedBlock& ) = default;
			RequestedBlock(RequestedBlock&& ) = default;
		};

		public:

			PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream); // incoming
			PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream,
				std::shared_ptr<Torrent> torrent); // outgoing
			~PeerConnection ();

			void Connect ();
			void ReceiveHandshake ();
			void CheckKeepAlive (uint64_t ts);

			bool IsPieceAvailable (size_t ind) const;
			std::shared_ptr<i2p::stream::Stream> GetStream () const { return m_Stream; }
			std::shared_ptr<Torrent> GetTorrent () const { return m_Torrent; }
			int GetLastRequestedPieceIndex () const { return m_LastRequestedPieceIndex; }
			const boost::dynamic_bitset<>& GetRemoteBitfield () const  { return m_RemoteBitfield;} ;

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

			void HandleHaveMsg (const uint8_t * buf, size_t len);
			void SendHaveMsg (uint32_t index);
			void HandleBitfieldMsg (const uint8_t * buf, size_t len);
			void SendBitfieldMsg (const uint8_t * bitfield, size_t bitfieldLen);
			void HandleHaveAllMsg ();
			void HandleHaveNoneMsg ();
			void HandlePieceMsg (const uint8_t * buf, size_t len);
			void SendPieceMsg (uint32_t index, uint32_t offset, const uint8_t * data, size_t len);
			void HandleRequestMsg (const uint8_t * buf, size_t len);
			void SendRequestMsg (uint32_t index, uint32_t offset, uint32_t len);
			void SendInterestedMsg ();
			void SendNotinterestedMsg ();
			void SendUnchokeMsg ();
			void HandleChokeMsg ();

			bool RequestNextBlock ();
			void RequestNextBlocks ();

			bool SendRequestedBlock (const RequestedBlock& requestedBlock);

		private:

			std::shared_ptr<i2p::stream::Stream> m_Stream;
			uint8_t m_ReceiveBuffer[PEER_CONNECTION_RECEIVE_BUFFER_SIZE];
			size_t m_ReceiveBufferOffset;
			std::shared_ptr<Torrent> m_Torrent;
			std::string m_RemotePeerID;
			boost::dynamic_bitset<> m_RemoteBitfield;
			bool m_IsHandshakeSent, m_IsEstablished, m_IsChoked;
			uint64_t m_LastReceiveTime, m_LastSendTime; // monotonic seconds
			size_t m_NumRequests, m_NumPieces; // outgoing
			std::list<RequestedBlock> m_IncomingRequestsQueue;
			int m_LastRequestedPieceIndex;
	};

	class TorrentsTunnel final: public i2p::client::I2PService
	{
		private:

			class DiskIOService: public i2p::util::RunnableServiceWithWork
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
			std::string GetTorrentFilePath (const std::string& filename) const;
			std::shared_ptr<Torrent> FindTorrent (const Torrent::InfoHash& infoHash) const;
			std::list<std::shared_ptr<PeerConnection> > GetTorrentConnections (std::shared_ptr<Torrent> torrent);

			const char* GetName() const override { return m_Name.c_str (); }

		private:

			void Accept ();
			void ReadTorrentFile (const std::string& path);
			void CompleteTorrent (std::shared_ptr<Torrent> torrent);
			void RequestTracker (std::shared_ptr<Torrent> torrent);
			void TrackerRequestSent (const boost::beast::error_code& ecode, size_t bytes_transferred,
				std::shared_ptr<i2p::client::BoostAsyncStream> httpStream, std::shared_ptr<Torrent> torrent,
				std::shared_ptr<boost::beast::http::request<boost::beast::http::string_body> > req);

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

		private:

			std::string m_Name, m_TorrentsDir, m_PeerID; // 20 characters
			std::vector<std::string> m_Trackers;
			std::map<Torrent::InfoHash, std::shared_ptr<Torrent> > m_Torrents;
			std::mt19937 m_Rng;
			boost::asio::steady_timer m_TrackerRequestsCheckTimer, m_KeepAliveCheckTimer,
				m_ReconnectCheckTimer, m_TorrentsStatusUpdateTimer;
			DiskIOService m_DiskIOService;
	};
}
}
#endif
