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
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <memory>
#include <vector>
#include <array>
#include <list>
#include <map>
#include <string>
#include <string_view>
#include "Streaming.h"
#include "HTTP.h"
#include "I2PService.h"
#include "AddressBook.h"

namespace i2p
{
namespace torrents
{
	constexpr size_t REQUEST_BLOCK_SIZE = 16384;
	constexpr int TRACKER_RESPONSE_TIMEOUT = 8; // in seconds
	constexpr size_t TRACKER_RESPONSE_BUFFER_SIZE = 65535;
	constexpr size_t PEER_CONNECTION_RECEIVE_BUFFER_SIZE = 16384;
	constexpr int PEER_CONNECTION_MAX_IDLE = 3600; // in seconds

	constexpr size_t HANDSHAKE_MSG_LENGTH = 68;

	enum MessageType
	{
		eMessageTypeBitfield = 5
	};

	class Piece final
	{
		public:

			Piece (size_t size, const uint8_t * hash);
			~Piece ();

			bool IsComplete () const { return BN_is_zero (m_Missing); }
			bool VerifyHash () const;
			bool IsAvailable (int block) const;

		private:

			size_t m_Size;
			uint8_t * m_Data, m_Hash[SHA_DIGEST_LENGTH];
			BIGNUM * m_Missing; // bit is set if block is missing
	};

	class Torrent final
	{
		public:

			using InfoHash = std::array<uint8_t, 20>;

			Torrent (std::string_view buf);
			i2p::http::HTTPReq GetTrackerRequest () const;
			void ParseTrackerResponse (std::string_view buf);

			const std::string& GetName () const { return m_Name; }
			const InfoHash& GetInfoHash () const { return m_InfoHash; }
			size_t GetNumPieces () const { return m_Pieces.size (); };

		private:

			std::string GetHexStraingInfoHash () const;

			size_t ParsePieces (std::string_view buf);
			size_t ParseInfo (std::string_view buf);
			size_t ParsePeers (std::string_view buf);
			size_t ParsePeer (std::string_view buf);

		private:

			std::string m_Name, m_Announce;
			size_t m_Length, m_PieceLength;
			int m_Interval;
			InfoHash m_InfoHash; // SHA1
			std::vector<Piece> m_Pieces;
			std::list<std::pair<std::string, std::shared_ptr<const i2p::client::Address> > > m_Peers;
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

		private:

			void Terminate ();
			TorrentsTunnel * GetTorrentsTunnel () const;

			void StreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, size_t bytes_transferred);
			void HandleReceived ();
			size_t HandleNextMsg (size_t offset);

			size_t HandleHandshakeMsg ();
			void SendHandshakeMsg ();

			void HandleBitfieldMsg (const uint8_t * buf, size_t len);

		private:

			std::shared_ptr<i2p::stream::Stream> m_Stream;
			uint8_t m_ReceiveBuffer[PEER_CONNECTION_RECEIVE_BUFFER_SIZE];
			size_t m_ReceiveBufferOffset;
			std::shared_ptr<Torrent> m_Torrent;
			std::string m_RemotePeerID;
			BIGNUM * m_RemoteBitfield;
			bool m_IsHandshakeSent, m_IsEstablished;
	};

	class TorrentsTunnel: public i2p::client::I2PService
	{
		using TrackerResponseBuffer = std::array<uint8_t, TRACKER_RESPONSE_BUFFER_SIZE>;

		public:

			TorrentsTunnel (std::shared_ptr<i2p::client::ClientDestination> localDestination, std::string_view torrentsDir);

			void Start () override;
			void Stop () override;

			const std::string& GetPeerID () const { return m_PeerID; }
			std::shared_ptr<Torrent> FindTorrent (const Torrent::InfoHash& infoHash) const;
			void ConnectToPeer (std::shared_ptr<Torrent> torrent, std::shared_ptr<const i2p::client::Address> peer);

			const char* GetName() const override { return "Torrents"; }

		private:

			void Accept ();

			void ReadTorrentFile (const std::string& path);
			void RequestTracker (std::shared_ptr<Torrent> torrent);
			void ReceiveFromTracker (std::shared_ptr<i2p::stream::Stream> stream,
				std::shared_ptr<Torrent> torrent, std::shared_ptr<TrackerResponseBuffer> buf, size_t offset);
			void HandleTrackerResponse (std::shared_ptr<Torrent> torrent,
				std::shared_ptr<TrackerResponseBuffer> buf, size_t len);

		private:

			std::string m_TorrentsDir, m_PeerID; // 20 characters
			std::map<Torrent::InfoHash, std::shared_ptr<Torrent> > m_Torrents;
	};
}
}
#endif
