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

			Torrent (std::string_view buf);
			i2p::http::HTTPReq GetTrackerRequest () const;
			const std::string& GetName () const { return m_Name; }

		private:

			std::pair<std::string_view, size_t> ExtractByteString (std::string_view buf) const;
			std::pair<int64_t, size_t> ExtractInteger (std::string_view buf) const;
			size_t ParsePieces (std::string_view buf);
			size_t ParseInfo (std::string_view buf);
			size_t Skip (std::string_view buf);

		private:

			std::string m_Name, m_Announce, m_InfoHash; // 40 hex chars
			size_t m_Length, m_PieceLength;
			std::vector<Piece> m_Pieces;
	};

	class Peer: public i2p::client::I2PServiceHandler
	{
		public:

			Peer (i2p::client::I2PService * owner, std::string_view address);

		private:

			std::shared_ptr<const i2p::client::Address> m_Address;
	};

	class TorrentsTunnel: public i2p::client::I2PService
	{
		using TrackerResponseBuffer = std::array<uint8_t, TRACKER_RESPONSE_BUFFER_SIZE>;

		public:

			TorrentsTunnel (std::shared_ptr<i2p::client::ClientDestination> localDestination, std::string_view torrentsDir);

			void Start () override;
			void Stop () override;

			const char* GetName() const override { return "Torrents"; }

		private:

			void ReadTorrentFile (const std::string& path);
			void RequestTracker (std::shared_ptr<const Torrent> torrent);
			void ReceiveFromTracker (std::shared_ptr<i2p::stream::Stream> stream, std::shared_ptr<TrackerResponseBuffer> buf, size_t offset);
			void HandleTrackerResponse (std::shared_ptr<TrackerResponseBuffer> buf, size_t len);

		private:

			std::string m_TorrentsDir, m_PeerID; // 20 characters
			std::list<std::shared_ptr<Torrent> > m_Torrents;
	};
}
}
#endif
