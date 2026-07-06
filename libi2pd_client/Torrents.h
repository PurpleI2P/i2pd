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
#include <vector>
#include <string>
#include <string_view>

namespace i2p
{
namespace torrents
{
	constexpr size_t REQUEST_BLOCK_SIZE = 16384;

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

		private:

			std::pair<std::string_view, size_t> ExtractByteString (std::string_view buf) const;
			std::pair<int64_t, size_t> ExtractInteger (std::string_view buf) const;
			size_t ParsePieces (std::string_view buf);
			size_t ParseInfo (std::string_view buf);
			size_t Skip (std::string_view buf);

		private:

			std::string m_Name;
			size_t m_Length, m_PieceLength;
			std::vector<Piece> m_Pieces;
	};
}
}
#endif
