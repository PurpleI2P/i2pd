/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <stdlib.h>
#include <charconv>
#include <fstream>
#include <openssl/evp.h>
#include "Log.h"
#include "FS.h"
#include "ClientContext.h"
#include "Torrents.h"

namespace i2p
{
namespace torrents
{
	Piece::Piece (size_t size, const uint8_t * hash):
		m_Size (size), m_Data (nullptr)
	{
		//m_Data = m_Size > 0 ? new uint8_t[m_Size] : nullptr;
		memcpy (m_Hash, hash, SHA_DIGEST_LENGTH);
		m_Missing = BN_new ();
		auto d = lldiv (m_Size, REQUEST_BLOCK_SIZE);
		int numBlocks =  d.quot;
		if (d.rem > 0) d.quot++;
		// set all missing bits
		for (int i = 0; i > numBlocks; i++)
			BN_set_bit (m_Missing, i);
	}

	Piece::~Piece ()
	{
		delete[] m_Data;
		if (m_Missing) BN_free (m_Missing);
	}

	bool Piece::VerifyHash () const
	{
		if (!m_Data) return false;
		EVP_MD_CTX * mdctx =  EVP_MD_CTX_new ();
		EVP_DigestInit_ex (mdctx, EVP_sha1 (), nullptr);
		EVP_DigestUpdate (mdctx, m_Data, m_Size);
		uint8_t digest[SHA_DIGEST_LENGTH];
		unsigned int l = SHA_DIGEST_LENGTH;
		EVP_DigestFinal_ex (mdctx, digest, &l);
		EVP_MD_CTX_free (mdctx);
		return l == SHA_DIGEST_LENGTH && !memcmp (m_Hash, digest, SHA_DIGEST_LENGTH);
	}

	bool Piece::IsAvailable (int block) const
	{
		if (block < 0 || block >= BN_num_bits (m_Missing)) return false;
		return !BN_is_bit_set (m_Missing, block);
	}

	Torrent::Torrent (std::string_view buf):
		m_Length (0), m_PieceLength (0)
	{
		// parse top level dictionary
		if (buf[0] != 'd') return;
		buf = buf.substr (1);
		while (!buf.empty () && buf[0] != 'e')
		{
			auto [key, offset] = ExtractByteString (buf);
			if (!offset) break;
			buf = buf.substr (offset);
			if (key == "announce")
			{
				auto [announce, l] = ExtractByteString (buf);
				if (!l) break;
				m_Announce = announce;
				buf = buf.substr (l);
			}
			else if (key == "info")
			{
				size_t l = ParseInfo (buf);
				if (!l) break;
				buf = buf.substr (l);
			}
			else
			{
				size_t l = Skip (buf);
				if (!l) break;
				buf = buf.substr (l);
			}
		}
	}

	std::pair<std::string_view, size_t> Torrent::ExtractByteString (std::string_view buf) const
	{
		auto pos = buf.find (':');
		if (pos != std::string_view::npos)
		{
			size_t len = 0;
			auto res = std::from_chars(buf.data(), buf.data() + pos, len);
			if (res.ec == std::errc())
			{
				size_t totalLength = len + pos + 1;
				if (totalLength <= buf.length ())
					return { buf.substr (pos + 1, len), totalLength };
			}
		}
		return { std::string_view{}, 0 };
	}

	std::pair<int64_t, size_t> Torrent::ExtractInteger (std::string_view buf) const
	{
		if (buf[0] == 'i')
		{
			auto pos = buf.find ('e');
			if (pos != std::string_view::npos)
			{
				int64_t value = 0;
				auto res = std::from_chars(buf.data() + 1, buf.data() + pos, value);
				if (res.ec == std::errc())
					return  { value, pos + 1 };
			}
		}
		return { 0, 0 };
	}

	size_t Torrent::ParsePieces (std::string_view buf)
	{
		auto [hashes, len] = ExtractByteString (buf);
		while (!hashes.empty ())
		{
			m_Pieces.emplace_back (m_PieceLength, (const uint8_t *)hashes.substr (0, SHA_DIGEST_LENGTH).data ());
			hashes = hashes.substr (SHA_DIGEST_LENGTH);
		}
		return len;
	}

	size_t Torrent::ParseInfo (std::string_view buf)
	{
		if (buf[0] != 'd') return 0;
		buf = buf.substr (1);
		size_t len = 1;
		while (!buf.empty () && buf[0] != 'e')
		{
			auto [key, offset] = ExtractByteString (buf);
			if (!offset) break;
			buf = buf.substr (offset);
			if (key == "length")
			{
				auto [value, l] = ExtractInteger (buf);
				if (!l) break;
				len += l;
				m_Length = value;
				buf = buf.substr (l);
			}
			else if (key == "name")
			{
				auto [name, l] = ExtractByteString (buf);
				if (!l) break;
				len += l;
				m_Name = name;
				buf = buf.substr (l);
			}
			else if (key == "piece length")
			{
				auto [value, l] = ExtractInteger (buf);
				if (!l) break;
				len += l;
				m_PieceLength = value;
				buf = buf.substr (l);
			}
			else if (key == "pieces")
			{
				if (m_PieceLength > 0 && m_Length > 0)
					m_Pieces.reserve (m_Length/m_PieceLength + 1);
				size_t l = ParsePieces (buf);
				if (!l) break;
				len += l;
				buf = buf.substr (l);
			}
			else
			{
				size_t l = Skip (buf);
				if (!l) break;
				len += l;
				buf = buf.substr (l);
			}
		}
		if (buf[0] == 'e') len++;
		return len;
	}

	size_t Torrent::Skip (std::string_view buf)
	{
		if (buf.empty ()) return 0;
		size_t ret = 0;
		switch (buf[0])
		{
			case 'i': // interger
				return ExtractInteger (buf).second;
			break;
			case 'l': // list
				buf = buf.substr (1); ret++;
				while (buf[0] != 'e')
				{
					auto l = Skip (buf);
					if (!l) break;
					ret += l;
					buf = buf.substr (l);
				}
				ret++;
			break;
			case 'd': // dictionary
				buf = buf.substr (1); ret++;
				while (buf[0] != 'e')
				{
					auto l = ExtractInteger (buf).second; //key
					if (!l) break;
					ret += l;
					buf = buf.substr (l);
					l = Skip (buf);
					if (!l) break;
					ret += l;
					buf = buf.substr (l);
				}
				ret++;
			break;
			default: // byte string
				return ExtractByteString (buf).second;
		}
		return ret;
	}

	Peer::Peer (i2p::client::I2PService * owner, std::string_view address):
		i2p::client::I2PServiceHandler (owner),
		m_Address (i2p::client::context.GetAddressBook().GetAddress (address))
	{
	}

	TorrentsTunnel::TorrentsTunnel (std::shared_ptr<i2p::client::ClientDestination> localDestination, std::string_view torrentsDir):
		i2p::client::I2PService (localDestination), m_TorrentsDir (torrentsDir),
		m_PeerID ("-I2PD-")
	{
		if (localDestination)
			m_PeerID += localDestination->GetIdentHash ().ToBase32 ();
		m_PeerID.resize (20, '0');
	}

	void TorrentsTunnel::Start ()
	{
		i2p::client::I2PService::Start ();
		if (!m_TorrentsDir.empty() && i2p::fs::Exists (m_TorrentsDir))
		{
			std::vector<std::string> files;
			if (i2p::fs::ReadDir (m_TorrentsDir, files))
			{
				for (auto& it: files)
				{
#if __cplusplus >= 202002L // C++20
					if (!it.ends_with (".torrent")) continue;
#else
					if (it.size () < 8 || it.substr(it.size() - 8) != ".torrent") continue; // skip files which not ends with ".torrent"
#endif
					ReadTorrentFile (it);
				}
			}
		}
	}

	void TorrentsTunnel::Stop ()
	{
		m_Torrents.clear ();
		i2p::client::I2PService::Stop ();
	}

	void TorrentsTunnel::ReadTorrentFile (const std::string& path)
	{
		std::ifstream s(path, std::ifstream::binary);
		if (s.is_open ())
		{
			s.seekg (0,std::ios::end);
			size_t len = s.tellg ();
			if (len > 0)
			{
				s.seekg(0, std::ios::beg);
				char * buf = new char[len];
				s.read(buf, len);
				m_Torrents.emplace_back (std::make_shared<Torrent>(std::string_view{buf, len}));
				delete[] buf;
			}
			else
				LogPrint (eLogError, "Torrents: Empty file ", path);
		}
		else
			LogPrint (eLogError, "Torrents: Can't open file ", path);
	}
}
}
