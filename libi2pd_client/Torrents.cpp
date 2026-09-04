/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NO_TORRENTS

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <charconv>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <functional>
#include <set>
#include <boost/algorithm/string.hpp>
#include "Log.h"
#include "I2PEndian.h"
#include "Timestamp.h"
#include "TorrentsTunnel.h"
#include "Torrents.h"

namespace i2p
{
namespace torrents
{

// BEncoded
	static std::pair<std::string_view, size_t> ExtractByteString (std::string_view buf)
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

	static std::pair<int64_t, size_t> ExtractInteger (std::string_view buf)
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

	static size_t ParseBEncoded (std::string_view buf); // recursive
	static size_t ParseDictionary (std::string_view buf, std::function<size_t (std::string_view key, std::string_view buf)> handler = nullptr)
	{
		if (buf[0] != 'd') return 0;
		buf = buf.substr (1);
		size_t len = 1;
		while (!buf.empty () && buf[0] != 'e')
		{
			auto [key, offset] = ExtractByteString (buf);
			if (!offset) break;
			len += offset;
			buf = buf.substr (offset);
			offset = 0;
			if (handler)
				offset = handler (key, buf);
			if (!offset)
				offset = ParseBEncoded (buf);
			if (!offset) break;
			len += offset;
			buf = buf.substr (offset);
		}
		if (buf[0] == 'e') len++;
		return len;
	}

	static size_t ParseList (std::string_view buf, std::function<size_t (std::string_view buf)> handler = nullptr)
	{
		if (buf[0] != 'l') return 0 ;
		buf = buf.substr (1);
		size_t len = 1;
		while (!buf.empty () && buf[0] != 'e')
		{
			size_t l = 0;
			if (handler)
				l = handler (buf);
			if (!l)
				l = ParseBEncoded (buf);
			if (!l) break;
			len += l;
			buf = buf.substr (l);
		}
		if (buf[0] == 'e') len++;
		return len;
	}

	static size_t ParseBEncoded (std::string_view buf)
	{
		if (buf.empty ()) return 0;
		size_t ret = 0;
		switch (buf[0])
		{
			case 'i': // integer
				return ExtractInteger (buf).second;
			break;
			case 'l': // list
				return ParseList (buf);
			break;
			case 'd': // dictionary
				return ParseDictionary (buf);
			break;
			default: // byte string
				return ExtractByteString (buf).second;
		}
		return ret;
	}

	static std::pair<std::vector<std::string_view>, size_t> ParseStringList (std::string_view buf)
	{
		std::vector<std::string_view> strings;
		size_t len = ParseList (buf, [&strings](std::string_view str)->size_t
			{
				auto [s, l] = ExtractByteString (str);
				if (l) strings.push_back (s);
				return l;
			});
		return { strings, len };
	}

	static std::string CreateByteString (std::string_view str)
	{
		if (str.empty ()) return "";
		std::string ret (std::to_string (str.length ()));
		ret += ":";  ret += str;
		return ret;
	}

	static std::string CreateInteger (int64_t v)
	{
		std::string ret ("i");
		ret += std::to_string (v); ret += "e";
		return ret;
	}

	static std::string CreateDictionary (const std::vector<std::pair<std::string_view, std::string_view> >& items)
	{
		std::stringstream s;
		s << 'd';
		for (const auto& [name, value]: items)
			if (!name.empty () && !value.empty ())
			{
				s << CreateByteString (name); s << value;
			}
		s << 'e';
		return s.str ();
	}

//------------------------------------

	Piece::Piece (size_t size, const uint8_t * hash):
		m_Size (size), m_Data (nullptr), m_IsSending (false), m_IsRequested (false),
		m_LastActivityTimestamp (0), m_NumPeers (0)
	{
		memcpy (m_Hash, hash, SHA_DIGEST_LENGTH);
		m_Blocks = std::make_unique<std::vector<BlockStatus> >(GetNumBlocks (size), BlockStatus::Missing);
	}

	Piece::~Piece ()
	{
		delete[] m_Data;
	}

	bool Piece::VerifyHash () const
	{
		if (!m_Data) return false;
		uint8_t digest[SHA_DIGEST_LENGTH];
		SHA1 (m_Data, m_Size, digest);
		return !memcmp (m_Hash, digest, SHA_DIGEST_LENGTH);
	}

	bool Piece::IsAvailable (int block) const
	{
		if (!m_Blocks) return true;
		if (block < 0 || block >= (int)m_Blocks->size ()) return false;
		return (*m_Blocks)[block] == BlockStatus::Available;
	}

	void Piece::SetIsSending (bool isSending)
	{
		m_IsSending = isSending;
		if (m_IsSending)
			m_LastActivityTimestamp = i2p::util::GetMonotonicSeconds ();
	}

	size_t Piece::GetNumBlocks (size_t len) const
	{
		auto d = lldiv (len, REQUEST_BLOCK_SIZE);
		int numBlocks = d.quot;
		if (d.rem > 0) numBlocks++;
		return numBlocks;
	}

	void Piece::BlockReceived (const uint8_t * block, size_t len, size_t offset)
	{
		if (!len || offset + len > m_Size || !m_Blocks) return;
		size_t blockIndex = offset/REQUEST_BLOCK_SIZE;
		if ((*m_Blocks)[blockIndex] == BlockStatus::Requested)
		{
			if (!m_Data) m_Data = new uint8_t[m_Size];
			memcpy (m_Data + offset, block, len);
			(*m_Blocks)[blockIndex] = BlockStatus::Available;
			if (std::find_if (m_Blocks->begin (), m_Blocks->end (),
				[](BlockStatus status) { return status != BlockStatus::Available; }) == m_Blocks->end ())
			{
				// all blocks are available
				LogPrint (eLogDebug, "Torrents: piece complete");
				Complete ();
			}
		}
		else
		{
			if ((*m_Blocks)[blockIndex] == BlockStatus::Available)
				LogPrint (eLogWarning, "Torrents: Duplicated piece block ", blockIndex);
			else
				LogPrint (eLogWarning, "Torrents: Late or unsolicited piece block ", blockIndex);
		}
	}

	void Piece::Dump (PieceFileFragment&& fragment)
	{
		m_IsSending = true;
		if (m_Data && fragment.fragmentOffset + fragment.fragmentSize <= m_Size)
		{
			std::fstream f(fragment.fullFilePath, std::ios::binary | std::ios::in | std::ios::out );
			if (f)
			{
				f.seekp (fragment.fileOffset, std::ios::beg);
				f.write ((const char *)m_Data + fragment.fragmentOffset, fragment.fragmentSize);
				LogPrint (eLogDebug, "Torrents: Saved bytes ", fragment.fileOffset, " - ", fragment.fileOffset + fragment.fragmentSize - 1, " to ", fragment.fullFilePath);
			}
		}
		m_IsSending = false;
	}

	bool Piece::Load (PieceFileFragment&& fragment)
	{
		if (fragment.fragmentOffset + fragment.fragmentSize > m_Size) return false;
		std::ifstream f(fragment.fullFilePath, std::ifstream::binary);
		if (f)
		{
			if (!m_Data) m_Data = new uint8_t[m_Size];
			f.seekg (fragment.fileOffset, std::ios::beg);
			f.read ((char *)m_Data + fragment.fragmentOffset, fragment.fragmentSize);
			LogPrint (eLogDebug, "Torrents: Loaded bytes ", fragment.fileOffset, " - ", fragment.fileOffset + fragment.fragmentSize - 1, " from ", fragment.fullFilePath);
		}
		else
			return false;
		return true;
	}

	bool Piece::HasBlock (size_t offset) const
	{
		if (offset >= m_Size) return false;
		return IsAvailable (offset/REQUEST_BLOCK_SIZE);
	}

	std::pair<size_t, size_t> Piece::GetNextBlockToRequest ()
	{
		if (m_Blocks)
		{
			size_t ind = 0;
			for (auto& it: *m_Blocks)
			{
				if (it == BlockStatus::Missing)
				{
					it = BlockStatus::Requested;
					auto offset = ind*REQUEST_BLOCK_SIZE;
					m_LastActivityTimestamp = i2p::util::GetMonotonicSeconds ();
					m_IsRequested = true;
					return { offset, (offset + REQUEST_BLOCK_SIZE <= m_Size) ? REQUEST_BLOCK_SIZE : m_Size - offset };
				}
				ind++;
			}
		}
		return { 0, 0 };
	}

	void Piece::ClearAllRequests ()
	{
		if (!m_Blocks) return;
		for (auto& it: *m_Blocks)
			if (it == BlockStatus::Requested)
				it = BlockStatus::Missing;
	}

	void Piece::InvalidateAllBlocks ()
	{
		m_Blocks = nullptr;
		m_Blocks = std::make_unique<std::vector<BlockStatus> >(GetNumBlocks (m_Size), BlockStatus::Missing);
		if (m_Data)
		{
			delete[] m_Data; m_Data = nullptr;
		}
	}

	void Piece::Reset ()
	{
		if (m_Blocks)
		{
			ClearAllRequests ();
			m_IsRequested = false;
		}
		else if (m_Data && !m_IsSending)
		{
			delete[] m_Data; m_Data = nullptr;
			LogPrint (eLogDebug, "Torrents: piece's data deleted");
		}
	}

	Torrent::Torrent ():
		m_Length (0), m_PieceLength (0), m_IsComplete (false), m_IsStopped (false),
		m_Uploaded (0), m_Downloaded (0)
	{
		ResetStats ();
	}

	Torrent::Torrent (std::string_view buf): Torrent ()
	{
		ParseDictionary (buf, [this](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "announce")
				{
					auto [announce, l] = ExtractByteString (buf);
					if (l) m_Announce = announce;
					return l;
				}
				else if (key == "info")
					return ParseInfo (buf);
				return 0;
			});
	}

	Torrent::Torrent (const InfoHash& infoHash): Torrent ()
	{
		m_InfoHash = infoHash;
	}

	size_t Torrent::ParsePieces (std::string_view buf)
	{
		auto [hashes, len] = ExtractByteString (buf);
		size_t totalLen = 0;
		while (!hashes.empty () && totalLen < m_Length)
		{
			auto l = (totalLen + m_PieceLength <= m_Length) ? m_PieceLength : m_Length - totalLen;
			m_Pieces.emplace_back (l, (const uint8_t *)hashes.substr (0, SHA_DIGEST_LENGTH).data ());
			hashes = hashes.substr (SHA_DIGEST_LENGTH);
			totalLen += l;
		}
		return len;
	}

	size_t Torrent::ParseInfo (std::string_view buf)
	{
		size_t len = ParseDictionary (buf, [this](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "length")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l) m_Length = value;
					return l;
				}
				else if (key == "name")
				{
					auto [name, l] = ExtractByteString (buf);
					if (l)
					{
						if (!IsSafeName (name))
						{
							LogPrint (eLogError, "Torrents: Unsafe name in torrent: ", name);
							return 0;
						}
						m_Name = name;
					}
					return l;
				}
				else if (key == "piece length")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l)  m_PieceLength = value;
					return l;
				}
				else if (key == "pieces")
				{
					if (m_PieceLength > 0 && m_Length > 0)
						m_Pieces.reserve (m_Length/m_PieceLength + 1);
					return ParsePieces (buf);
				}
				else if (key == "files")
					return ParseFiles (buf);
				return 0;
			});
		if (!len) return 0;
		// save info
		m_Info.resize (len);
		memcpy (m_Info.data (), (const uint8_t *)buf.data (), len);
		// calculate info hash
		SHA1 (m_Info.data (), len, m_InfoHash.data ());
		return len;
	}

	std::string Torrent::CreateTorrentFileContent () const
	{
		if (m_Info.empty ()) return "";
		return CreateDictionary ( {{ "info", std::string_view ((const char *)m_Info.data (), m_Info.size ()) }} );
	}

	bool Torrent::IsSafeName (std::string_view name)
	{
		if (name.empty () || name == "." || name == "..") return false;
		if (name.back () == '.' || name.back () == ' ') return false; // Windows drops those
		for (char ch: name)
			if (ch == '/' || ch == '\\' || ch == ':' || ch == '<' || ch == '>' ||
				ch == '"' || ch == '|' || ch == '?' || ch == '*' || (unsigned char)ch < 0x20)
				return false;
#ifdef _WIN32
		static constexpr std::array reserved
		{
			"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
			"COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
			"LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
		};
		std::string stem (name.substr (0, name.find ('.')));
		boost::to_upper (stem);
		return std::find (reserved.begin (), reserved.end (), stem) == reserved.end ();
#else
		return true;
#endif
	}

	size_t Torrent::ParseFiles (std::string_view buf)
	{
		m_Length = 0;
		return ParseList (buf, [this](std::string_view file)->size_t
			{
				std::filesystem::path filePath; size_t fileLength = 0;
				auto len = ParseDictionary (file, [&filePath, &fileLength](std::string_view key, std::string_view value)->size_t
					{
						if (key == "path")
						{
							auto [subdirs, l] = ParseStringList (value);
							if (l)
								for (const auto& it: subdirs)
								{
									if (!IsSafeName (it))
									{
										LogPrint (eLogError, "Torrents: Unsafe path component in torrent: ", it);
										return 0;
									}
									filePath /= it;
								}
							return l;
						}
						else if (key == "length")
						{
							auto [length, l] = ExtractInteger (value);
							if (l)
								fileLength = length;
							return l;
						}
						return 0;
					});
				if (len && fileLength && !filePath.empty ())
				{
					m_Files.emplace_back (filePath, fileLength);
					m_Length += fileLength;
				}
				return len;
			});
	}

	std::string Torrent::GetHexStringInfoHash () const
	{
		std::string infoHash;
		for (auto it: m_InfoHash)
		{
			char str[4];
			snprintf (str, 4, "%%%02x", it);
			infoHash.append (str);
		}
		return infoHash;
	}

	size_t Torrent::GetLeft () const
	{
		if (IsComplete ()) return 0;
		size_t completed = 0;
		for (const auto& it: m_Pieces)
			if (it.IsComplete ()) completed += it.GetSize ();
		return m_Length > completed ? m_Length - completed : 0;
	}

	void Torrent::ParseTrackerResponse (size_t trackerID, std::string_view buf)
	{
		CheckTrackerStatsSize (trackerID);
		std::get<6>(m_TrackerStats[trackerID]) = ""; // clear error
		ParseDictionary (buf, [this, trackerID](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "interval")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l)
					{
						int interval = std::max (MIN_TRACKER_REQUESTS_INTERVAL, (int)value*1000); // in milliseconds
						std::get<1>(m_TrackerStats[trackerID]) = interval;
						std::get<2>(m_TrackerStats[trackerID]) = i2p::util::GetMonotonicMilliseconds () + interval; // reset next request
					}
					return l;
				}
				else if (key == "peers")
					return ParsePeers (trackerID, buf);
				else if (key == "complete")
				{
					auto [seeders, l] = ExtractInteger (buf);
					if (l) std::get<3>(m_TrackerStats[trackerID]) = seeders;
					return l;
				}
				else if (key == "incomplete")
				{
					auto [leechers, l] = ExtractInteger (buf);
					if (l) std::get<4>(m_TrackerStats[trackerID]) = leechers;
					return l;
				}
				else if (key == "failure reason")
				{
					auto [reason, l] = ExtractByteString (buf);
					LogPrint (eLogError, "Torrents: Tracker error: ", reason);
					std::get<6>(m_TrackerStats[trackerID]) = reason;
					// double interval if tracker failure
					int interval = std::max (MIN_TRACKER_REQUESTS_INTERVAL, std::get<1>(m_TrackerStats[trackerID])*2);
					std::get<1>(m_TrackerStats[trackerID]) = interval;
					std::get<2>(m_TrackerStats[trackerID]) = i2p::util::GetMonotonicMilliseconds () + interval;
					return l;
				}
				return 0;
			});
		std::get<5>(m_TrackerStats[trackerID]) = i2p::util::GetSecondsSinceEpoch ();
	}

	size_t Torrent::ParsePeers (size_t trackerID, std::string_view buf)
	{
		auto& peers = std::get<0>(m_TrackerStats[trackerID]);
		peers.clear ();
		auto [hashes, len] = ExtractByteString (buf);
		while (!hashes.empty ())
		{
			peers.emplace (i2p::data::IdentHash ((const uint8_t *)hashes.substr (0, i2p::data::IdentHash::len).data ()));
			hashes = hashes.substr (i2p::data::IdentHash::len);
		}
		return len;
	}

	void Torrent::HandleDatagramTrackerResponse (size_t trackerID, uint32_t interval,
		const uint8_t * hashes, size_t hashesLen, int numSeeders, int numLeechers)
	{
		CheckTrackerStatsSize (trackerID);
		auto& [peers, trackerRequestInterval, nextRequestTime, seeders, leechers,
			lastUpdateTime, error] = m_TrackerStats[trackerID];
		trackerRequestInterval = interval*1000; // milliseconds
		nextRequestTime = i2p::util::GetMonotonicMilliseconds () + trackerRequestInterval;
		seeders = numSeeders;
		leechers = numLeechers;
		lastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
		peers.clear ();
		size_t offset = 0;
		while (offset + i2p::data::IdentHash::len <= hashesLen)
		{
			i2p::data::IdentHash ident (hashes + offset);
			if (ident.IsZero ()) break;
			peers.emplace (std::move (ident));
			offset += i2p::data::IdentHash::len;
		}
	}

	void Torrent::SetTrackerError (size_t trackerID, std::string_view error)
	{
		CheckTrackerStatsSize (trackerID);
		std::get<6>(m_TrackerStats[trackerID]) = error;
	}

	void Torrent::CheckTrackerStatsSize (size_t trackerID)
	{
		if (trackerID >= m_TrackerStats.size ())
			m_TrackerStats.resize (trackerID + 1, TrackerStats{{}, MIN_TRACKER_REQUESTS_INTERVAL,
				0, 0, 0, i2p::util::GetSecondsSinceEpoch (), ""});
	}

	std::pair<std::vector<uint8_t>, bool> Torrent::CreateBitfield () const
	{
		size_t numPieces = m_Pieces.size ();
		size_t bitfieldSize = numPieces / 8;
		if (numPieces % 8) bitfieldSize++;
		std::vector<uint8_t> ret(bitfieldSize); // filled with 0
		bool empty = true;
		size_t idx = 0;
		for (size_t i = 0; i < ret.size (); i++) // bytes
		{
			uint8_t bit = 0x80;
			for (int j = 0; j < 8; j++)
			{
				if (idx >= numPieces) break;
				if (m_Pieces[idx].IsComplete ())
				{
					ret[i] |= bit;
					empty = false;
				}
				bit >>= 1;
				idx++;
			}
		}
		return { ret, empty };
	}

	bool Torrent::ApplyBitfield (const std::vector<uint8_t>& bitfield)
	{
		bool complete = true;
		size_t numPieces = m_Pieces.size ();
		size_t idx = 0;
		for (size_t i = 0; i < bitfield.size (); i++)
		{
			uint8_t bit = 0x80;
			for (int j = 0; j < 8; j++)
			{
				if (idx >= numPieces) break;
				if (bitfield[i] & bit)
					m_Pieces[idx].Complete ();
				else
					complete = false;
				bit >>= 1;
				idx++;
			}
			if (idx >= numPieces) break;
		}
		return complete;
	}

	RequestedBlock Torrent::GetNextBlockToRequest (std::shared_ptr<PeerConnection> conn, bool skipRequested)
	{
		if (conn)
		{
			// continue with current piece
			int lastIndex = conn->GetLastRequestedPieceIndex ();
			if (lastIndex >= 0)
			{
				auto [offset, len] = m_Pieces[(size_t)lastIndex].GetNextBlockToRequest ();
				if (len > 0)
					return { (uint32_t)lastIndex, offset, len };
			}
			// try another piece if not current piece or no more blocks in current piece
			std::set<std::pair<uint32_t, size_t>, std::function<bool(const std::pair<uint32_t, size_t>&, const std::pair<uint32_t, size_t>&)> >
				sortedByNumPeers ([](const std::pair<uint32_t, size_t>& p1, const std::pair<uint32_t, size_t>& p2)->bool
				{
					if (p1.second != p2.second) return p1.second < p2.second;
					return p1.first < p2.first;
				});
			// sort eligible pieces by num peers
			uint32_t ind = 0;
			for (auto& it: m_Pieces)
			{
				if (!it.IsComplete () && conn->IsPieceAvailable (ind) && (!skipRequested || !it.IsRequested ()))
					sortedByNumPeers.emplace (ind, it.GetNumPeers ());
				ind++;
			}
			for (const auto& it: sortedByNumPeers)
			{
				auto [offset, len] = m_Pieces[it.first].GetNextBlockToRequest ();
				if (len > 0)
					return { it.first, offset, len };
			}
		}
		return { 0, 0, 0 };
	}

	bool Torrent::UpdateStatus (uint64_t ts)
	{
		bool complete = true;
		for (auto& it: m_Pieces)
		{
			if (!it.IsComplete ()) complete = false;
			if (ts > it.GetLastActivityTimestamp () + PIECE_INACTIVITY_TIMEOUT) // piece was inactive recently
				it.Reset ();
		}
		return complete;
	}

	void Torrent::SetComplete ()
	{
		m_IsComplete = true;
		for (auto& it: m_Pieces)
			if (!it.IsComplete ())
				it.Complete ();
	}

	void Torrent::SaveTorrentResumeFile (const std::filesystem::path& fullPath)
	{
		auto [bitfield, empty] = CreateBitfield ();
		if (empty) return;
		std::ofstream f(fullPath, std::ofstream::binary);
		if (f.is_open ())
			f.write ((const char *)bitfield.data (), bitfield.size ());
	}

	void Torrent::StartCountingPeers ()
	{
		for (auto& it: m_Pieces)
			it.SetNumPeers (0);
	}

	void Torrent::ApplyPeerRemoteBitfield (const boost::dynamic_bitset<>& peerRemoteBitfield)
	{
		size_t ind = peerRemoteBitfield.find_first();
		while (ind != boost::dynamic_bitset<>::npos)
		{
			auto& piece = m_Pieces[ind];
			if (!piece.IsComplete ())
				piece.SetNumPeers (piece.GetNumPeers () + 1);
			ind = peerRemoteBitfield.find_next(ind);
		}
	}

	bool Torrent::HasIncompletePieces (const boost::dynamic_bitset<>& peerRemoteBitfield) const
	{
		size_t ind = peerRemoteBitfield.find_first();
		while (ind != boost::dynamic_bitset<>::npos)
		{
			if (!m_Pieces[ind].IsComplete ()) return true;
			ind = peerRemoteBitfield.find_next(ind);
		}
		return false;
	}

	std::vector<PieceFileFragment> Torrent::GetPieceFileFragments (int index) const
	{
		if (index < 0 || index >= (int)m_Pieces.size ()) return {};
		if (m_Files.empty ())
		{
			auto fullPath = m_FullPath;
			if (!IsComplete ()) fullPath += ".part";
			return { { fullPath, index*m_PieceLength, 0, m_Pieces[index].GetSize () } };
		}
		else
		{
			std::vector<PieceFileFragment> ret;
			// first file and offset for start of piece
			size_t offset = index*m_PieceLength;
			auto it = m_Files.begin ();
			while (it != m_Files.end ())
			{
				if (offset < it->second) break;
				offset -= it->second;
				it++;
			}
			if (it != m_Files.end ())
			{
				// split piece by files
				size_t size = m_Pieces[index].GetSize (), fragmentOffset = 0;
				while (size > 0)
				{
					auto filePath = it->first;
					if (!IsComplete ()) filePath += ".part";
					if (offset + size <= it->second)
					{
						// last fragment
						ret.emplace_back (filePath, offset, fragmentOffset, size);
						size = 0;
					}
					else
					{
						size_t l = it->second - offset;
						ret.emplace_back (filePath, offset, fragmentOffset, l);
						size -= l; fragmentOffset += l;
						offset = 0; it++;
						if (it == m_Files.end ()) break;
					}
				}
				if (size > 0)
					LogPrint (eLogError, "Torrents: Piece ", index, " is beyond files");
			}
			return ret;
		}
	}

	std::vector<size_t> Torrent::GetFilesCompleted () const
	{
		std::vector<size_t> completed;
		if (!m_Files.empty ())
		{
			auto filesIT = m_Files.begin ();
			size_t currentSize = 0, currentCompletedSize = 0;
			for (const auto& piece: m_Pieces)
			{
				if (currentSize + m_PieceLength < filesIT->second)
				{
					currentSize += m_PieceLength;
					if (piece.IsComplete ()) currentCompletedSize += m_PieceLength;
				}
				else
				{
					size_t leftoverSize = filesIT->second - currentSize;
					if (piece.IsComplete ()) currentCompletedSize += leftoverSize;
					completed.push_back (currentCompletedSize);
					currentSize = m_PieceLength - leftoverSize;
					filesIT++;
					while (filesIT != m_Files.end () && filesIT->second <= currentSize)
					{
						completed.push_back (filesIT->second);
						currentSize -= filesIT->second;
						filesIT++;
					}
					currentCompletedSize = piece.IsComplete () ?  currentSize : 0;
					if (filesIT == m_Files.end ()) break;
				}
			}
		}
		return completed;
	}

	std::unordered_set<i2p::data::IdentHash> Torrent::GetPeers () const
	{
		if (m_TrackerStats.size () == 1)
			return std::get<0>(m_TrackerStats.front ());
		std::unordered_set<i2p::data::IdentHash> ret;
		for (const auto& it: m_TrackerStats)
		{
			const auto& peers = std::get<0>(it);
			ret.insert (peers.begin (), peers.end ());
		}
		return ret;
	}

	uint64_t Torrent::GetNextTrackerRequestTime (size_t trackerID) const
	{
		if (trackerID < m_TrackerStats.size ()) return std::get<2>(m_TrackerStats[trackerID]);
		return 0;
	}

	void Torrent::SetNextTrackerRequestTime (size_t trackerID, uint64_t ts)
	{
		if (trackerID >= m_TrackerStats.size ())
			m_TrackerStats.resize (trackerID + 1, TrackerStats{{}, MIN_TRACKER_REQUESTS_INTERVAL,
				0, 0, 0, i2p::util::GetSecondsSinceEpoch (), ""});
		std::get<2>(m_TrackerStats[trackerID]) = ts;
	}

	TorrentStatus Torrent::GetStatus () const
	{
		if (m_IsStopped) return eTorrentStatusStopped;
		if (m_IsComplete) return eTorrentStatusSeeding;
		return eTorrentStatusDownloading;
	}

	PeerConnection::PeerConnection (std::shared_ptr<i2p::client::I2PService> owner,
		std::shared_ptr<i2p::stream::Stream> stream): i2p::client::I2PServiceHandler (owner),
		m_Stream (stream), m_ReceiveBufferOffset (0), m_NextMsgLength (0),
		m_IsHandshakeSent (false), m_IsEstablished (false), m_IsChoked (true), m_IsRemoteChoked (true),
		m_IsInterested (false), m_IsRemoteInterested (false), m_LastReceiveTime (0), m_LastSendTime (0),
		m_NumRequests (0), m_NumPieces (0), m_LastRequestedPieceIndex (-1), m_RemoteMetadataSize (0),
		m_Downloaded (0), m_Uploaded (0)
	{
		ResetStats ();
	}

	PeerConnection::PeerConnection (std::shared_ptr<i2p::client::I2PService> owner,
		std::shared_ptr<i2p::stream::Stream> stream, std::shared_ptr<Torrent> torrent):
		PeerConnection (owner, stream)
	{
		m_Torrent = torrent;
	}

	PeerConnection::~PeerConnection ()
	{
	}

	void PeerConnection::Terminate ()
	{
		if (Kill()) return;
		if (m_Torrent && m_LastRequestedPieceIndex >= 0) // pending requests by us
		{
			auto& piece = m_Torrent->GetPiece (m_LastRequestedPieceIndex);
			if (piece.IsRequested ())
				piece.Reset (); // piece can be requested by other connections
		}
		if (m_Stream)
		{
			m_Stream->Close ();
			m_Stream = nullptr;
		}
		if (m_HandshakeReceiveTimer)
		{
			m_HandshakeReceiveTimer->cancel ();
			m_HandshakeReceiveTimer = nullptr;
		}
		Done(shared_from_this ());
	}

	void PeerConnection::ResetStats ()
	{
		m_DownloadRate = 0; m_UploadRate = 0;
		m_LastBlockDownloadTimestamp = 0; m_LastBlockUploadTimestamp = 0;
		m_ReceivedSinceLastTimestamp = 0; m_SentSinceLastTimestamp = 0;
	}

	void PeerConnection::ScheduleHandshakeReceiveTimer ()
	{
		if (m_HandshakeReceiveTimer)
			m_HandshakeReceiveTimer->cancel ();
		else
			m_HandshakeReceiveTimer = std::make_unique<boost::asio::steady_timer>(GetTorrentsTunnel ()->GetService ());
		m_HandshakeReceiveTimer->expires_after (std::chrono::seconds(HANDSHAKE_RECEIVE_TIMEOUT));
		m_HandshakeReceiveTimer->async_wait ([s = shared_from_this ()](const boost::system::error_code& ecode)
			{
				if (ecode != boost::asio::error::operation_aborted)
				{
					LogPrint (eLogInfo, "Torrents: Handshake was not received after ", HANDSHAKE_RECEIVE_TIMEOUT,  " seconds");
					s->Terminate ();
				}
				else
					s->m_HandshakeReceiveTimer = nullptr;
			});
	}

	std::shared_ptr<TorrentsTunnel> PeerConnection::GetTorrentsTunnel () const
	{
		return std::static_pointer_cast<TorrentsTunnel>(GetOwner ());
	}

	bool PeerConnection::IsPieceAvailable (size_t ind) const
	{
		if (ind >= m_RemoteBitfield.size ()) return false;
		return m_RemoteBitfield.test (ind);
	}

	void PeerConnection::WriteToStream (const uint8_t * buf, size_t len)
	{
		if (!m_Stream) return;
		LogPrint (eLogDebug, "Torrents: Sending ", len, " bytes");
		m_Stream->AsyncSend (buf, len,
			[s = shared_from_this ()](const boost::system::error_code& ecode, size_t bytes_transferred)
			{
				if (ecode) s->Terminate ();
			});
		m_LastSendTime = i2p::util::GetMonotonicSeconds ();
	}

	void PeerConnection::Connect ()
	{
		SendHandshakeMsg ();
		ScheduleHandshakeReceiveTimer ();
		StreamReceive ();
	}

	void PeerConnection::ReceiveHandshake ()
	{
		LogPrint (eLogDebug, "Torrents: Incoming connection from ", m_Stream->GetRemoteIdentity () ?
			(m_Stream->GetRemoteIdentity ()->GetIdentHash ().ToBase32 () + ".b32.i2p") : "");
		ScheduleHandshakeReceiveTimer ();
		StreamReceive ();
	}

	void PeerConnection::Close ()
	{
		boost::asio::post (GetTorrentsTunnel ()->GetService (), [s = shared_from_this ()]()
		{
			s->Terminate ();
		});
	}

	void PeerConnection::CheckKeepAlive (uint64_t ts)
	{
		if (m_IsEstablished)
		{
			if (ts > m_LastReceiveTime + PEER_KEEP_ALIVE_TIMEOUT)
			{
				LogPrint (eLogInfo, "Torrent: Peer timeout expired");
				Close (); // Terminate shouldn't be called from IterateHandler directly
			}
			else if (ts > m_LastSendTime + PEER_KEEP_SEND_INTERVAL)
			{
				m_NumRequests = 0; // if we need to send keep-alive, all pending requests are invalid now
				bool requested = false;
				if (!m_Torrent->IsComplete () && m_Torrent->HasIncompletePieces (m_RemoteBitfield))
				{
					 // try to request if we still have blocks to request
					if (!m_IsChoked)
						requested = RequestNextBlocks ();
					else if (!m_IsInterested)
					{
						m_IsInterested = true;
						SendInterestedMsg ();
					}
				}
				if (!requested)
				{
					// send keep-alive
					uint32_t len = 0;
					WriteToStream ((const uint8_t *)&len, 4);
					m_LastSendTime = ts;
				}
			}
		}
	}

	void PeerConnection::StreamReceive ()
	{
		if (m_Stream && m_ReceiveBufferOffset < PEER_CONNECTION_RECEIVE_BUFFER_SIZE)
		{
			if (m_Stream->GetStatus () == i2p::stream::eStreamStatusNew ||
				m_Stream->GetStatus () == i2p::stream::eStreamStatusOpen) // regular
			{
				m_Stream->AsyncReceive (boost::asio::buffer (m_ReceiveBuffer + m_ReceiveBufferOffset,
					PEER_CONNECTION_RECEIVE_BUFFER_SIZE - m_ReceiveBufferOffset),
					std::bind (&PeerConnection::HandleStreamReceive, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2),
					PEER_CONNECTION_MAX_IDLE,
					m_NextMsgLength > m_ReceiveBufferOffset ? m_NextMsgLength - m_ReceiveBufferOffset : 0);
			}
			else // closed by peer
			{
				// get remaining data
				auto len = m_Stream->ReadSome (m_ReceiveBuffer + m_ReceiveBufferOffset,
					PEER_CONNECTION_RECEIVE_BUFFER_SIZE - m_ReceiveBufferOffset);
				if (len > 0) // still some data
				{
					m_ReceiveBufferOffset += len;
					HandleReceived ();
				}
				else // no more data*/
					Terminate ();
			}
		}
	}

	void PeerConnection::HandleStreamReceive (const boost::system::error_code& ecode, size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogInfo, "Torrents: Stream read error: ", ecode.message ());
				if (bytes_transferred > 0)
				{
					m_ReceiveBufferOffset += bytes_transferred;
					HandleReceived ();
				}
				else if (ecode == boost::asio::error::timed_out && m_Stream && m_Stream->IsOpen ())
					StreamReceive ();
				else
					Terminate ();
			}
			else
				Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "Torrents: Received ", bytes_transferred, " bytes");
			m_ReceiveBufferOffset += bytes_transferred;
			HandleReceived ();
			StreamReceive ();
		}
	}

	void PeerConnection::HandleReceived ()
	{
		m_LastReceiveTime = i2p::util::GetMonotonicSeconds ();
		if (m_NextMsgLength > 0 && m_ReceiveBufferOffset < m_NextMsgLength) return; // not enough received
		size_t offset = 0;
		while (size_t len = HandleNextMsg (offset))
			offset += len;

		if (offset)
		{
			if (offset < m_ReceiveBufferOffset)
			{
				// move remaining data
				m_ReceiveBufferOffset -= offset;
				memmove (m_ReceiveBuffer, m_ReceiveBuffer + offset, m_ReceiveBufferOffset);
			}
			else
			{
				m_ReceiveBufferOffset = 0;
				m_NextMsgLength = 0;
			}
		}
	}

	size_t PeerConnection::HandleNextMsg (size_t offset)
	{
		if (offset >= m_ReceiveBufferOffset)
		{
			if (offset > m_ReceiveBufferOffset)
				LogPrint (eLogError, "Torrents: Start of message ", offset, " is beyond received buffer ", m_ReceiveBufferOffset);
			return 0;
		}
		if (!m_IsEstablished)
			return HandleHandshakeMsg ();
		// regular messages
		size_t len = m_ReceiveBufferOffset - offset;
		if (len < 4)
		{
			m_NextMsgLength = 0;
			return 0;
		}
		uint32_t msgLen = bufbe32toh (m_ReceiveBuffer + offset);
		if (len < msgLen + 4)
		{
			m_NextMsgLength = msgLen + 4;
			return 0;
		}
		offset += 4;
		if (msgLen >= 1)
		{
			LogPrint (eLogDebug, "Torrents: Received msg type ", (int)m_ReceiveBuffer[offset], " len ", msgLen);
			switch (m_ReceiveBuffer[offset])
			{
				case eMessageTypeRequest:
					HandleRequestMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypePiece:
					HandlePieceMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeChoke:
					HandleChokeMsg ();
				break;
				case eMessageTypeUnchoke:
					m_IsChoked = false;
					RequestNextBlocks ();
				break;
				case eMessageTypeInterested:
					m_IsRemoteInterested = true;
					if (m_IsRemoteChoked)
					{
						m_IsRemoteChoked = false;
						SendUnchokeMsg ();
					}
				break;
				case eMessageTypeNotInterested:
					m_IsRemoteInterested = false;
				break;
				case eMessageTypeHave:
					HandleHaveMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeBitfield:
					HandleBitfieldMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeHaveAll:
					HandleHaveAllMsg ();
				break;
				case eMessageTypeHaveNone:
					HandleHaveNoneMsg ();
				break;
				case eMessageTypeExtended:
					HandleExtendedMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				default:
					LogPrint (eLogWarning, "Torrents: Unexpected message type ", (int)m_ReceiveBuffer[offset], ". Ignored");
			};
		}
		else
			LogPrint (eLogInfo, "Torrents: Keep-alive received");
		return msgLen + 4;
	}

	size_t PeerConnection::HandleHandshakeMsg ()
	{
		LogPrint (eLogDebug, "Torrents: Handshake received");
		if (m_ReceiveBufferOffset < HANDSHAKE_MSG_LENGTH) return 0;
		if (m_HandshakeReceiveTimer)
		{
			m_HandshakeReceiveTimer->cancel ();
			m_HandshakeReceiveTimer = nullptr;
		}
		if (m_ReceiveBuffer[0] != 19 || std::string_view ((const char *)(m_ReceiveBuffer + 1), 19) != "BitTorrent protocol")
		{
			LogPrint (eLogError, "Torrents: Unexpected handshake protocol string");
			Terminate ();
			return 0;
		}
		if (GetTorrentsTunnel ())
		{
			Torrent::InfoHash infoHash;
			memcpy (infoHash.data (), m_ReceiveBuffer + 28, 20);
			m_Torrent = GetTorrentsTunnel ()->FindTorrent (infoHash);
		}
		if (!m_Torrent)
		{
			LogPrint (eLogError, "Torrents: Torrent with InfoHash not found");
			Terminate ();
			return 0;
		}
		memcpy (m_RemotePeerID.data (), m_ReceiveBuffer + 48, m_RemotePeerID.size ());
		// respond with handshake if incoming
		if (!m_IsHandshakeSent)
			SendHandshakeMsg ();
		if (m_ReceiveBuffer[20 + 5] & 0x10) // bit 20 of reserved, BEP10
			SendExtendedMsg (); // extended handshake if peer supports BEP10
		// send bitfield if not empty
		auto [bitfield, empty] = m_Torrent->CreateBitfield ();
		if (!empty)
			SendBitfieldMsg (bitfield.data (), bitfield.size ());
		m_IsEstablished = true;
		return HANDSHAKE_MSG_LENGTH;
	}

	void PeerConnection::SendHandshakeMsg ()
	{
		if (!m_Torrent || !m_Stream) return;
		uint8_t buf[HANDSHAKE_MSG_LENGTH];
		buf[0] = 19; memcpy (buf + 1, "BitTorrent protocol", 19);
		memset (buf + 20, 0, 8); // reserved
		buf[20 + 5] |= 0x10; // bit 20 of reserved, BEP10
		memcpy (buf + 28, m_Torrent->GetInfoHash ().data (), 20);
		memset (buf + 48, '0', 20);
		if (GetTorrentsTunnel ())
		{
			const auto& peerID = GetTorrentsTunnel ()->GetPeerID ();
			size_t len = peerID.length (); if (len > 20) len = 20;
			memcpy (buf + 48, peerID.data (), len);
		}
		WriteToStream (buf, HANDSHAKE_MSG_LENGTH);
		m_IsHandshakeSent = true;
	}

	void PeerConnection::HandleHaveMsg (const uint8_t * buf, size_t len)
	{
		if (len < 4) return;
		if (m_RemoteBitfield.empty ()) // bitfield was not received before because was empty
			m_RemoteBitfield.resize (m_Torrent->GetNumPieces ());
		uint32_t index = bufbe32toh (buf);
		if (index < m_RemoteBitfield.size ())
		{
			m_RemoteBitfield.set (index);
			if (m_Torrent && !m_Torrent->IsComplete ())
			{
				Piece& piece = m_Torrent->GetPiece (index);
				if (!piece.IsComplete ())
				{
					// new piece
					if (!m_IsInterested)
					{
						m_IsInterested = true;
						SendInterestedMsg ();
					}
					if (m_LastRequestedPieceIndex < 0 && !m_IsChoked)
						RequestNextBlocks ();
				}
			}
		}
	}

	void PeerConnection::SendHaveMsg (uint32_t index)
	{
		if (m_IsEstablished)
		{
			uint8_t buf[HAVE_MSG_PAYLOAD_LENGTH + 5];
			htobe32buf (buf, HAVE_MSG_PAYLOAD_LENGTH + 1); // length
			buf[4] = eMessageTypeHave; // msg ID
			htobe32buf (buf + 5, index);
			WriteToStream (buf, HAVE_MSG_PAYLOAD_LENGTH + 5);
		}
	}

	void PeerConnection::HandleBitfieldMsg (const uint8_t * buf, size_t len)
	{
		if (!m_Torrent || !m_Torrent->GetLength ()) return; // we are magnet and don't have torrent info yet
		m_IsInterested = false;
		size_t numPieces = m_Torrent->GetNumPieces ();
		m_RemoteBitfield.resize (numPieces);
		size_t idx = 0;
		for (size_t i = 0; i < len; i++) // bytes
		{
			uint8_t bit = 0x80;
			for (int j = 0; j < 8; j++)
			{
				if (idx >= numPieces) break;
				if (buf[i] & bit)
				{
					m_RemoteBitfield.set (idx);
					if (!m_IsInterested && !m_Torrent->GetPiece (idx).IsComplete ())
						m_IsInterested = true;
				}
				bit >>= 1;
				idx++;
			}
		}
		if (m_IsInterested)
			SendInterestedMsg ();
		else if (m_RemoteBitfield.all ()) // remote is seeding
			Terminate (); // we don't need this connection
	}

	void PeerConnection::SendBitfieldMsg (const uint8_t * bitfield, size_t bitfieldLen)
	{
		std::vector<uint8_t> sendBuffer(bitfieldLen + 5);
		htobe32buf (sendBuffer.data (), bitfieldLen + 1); // length
		sendBuffer[4] = eMessageTypeBitfield; // msg ID
		memcpy (sendBuffer.data () + 5, bitfield, bitfieldLen);
		WriteToStream (sendBuffer.data (), sendBuffer.size ());
	}

	void PeerConnection::HandleHaveAllMsg ()
	{
		if (!m_Torrent) return;
		size_t numPieces = m_Torrent->GetNumPieces ();
		m_RemoteBitfield.resize (numPieces);
		m_RemoteBitfield.set ();
		if (!m_Torrent->IsComplete ())
		{
			m_IsInterested = true;
			SendInterestedMsg ();
		}
		else
			Terminate (); // we don't need this connection
	}

	void PeerConnection::HandleHaveNoneMsg ()
	{
		if (!m_Torrent) return;
		size_t numPieces = m_Torrent->GetNumPieces ();
		m_RemoteBitfield.resize (numPieces);
		m_RemoteBitfield.reset ();
	}

	void PeerConnection::HandlePieceMsg (const uint8_t * buf, size_t len)
	{
		if (len < 8) return;
		uint32_t index = bufbe32toh (buf);
		uint32_t offset = bufbe32toh (buf + 4);
		len -= 8;
		if (len && index < m_Torrent->GetNumPieces ())
		{
			Piece& piece = m_Torrent->GetPiece (index);
			piece.BlockReceived (buf + 8, len, offset);
			if (piece.IsComplete ())
			{
				if (piece.VerifyHash ())
				{
					boost::asio::post (GetTorrentsTunnel ()->GetDiskIOService (),
						[index, torrent = m_Torrent]() mutable
						{
							auto fragments = torrent->GetPieceFileFragments (index);
							Piece& piece = torrent->GetPiece (index);
							for (auto& it: fragments)
								piece.Dump (std::move (it));
							auto resumeFilePath = torrent->GetFullPath (); resumeFilePath += ".resume";
							torrent->SaveTorrentResumeFile (resumeFilePath);
						});
					// send have
					auto conns = GetTorrentsTunnel ()->GetTorrentConnections (m_Torrent);
					for (auto it: conns)
						it->SendHaveMsg (index);
				}
				else
				{
					LogPrint (eLogWarning, "Torrents: Received piece hash mismatch");
					piece.InvalidateAllBlocks ();
				}
			}
		}
		if (m_NumRequests > 0) m_NumRequests--;
		if (m_NumRequests <= MAX_NUM_REQUESTS*2/3)
			RequestNextBlocks ();
		// update stats
		m_Downloaded += REQUEST_BLOCK_SIZE;
		m_Torrent->AddDownloaded (REQUEST_BLOCK_SIZE);
		auto ts = i2p::util::GetMonotonicMilliseconds ();
		if (m_LastBlockDownloadTimestamp)
		{
			m_ReceivedSinceLastTimestamp += REQUEST_BLOCK_SIZE;
			auto delta = ts - m_LastBlockDownloadTimestamp;
			if (delta >= BANDWIDTH_RATE_SAMPLING_INTERVAL)
			{
				if (m_DownloadRate)
					m_DownloadRate = (m_DownloadRate + m_ReceivedSinceLastTimestamp*1000/delta)/2;
				else
					m_DownloadRate = m_ReceivedSinceLastTimestamp*1000/delta;
				m_LastBlockDownloadTimestamp = ts;
				m_ReceivedSinceLastTimestamp = 0;
			}
		}
		else
			m_LastBlockDownloadTimestamp = ts;
	}

	void PeerConnection::SendPieceMsg (uint32_t index, uint32_t offset, const uint8_t * data, size_t len)
	{
		if (!m_Stream) return;
		std::vector<uint8_t> sendBuffer(len + 8 + 5);
		htobe32buf (sendBuffer.data (), len + 8 + 1); // length
		sendBuffer[4] = eMessageTypePiece; // msg ID
		htobe32buf (sendBuffer.data () + 5, index);
		htobe32buf (sendBuffer.data () + 9, offset);
		memcpy (sendBuffer.data () + 13, data, len);
		LogPrint (eLogDebug, "Torrents: Sending piece index ", index, " offset ", offset, " length ", len);
		m_NumPieces++;
		m_Stream->AsyncSend (sendBuffer.data (), sendBuffer.size (),
			[s = shared_from_this ()](const boost::system::error_code& ecode, size_t bytes_transferred)
			{
				if (s->m_NumPieces > 0) s->m_NumPieces--;
				if (!ecode)
				{
					while (!s->m_IncomingRequestsQueue.empty () && s->m_NumPieces < MAX_NUM_PIECES)
					{
						s->SendRequestedBlock (s->m_IncomingRequestsQueue.front ());
						s->m_IncomingRequestsQueue.pop_front ();
					}
					if (s->m_IsRemoteChoked && s->m_IncomingRequestsQueue.size () < 2*MAX_NUM_PIECES)
					{
						LogPrint (eLogDebug, "Torrents: Unchoke");
						s->m_IsRemoteChoked = false;
						s->SendUnchokeMsg ();
					}
					// update stats
					auto ts = i2p::util::GetMonotonicMilliseconds ();
					if (s->m_LastBlockUploadTimestamp)
					{
						s->m_SentSinceLastTimestamp += REQUEST_BLOCK_SIZE;
						auto delta = ts - s->m_LastBlockUploadTimestamp;
						if (delta >= BANDWIDTH_RATE_SAMPLING_INTERVAL)
						{
							if (s->m_UploadRate)
								s->m_UploadRate = (s->m_UploadRate + s->m_SentSinceLastTimestamp*1000/delta)/2;
							else
								s->m_UploadRate = s->m_SentSinceLastTimestamp*1000/delta;
							s->m_LastBlockUploadTimestamp = ts;
							s->m_SentSinceLastTimestamp = 0;
						}
					}
					else
						s->m_LastBlockUploadTimestamp = ts;
				}
				else
					s->Terminate ();
			});
		m_LastSendTime = i2p::util::GetMonotonicSeconds ();
		m_Uploaded += REQUEST_BLOCK_SIZE;
		m_Torrent->AddUploaded (len);
	}

	void PeerConnection::HandleRequestMsg (const uint8_t * buf, size_t len)
	{
		if (!m_Torrent) return;
		if (len != REQUEST_MSG_PAYLOAD_LENGTH)
		{
			LogPrint (eLogWarning, "Torrents: Unexpected length of request message ", len);
			return;
		}
		uint32_t index = bufbe32toh (buf);
		uint32_t offset = bufbe32toh (buf + 4);
		uint32_t length = bufbe32toh (buf + 8);
		if (length > REQUEST_BLOCK_SIZE)
		{
			LogPrint (eLogWarning, "Torrents: Requested length is too long ", length);
			return;
		}
		if (index < m_Torrent->GetNumPieces ())
		{
			LogPrint (eLogDebug, "Torrents: Received request index ", index, " offset ", offset, " length ", length);
			Piece& piece = m_Torrent->GetPiece (index);
			if (piece.HasBlock (offset))
			{
				if (m_NumPieces >= MAX_NUM_PIECES)
				{
					 m_IncomingRequestsQueue.emplace_back (index, offset, length);
					 if (!m_IsRemoteChoked && m_IncomingRequestsQueue.size () > 5*MAX_NUM_PIECES)
					 {
						LogPrint (eLogDebug, "Torrents: Choke");
						m_IsRemoteChoked = true;
						SendChokeMsg ();
					 }
				}
				else if (!SendRequestedBlock ({index, offset, length})) // block was not sent
				{
					// try to load from file
					boost::asio::post (GetTorrentsTunnel ()->GetDiskIOService (),
					[requestBlock = RequestedBlock{index, offset, length}, torrent = m_Torrent, s = shared_from_this ()]() mutable
					{
						bool loaded = true;
						auto [index, offset, len] = requestBlock;
						Piece& piece = torrent->GetPiece (index);
						if (!piece.GetData ()) // don't try to load if already loaded
						{
							auto fragments = torrent->GetPieceFileFragments (index);
							piece.SetIsSending (true);
							for (auto& it: fragments)
							{
								if (!piece.Load (std::move (it)))
									loaded = false;
							}
							if (loaded && !piece.VerifyHash ())
							{
								LogPrint (eLogError, "Torrent: Corrupted piece ", index);
								loaded = false;
							}
							piece.SetIsSending (false);
						}
						if (loaded)
							boost::asio::post (s->GetTorrentsTunnel ()->GetService (),
								[requestedBlock = std::move (requestBlock), s]()
								{
									if (s->m_NumPieces < MAX_NUM_PIECES)
										s->SendRequestedBlock (requestedBlock);
									else
										s->m_IncomingRequestsQueue.emplace_back (std::move (requestedBlock));
								});
						else
						{
							LogPrint (eLogError, "Torrent: Failed to load piece ", index);
							piece.Reset ();
						}
					});
				}
			}
			else
				LogPrint (eLogWarning, "Torrents: Requested block (", index, ",", offset, ") is not available");
		}
		else
			LogPrint (eLogWarning, "Torrents: Requested index ", index, "exceeds number of pieces", m_Torrent->GetNumPieces ());
	}

	bool PeerConnection::SendRequestedBlock (const RequestedBlock& requestedBlock)
	{
		bool ret = true;
		auto [index, offset, len] = requestedBlock;
		Piece& piece = m_Torrent->GetPiece (index);
		piece.SetIsSending (true);
		auto data = piece.GetData ();
		if (data && piece.HasBlock (offset))
			SendPieceMsg (index, offset, data + offset, len);
		else
			ret = false;
		piece.SetIsSending (false);
		return ret;
	}

	void PeerConnection::SendRequestMsg (uint32_t index, uint32_t offset, uint32_t len)
	{
		uint8_t buf[REQUEST_MSG_LENGTH];
		FillRequestMsg (buf, index, offset, len);
		WriteToStream (buf, REQUEST_MSG_LENGTH);
	}

	size_t PeerConnection::FillRequestMsg (uint8_t * buf, uint32_t index, uint32_t offset, uint32_t len)
	{
		htobe32buf (buf, REQUEST_MSG_PAYLOAD_LENGTH + 1); // msg length
		buf[4] = eMessageTypeRequest; // msg ID
		htobe32buf (buf + 5, index); // index
		htobe32buf (buf + 9, offset); // offset
		htobe32buf (buf + 13, len); // length
		return REQUEST_MSG_LENGTH;
	}

	void PeerConnection::SendInterestedMsg ()
	{
		uint8_t buf[INTERESTED_MSG_LENGTH];
		htobe32buf (buf, 1);
		buf[4] = eMessageTypeInterested;
		WriteToStream (buf, INTERESTED_MSG_LENGTH);
	}

	void PeerConnection::SendNotinterestedMsg ()
	{
		uint8_t buf[NOTINTERESTED_MSG_LENGTH];
		htobe32buf (buf, 1);
		buf[4] = eMessageTypeNotInterested;
		WriteToStream (buf, NOTINTERESTED_MSG_LENGTH);
	}

	void PeerConnection::SendChokeMsg ()
	{
		uint8_t buf[CHOKE_MSG_LENGTH];
		htobe32buf (buf, 1);
		buf[4] = eMessageTypeChoke;
		WriteToStream (buf, CHOKE_MSG_LENGTH);
	}

	void PeerConnection::SendUnchokeMsg ()
	{
		uint8_t buf[UNCHOKE_MSG_LENGTH];
		htobe32buf (buf, 1);
		buf[4] = eMessageTypeUnchoke;
		WriteToStream (buf, UNCHOKE_MSG_LENGTH);
	}

	void PeerConnection::HandleChokeMsg ()
	{
		m_IsChoked = true;
		m_NumRequests = 0;
		if (m_Torrent && m_LastRequestedPieceIndex >= 0)
			m_Torrent->GetPiece (m_LastRequestedPieceIndex).ClearAllRequests ();
		m_LastRequestedPieceIndex = -1;
	}

	void PeerConnection::HandleExtendedMsg (const uint8_t * buf, size_t len)
	{
		if (len < 1) return;
		if (!buf[0]) // Handshake
		{
			ParseDictionary (std::string_view ((const char *)(buf + 1), len -1),
				[this](std::string_view key, std::string_view buf)->size_t
				{
					if (key == "m")
					{
						return ParseDictionary (buf, [this](std::string_view msg, std::string_view msgID)->size_t
							{
								auto [id, l] = ExtractInteger (msgID);
								if (l)
									AddExtendedMsgHandler (msg, id);
								return l;
							});
					}
					else if (key == "metadata_size")
					{
						auto [s, l] = ExtractInteger (buf);
						if (l) m_RemoteMetadataSize = s;
						return l;
					}
					else if (key == "v")
					{
						auto [v, l] = ExtractByteString (buf);
						if (l) m_RemoteName = v;
						return l;
					}
					return 0;
				});
			if (!m_Torrent->GetLength () && m_RemoteMetadataSize) // torrent is magnet and peer supports BEP9
				// request first piece of info
				SendExtendedMsg (EXTENSION_MSGID_UT_METADATA, CreateDictionary ({{ "msg_type", CreateInteger (0) }, { "piece", CreateInteger (0) }}));
		}
		else
		{
			auto it = m_ExtendedMessageHandlers.find (buf[0]);
			if (it != m_ExtendedMessageHandlers.end ())
				(this->*(it->second))(buf + 1, len - 1);
			else
				LogPrint (eLogInfo, "Torrents: Unexpected extended message type ", (int)buf[0], " received");
		}
	}

	void PeerConnection::AddExtendedMsgHandler (std::string_view extensionName, int64_t msgID)
	{
		if (extensionName == EXTENSION_NAME_UT_METADATA)
			m_ExtendedMessageHandlers.emplace (msgID, &PeerConnection::HandleUtMetadataExtension);
	}

	void PeerConnection::SendExtendedMsg (uint8_t extendedMsgID, std::string_view payload, std::string_view data)
	{
		std::string str;
		if (!extendedMsgID) // handshake
		{
			str = CreateDictionary ({
				{ "m", CreateDictionary ({
					{ EXTENSION_NAME_UT_METADATA, CreateInteger (EXTENSION_MSGID_UT_METADATA) }
										  }) },
				{ "metadata_size",  CreateInteger (m_Torrent->GetInfo ().size ()) },
				{ "v", CreateByteString ("i2pd") }
									});
			payload = str;
		}
		std::vector<uint8_t> sendBuffer (payload.length () + data.length () + 1 + 5);
		htobe32buf (sendBuffer.data (), payload.length () + data.length () + 1 + 1); // length
		sendBuffer[4] = eMessageTypeExtended; // msg ID
		sendBuffer[5] = extendedMsgID;
		memcpy (sendBuffer.data () + 6, payload.data (), payload.size ());
		if (!data.empty ())
			memcpy (sendBuffer.data () + 6 + payload.size (), data.data (), data.size ());
		WriteToStream (sendBuffer.data (), sendBuffer.size ());
	}

	void PeerConnection::HandleUtMetadataExtension (const uint8_t * buf, size_t len)
	{
		if (!m_Torrent) return;
		int msgType = -1, piece = -1;
		size_t size = 0;
		auto payloadLen = ParseDictionary (std::string_view ((const char *)buf, len),
			[&msgType, &piece, &size](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "msg_type")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l) msgType = value;
					return l;
				}
				else if (key == "piece")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l) piece = value;
					return l;
				}
				else if (key == "total_size")
				{
					auto [s, l] = ExtractInteger (buf);
					if (l) size = s;
					return l;
				}
				return 0;
			});
		if (msgType >=0 && piece >= 0)
		{
			switch (msgType)
			{
				case 0: // request
				{
					auto& info = m_Torrent->GetInfo ();
					size_t offset = piece*REQUEST_BLOCK_SIZE;
					if (offset < info.size ())
					{
						size_t totalSize = std::min (info.size () - offset, REQUEST_BLOCK_SIZE);
						SendExtendedMsg (EXTENSION_MSGID_UT_METADATA,
							CreateDictionary ({{ "msg_type", CreateInteger (1) },
								{ "piece", CreateInteger (piece) },
								{ "total_size", CreateInteger (totalSize) } }),
							std::string_view ((const char *)info.data () + offset, totalSize));
					}
					else
						SendExtendedMsg (EXTENSION_MSGID_UT_METADATA, CreateDictionary ({{ "msg_type", CreateInteger (2) }, { "piece", CreateInteger (piece) }}));
					break;
				}
				case 1: // data
				{
					if (payloadLen + size > len) break;
					size_t offset = piece*REQUEST_BLOCK_SIZE;
					if (offset == m_RemoteMetadata.size () && size)
					{
						m_RemoteMetadata.resize (m_RemoteMetadata.size () + size);
						memcpy (m_RemoteMetadata.data () + offset,buf + payloadLen, size);
						if (m_RemoteMetadata.size () < m_RemoteMetadataSize)
							// request next piece
							SendExtendedMsg (EXTENSION_MSGID_UT_METADATA, CreateDictionary ({{ "msg_type", CreateInteger (0) }, { "piece", CreateInteger (piece + 1) }}));
						else
						{
							// all info received
							LogPrint (eLogDebug, "Torrents: ut_metadata ", m_RemoteMetadataSize, " bytes of info received");
							uint8_t digest[SHA_DIGEST_LENGTH];
							SHA1 (m_RemoteMetadata.data (), m_RemoteMetadata.size (), digest);
							if (memcmp (m_Torrent->GetInfoHash ().data (), digest, SHA_DIGEST_LENGTH))
								GetTorrentsTunnel ()->UpdateTorrentInfo (m_Torrent, std::string_view ((const char *)m_RemoteMetadata.data (), m_RemoteMetadata.size ()));
							else
								LogPrint (eLogError, "Torrents: ut_metadata info doesn't match infoHash");
							Close (); // we need to reconnect to receive bitfield
						}
					}
					break;
				}
				case 2: // reject
					LogPrint (eLogError, "Torrents: ut_metadata piece ", piece, " request rejected");
				break;
				default:
					LogPrint (eLogInfo, "Torrents: ut_metadata msg_type ", msgType, " is not supported");
			}
		}
	}

	std::optional<RequestedBlock> PeerConnection::GetNextBlockToRequest ()
	{
		auto block = m_Torrent->GetNextBlockToRequest (shared_from_this (), true); // skip already requested pieces
		if (std::get<2>(block) > 0) return block;
		// try to get block from requested by another connection piece
		auto block1 = m_Torrent->GetNextBlockToRequest (shared_from_this (), false);
		if (std::get<2>(block1) > 0) return block1;
		if (m_LastRequestedPieceIndex >= 0)
		{
			m_LastRequestedPieceIndex = -1; // no request
			if (m_IsInterested)
			{
				m_IsInterested = false;
				SendNotinterestedMsg ();
			}
		}
		return {};
	}

	bool PeerConnection::RequestNextBlocks ()
	{
		if (m_IsChoked || !m_Torrent || m_Torrent->IsComplete ()) return false;
		if (m_NumRequests >= MAX_NUM_REQUESTS) return false;
		std::vector<uint8_t> buf;
		buf.reserve (REQUEST_MSG_LENGTH*(MAX_NUM_REQUESTS - m_NumRequests));
		size_t bufOffset = 0;
		while (m_NumRequests < MAX_NUM_REQUESTS)
		{
			auto nextBlock = GetNextBlockToRequest ();
			if (!nextBlock) break;
			auto [index, offset, len] = *nextBlock;
			FillRequestMsg (buf.data () + bufOffset, index, offset, len);
			bufOffset += REQUEST_MSG_LENGTH;
			m_LastRequestedPieceIndex = index;
			m_NumRequests++;
		}
		if (bufOffset > 0)
			WriteToStream (buf.data (), bufOffset);
		return bufOffset > 0;
	}
}
}

#endif // NO_TORRENTS
