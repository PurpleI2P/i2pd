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
#include <sstream>
#include <algorithm>
#include <functional>
#include <limits>
#include <set>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/hex.hpp>
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

	constexpr size_t BENCODED_MAX_DEPTH = 10;

	std::pair<std::string_view, size_t> ExtractByteString (std::string_view buf)
	{
		auto pos = buf.find (':');
		if (pos != std::string_view::npos)
		{
			size_t len = 0;
			auto res = std::from_chars(buf.data(), buf.data() + pos, len);
			if (res.ec == std::errc() && len <= std::numeric_limits<size_t>::max () - pos - 1)
			{
				size_t totalLength = len + pos + 1;
				if (totalLength <= buf.length ())
					return { buf.substr (pos + 1, len), totalLength };
			}
		}
		return { std::string_view{}, 0 };
	}

	std::pair<int64_t, size_t> ExtractInteger (std::string_view buf)
	{
		if (!buf.empty () && buf[0] == 'i')
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

	static size_t ParseBEncoded (std::string_view buf, size_t depth); // recursive
	size_t ParseDictionary (std::string_view buf, std::function<size_t (std::string_view key, std::string_view buf)> handler, size_t depth)
	{
		if (buf.empty () || buf[0] != 'd') return 0;
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
				offset = ParseBEncoded (buf, depth);
			if (!offset) break;
			len += offset;
			buf = buf.substr (offset);
		}
		if (buf.empty () || buf[0] != 'e') return 0; // malformed dictionary without terminating 'e'
		len++; // 'e'
		return len;
	}

	size_t ParseList (std::string_view buf, std::function<size_t (std::string_view buf)> handler, size_t depth)
	{
		if (buf.empty () || buf[0] != 'l') return 0;
		buf = buf.substr (1);
		size_t len = 1;
		while (!buf.empty () && buf[0] != 'e')
		{
			size_t l = 0;
			if (handler)
				l = handler (buf);
			if (!l)
				l = ParseBEncoded (buf, depth);
			if (!l) break;
			len += l;
			buf = buf.substr (l);
		}
		if (buf.empty () || buf[0] != 'e') return 0; // malformed list without terminating 'e'
		len++; // 'e'
		return len;
	}

	static size_t ParseBEncoded (std::string_view buf, size_t depth)
	{
		if (buf.empty () || depth > BENCODED_MAX_DEPTH) return 0;
		size_t ret = 0;
		switch (buf[0])
		{
			case 'i': // integer
				return ExtractInteger (buf).second;
			break;
			case 'l': // list
				return ParseList (buf, nullptr, depth + 1);
			break;
			case 'd': // dictionary
				return ParseDictionary (buf, nullptr, depth + 1);
			break;
			default: // byte string
				return ExtractByteString (buf).second;
		}
		return ret;
	}

	std::pair<std::vector<std::string_view>, size_t> ParseStringList (std::string_view buf)
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

	std::string CreateByteString (std::string_view str)
	{
		if (str.empty ()) return "";
		std::string ret (std::to_string (str.length ()));
		ret += ":";  ret += str;
		return ret;
	}

	std::string CreateInteger (int64_t v)
	{
		std::string ret ("i");
		ret += std::to_string (v); ret += "e";
		return ret;
	}

	std::string CreateDictionary (const std::vector<std::pair<std::string_view, std::string_view> >& items)
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

	std::string CreateList (const std::vector<std::string>& items)
	{
		std::stringstream s;
		s << 'l';
		for (const auto& it: items)
			s << it;
		s << 'e';
		return s.str ();
	}

//------------------------------------

	bool TorrentFile::Save (size_t offset, const uint8_t * buf, size_t len)
	{
		Open ();
		if (m_File)
		{
			m_File.seekp (offset, std::ios::beg);
			m_File.write ((const char *)buf, len);
		}
		else
			return false;
		return true;
	}

	bool TorrentFile::Load (size_t offset, uint8_t * buf, size_t len)
	{
		Open ();
		if (m_File)
		{
			m_File.seekg (offset, std::ios::beg);
			m_File.read ((char *)buf, len);
		}
		else
			return false;
		return true;
	}

	void TorrentFile::Complete ()
	{
		m_IsPart = false;
		Close ();
	}

	void TorrentFile::Open ()
	{
		if (!m_File.is_open ())
		{
			auto mode = std::ios::binary | std::ios::in;
			auto filePath = m_FullFilePath;
			if (m_IsPart)
			{
				filePath += ".part";
				mode |= std::ios::out;
			}
			m_File.open (filePath, mode);
		}
		auto ts = i2p::util::GetMonotonicSeconds ();
		if (ts > m_LastFlushTime + TORRENT_FILE_FLUSH_INTERVAL)
		{
			m_File.flush ();
			m_LastFlushTime = ts;
		}
		m_LastAccessTime = ts;
	}

	void TorrentFile::Close ()
	{
		m_File.close ();
	}

	void TorrentFile::UpdateFullPath (const std::filesystem::path& rootDir)
	{
		m_FullFilePath = rootDir/m_FullFilePath;
	}

	Piece::Piece (size_t size, const uint8_t * hash):
		m_Size (size), m_Data (nullptr), m_IsSending (false), m_IsRequested (false),
		m_LastActivityTimestamp (0), m_NumPeers (0)
	{
		memcpy (m_Hash, hash, SHA_DIGEST_LENGTH);
		m_Blocks = std::make_unique<std::vector<BlockStatus> >(GetNumBlocks (size), BlockStatus::Missing);
	}

	Piece::~Piece ()
	{
		DeleteDataBuffer ();
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
			if (!m_Data) NewDataBuffer ();
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
			if (fragment.file->Save (fragment.fileOffset, m_Data + fragment.fragmentOffset, fragment.fragmentSize))
				LogPrint (eLogDebug, "Torrents: Saved bytes ", fragment.fileOffset, " - ", fragment.fileOffset + fragment.fragmentSize - 1, " to ", fragment.file->GetFullFilePath ());
		}
		m_IsSending = false;
	}

	bool Piece::Load (PieceFileFragment&& fragment)
	{
		if (fragment.fragmentOffset + fragment.fragmentSize > m_Size) return false;
		uint8_t * data = m_Data;
		if (!data) data = new uint8_t[m_Size];
		bool success = fragment.file->Load (fragment.fileOffset, data + fragment.fragmentOffset, fragment.fragmentSize);
		UpdateDataBuffer (data);
		if (success)
		{
			LogPrint (eLogDebug, "Torrents: Loaded bytes ", fragment.fileOffset, " - ", fragment.fileOffset + fragment.fragmentSize - 1, " from ", fragment.file->GetFullFilePath ());
			return true;
		}
		else
		{
			LogPrint (eLogError, "Torrents: Failed to load bytes ", fragment.fileOffset, " - ", fragment.fileOffset + fragment.fragmentSize - 1, " from ", fragment.file->GetFullFilePath ());
			return false;
		}
	}

	void Piece::NewDataBuffer ()
	{
#if defined(__cpp_lib_atomic_ref)
		std::atomic_ref<uint8_t *> data (m_Data);
		auto old = data.exchange (new uint8_t[m_Size]);
		if (old) delete[] old;
#else
		if (!m_Data) m_Data = new uint8_t[m_Size];
#endif
	}

	void Piece::DeleteDataBuffer ()
	{
#if defined(__cpp_lib_atomic_ref)
		std::atomic_ref<uint8_t *> data (m_Data);
		auto old = data.exchange (nullptr);
		if (old) delete[] old;
#else
		delete[] m_Data; m_Data = nullptr;
#endif
	}

	void Piece::UpdateDataBuffer (uint8_t * newData)
	{
#if defined(__cpp_lib_atomic_ref)
		std::atomic_ref<uint8_t *> data (m_Data);
		auto old = data.exchange (newData);
		if (old && old != newData) delete[] old;
#else
		if (newData != m_Data)
		{
			auto old = m_Data;
			m_Data = newData; delete[] old;
		}
#endif

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
		m_IsRequested = false;
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
			DeleteDataBuffer ();
	}

	void Piece::Reset ()
	{
		if (m_Blocks)
			ClearAllRequests ();
		else if (m_Data && !m_IsSending)
		{
			DeleteDataBuffer ();
			LogPrint (eLogDebug, "Torrents: piece's data deleted");
		}
	}

	Torrent::Torrent ():
		m_AnnounceTrackerID (-1), m_Length (0), m_PieceLength (0), m_IsComplete (false),
		m_IsStopped (false), m_IsSingleFile (true), m_Uploaded (0), m_Downloaded (0),
		m_NextUpdateStatusTime (0), m_NextReconnectTime (0), m_Error (eTorrentErrorNoError)
	{
	}

	Torrent::Torrent (std::string_view buf): Torrent ()
	{
		if (!ParseDictionary (buf, [this](std::string_view key, std::string_view buf)->size_t
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
			}))
		m_Error = eTorrentErrorMalformedMetaInfo;
	}

	Torrent::Torrent (const InfoHash& infoHash): Torrent ()
	{
		m_InfoHash = infoHash;
	}

	size_t Torrent::ParsePieces (std::string_view buf)
	{
		auto [hashes, len] = ExtractByteString (buf);
		size_t totalLen = 0;
		while (hashes.length () >= SHA_DIGEST_LENGTH && totalLen < m_Length)
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
					if (l)
					{
						if (value < 0 || (size_t)value > MAX_TORRENT_LENGTH)
						{
							LogPrint (eLogError, "Torrents: Invalid length ", value);
							value = 0;
						}
						m_Length = value;
					}
					return l;
				}
				else if (key == "name")
				{
					auto [name, l] = ExtractByteString (buf);
					if (l)
					{
						m_Name = AdjustName (name);
						if (m_Name.empty () && !name.empty ())
						{
							LogPrint (eLogError, "Torrents: Unsafe name in torrent: ", name);
							return 0;
						}
					}
					return l;
				}
				else if (key == "piece length")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l)
					{
						if ((size_t)value < MIN_PIECE_LENGTH || (size_t)value > MAX_PIECE_LENGTH)
						{
							LogPrint (eLogError, "Torrents: Invalid piece length ", value);
							value = 0;
						}
						m_PieceLength = value;
					}
					return l;
				}
				else if (key == "pieces")
				{
					{
						std::vector<Piece> tmp;
						m_Pieces.swap (tmp);
					}
					if (m_PieceLength > 0 && m_Length > 0)
					{
						auto d = lldiv (m_Length, m_PieceLength);
						size_t numPieces = d.quot;
						if (d.rem > 0) numPieces++;
						if (numPieces <= MAX_NUM_TORRENT_PIECES)
							m_Pieces.reserve (numPieces);
						else
						{
							LogPrint (eLogError, "Torrents: Too many pieces ", numPieces);
							m_Error = eTorrentErrorMalformedMetaInfo;
						}
					}
					else
						m_Error = eTorrentErrorMalformedMetaInfo;
					return ParsePieces (buf);
				}
				else if (key == "files")
					return ParseFiles (buf);
				return 0;
			});
		if (!len)
		{
			m_Error = eTorrentErrorMalformedMetaInfo;
			return 0;
		}
		if (m_IsSingleFile && !m_Name.empty ()) // single file
			m_Files.emplace_back (std::make_shared<TorrentFile> (m_Name, m_Length));
		// save info
		m_Info.resize (len);
		memcpy (m_Info.data (), (const uint8_t *)buf.data (), len);
		// calculate info hash
		SHA1 (m_Info.data (), len, m_InfoHash.data ());
		if (m_Error) m_IsStopped = true;
		return len;
	}

	std::string Torrent::CreateTorrentFileContent () const
	{
		if (m_Info.empty ()) return "";
		return CreateDictionary ({ { "announce", CreateByteString (m_Announce) },
			{ "info", std::string_view ((const char *)m_Info.data (), m_Info.size ()) } });
	}

	std::string Torrent::AdjustName (std::string_view name)
	{
		if (name.empty () || name == "." || name == "..") return "";
#ifdef _WIN32
		if (name.back () == '.' || name.back () == ' ') return ""; // Windows drops those
#endif
		std::string adjustedName;
		for (char ch: name)
		{
			if ((unsigned char)ch < 0x20) return "";
			if (ch == '/' || ch == '\\' || ch == ':' || ch == '<' || ch == '>' ||
				ch == '"' || ch == '|' || ch == '?' || ch == '*')
				adjustedName.push_back ('_');
			else
				adjustedName.push_back (ch);
		}

#ifdef _WIN32
		static constexpr std::array reserved
		{
			"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
			"COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
			"LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
		};
		std::string stem (name.substr (0, name.find ('.')));
		boost::to_upper (stem);
		if (std::find (reserved.begin (), reserved.end (), stem) != reserved.end ()) return "";
#endif
		return adjustedName;
	}

	size_t Torrent::ParseFiles (std::string_view buf)
	{
		m_IsSingleFile = false;
		m_Length = 0;
		m_Files.clear ();
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
									auto name = AdjustName (it);
									if (name.empty ())
									{
										LogPrint (eLogError, "Torrents: Unsafe path component in torrent: ", it);
										filePath.clear ();
										return 0;
									}
									filePath /= name;
								}
							return l;
						}
						else if (key == "length")
						{
							auto [length, l] = ExtractInteger (value);
							if (l)
							{
								if (length < 0 || (size_t)length > MAX_TORRENT_LENGTH)
								{
									LogPrint (eLogError, "Torrents: Invalid file length ", length);
									length = 0;
								}
								fileLength = length;
							}
							return l;
						}
						return 0;
					});
				if (len && fileLength && !filePath.empty ())
				{
					if (m_Files.size () < MAX_NUM_TORRENT_FILES)
						m_Files.emplace_back (std::make_shared<TorrentFile> (filePath, fileLength));
					else
						m_Error = eTorrentErrorMalformedMetaInfo;
					if (m_Length + fileLength <= MAX_TORRENT_LENGTH)
						m_Length += fileLength;
					else
						m_Error = eTorrentErrorMalformedMetaInfo;
				}
				else
					m_Error = eTorrentErrorMalformedMetaInfo;
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
						int interval = std::clamp ((int)value, MIN_TRACKER_REQUESTS_INTERVAL/1000, MAX_TRACKER_REQUESTS_INTERVAL/1000)*1000; // in milliseconds
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
					int interval = std::clamp (std::get<1>(m_TrackerStats[trackerID])*2, MIN_TRACKER_REQUESTS_INTERVAL, MAX_TRACKER_REQUESTS_INTERVAL);
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
		while (hashes.length () >= i2p::data::IdentHash::len)
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
		error = "";
		trackerRequestInterval = std::clamp ((int)interval, MIN_TRACKER_REQUESTS_INTERVAL/1000, MAX_TRACKER_REQUESTS_INTERVAL/1000)*1000; // milliseconds
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

	void Torrent::SetInterval (size_t trackerID, int interval)
	{
		CheckTrackerStatsSize (trackerID);
		std::get<1>(m_TrackerStats[trackerID]) = interval;
	}

	std::pair<std::vector<uint8_t>, boost::logic::tribool> Torrent::CreateBitfield () const
	{
		size_t numPieces = m_Pieces.size ();
		size_t bitfieldSize = numPieces / 8;
		if (numPieces % 8) bitfieldSize++;
		if (!bitfieldSize) return { {}, false }; // magnet, have none
		std::vector<uint8_t> ret(bitfieldSize); // filled with 0
		bool none = true, all = true;
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
					none = false;
				}
				else
					all = false;
				bit >>= 1;
				idx++;
			}
		}
		return { ret, all ? boost::logic::tribool (true) : (none ? boost::logic::tribool (false) : boost::logic::indeterminate) };
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
			// try suggested piece
			int suggestedIndex = conn->ResetSuggestedPieceIndex ();
			if (suggestedIndex >= 0)
			{
				Piece& piece = m_Pieces[suggestedIndex];
				if (!piece.IsComplete () && !piece.IsRequested ())
				{
					auto [offset, len] = piece.GetNextBlockToRequest ();
					if (len > 0)
						return { (uint32_t)suggestedIndex, offset, len };
				}
			}
			// try another piece if not current piece or no more blocks in current piece
			using PieceNumPeers = std::tuple<uint32_t, size_t, uint_fast32_t>; // (index, num peers, random value)
			std::set<PieceNumPeers, std::function<bool(const PieceNumPeers&, const PieceNumPeers&)> >
				sortedByNumPeers ([](const PieceNumPeers& p1, const PieceNumPeers& p2)->bool
				{
					if (std::get<1>(p1) != std::get<1>(p2)) return std::get<1>(p1) < std::get<1>(p2);
					if (std::get<2>(p1) != std::get<2>(p2)) return std::get<2>(p1) < std::get<2>(p2);
					return std::get<0>(p1) < std::get<0>(p2);
				});
			// sort eligible pieces by num peers
			std::mt19937 rng (i2p::util::GetRngSeed ());
			uint32_t ind = 0;
			for (auto& it: m_Pieces)
			{
				if (!it.IsComplete () && conn->IsPieceAvailable (ind) && (!skipRequested || !it.IsRequested ()))
					sortedByNumPeers.emplace (ind, it.GetNumPeers (), rng ());
				ind++;
			}
			for (const auto& it: sortedByNumPeers)
			{
				uint32_t ind = std::get<0>(it);
				auto [offset, len] = m_Pieces[ind].GetNextBlockToRequest ();
				if (len > 0)
					return { ind, offset, len };
			}
		}
		return { 0, 0, 0 };
	}

	bool Torrent::UpdateStatus (uint64_t ts)
	{
		GetConnections (); // cleanup expired connections
		if (!m_Length) return false; // non ready magnet
		bool complete = true;
		for (auto& it: m_Pieces)
		{
			if (!it.IsComplete ()) complete = false;
			if (m_IsStopped || (ts > it.GetLastActivityTimestamp () + PIECE_INACTIVITY_TIMEOUT)) // piece was inactive recently
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
		for (auto it: m_Files)
			it->Complete ();
	}

	void Torrent::SaveTorrentResumeFile ()
	{
		auto [bitfield, have] = CreateBitfield ();
		if (!have) return; // empty
		std::filesystem::path resumeFilePath = m_FullPath; resumeFilePath += ".resume";
		if (have) // all
		{
			// delete resume file
			if (!std::filesystem::remove (resumeFilePath))
				LogPrint (eLogError, "Torrents: Can't delete resume file ", resumeFilePath);
		}
		else
		{
			std::ofstream f(resumeFilePath, std::ofstream::binary);
			if (f.is_open ())
				f.write ((const char *)bitfield.data (), bitfield.size ());
			else
				LogPrint (eLogError, "Torrents: Can't open resume file ", resumeFilePath);
		}
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

		std::vector<PieceFileFragment> ret;
		// first file and offset for start of piece
		size_t offset = index*m_PieceLength;
		auto it = m_Files.begin ();
		while (it != m_Files.end ())
		{
			if (offset < (*it)->GetFileLength ()) break;
			offset -= (*it)->GetFileLength ();
			it++;
		}
		if (it != m_Files.end ())
		{
			// split piece by files
			size_t size = m_Pieces[index].GetSize (), fragmentOffset = 0;
			while (size > 0)
			{
				auto file = *it;
				file->SetIsPart (!IsComplete ());
				if (offset + size <= file->GetFileLength ())
				{
					// last fragment
					ret.emplace_back (file, offset, fragmentOffset, size);
					size = 0;
				}
				else
				{
					size_t l = file->GetFileLength () - offset;
					ret.emplace_back (file, offset, fragmentOffset, l);
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

	std::vector<size_t> Torrent::GetFilesCompleted () const
	{
		std::vector<size_t> completed;
		if (!m_Files.empty ())
		{
			auto filesIT = m_Files.begin ();
			size_t currentSize = 0, currentCompletedSize = 0;
			for (const auto& piece: m_Pieces)
			{
				if (currentSize + m_PieceLength < (*filesIT)->GetFileLength ())
				{
					currentSize += m_PieceLength;
					if (piece.IsComplete ()) currentCompletedSize += m_PieceLength;
				}
				else
				{
					size_t leftoverSize = (*filesIT)->GetFileLength () - currentSize;
					if (piece.IsComplete ()) currentCompletedSize += leftoverSize;
					completed.push_back (currentCompletedSize);
					currentSize = m_PieceLength - leftoverSize;
					filesIT++;
					while (filesIT != m_Files.end () && (*filesIT)->GetFileLength () <= currentSize)
					{
						completed.push_back ((*filesIT)->GetFileLength ());
						currentSize -= (*filesIT)->GetFileLength ();
						filesIT++;
					}
					currentCompletedSize = piece.IsComplete () ?  currentSize : 0;
					if (filesIT == m_Files.end ()) break;
				}
			}
		}
		return completed;
	}

	std::unordered_set<i2p::data::IdentHash> Torrent::GetNonConnectedPeers ()
	{
		std::unordered_set<i2p::data::IdentHash> ret;
		for (size_t i = 0; i < m_TrackerStats.size (); i++)
			ret.merge (GetNonConnectedPeers (i));
		return ret;
	}

	std::unordered_set<i2p::data::IdentHash> Torrent::GetNonConnectedPeers (size_t trackerID)
	{
		std::unordered_set<i2p::data::IdentHash> ret;
		if (trackerID < m_TrackerStats.size ())
		{
			const auto& peers = std::get<0>(m_TrackerStats[trackerID]);
			for (const auto& it: peers)
			{
				if (!IsConnectedToPeer (it))
					ret.emplace (it);
			}
		}
		return ret;
	}

	std::unordered_set<i2p::data::IdentHash> Torrent::GetAllPeers () const
	{
		std::unordered_set<i2p::data::IdentHash> ret;
		for (const auto& it: m_TrackerStats)
		{
			const auto& peers = std::get<0>(it);
			for (const auto& it1: peers)
				ret.emplace (it1);
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

	bool Torrent::AddConnection (std::shared_ptr<PeerConnection> conn)
	{
		if (!conn) return false;
		auto remoteIdentHash = conn->GetRemoteIdentHash ();
		if (!remoteIdentHash) return false;
		auto [it, inserted] = m_Connections.emplace (*remoteIdentHash, conn);
		if (!inserted)
		{
			if (it->second.expired ())
			{
				m_Connections.erase (it); // delete not longer existing
				return m_Connections.emplace (*remoteIdentHash, conn).second; // try again
			}
			else
				return false;
		}
		return true;
	}

	void Torrent::RemoveConnection (std::shared_ptr<PeerConnection> conn)
	{
		if (!conn) return;
		auto remoteIdentHash = conn->GetRemoteIdentHash ();
		if (!remoteIdentHash) return;
		m_Connections.erase (*remoteIdentHash);
	}

	std::list<std::shared_ptr<PeerConnection> > Torrent::GetConnections ()
	{
		std::list<std::shared_ptr<PeerConnection> > ret;
		auto it = m_Connections.begin ();
		while (it != m_Connections.end ())
		{
			auto conn = it->second.lock ();
			if (conn)
			{
				ret.emplace_back (conn);
				it++;
			}
			else
				it = m_Connections.erase (it);
		}
		return ret;
	}

	bool Torrent::IsConnectedToPeer (const i2p::data::IdentHash& peer)
	{
		auto it = m_Connections.find (peer);
		if (it != m_Connections.end ())
		{
			if (!it->second.expired ()) return true;
			m_Connections.erase (it);
		}
		return false;
	}

	uint64_t Torrent::GetDownloadRate ()
	{
		uint64_t downloadRate = 0;
		auto conns = GetConnections ();
		for (auto it: conns)
			downloadRate += it->GetDownloadRate ();
		return downloadRate;
	}

	uint64_t Torrent::GetUploadRate ()
	{
		uint64_t uploadRate = 0;
		auto conns = GetConnections ();
		for (auto it: conns)
			uploadRate += it->GetUploadRate ();
		return uploadRate;
	}

	int Torrent::GetNumDownloadingFromPeers ()
	{
		int numDownloadingFromPeers = 0;
		auto conns = GetConnections ();
		for (auto it: conns)
			if (it->IsDownloading ()) numDownloadingFromPeers++;
		return numDownloadingFromPeers;
	}

	int Torrent::GetNumUploadingToPeers ()
	{
		int numUploadingToPeers = 0;
		auto conns = GetConnections ();
		for (auto it: conns)
			if (it->IsUploading ()) numUploadingToPeers++;
		return numUploadingToPeers;
	}

	PeerConnection::PeerConnection (std::shared_ptr<i2p::client::I2PService> owner,
		std::shared_ptr<i2p::stream::Stream> stream): i2p::client::I2PServiceHandler (owner),
		m_Stream (stream), m_ReceiveBufferOffset (0), m_NextMsgLength (0), m_MaxNumRequests (MIN_NUM_REQUESTS),
		m_IsHandshakeSent (false), m_IsEstablished (false), m_IsChoked (true), m_IsRemoteChoked (true),
		m_IsInterested (false), m_IsRemoteInterested (false), m_LastReceiveTime (0), m_LastSendTime (0),
		m_NumRequests (0), m_NumPieces (0), m_LastRequestedPieceIndex (-1),
		m_RemoteMsgIDUtMetadata (0), m_RemoteMsgIDI2PPEX (0), m_RemoteMsgIDI2PDHT (0),
		m_RemoteMetadataSize (0), m_IsFast (false), m_SuggestedPieceIndex (-1),
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
		if (m_Torrent)
		{
			if (m_LastRequestedPieceIndex >= 0) // pending requests by us
			{
				auto& piece = m_Torrent->GetPiece (m_LastRequestedPieceIndex);
				if (piece.IsRequested ())
					piece.ClearAllRequests (); // piece can be requested by other connections
			}
			m_Torrent->RemoveConnection (shared_from_this ());
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
		Done(shared_from_this());
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
				if (ecode || !s->m_Stream) s->Terminate ();
			});
		m_LastSendTime = i2p::util::GetMonotonicSeconds ();
	}

	void PeerConnection::Connect ()
	{
		if (m_Torrent && m_Torrent->AddConnection (shared_from_this ()))
		{
			SendHandshakeMsg ();
			ScheduleHandshakeReceiveTimer ();
			StreamReceive ();
		}
		else
		{
			LogPrint (eLogWarning, "Torrents: Connection with peer ",
				i2p::data::GetIdentHashAbbreviation (m_Stream->GetRemoteIdentity ()->GetIdentHash ()), " already exists");
			Terminate ();
			return;
		}
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
		if (!m_Stream) return;
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
		if (msgLen > PEER_CONNECTION_RECEIVE_BUFFER_SIZE)
		{
			LogPrint (eLogError, "Torrents: Unexpected received message length ", msgLen);
			m_ReceiveBufferOffset = 0;
			Terminate ();
			return 0;
		}
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
				case eMessageTypeSuggestPiece:
					HandleSuggestPieceMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeRejectRequest:
					HandleRejectRequestMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeAllowedFast:
					HandleAllowedFastMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
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
		if (!m_Stream || m_ReceiveBufferOffset < HANDSHAKE_MSG_LENGTH) return 0;
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
			auto torrent = GetTorrentsTunnel ()->FindTorrent (infoHash);
			if (!torrent)
			{
				std::string hexHash;
				boost::algorithm::hex (infoHash.begin(), infoHash.end(), std::back_inserter(hexHash));
				LogPrint (eLogWarning, "Torrents: Torrent with InfoHash ", hexHash, " not found");
				Terminate ();
				return 0;
			}
			if (torrent->IsStopped ())
			{
				LogPrint (eLogInfo, "Torrents: Torrent ", torrent->GetName (), " is stopped");
				Terminate ();
				return 0;
			}
			if (m_Torrent)
			{
				// outgoing
				if (m_Torrent->GetInfoHash () != infoHash)
				{
					LogPrint (eLogWarning, "Torrents: InfoHash mistmatch for ", torrent->GetName ());
					Terminate ();
					return 0;
				}
			}
			else
			{
				// incoming
				if (torrent->AddConnection (shared_from_this ()))
					m_Torrent = torrent;
				else
				{
					LogPrint (eLogWarning, "Torrents: Incoming connection with peer ",
						i2p::data::GetIdentHashAbbreviation (m_Stream->GetRemoteIdentity ()->GetIdentHash ()), " already exists");
					Terminate ();
					return 0;
				}
			}
		}
		memcpy (m_RemotePeerID.data (), m_ReceiveBuffer + 48, m_RemotePeerID.size ());
		// respond with handshake if incoming
		if (!m_IsHandshakeSent)
			SendHandshakeMsg ();
		// BEP10
		if (m_ReceiveBuffer[20 + 5] & 0x10) // bit 20 of reserved
			SendExtendedMsg (); // extended handshake if peer supports BEP10
		else if (!m_Torrent->GetLength ()) // we are magnet without info
		{
			LogPrint (eLogInfo, "Torrents: Magnet doesn't have info yet, but BEP10 is not supported by this peer");
			Terminate ();
			return 0;
		}
		// BEP6
		if (m_ReceiveBuffer[20 + 7] & 0x04) // bit 61 of reserved
			m_IsFast = true;
		m_IsEstablished = true;
		// send bitfield, have all or have none
		auto [bitfield, have] = m_Torrent->CreateBitfield ();
		if (!have) // have none
		{
			if (m_IsFast)
				SendHaveNoneMsg ();
			// otherwise send nothing
		}
		else if (have && m_IsFast) // have all
			SendHaveAllMsg ();
		else
			SendBitfieldMsg (bitfield.data (), bitfield.size ());

		return HANDSHAKE_MSG_LENGTH;
	}

	void PeerConnection::SendHandshakeMsg ()
	{
		if (!m_Torrent || !m_Stream) return;
		uint8_t buf[HANDSHAKE_MSG_LENGTH];
		buf[0] = 19; memcpy (buf + 1, "BitTorrent protocol", 19);
		memset (buf + 20, 0, 8); // reserved
		buf[20 + 5] |= 0x10; // bit 20 of reserved, BEP10
		buf[20 + 7] |= 0x04; // bit 61 of reserved, BEP6
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

	void PeerConnection::SendHaveAllMsg ()
	{
		uint8_t buf[HAVE_ALL_MSG_LENGTH];
		htobe32buf (buf, 1);
		buf[4] = eMessageTypeHaveAll;
		WriteToStream (buf, HAVE_ALL_MSG_LENGTH);
	}

	void PeerConnection::HandleHaveNoneMsg ()
	{
		if (!m_Torrent) return;
		size_t numPieces = m_Torrent->GetNumPieces ();
		m_RemoteBitfield.resize (numPieces);
		m_RemoteBitfield.reset ();
	}

	void PeerConnection::SendHaveNoneMsg ()
	{
		uint8_t buf[HAVE_NONE_MSG_LENGTH];
		htobe32buf (buf, 1);
		buf[4] = eMessageTypeHaveNone;
		WriteToStream (buf, HAVE_NONE_MSG_LENGTH);
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
							torrent->SaveTorrentResumeFile ();
						});
					// send have
					auto conns = m_Torrent->GetConnections ();
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
		if (m_NumRequests <= m_MaxNumRequests*2/3)
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
				if (!ecode && s->m_Stream)
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

	void PeerConnection::HandleRejectRequestMsg (const uint8_t * buf, size_t len)
	{
		if (len < 8 || !m_Torrent) return;
		uint32_t index = bufbe32toh (buf);
		uint32_t offset = bufbe32toh (buf + 4);
		LogPrint (eLogDebug, "Torrents: Reject request msg received index ", index, " offset ", offset);
		if (m_NumRequests > 0) m_NumRequests--;
		RequestNextBlocks ();
	}

	void PeerConnection::SendRejectRequestMsg (uint32_t index, uint32_t offset, uint32_t len)
	{
		uint8_t buf[REJECT_REQUEST_MSG_LENGTH];
		htobe32buf (buf, REJECT_REQUEST_MSG_PAYLOAD_LENGTH + 1); // msg length
		buf[4] = eMessageTypeRejectRequest; // msg ID
		htobe32buf (buf + 5, index); // index
		htobe32buf (buf + 9, offset); // offset
		htobe32buf (buf + 13, len); // length
		WriteToStream (buf, REJECT_REQUEST_MSG_LENGTH);
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
			if (piece.HasBlock (offset) && offset + length <= piece.GetSize ())
			{
				if (m_NumPieces >= MAX_NUM_PIECES)
				{
					if (m_IncomingRequestsQueue.size () + m_NumPieces < MAX_INCOMING_REQUESTS_QUEUE_SIZE)
						m_IncomingRequestsQueue.emplace_back (index, offset, length);
					else if (m_IsFast)
						SendRejectRequestMsg (index, offset, length);
					else if (!m_IsRemoteChoked)
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
						piece.SetIsSending (true);
						if (!piece.GetData ()) // don't try to load if already loaded
						{
							auto fragments = torrent->GetPieceFileFragments (index);
							for (auto& it: fragments)
							{
								if (!piece.Load (std::move (it)))
									loaded = false;
							}
							if (loaded && !piece.VerifyHash ())
							{
								LogPrint (eLogError, "Torrents: Corrupted piece ", index);
								loaded = false;
							}
						}
						piece.SetIsSending (false);
						if (loaded)
							boost::asio::post (s->GetTorrentsTunnel ()->GetService (),
								[requestedBlock = std::move (requestBlock), s]()
								{
									if (!s->SendRequestedBlock (requestedBlock))
									{
										LogPrint (eLogError, "Torrents: Couldn't send block from loaded piece");
										std::apply (std::bind_front(&PeerConnection::SendRejectRequestMsg, s), requestedBlock);
									}
								});
						else
						{
							LogPrint (eLogError, "Torrents: Failed to load piece ", index);
							piece.Reset ();
							if (s->m_IsFast)
								boost::asio::post (s->GetTorrentsTunnel ()->GetService (),
								[requestedBlock = std::move (requestBlock), s]()
								{
									std::apply (std::bind_front(&PeerConnection::SendRejectRequestMsg, s), requestedBlock);
								});
						}
					});
				}
			}
			else
			{
				LogPrint (eLogWarning, "Torrents: Requested block (", index, ",", offset, ") is not available");
				if (m_IsFast)
					SendRejectRequestMsg (index, offset, length);
			}
		}
		else
		{
			LogPrint (eLogWarning, "Torrents: Requested index ", index, "exceeds number of pieces", m_Torrent->GetNumPieces ());
			if (m_IsFast)
				SendRejectRequestMsg (index, offset, length);
		}
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

	void PeerConnection::HandleSuggestPieceMsg (const uint8_t * buf, size_t len)
	{
		if (len < 4) return;
		uint32_t index = bufbe32toh (buf);
		LogPrint (eLogDebug, "Torrents: suggest piece msg received ", index);
		if (IsPieceAvailable (index))
			m_SuggestedPieceIndex = index;
	}

	void PeerConnection::HandleAllowedFastMsg (const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "Torrents: allowed fast msg received");
		// ignore for now
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
						if (l)
						{
							if (s < 0 || (size_t)s > MAX_NUM_TORRENT_PIECES*SHA_DIGEST_LENGTH)
							{
								LogPrint (eLogError, "Torrents: Invalid metadata_size ", s);
								s = 0;
							}
							m_RemoteMetadataSize = s;
						}
						return l;
					}
					else if (key == "reqq")
					{
						auto [q, l] = ExtractInteger (buf);
						if (l) m_MaxNumRequests = std::clamp ((size_t)q, MIN_NUM_REQUESTS, MAX_NUM_REQUESTS);
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
			// trigger extensions
			// BEP9
			if (!m_Torrent->GetLength ()) // magnet without info
			{
				if (m_RemoteMsgIDUtMetadata && m_RemoteMetadataSize) // peer supports BEP9
					// request first piece of info
					RequestUtMetadata ();
				else
				{
					LogPrint (eLogInfo, "Torrents: Magnet doesn't have info yet, but BEP9 is not supported by this peer");
					Close ();
				}
			}
			// BEP11
			if (m_RemoteMsgIDI2PPEX && m_Stream && m_Stream->IsIncoming ())
				NotifyPEXPeers ();
			// BEP5
			if (m_RemoteMsgIDI2PDHT)
				SendDHTPortAdvertisement ();
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
		{
			m_ExtendedMessageHandlers.emplace (EXTENSION_MSGID_UT_METADATA, &PeerConnection::HandleUtMetadataExtension);
			m_RemoteMsgIDUtMetadata = msgID;
		}
		else if (extensionName == EXTENSION_NAME_I2P_PEX)
		{
			m_ExtendedMessageHandlers.emplace (EXTENSION_MSGID_I2P_PEX, &PeerConnection::HandleI2PPEXExtension);
			m_RemoteMsgIDI2PPEX = msgID;
		}
		else if (extensionName == EXTENSION_NAME_I2P_DHT)
		{
			m_ExtendedMessageHandlers.emplace (EXTENSION_MSGID_I2P_DHT, &PeerConnection::HandleI2PDHTExtension);
			m_RemoteMsgIDI2PDHT = msgID;
		}
	}

	void PeerConnection::SendExtendedMsg (uint8_t extendedMsgID, std::string_view payload, std::string_view data)
	{
		std::string str;
		if (!extendedMsgID) // handshake
		{
			str = CreateDictionary ({
				{ "m", CreateDictionary ({
					{ EXTENSION_NAME_I2P_DHT, CreateInteger (EXTENSION_MSGID_I2P_DHT) },
					{ EXTENSION_NAME_I2P_PEX, CreateInteger (EXTENSION_MSGID_I2P_PEX) },
					{ EXTENSION_NAME_UT_METADATA, CreateInteger (EXTENSION_MSGID_UT_METADATA) }
										  }) },
				{ "metadata_size",  CreateInteger (m_Torrent->GetInfo ().size ()) },
				{ "reqq", CreateInteger (MAX_INCOMING_REQUESTS_QUEUE_SIZE) },
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
		auto payloadLen = ParseDictionary (std::string_view ((const char *)buf, len),
			[&msgType, &piece](std::string_view key, std::string_view buf)->size_t
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
				// ignore total_szie
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
						size_t pieceSize = std::min (info.size () - offset, REQUEST_BLOCK_SIZE);
						SendExtendedMsg (m_RemoteMsgIDUtMetadata,
							CreateDictionary ({{ "msg_type", CreateInteger (1) },
								{ "piece", CreateInteger (piece) },
								{ "total_size", CreateInteger (m_Torrent->GetInfo ().size ()) } }),
							std::string_view ((const char *)info.data () + offset, pieceSize));
					}
					else
						SendExtendedMsg (m_RemoteMsgIDUtMetadata, CreateDictionary ({{ "msg_type", CreateInteger (2) }, { "piece", CreateInteger (piece) }}));
					break;
				}
				case 1: // data
				{
					if (m_Torrent->GetLength ())
					{
						// we have info
						if (m_RemoteMetadata.size () < m_RemoteMetadataSize) // response to our request
							Terminate (); // reconnect
						// otherwise unsolicited data, ignore
						break;
					}
					size_t offset = piece*REQUEST_BLOCK_SIZE;
					if (offset > m_RemoteMetadataSize) break;
					size_t size = m_RemoteMetadataSize - offset;
					if (size > REQUEST_BLOCK_SIZE) size = REQUEST_BLOCK_SIZE;
					if (payloadLen + size > len) break;
					if (offset == m_RemoteMetadata.size () && size)
					{
						m_RemoteMetadata.resize (m_RemoteMetadata.size () + size);
						memcpy (m_RemoteMetadata.data () + offset, buf + payloadLen, size);
						if (m_RemoteMetadata.size () < m_RemoteMetadataSize)
							// request next piece
							SendExtendedMsg (m_RemoteMsgIDUtMetadata, CreateDictionary ({{ "msg_type", CreateInteger (0) }, { "piece", CreateInteger (piece + 1) }}));
						else
						{
							// all info received
							LogPrint (eLogDebug, "Torrents: ut_metadata ", m_RemoteMetadataSize, " bytes of info received");
							uint8_t digest[SHA_DIGEST_LENGTH];
							SHA1 (m_RemoteMetadata.data (), m_RemoteMetadata.size (), digest);
							if (!memcmp (m_Torrent->GetInfoHash ().data (), digest, SHA_DIGEST_LENGTH))
								GetTorrentsTunnel ()->UpdateTorrentInfo (m_Torrent, std::string_view ((const char *)m_RemoteMetadata.data (), m_RemoteMetadata.size ()));
							else
								LogPrint (eLogError, "Torrents: ut_metadata info doesn't match infoHash");
							Terminate (); // we need to reconnect to receive bitfield
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

	void PeerConnection::RequestUtMetadata ()
	{
		SendExtendedMsg (m_RemoteMsgIDUtMetadata, CreateDictionary ({{ "msg_type", CreateInteger (0) }, { "piece", CreateInteger (0) }}));
	}

	void PeerConnection::HandleI2PPEXExtension (const uint8_t * buf, size_t len)
	{
		std::unordered_set<i2p::data::IdentHash> newPeers;
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&newPeers](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "added")
				{
					auto [idents, l] = ExtractByteString (buf);
					if (l && !(idents.size () & 0x1F)) // multiple of 32
						while (idents.length () >= i2p::data::IdentHash::len)
						{
							newPeers.emplace (i2p::data::IdentHash ((const uint8_t *)idents.substr (0, i2p::data::IdentHash::len).data ()));
							idents = idents.substr (i2p::data::IdentHash::len);
						};
					return l;
				}
				return 0;
			});
		if (!newPeers.empty ())
		{
			LogPrint (eLogDebug, "Torrents: I2P_PEX ", newPeers.size (), " new peers received");
			GetTorrentsTunnel ()->ConnectToNewPeers (m_Torrent, newPeers);
		}
	}

	void PeerConnection::HandleI2PDHTExtension (const uint8_t * buf, size_t len)
	{
		uint16_t port = 0; // rport is always port + 1
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&port](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "port")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l && value > 0 && value <= 65535)
						port = value;
					return l;
				}
				return 0;
			});
		if (port)
		{
			auto ident = GetRemoteIdentHash ();
			if (ident)
				GetTorrentsTunnel ()->SendDHTPingQuery (*ident, port);
		}
	}

	void PeerConnection::NotifyPEXPeers ()
	{
		auto conns = m_Torrent->GetConnections ();
		if (conns.size () > 1) // including us
		{
			std::string addedPayload;
			auto remoteIdent = GetRemoteIdentHash ();
			if (remoteIdent)
				addedPayload = CreateDictionary ({{ "added", CreateByteString (std::string_view ((const char *)remoteIdent->data (), i2p::data::IdentHash::len)) }});
			std::vector<uint8_t> hashes;
			for (auto it: conns)
			{
				auto ident = it->GetRemoteIdentHash ();
				if (ident && ident != remoteIdent)
				{
					if (!addedPayload.empty () && it->m_RemoteMsgIDI2PPEX) // connection suuprts PEX
						it->SendExtendedMsg (it->m_RemoteMsgIDI2PPEX, addedPayload);
					hashes.insert (hashes.end(), ident->data (), ident->data () + i2p::data::IdentHash::len);
				}
			}
			if (!hashes.empty ())
				SendExtendedMsg (m_RemoteMsgIDI2PPEX, CreateDictionary ({{ "added", CreateByteString (std::string_view ((const char *)hashes.data (), hashes.size ())) }}));
		}
	}

	void PeerConnection::SendDHTPortAdvertisement ()
	{
		auto [port, rport] = GetTorrentsTunnel ()->GetDHTPorts ();
		SendExtendedMsg (m_RemoteMsgIDI2PDHT, CreateDictionary ({{ "port", CreateInteger (port) }, { "rport", CreateInteger (rport) }}));
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
		if (m_NumRequests >= m_MaxNumRequests) return false;
		std::vector<uint8_t> buf;
		buf.reserve (REQUEST_MSG_LENGTH*(m_MaxNumRequests - m_NumRequests));
		size_t bufOffset = 0;
		while (m_NumRequests < m_MaxNumRequests)
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

	std::optional<i2p::data::IdentHash> PeerConnection::GetRemoteIdentHash () const
	{
		if (m_Stream)
		{
			auto ident = m_Stream->GetRemoteIdentity ();
			if (ident)
				return ident->GetIdentHash ();
		}
		return {};
	}
}
}

#endif // NO_TORRENTS
