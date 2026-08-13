/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

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
#include "ClientContext.h"
#include "Timestamp.h"
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
		if (offset + len > m_Size || !m_Blocks) return;
		if (!m_Data) m_Data = new uint8_t[m_Size];
		memcpy (m_Data + offset, block, len);
		size_t startBlock = offset/REQUEST_BLOCK_SIZE;
		auto numBlocks = GetNumBlocks (len);
		if (numBlocks > 0)
		{
			std::fill_n (m_Blocks->begin () + startBlock, numBlocks, BlockStatus::Available);
			if (std::find_if (m_Blocks->begin (), m_Blocks->end (),
				[](BlockStatus status) { return status != BlockStatus::Available; }) == m_Blocks->end ())
			{
				// all blocks are available
				LogPrint (eLogDebug, "Torrents: piece complete");
				Complete ();
			}
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

	Torrent::Torrent (std::string_view buf):
		m_Length (0), m_PieceLength (0), m_Interval (MIN_TRACKER_REQUESTS_INTERVAL),
		m_NextTrackerRequestTime (0), m_IsComplete (false),  m_Uploaded (0)
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
					if (l) m_Name = name;
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
		// calculate info hash
		SHA1 ((const uint8_t *)buf.data (), len, m_InfoHash.data ());
		return len;
	}

	size_t Torrent::ParseFiles (std::string_view buf)
	{
		m_Length = 0;
		return ParseList (buf, [this](std::string_view file)->size_t
			{
				std::string filePath; size_t fileLength = 0;
				auto len = ParseDictionary (file, [this, &filePath, &fileLength](std::string_view key, std::string_view value)->size_t
					{
						if (key == "path")
						{
							auto [subdirs, l] = ParseStringList (value);
							if (l) filePath = i2p::fs::CreatePath (subdirs);
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

	void Torrent::ParseTrackerResponse (std::string_view buf)
	{
		ParseDictionary (buf, [this](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "interval")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l)
					{
						m_Interval = std::max (MIN_TRACKER_REQUESTS_INTERVAL, (int)value*1000); // in milliseconds
						m_NextTrackerRequestTime = i2p::util::GetMonotonicMilliseconds () + m_Interval; // reset next request
					}
					return l;
				}
				else if (key == "peers")
					return ParsePeers (buf);
				else if (key == "Failure Reason")
				{
					auto [reason, l] = ExtractByteString (buf);
					LogPrint (eLogError, "Torrents: Tracker error: ", reason);
					return l;
				}
				return 0;
			});
	}

	size_t Torrent::ParsePeers (std::string_view buf)
	{
		m_Peers.clear ();
		auto [hashes, len] = ExtractByteString (buf);
		while (!hashes.empty ())
		{
			m_Peers.emplace (i2p::data::IdentHash ((const uint8_t *)hashes.substr (0, i2p::data::IdentHash::len).data ()));
			hashes = hashes.substr (i2p::data::IdentHash::len);
		}
		return len;
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

	std::tuple<uint32_t, uint32_t, uint32_t> Torrent::GetNextBlockToRequest (std::shared_ptr<PeerConnection> conn)
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
				if (!it.IsComplete () && conn->IsPieceAvailable (ind) && !it.IsRequested ())
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
		for (auto& it: m_Pieces)
			if (!it.IsComplete ())
				it.Complete ();
		m_IsComplete = true;
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

	PeerConnection::PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream):
		i2p::client::I2PServiceHandler (owner), m_Stream (stream), m_ReceiveBufferOffset (0),
		m_IsHandshakeSent (false), m_IsEstablished (false), m_IsChoked (true), m_IsRemoteChoked (true),
		m_LastReceiveTime (0), m_LastSendTime (0), m_NumRequests (0), m_NumPieces (0),
		 m_LastRequestedPieceIndex (-1)
	{
	}

	PeerConnection::PeerConnection (i2p::client::I2PService * owner,
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

	TorrentsTunnel * PeerConnection::GetTorrentsTunnel () const
	{
		return static_cast<TorrentsTunnel *>(GetOwner ());
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
				// send keep-alive
				uint32_t len = 0;
				WriteToStream ((const uint8_t *)&len, 4);
				m_LastSendTime = ts;
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
					PEER_CONNECTION_MAX_IDLE);
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
				LogPrint (eLogError, "Torrents: Stream read error: ", ecode.message ());
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
				m_ReceiveBufferOffset = 0;
		}
	}

	size_t PeerConnection::HandleNextMsg (size_t offset)
	{
		if (offset >= m_ReceiveBufferOffset) return 0;
		if (!m_IsEstablished)
			return HandleHandshakeMsg ();
		// regular messages
		size_t len = m_ReceiveBufferOffset - offset;
		if (len < 4) return 0;
		uint32_t msgLen = bufbe32toh (m_ReceiveBuffer + offset);
		if (len < msgLen + 4) return 0;
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
					if (m_IsRemoteChoked)
					{
						m_IsRemoteChoked = false;
						SendUnchokeMsg ();
					}
				break;
				case eMessageTypeNotInterested:
					LogPrint (eLogInfo, "Torrents: Not interested message is not implemented");
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
		m_RemotePeerID = std::string_view ((const char *)(m_ReceiveBuffer + 48), 20);
		// respond wiith handshake if incoming
		if (!m_IsHandshakeSent)
			SendHandshakeMsg ();
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
		memset (buf + 20, 0, 8);
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
		uint32_t index = bufbe32toh (buf);
		if (index < m_RemoteBitfield.size ())
		{
			m_RemoteBitfield.set (index);
			if (m_NumRequests < MAX_NUM_REQUESTS && m_Torrent && !m_Torrent->IsComplete ())
			{
				Piece& piece = m_Torrent->GetPiece (index);
				if (!piece.IsComplete () && !piece.IsRequested ())
				{
					// new piece that was not requested yet
					SendInterestedMsg ();
					if (!m_IsChoked)
					{
						auto [offset, len] = piece.GetNextBlockToRequest ();
						if (len > 0)
							SendRequestMsg (index, offset, len);
					}
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
		if (!m_Torrent) return;
		bool isInterested = false;
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
					if (!isInterested && !m_Torrent->GetPiece (idx).IsComplete ())
						isInterested = true;
				}
				bit >>= 1;
				idx++;
			}
		}
		if (isInterested)
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
		RequestNextBlocks ();
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
				}
				else
					s->Terminate ();
			});
		m_LastSendTime = i2p::util::GetMonotonicSeconds ();
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
					RequestedBlock requestBlock{index, offset, length};
					boost::asio::post (GetTorrentsTunnel ()->GetDiskIOService (),
					[requestBlock = std::move(requestBlock), torrent = m_Torrent, s = shared_from_this ()]() mutable
					{
						bool loaded = true;
						Piece& piece = torrent->GetPiece (requestBlock.index);
						if (!piece.GetData ()) // don't try to load if already loaded
						{
							auto fragments = torrent->GetPieceFileFragments (requestBlock.index);
							piece.SetIsSending (true);
							for (auto& it: fragments)
							{
								if (!piece.Load (std::move (it)))
									loaded = false;
							}
							if (loaded && !piece.VerifyHash ())
							{
								LogPrint (eLogError, "Torrent: Corrupted piece ", requestBlock.index);
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
							LogPrint (eLogError, "Torrent: Failed to load piece ", requestBlock.index);
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
		Piece& piece = m_Torrent->GetPiece (requestedBlock.index);
		piece.SetIsSending (true);
		auto data = piece.GetData ();
		if (data && piece.HasBlock (requestedBlock.offset))
			SendPieceMsg (requestedBlock.index, requestedBlock.offset, data + requestedBlock.offset, requestedBlock.length);
		else
			ret = false;
		piece.SetIsSending (false);
		return ret;
	}

	void PeerConnection::SendRequestMsg (uint32_t index, uint32_t offset, uint32_t len)
	{
		uint8_t buf[REQUEST_MSG_PAYLOAD_LENGTH + 5];
		htobe32buf (buf, REQUEST_MSG_PAYLOAD_LENGTH + 1); // msg length
		buf[4] = eMessageTypeRequest; // msg ID
		htobe32buf (buf + 5, index); // index
		htobe32buf (buf + 9, offset); // offset
		htobe32buf (buf + 13, len); // length
		WriteToStream (buf, REQUEST_MSG_PAYLOAD_LENGTH + 5);
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

	bool PeerConnection::RequestNextBlock ()
	{
		if (!m_Torrent) return false;
		auto [index, offset, len] = m_Torrent->GetNextBlockToRequest (shared_from_this ());
		if (len > 0)
		{
			m_LastRequestedPieceIndex = index;
			SendRequestMsg (index, offset, len);
			m_NumRequests++;
		}
		else if (m_LastRequestedPieceIndex >= 0)
		{
			m_LastRequestedPieceIndex = -1; // no request
			SendNotinterestedMsg ();
		}
		return len > 0;
	}

	void PeerConnection::RequestNextBlocks ()
	{
		if (m_IsChoked || !m_Torrent || m_Torrent->IsComplete ()) return;
		while (m_NumRequests < MAX_NUM_REQUESTS)
		{
			if (!RequestNextBlock ()) break;
		}
	}

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
		Accept ();

		if (!m_TorrentsDir.empty() && std::filesystem::exists (m_TorrentsDir) &&
			std::filesystem::is_directory (m_TorrentsDir))
		{
			for (const auto& it: std::filesystem::directory_iterator (m_TorrentsDir))
				if (std::filesystem::is_regular_file (it.status()) && it.path ().extension () == "torrent")
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
			localDestination->StopAcceptingStreams ();
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
				auto torrent = std::make_shared<Torrent>(std::string_view{buf, len});
				delete[] buf;
				torrent->SetFullPath (m_TorrentsDir / std::filesystem::path (torrent->GetName ()));
				m_Torrents.emplace (torrent->GetInfoHash (), torrent);
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
						filePath = std::filesystem::path (torrent->GetName ())/filePath;
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
				if (std::filesystem::exists (resumeFilePath ))
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
			else
				LogPrint (eLogError, "Torrents: Empty file ", torrentFilePath);
		}
		else
			LogPrint (eLogError, "Torrents: Can't open file ", torrentFilePath);
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
				LogPrint (eLogError, "FS: Can't create subdirs ", subdirs, " : ", ex.what());
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
				LogPrint (eLogError, "FS: Can't resize file ", filePath, " to ", reserve, " : ", ex.what());
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
					LogPrint (eLogError, "Torrents: Can't rename ", partFilePath);
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
						LogPrint (eLogError, "Torrents: Can't rename ", partFilePath);
					}
				}
			}
			if (completed)
			{
				torrent->SetComplete ();
				RequestTracker (torrent, "completed");
				auto resumeFilePath = torrent->GetFullPath (); resumeFilePath += ".resume";
				if (!std::filesystem::remove (resumeFilePath))
					LogPrint (eLogError, "Torrents: Can't delete resume file ", resumeFilePath);
				LogPrint (eLogInfo, "Torrents: Download complete ", torrent->GetFullPath ());
				// close connections with seeds
				auto conns = GetTorrentConnections (torrent);
				for (auto it: conns)
					if (it->GetRemoteBitfield ().all ()) // seed
						it->Close ();
			}
		});
	}

	std::shared_ptr<Torrent> TorrentsTunnel::FindTorrent (const Torrent::InfoHash& infoHash) const
	{
		auto it = m_Torrents.find (infoHash);
		if (it != m_Torrents.end ())
			return it->second;
		return nullptr;
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
							auto conn = std::make_shared<PeerConnection> (this, stream);
							AddHandler (conn);
							conn->ReceiveHandshake ();
						}
					});
		}
		else
			LogPrint (eLogError, "Torrents: Local destination not set");
	}

	void TorrentsTunnel::RequestTracker (std::shared_ptr<Torrent> torrent, std::string_view event)
	{
		if (!torrent) return;
		i2p::http::URL reqURL;
		if (!m_Trackers.empty())
			reqURL.parse (m_Trackers.front ());
		else
			reqURL.parse (torrent->GetAnnounce ());
#if __cplusplus >= 202002L // C++20
		if (!reqURL.host.ends_with (".i2p"))
#else
		if (reqURL.host.find(".i2p") == reqURL.host.npos)
#endif
		{
			LogPrint (eLogWarning, "Torrents: Non-I2P address ", reqURL.host, " for torrent ", torrent->GetName ());
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
		params.emplace ("numwant", torrent->IsComplete () ? "0" : "25"); // max num of peers, 0 if seeding
		if (!event.empty ())
			params.emplace ("event", event);
		reqURL.create_query (params);

		auto req = std::make_shared<boost::beast::http::request<boost::beast::http::string_body> >(boost::beast::http::verb::get, reqURL.to_string (true), 11); // HTTP 1.1
		req->set (boost::beast::http::field::host, reqURL.host);
		req->set (boost::beast::http::field::user_agent, "I2PSocketEepGet");
		req->keep_alive (false); // Connection: close
		CreateStream ([this, req, torrent](std::shared_ptr<i2p::stream::Stream> stream)
			{
				if (stream)
				{
					auto httpStream = std::make_shared<i2p::client::BoostAsyncStream>(stream);
					boost::beast::http::async_write (*httpStream, *req,
						std::bind (&TorrentsTunnel::TrackerRequestSent, this, std::placeholders::_1, std::placeholders::_2, httpStream, torrent, req));
				}
			}, reqURL.host, reqURL.port);
	}

	void TorrentsTunnel::TrackerRequestSent (const boost::beast::error_code& ecode, size_t bytes_transferred,
		std::shared_ptr<i2p::client::BoostAsyncStream> httpStream, std::shared_ptr<Torrent> torrent,
		std::shared_ptr<boost::beast::http::request<boost::beast::http::string_body> > req)
	{
		if (!ecode)
		{
			// receive
			auto buf = std::make_shared<boost::beast::flat_buffer> ();
			auto res = std::make_shared<boost::beast::http::response<boost::beast::http::string_body> >();
			boost::beast::http::async_read (*httpStream, *buf, *res,
				[this, httpStream, torrent, buf, res](const boost::beast::error_code& ecode, size_t bytes_transferred)
				{
					httpStream->GetStream ()->AsyncClose ();
					if (!ecode)
					{
						if (res->result () == boost::beast::http::status::ok)
						{
							torrent->ParseTrackerResponse (res->body ());
							ConnectToPeers (torrent);
							ScheduleReconnectCheck ();
						}
						else
							LogPrint (eLogWarning, "Torrents: Tracker response code ", res->result_int());
					}
				});
		}
	}

	void TorrentsTunnel::ConnectToPeer (std::shared_ptr<Torrent> torrent, const i2p::data::IdentHash& peer)
	{
		if (!torrent) return;
		LogPrint (eLogDebug, "Torrents: Connecting to peer ", peer.ToBase32 () + ".b32.i2p");
		CreateStream ([this, torrent, peer](std::shared_ptr<i2p::stream::Stream> stream)
			{
				if (stream)
				{
					LogPrint (eLogDebug, "Torrents: Connected to peer ", peer.ToBase32 () + ".b32.i2p");
					auto connection = std::make_shared<PeerConnection>(this, stream, torrent);
					AddHandler (connection);
					connection->Connect ();
				}
				else
					LogPrint (eLogInfo, "Torrents: Can't connect to peer ", peer.ToBase32 () + ".b32.i2p");
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
			for (auto it: m_Torrents)
				if (ts > it.second->GetNextTrackerRequestTime ())
				{
					auto nextInterval = it.second->GetInterval () + GetLocalDestination ()->GetRng()() % TRACKER_REQUESTS_INTERVAL_VARIANCE;
					it.second->SetNextTrackerRequestTime (ts + nextInterval);
					RequestTracker (it.second);
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
				if (!it.second->IsComplete ())
				{
					auto numPeers = ConnectToPeers (it.second);
					if (numPeers)
						LogPrint (eLogDebug, "Torrents: Reconnecting to ", numPeers, " peers");
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
				if (!it.second->IsComplete ())
				{
					if (it.second->UpdateStatus (ts))
						CompleteTorrent (it.second);
					else
						UpdatePeersPerPiece (it.second);
				}
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
						if (conn->GetTorrent () == torrent)
						{
							auto ident = conn->GetStream ()->GetRemoteIdentity ();
							if (ident)
							{
#if __cplusplus >= 202002L // C++20
								if (torrent->GetPeers ().contains (ident->GetIdentHash ()))
#else
								if (torrent->GetPeers ().count (ident->GetIdentHash ()) > 0)
#endif
									ret.emplace_back (conn);
							}
						}
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
							if (conn->GetTorrent () == torrent)
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
}
}
