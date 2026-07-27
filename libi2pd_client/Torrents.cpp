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
#include <boost/algorithm/string.hpp>
#include "Log.h"
#include "FS.h"
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
			case 'i': // interger
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

//------------------------------------

	Piece::Piece (size_t size, const uint8_t * hash):
		m_Size (size), m_Data (nullptr), m_Blocks (GetNumBlocks (size))
	{
		memcpy (m_Hash, hash, SHA_DIGEST_LENGTH);
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
		if (m_Blocks.empty ()) return true;
		if (block < 0 || block >= (int)m_Blocks.size ()) return false;
		return m_Blocks.test (block);
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
		if (offset + len >= m_Size) return;
		if (!m_Data) m_Data = new uint8_t[m_Size];
		memcpy (m_Data + offset, block, len);
		size_t startBlock = offset/REQUEST_BLOCK_SIZE;
		auto numBlocks = GetNumBlocks (len);
		for (size_t i = 0; i < numBlocks; i++)
			m_Blocks.set (startBlock + i);
	}

	void Piece::Dump (const std::string& fullPath, size_t offset)
	{
		if (!m_Data) return;
		// TODO: file I/O must be in separate thread
		std::ofstream f(fullPath, std::ofstream::binary | std::ofstream::app);
		if (f.is_open ())
		{
			f.seekp (offset, std::ios::beg);
			f.write ((const char *)m_Data, m_Size);
			delete[] m_Data; m_Data = nullptr;
			m_Blocks.resize (0);
			m_Connections.clear ();
		}
	}

	void Piece::Load (const std::string& fullPath, size_t offset)
	{
		if (m_Data) return;
		// TODO: file I/O must be in separate thread
		m_Data = new uint8_t[m_Size];
		std::ifstream f(fullPath, std::ifstream::binary);
		if (f.is_open ())
		{
			f.seekg (offset, std::ios::beg);
			f.read ((char *)m_Data, m_Size);
		}
	}

	std::pair<size_t, size_t> Piece::GetAvailableBuffer (size_t offset, size_t len) const
	{
		size_t block = offset/REQUEST_BLOCK_SIZE;
		auto numBlocks = GetNumBlocks (len);
		size_t ind = 0;
		while (ind < numBlocks)
		{
			if (!IsAvailable (block + ind)) break;
			ind++;
		}
		if (ind > 0)
		{
			if (offset + ind*REQUEST_BLOCK_SIZE > m_Size)
				return { offset, m_Size - offset };
			else
				return { offset, ind*REQUEST_BLOCK_SIZE };
		}
		return { 0, 0 };
	}

	void Piece::AddConnection (std::shared_ptr<PeerConnection> connection)
	{
		m_Connections.emplace_back (connection);
	}

	void Piece::RemoveConnection (std::shared_ptr<PeerConnection> connection)
	{
		m_Connections.remove_if ([connection](std::weak_ptr<PeerConnection> c) { return c.lock () == connection; });
	}

	Torrent::Torrent (std::string_view buf):
		m_Length (0), m_PieceLength (0), m_Interval (MIN_TRACKER_REQUESTS_INTERVAL),
		m_NextTrackerRequestTime (0)
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
		while (!hashes.empty ())
		{
			m_Pieces.emplace_back (m_PieceLength, (const uint8_t *)hashes.substr (0, SHA_DIGEST_LENGTH).data ());
			hashes = hashes.substr (SHA_DIGEST_LENGTH);
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
				return 0;
			});
		if (!len) return 0;
		// calculate info hash
		SHA1 ((const uint8_t *)buf.data (), len, m_InfoHash.data ());
		return len;
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

	void Torrent::ParseTrackerResponse (std::string_view buf)
	{
		ParseDictionary (buf, [this](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "interval")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l) m_Interval = std::max (MIN_TRACKER_REQUESTS_INTERVAL, (int)value*1000); // in milliseconds
					return l;
				}
				else if (key == "peers")
					return ParsePeers (buf);
				return 0;
			});
	}

	size_t Torrent::ParsePeers (std::string_view buf)
	{
		m_Peers.clear ();
		auto [hashes, len] = ExtractByteString (buf);
		while (!hashes.empty ())
		{
			m_Peers.emplace_back (std::make_shared<const i2p::client::Address>(
				i2p::data::IdentHash((const uint8_t *)hashes.substr (0, i2p::data::IdentHash::len).data ())));
			hashes = hashes.substr (i2p::data::IdentHash::len);
		}
		return len;
	}

	std::vector<uint8_t> Torrent::CreateBitfield () const
	{
		size_t numPieces = m_Pieces.size ();
		size_t bitfieldSize = numPieces / 8;
		if (numPieces % 8) bitfieldSize++;
		std::vector<uint8_t> ret(bitfieldSize); // filled with 0
		size_t idx = 0;
		for (size_t i = 0; i < ret.size (); i++) // bytes
		{
			uint8_t bit = 0x80;
			for (int j = 0; j < 8; j++)
			{
				if (idx >= numPieces) break;
				if (m_Pieces[idx].IsComplete ())
					ret[i] |= bit;
				bit >>= 1;
				idx++;
			}
		}
		return ret;
	}

	PeerConnection::PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream):
		i2p::client::I2PServiceHandler (owner), m_Stream (stream), m_ReceiveBufferOffset (0),
		m_IsHandshakeSent (false), m_IsEstablished (false), m_LastReceiveTime (0), m_LastSendTime (0)
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
		if (m_Stream)
		{
			m_Stream->Close ();
			m_Stream = nullptr;
		}
		Done(shared_from_this ());
	}

	TorrentsTunnel * PeerConnection::GetTorrentsTunnel () const
	{
		return static_cast<TorrentsTunnel *>(GetOwner ());
	}

	void PeerConnection::WriteToStream (const uint8_t * buf, size_t len)
	{
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
	}

	void PeerConnection::ReceiveHandshake ()
	{
		StreamReceive ();
	}

	void PeerConnection::CheckKeepAlive (uint64_t ts)
	{
		if (ts > m_LastSendTime)
		{
			// send keep-alive
			uint32_t len = 0;
			WriteToStream ((const uint8_t *)&len, 4);
			m_LastSendTime = ts;
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
		if (offset && offset < m_ReceiveBufferOffset)
		{
			// move remaining data
			m_ReceiveBufferOffset -= offset;
			memmove (m_ReceiveBuffer, m_ReceiveBuffer + offset, m_ReceiveBufferOffset);
		}
		else
			m_ReceiveBufferOffset = 0;
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
			switch (m_ReceiveBuffer[offset])
			{
				case eMessageTypeHave:
					HandleHaveMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeBitfield:
					HandleBitfieldMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeRequest:
					HandleRequestMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypePiece:
					HandlePieceMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
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
			LogPrint (eLogInfo, "Torrents: Keep-alieve received");
		return msgLen + 4;
	}

	size_t PeerConnection::HandleHandshakeMsg ()
	{
		if (m_ReceiveBufferOffset < HANDSHAKE_MSG_LENGTH) return 0;
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
		auto bitfield = m_Torrent->CreateBitfield ();
		if (bitfield.size ())
			SendBitfieldMsg (bitfield.data (), bitfield.size ());
		m_IsEstablished = true;
		return HANDSHAKE_MSG_LENGTH;
	}

	void PeerConnection::SendHandshakeMsg ()
	{
		if (!m_Torrent || !m_Stream || !m_Stream->IsOpen ()) return;
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
			m_RemoteBitfield.set (index);
	}

	void PeerConnection::HandleBitfieldMsg (const uint8_t * buf, size_t len)
	{
		if (!m_Torrent) return;
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
					m_Torrent->GetPiece (idx).AddConnection (shared_from_this ());
				}
				bit >>= 1;
				idx++;
			}
		}
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
		for (size_t i = 0; i < numPieces; i++)
		{
			Piece& piece = m_Torrent->GetPiece (i);
			if (!piece.IsComplete ())
				piece.AddConnection (shared_from_this ());
		}
	}

	void PeerConnection::HandleHaveNoneMsg ()
	{
		if (!m_Torrent) return;
		size_t numPieces = m_Torrent->GetNumPieces ();
		m_RemoteBitfield.resize (numPieces);
		m_RemoteBitfield.reset ();
		for (size_t i = 0; i < numPieces; i++)
		{
			Piece& piece = m_Torrent->GetPiece (i);
			if (!piece.IsComplete ())
				piece.RemoveConnection (shared_from_this ());
		}
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
			if (piece.IsComplete () && piece.VerifyHash ())
				piece.Dump (GetTorrentsTunnel ()->GetTorrentFilePath (m_Torrent->GetName ()),
					index*m_Torrent->GetPieceLength ());
		}
	}

	void PeerConnection::SendPieceMsg (uint32_t index, uint32_t offset, const uint8_t * data, size_t len)
	{
		std::vector<uint8_t> sendBuffer(len + 8 + 5);
		htobe32buf (sendBuffer.data (), len + 8 + 1); // length
		sendBuffer[4] = eMessageTypePiece; // msg ID
		htobe32buf (sendBuffer.data () + 5, index);
		htobe32buf (sendBuffer.data () + 9, offset);
		memcpy (sendBuffer.data () + 13, data, len);
		WriteToStream (sendBuffer.data (), sendBuffer.size ());
	}

	void PeerConnection::HandleRequestMsg (const uint8_t * buf, size_t len)
	{
		if (len != REQUEST_MSG_PAYLOAD_LENGTH)
		{
			LogPrint (eLogWarning, "Torrents: Unexpected length of request message ", len);
			return;
		}
		uint32_t index = bufbe32toh (buf);
		uint32_t offset = bufbe32toh (buf + 4);
		uint32_t length = bufbe32toh (buf + 8);
		if (index < m_Torrent->GetNumPieces ())
		{
			Piece& piece = m_Torrent->GetPiece (index);
			auto [availableOffset, availableLen] = piece.GetAvailableBuffer (offset, length);
			if (availableLen)
			{
				auto data = piece.GetData ();
				if (!data)
				{
					// try to load from file
					piece.Load (GetTorrentsTunnel ()->GetTorrentFilePath (m_Torrent->GetName ()),
						index*m_Torrent->GetPieceLength ());
					data = piece.GetData ();
				}
				if (data)
					SendPieceMsg (index, availableOffset, data + availableOffset, availableLen);
			}
		}
	}

	void PeerConnection::RequestPiece (uint32_t index)
	{
		if (!m_Torrent) return;
		std::vector<uint8_t> sendBuffer (REQUEST_MSG_PAYLOAD_LENGTH + 5);
		htobe32buf (sendBuffer.data (), REQUEST_MSG_PAYLOAD_LENGTH + 1); // msg length
		sendBuffer[4] = eMessageTypeRequest; // msg ID
		htobe32buf (sendBuffer.data () + 5, index); // index
		memset (sendBuffer.data () + 9, 0, 4); // offset
		htobe32buf (sendBuffer.data () + 13, m_Torrent->GetPieceLength ()); // length
		WriteToStream (sendBuffer.data (), sendBuffer.size ());
	}

	TorrentsTunnel::TorrentsTunnel (std::shared_ptr<i2p::client::ClientDestination> localDestination,
		std::string_view torrentsDir, std::string_view trackers):
		i2p::client::I2PService (localDestination), m_TorrentsDir (torrentsDir),
		m_PeerID ("-I2PD-"), m_Rng(i2p::util::GetMonotonicMicroseconds ()%1000000LL),
		m_TrackerRequestsCheckTimer (GetService ()), m_KeepAliveCheckTimer (GetService ())
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
		Accept ();

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
		ScheduleTrackerRequestsCheck ();
		ScheduleKeepAliveCheck ();
	}

	void TorrentsTunnel::Stop ()
	{
		m_TrackerRequestsCheckTimer.cancel ();
		m_KeepAliveCheckTimer.cancel ();
		m_Torrents.clear ();
		for (auto it: m_Torrents)
			SaveTorrentResumeFile (it.second);
		i2p::client::I2PService::Stop ();
	}

	void TorrentsTunnel::ReadTorrentFile (const std::string& path)
	{
		std::ifstream s(path, std::ifstream::binary);
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
				m_Torrents.emplace (torrent->GetInfoHash (), torrent);
				i2p::fs::CreateAndReserveFile (GetTorrentFilePath (torrent->GetName ()), torrent->GetLength ());
			}
			else
				LogPrint (eLogError, "Torrents: Empty file ", path);
		}
		else
			LogPrint (eLogError, "Torrents: Can't open file ", path);
	}

	void TorrentsTunnel::SaveTorrentResumeFile (std::shared_ptr<const Torrent> torrent)
	{
		if (!torrent) return;
		auto bitfield = torrent->CreateBitfield ();
		if (!bitfield.size ()) return;
		std::ofstream f(GetTorrentFilePath (torrent->GetName ()) + ".resume", std::ofstream::binary);
		if (f.is_open ())
			f.write ((const char *)bitfield.data (), bitfield.size ());
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

	void TorrentsTunnel::RequestTracker (std::shared_ptr<Torrent> torrent)
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
		params.emplace ("ip", GetLocalDestination ()->GetIdentity ()->ToBase64 ());
		params.emplace ("port", std::to_string (6881));
		params.emplace ("compact", "1");
		params.emplace ("uploaded", "0"); // TODO
		params.emplace ("downloaded", "0"); // TODO
		params.emplace ("left", "1"); // TODO
		params.emplace ("numwant", "25"); // max num of peers, 0 if seeding
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
				[httpStream, torrent, buf, res](const boost::beast::error_code& ecode, size_t bytes_transferred)
				{
					if (!ecode)
					{
						if (res->result () == boost::beast::http::status::ok)
							torrent->ParseTrackerResponse (res->body ());
						else
							LogPrint (eLogWarning, "Torrents: Tracker response code ", res->result_int());
					}
				});
		}
	}

	void TorrentsTunnel::ConnectToPeer (std::shared_ptr<Torrent> torrent,
		std::shared_ptr<const i2p::client::Address> peer)
	{
		if (!torrent && !peer) return;
		CreateStream ([this, torrent](std::shared_ptr<i2p::stream::Stream> stream)
			{
				if (stream)
				{
					auto connection = std::make_shared<PeerConnection>(this, stream, torrent);
					AddHandler (connection);
					connection->Connect ();
				}
				else
					LogPrint (eLogInfo, "Torrents: Can't connect to peer");
			}, peer, 6881);
	}

	std::string TorrentsTunnel::GetTorrentFilePath (const std::string& filename) const
	{
		std::stringstream s("");
		s << m_TorrentsDir;
		i2p::fs::_ExpandPath(s, filename);
		return s.str ();
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
					it.second->SetNextTrackerRequestTime (ts + it.second->GetInterval () + m_Rng () % TRACKER_REQUESTS_INTERVAL_VARIANCE);
					RequestTracker (it.second);
				}
			ScheduleTrackerRequestsCheck ();
		}
	}

	void TorrentsTunnel::ScheduleKeepAliveCheck ()
	{
		m_KeepAliveCheckTimer.expires_after (std::chrono::seconds(PEER_KEEP_ALIVE_CHECK_TIMEOUT));
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
}
}
