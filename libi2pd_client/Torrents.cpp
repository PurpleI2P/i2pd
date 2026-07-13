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
#include <sstream>
#include <functional>
#include "Log.h"
#include "FS.h"
#include "I2PEndian.h"
#include "ClientContext.h"
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
		m_Size (size), m_Data (nullptr)
	{
		//m_Data = m_Size > 0 ? new uint8_t[m_Size] : nullptr;
		memcpy (m_Hash, hash, SHA_DIGEST_LENGTH);
		m_Missing = BN_new ();
		auto d = lldiv (m_Size, REQUEST_BLOCK_SIZE);
		int numBlocks = d.quot;
		if (d.rem > 0) numBlocks++;
		// set all missing bits
		for (int i = 0; i < numBlocks; i++)
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
		uint8_t digest[SHA_DIGEST_LENGTH];
		SHA1 (m_Data, m_Size, digest);
		return !memcmp (m_Hash, digest, SHA_DIGEST_LENGTH);
	}

	bool Piece::IsAvailable (int block) const
	{
		if (!m_Missing) return true;
		if (block < 0 || block >= BN_num_bits (m_Missing)) return false;
		return !BN_is_bit_set (m_Missing, block);
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
		if (m_Missing)
		{
			size_t block = offset/REQUEST_BLOCK_SIZE;
			auto numBlocks = GetNumBlocks (len);
			for (size_t i = 0; i < numBlocks; i++)
				BN_clear_bit (m_Missing, block + i);
		}

	}

	void Piece::Dump (const std::string& fullPath, size_t offset)
	{
		if (!m_Data) return;
		// TODO: file I/O must be in separate thread
		std::ofstream f(fullPath, std::ifstream::binary);
		if (f.is_open ())
		{
			f.seekp (offset, std::ios::beg);
			f.write ((const char *)m_Data, m_Size);
			delete[] m_Data; m_Data = nullptr;
			if (m_Missing) BN_free (m_Missing);
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

	Torrent::Torrent (std::string_view buf):
		m_Length (0), m_PieceLength (0), m_Interval (0)
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

	std::string Torrent::GetHexStraingInfoHash () const
	{
		std::string infoHash;
		BIGNUM * bn = BN_bin2bn (m_InfoHash.data (), SHA_DIGEST_LENGTH, nullptr);
		char * str = BN_bn2hex (bn);
		if (str)
		{
			infoHash = str;
			OPENSSL_free (str);
		}
		BN_free (bn);
		return infoHash;
	}

	i2p::http::HTTPReq Torrent::GetTrackerRequest () const
	{
		i2p::http::HTTPReq req;
		req.parse (m_Announce);
		req.AddHeader ("info_hash", GetHexStraingInfoHash ());
		return req;
	}

	void Torrent::ParseTrackerResponse (std::string_view buf)
	{
		ParseDictionary (buf, [this](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "interval")
				{
					auto [value, l] = ExtractInteger (buf);
					if (l) m_Interval = value;
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
		return ParseList (buf, std::bind (&Torrent::ParsePeer, this, std::placeholders::_1));
	}

	size_t Torrent::ParsePeer (std::string_view buf)
	{
		std::string peerID;
		std::shared_ptr<const i2p::client::Address> addr;
		size_t ret = ParseDictionary (buf, [&peerID, &addr](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "id") // peer_id
				{
					auto [id, l] = ExtractByteString (buf);
					if (l) peerID = id;
					return l;
				}
				else if (key == "ip") // address
				{
					auto [address, l] = ExtractByteString (buf);
					if (l) addr = i2p::client::context.GetAddressBook ().GetAddress (address);
					return l;
				}
				return 0;
			});
		if (ret	&& addr)
			m_Peers.emplace_back (std::pair{ peerID, addr });
		return ret;
	}

	PeerConnection::PeerConnection (i2p::client::I2PService * owner,  std::shared_ptr<i2p::stream::Stream> stream):
		i2p::client::I2PServiceHandler (owner), m_Stream (stream), m_ReceiveBufferOffset (0),
		m_RemoteBitfield (nullptr), m_IsHandshakeSent (false), m_IsEstablished (false)
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
		if (m_RemoteBitfield) BN_free (m_RemoteBitfield);
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
			[s = shared_from_this ()](const boost::system::error_code& ecode)
			{
				if (ecode) s->Terminate ();
			});
	}

	void PeerConnection::Connect ()
	{
		SendHandshakeMsg ();
	}

	void PeerConnection::ReceiveHandshake ()
	{
		StreamReceive ();
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
		size_t offset = 0;
		while (size_t len = HandleNextMsg (offset) > 0)
			offset += len;
		if (offset && offset < m_ReceiveBufferOffset)
		{
			// move reamining data
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
				case eMessageTypeBitfield:
					HandleBitfieldMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypeRequest:
					HandleRequestMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				case eMessageTypePiece:
					HandlePieceMsg (m_ReceiveBuffer + offset + 1, msgLen - 1);
				break;
				default:
					LogPrint (eLogWarning, "Torrents: Unexpected message type ", (int)m_ReceiveBuffer[offset], ". Ignored");
			};
		}
		else
			LogPrint (eLogError, "Torrents: Message length is zero");
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
		if (!m_IsHandshakeSent)
			SendHandshakeMsg ();
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

	void PeerConnection::HandleBitfieldMsg (const uint8_t * buf, size_t len)
	{
		if (m_RemoteBitfield) BN_free (m_RemoteBitfield);
		m_RemoteBitfield = BN_bin2bn (buf, len, nullptr);
		auto rem = m_Torrent->GetNumPieces () % 8;
		if (rem > 0)
		{
			BIGNUM * newBitfield = BN_new ();
			BN_rshift (newBitfield, m_RemoteBitfield, 8 - rem);
			BN_free (m_RemoteBitfield);
			m_RemoteBitfield = newBitfield;
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
		htobe32buf (sendBuffer.data (), len + 8); // length
		sendBuffer[4] = eMessageTypePiece; // msg ID
		htobe32buf (sendBuffer.data () + 5, index);
		htobe32buf (sendBuffer.data () + 9, offset);
		memcpy (sendBuffer.data () + 9, data, len);
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

	TorrentsTunnel::TorrentsTunnel (std::shared_ptr<i2p::client::ClientDestination> localDestination, std::string_view torrentsDir):
		i2p::client::I2PService (localDestination), m_TorrentsDir (torrentsDir),
		m_PeerID ("-I2PD-")
	{
		if (localDestination)
			m_PeerID += localDestination->GetIdentHash ().ToBase64 ();
		m_PeerID.resize (20, '0');
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
	}

	void TorrentsTunnel::Stop ()
	{
		m_Torrents.clear ();
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
		i2p::http::HTTPReq req = torrent->GetTrackerRequest ();
		i2p::http::URL reqURL;
		reqURL.parse (req.uri);
#if __cplusplus >= 202002L // C++20
		if (!reqURL.host.ends_with (".i2p"))
#else
		if (reqURL.host.find(".i2p") == reqURL.host.npos)
#endif
		{
			LogPrint (eLogWarning, "Torrents: Non-I2P address ", reqURL.host, " for torrent ", torrent->GetName ());
			return;
		}
		req.AddHeader ("peer_id", m_PeerID);
		req.AddHeader ("ip", GetLocalDestination ()->GetIdentHash ().ToBase32 () + ".b32.i2p");
		req.AddHeader ("port", std::to_string (6881));
		req.AddHeader ("uploaded", "0"); // TODO
		req.AddHeader ("downloaded", "0"); // TODO
		req.AddHeader ("left", "1"); // TODO
		req.AddHeader ("compact", "1"); // TODO
		req.AddHeader ("numwant", "0"); // TODO
		CreateStream ([this, req, torrent](std::shared_ptr<i2p::stream::Stream> stream)
			{
				if (stream)
				{
					auto reqStr = req.to_string ();
					stream->Send ((const uint8_t *)reqStr.data (), reqStr.length ());
					ReceiveFromTracker (stream, torrent, std::make_shared<TrackerResponseBuffer>(), 0);
				}
			}, reqURL.host, reqURL.port);
	}

	void TorrentsTunnel::ReceiveFromTracker (std::shared_ptr<i2p::stream::Stream> stream,
		std::shared_ptr<Torrent> torrent, std::shared_ptr<TrackerResponseBuffer> buf, size_t offset)
	{
		if (!stream || !buf) return;
		if (stream->GetStatus () == i2p::stream::eStreamStatusNew ||
			stream->GetStatus () == i2p::stream::eStreamStatusOpen) // regular
		{
			stream->AsyncReceive (boost::asio::buffer (buf->data() + offset, TRACKER_RESPONSE_BUFFER_SIZE - offset),
				[this, stream, torrent, buf, offset](const boost::system::error_code& ecode, size_t bytes_transferred)
				{
					if (ecode)
					{
						if (ecode != boost::asio::error::operation_aborted && bytes_transferred > 0)
							HandleTrackerResponse (torrent, buf, offset + bytes_transferred);
						stream->Close ();
					}
					else
					{
						size_t offset1 = offset + bytes_transferred;
						if (stream->IsOpen () && offset1 < TRACKER_RESPONSE_BUFFER_SIZE)
							ReceiveFromTracker (stream, torrent, buf, offset1);
						else
							HandleTrackerResponse (torrent, buf, offset1);
					}
				}, TRACKER_RESPONSE_TIMEOUT);
		}
		else // closed by peer
		{
			// get remaining data
			auto len = stream->ReadSome (buf->data() + offset, TRACKER_RESPONSE_BUFFER_SIZE - offset);
			if (len > 0) // still some data
			{
				offset += len;
				HandleTrackerResponse (torrent, buf, offset);
			}
			else // no more data
				stream->Close ();
		}
	}

	void TorrentsTunnel::HandleTrackerResponse (std::shared_ptr<Torrent> torrent,
		std::shared_ptr<TrackerResponseBuffer> buf, size_t len)
	{
		if (!len || !torrent) return;
		std::string_view response ((const char *)buf->data (), len);
		i2p::http::HTTPRes res;
		int headersLen = res.parse (response);
		if (headersLen <= 0)
		{
			LogPrint (eLogWarning, "Torrents: Can't parse tracker response");
			return;
		}
		if (res.code != 200)
		{
			LogPrint (eLogWarning, "Torrents: Tracker response code ", res.code);
			return;
		}
		int contentLen = res.content_length();
		if (headersLen + contentLen > (int)len)
		{
			LogPrint (eLogWarning, "Torrents: Tracker response incomplete");
			return;
		}
		torrent->ParseTrackerResponse (response.substr (headersLen, contentLen));
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
}
}
