/*
* Copyright (c) 2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <openssl/rand.h>
#include "Log.h"
#include "RouterContext.h"
#include "Transports.h"
#include "Config.h"
#include "SSU2.h"

namespace i2p
{
namespace transport
{
	static uint64_t CreateHeaderMask (const uint8_t * kh, const uint8_t * nonce)
	{
		uint64_t data = 0;
		i2p::crypto::ChaCha20 ((uint8_t *)&data, 8, kh, nonce, (uint8_t *)&data);
		return data;
	}	
	
	SSU2Session::SSU2Session (SSU2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr, bool peerTest):
		TransportSession (in_RemoteRouter, SSU2_TERMINATION_TIMEOUT),
		m_Server (server), m_Address (addr), m_DestConnID (0), m_SourceConnID (0)
	{
		m_NoiseState.reset (new i2p::crypto::NoiseSymmetricState);
		if (in_RemoteRouter && m_Address)
		{
			// outgoing
			InitNoiseXKState1 (*m_NoiseState, m_Address->s);
			m_RemoteEndpoint = boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port);
		}	
		else
		{
			// incoming
			InitNoiseXKState1 (*m_NoiseState, i2p::context.GetSSU2StaticPublicKey ());
		}		
	}
	
	SSU2Session::~SSU2Session ()
	{	
	}

	void SSU2Session::Connect ()
	{
		SendSessionRequest ();
	}	
		
	void SSU2Session::SendSessionRequest ()
	{
		// we are Alice
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		
		Header header;
		uint8_t headerX[48], payload[40]; 
		// fill packet
		RAND_bytes ((uint8_t *)&m_DestConnID, 8);
		header.h.connID = m_DestConnID; // dest id
		memset (header.h.packetNum, 0, 4);
		header.h.type = eSSU2SessionRequest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID 
		header.h.flags[2] = 0; // flag
		RAND_bytes ((uint8_t *)&m_SourceConnID, 8); 
		memcpy (headerX, &m_SourceConnID, 8); // source id
		RAND_bytes (headerX + 8, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // X
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		uint8_t paddingSize = (rand () & 0x0F) + 1; // 1 - 16
		payload[payloadSize] = eSSU2BlkPadding;
		htobe16buf (payload + payloadSize + 1, paddingSize);
		payloadSize += paddingSize + 3;
		// KDF for session request 
		m_NoiseState->MixHash ({ {header.buf, 16}, {headerX, 16} }); // h = SHA256(h || header) 
		m_NoiseState->MixHash (m_EphemeralKeys->GetPublicKey (), 32); // h = SHA256(h || aepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (m_Address->s, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// encrypt
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 12));
		i2p::crypto::ChaCha20 (headerX, 48, m_Address->i, nonce, headerX);
		m_NoiseState->MixHash (payload, 24); // h = SHA256(h || 24 byte encrypted payload from Session Request) for SessionCreated
		// send
		m_Server.AddPendingOutgoingSession (boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port), shared_from_this ());
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
	}	

	void SSU2Session::ProcessSessionRequest (uint64_t connID, uint8_t * buf, size_t len)
	{
		// we are Bob
		m_SourceConnID = connID;
		Header header;
		header.h.connID = connID;
		memcpy (header.buf + 8, buf + 8, 8);
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 12));
		if (header.h.type != eSSU2SessionRequest) 
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)header.h.type);
			return;
		}	
		const uint8_t nonce[12] = {0};
		uint8_t headerX[48];
		i2p::crypto::ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
		memcpy (&m_DestConnID, headerX, 8); 
		// KDF for session request 
		m_NoiseState->MixHash ( { {header.buf, 16}, {headerX, 16} } ); // h = SHA256(h || header) 
		m_NoiseState->MixHash (headerX + 16, 32); // h = SHA256(h || aepk);
		uint8_t sharedSecret[32];
		i2p::context.GetSSU2StaticKeys ().Agree (headerX + 16, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// decrypt
		uint8_t * payload = buf + 64;
		m_NoiseState->MixHash (payload, 24); // h = SHA256(h || 24 byte encrypted payload from Session Request) for SessionCreated
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 80, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, len - 80, false))
		{
			LogPrint (eLogWarning, "SSU2: SessionRequest AEAD verification failed ");
			return;
		}	
		// payload
		HandlePayload (payload, len - 80);
		
		m_Server.AddSession (m_SourceConnID, shared_from_this ());
		SendSessionCreated (headerX + 16);
	}	

	void SSU2Session::SendSessionCreated (const uint8_t * X)
	{
		// we are Bob
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();

		// fill packet
		Header header;
		uint8_t headerX[48], payload[64]; 
		header.h.connID = m_DestConnID; // dest id
		memset (header.h.packetNum, 0, 4);
		header.h.type = eSSU2SessionCreated;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID 
		header.h.flags[2] = 0; // flag
		memcpy (headerX, &m_SourceConnID, 8); // source id
		RAND_bytes (headerX + 8, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // Y
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (m_RemoteEndpoint, payload, 57);
		uint8_t paddingSize = rand () & 0x0F; // 0 - 15
		if (paddingSize)
		{	
			payload[payloadSize] = eSSU2BlkPadding;
			htobe16buf (payload + payloadSize + 1, paddingSize);
			payloadSize += paddingSize + 3;
		}	
		// KDF for SessionCreated
		m_NoiseState->MixHash ( { {header.buf, 16}, {headerX, 16} } ); // h = SHA256(h || header) 
		m_NoiseState->MixHash (headerX + 16, 32); // h = SHA256(h || bepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (X, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// encrypt
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), payload + (payloadSize - 24));
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessCreateHeader", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
		header.ll[1] ^= CreateHeaderMask (kh2, payload + (payloadSize - 12));
		i2p::crypto::ChaCha20 (headerX, 48, kh2, nonce, headerX);
		// send
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
	}	
		
	bool SSU2Session::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		// we are Alice
		Header header;
		header.h.connID = m_SourceConnID;
		memcpy (header.buf + 8, buf + 8, 8);
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessCreateHeader", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
		header.ll[1] ^= CreateHeaderMask (kh2, buf + (len - 12));
		if (header.h.type != eSSU2SessionCreated) 
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)header.h.type);
			return false;
		}	
		const uint8_t nonce[12] = {0};
		uint8_t headerX[48];
		i2p::crypto::ChaCha20 (buf + 16, 48, kh2, nonce, headerX);
		// KDF for SessionCreated
		m_NoiseState->MixHash ( { {header.buf, 16}, {headerX, 16} } ); // h = SHA256(h || header) 
		m_NoiseState->MixHash (headerX + 16, 32); // h = SHA256(h || bepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (headerX + 16, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// decrypt
		uint8_t * payload = buf + 64;
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 80, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, len - 80, false))
		{
			LogPrint (eLogWarning, "SSU2: SessionCreated AEAD verification failed ");
			return false;
		}	
		// payload
		HandlePayload (payload, len - 80);
		
		m_Server.AddSession (m_SourceConnID, shared_from_this ());
		
		return true;
	}	

	void SSU2Session::HandlePayload (const uint8_t * buf, size_t len)
	{
		size_t offset = 0;
		while (offset < len)
		{
			uint8_t blk = buf[offset];
			offset++;
			auto size = bufbe16toh (buf + offset);
			offset += 2;
			LogPrint (eLogDebug, "SSU2: Block type ", (int)blk, " of size ", size);
			if (size > len)
			{
				LogPrint (eLogError, "SSU2: Unexpected block length ", size);
				break;
			}
			switch (blk)
			{
				case eSSU2BlkDateTime:
					LogPrint (eLogDebug, "SSU2: Datetime");
				break;
				case eSSU2BlkOptions:
					LogPrint (eLogDebug, "SSU2: Options");
				break;
				case eSSU2BlkRouterInfo:
				break;	
				case eSSU2BlkI2NPMessage:
				break;	
				case eSSU2BlkFirstFragment:
				break;	
				case eSSU2BlkFollowOnFragment:
				break;	
				case eSSU2BlkTermination:
				break;	
				case eSSU2BlkRelayRequest:
				break;	
				case eSSU2BlkRelayResponse:
				break;	
				case eSSU2BlkRelayIntro:
				break;	
				case eSSU2BlkPeerTest:
				break;	
				case eSSU2BlkNextNonce:
				break;	
				case eSSU2BlkAck:
				break;	
				case eSSU2BlkAddress:
				{
					boost::asio::ip::udp::endpoint ep;	
					if (ExtractEndpoint (buf + offset, size, ep))
						LogPrint (eLogInfo, "SSU2: Our external address is ", ep);	
					break;
				}		
				case eSSU2BlkIntroKey:
				break;	
				case eSSU2BlkRelayTagRequest:
				break;	
				case eSSU2BlkRelayTag:
				break;	
				case eSSU2BlkNewToken:
				break;	
				case eSSU2BlkPathChallenge:
				break;	
				case eSSU2BlkPathResponse:
				break;	
				case eSSU2BlkFirstPacketNumber:
				break;	
				case eSSU2BlkPadding:
					LogPrint (eLogDebug, "SSU2: Padding");
				break;	
				default:
					LogPrint (eLogWarning, "SSU2: Unknown block type ", (int)blk);
			}	
			offset += size;
		}	
	}	

	bool SSU2Session::ExtractEndpoint (const uint8_t * buf, size_t size, boost::asio::ip::udp::endpoint& ep)
	{
		if (size < 2) return false;
		int port = bufbe16toh (buf);
		if (size == 6)
		{
			boost::asio::ip::address_v4::bytes_type bytes;
			memcpy (bytes.data (), buf + 2, 4);
			ep = boost::asio::ip::udp::endpoint (boost::asio::ip::address_v4 (bytes), port);
		}
		else if (size == 18)
		{
			boost::asio::ip::address_v6::bytes_type bytes;
			memcpy (bytes.data (), buf + 2, 16);
			ep = boost::asio::ip::udp::endpoint (boost::asio::ip::address_v6 (bytes), port);
		}
		else	
		{	
			LogPrint (eLogWarning, "SSU2: Address size ", int(size), " is not supported");
			return false;
		}	
		return true;
	}

	size_t SSU2Session::CreateAddressBlock (const boost::asio::ip::udp::endpoint& ep, uint8_t * buf, size_t len)
	{
		if (len < 9) return 0;
		buf[0] = eSSU2BlkAddress;
		htobe16buf (buf + 3, ep.port ());
		size_t size = 0;
		if (ep.address ().is_v4 ())
		{
			memcpy (buf + 5, ep.address ().to_v4 ().to_bytes ().data (), 4);
			size = 6;
		}	
		else if (ep.address ().is_v6 ())
		{
			if (len < 21) return 0;
			memcpy (buf + 5, ep.address ().to_v6 ().to_bytes ().data (), 16);
			size = 18;
		}	
		else
		{
			LogPrint (eLogWarning, "SSU2: Wrong address type ", ep.address ().to_string ());
			return 0;
		}	
		htobe16buf (buf + 1, size);
		return size + 3;	
	}	
		
	SSU2Server::SSU2Server ():
		RunnableServiceWithWork ("SSU2"), m_Socket (GetService ()), m_SocketV6 (GetService ())
	{
	}

	void SSU2Server::Start ()
	{
		if (!IsRunning ())
		{
			StartIOService ();
			auto& addresses = i2p::context.GetRouterInfo ().GetAddresses ();
			for (const auto& address: addresses)
			{
				if (!address) continue;
				if (address->transportStyle == i2p::data::RouterInfo::eTransportSSU2)
				{
					auto port = address->port;
					if (!port)
					{
						uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
						if (ssu2Port) port = ssu2Port;
						else
						{
							uint16_t p; i2p::config::GetOption ("port", p);
							if (p) port = p;
						}	
					}	
					if (port)
					{	
						if (address->IsV4 ())
							Receive (OpenSocket (boost::asio::ip::udp::endpoint (boost::asio::ip::udp::v4(), port)));
						if (address->IsV6 ())
							Receive (OpenSocket (boost::asio::ip::udp::endpoint (boost::asio::ip::udp::v6(), port)));
					}	
					else
						LogPrint (eLogError, "SSU2: Can't start server because port not specified");
				}
			}	
		}	
	}
		
	void SSU2Server::Stop ()
	{
		StopIOService ();
	}	

	boost::asio::ip::udp::socket& SSU2Server::OpenSocket (const boost::asio::ip::udp::endpoint& localEndpoint)
	{
		boost::asio::ip::udp::socket& socket = localEndpoint.address ().is_v6 () ? m_SocketV6 : m_Socket;
		try
		{
			socket.open (localEndpoint.protocol ());
			if (localEndpoint.address ().is_v6 ())
				socket.set_option (boost::asio::ip::v6_only (true));
			socket.set_option (boost::asio::socket_base::receive_buffer_size (SSU2_SOCKET_RECEIVE_BUFFER_SIZE));
			socket.set_option (boost::asio::socket_base::send_buffer_size (SSU2_SOCKET_SEND_BUFFER_SIZE));
			socket.bind (localEndpoint);
			LogPrint (eLogInfo, "SSU2: Start listening on ", localEndpoint);
		}
		catch (std::exception& ex )
		{
			LogPrint (eLogError, "SSU2: Failed to bind to  ", localEndpoint, ": ", ex.what());
			ThrowFatal ("Unable to start SSU2 transport on ", localEndpoint, ": ", ex.what ());
		}
		return socket;
	}
		
	void SSU2Server::Receive (boost::asio::ip::udp::socket& socket)
	{
		Packet * packet = m_PacketsPool.AcquireMt ();
		socket.async_receive_from (boost::asio::buffer (packet->buf, SSU2_MTU), packet->from,
			std::bind (&SSU2Server::HandleReceivedFrom, this, std::placeholders::_1, std::placeholders::_2, packet, std::ref (socket)));
	}

	void SSU2Server::HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred, 
		Packet * packet, boost::asio::ip::udp::socket& socket)
	{
		if (!ecode)
		{
			packet->len = bytes_transferred;
			ProcessNextPacket (packet->buf, packet->len, packet->from);
			m_PacketsPool.ReleaseMt (packet);
			Receive (socket);
		}
		else
		{
			m_PacketsPool.ReleaseMt (packet);
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU2: Receive error: code ", ecode.value(), ": ", ecode.message ());
				auto ep = socket.local_endpoint ();
				socket.close ();
				OpenSocket (ep);
				Receive (socket);
			}
		}
	}
		
	void SSU2Server::AddSession (uint64_t connID, std::shared_ptr<SSU2Session> session)
	{
		m_Sessions.emplace (connID, session);
	}	

	void SSU2Server::AddPendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep, std::shared_ptr<SSU2Session> session)
	{
		m_PendingOutgoingSessions.emplace (ep, session);
	}
		
	void SSU2Server::ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		uint64_t connID;
		memcpy (&connID, buf, 8);
		connID ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		auto it = m_Sessions.find (connID);
		if (it != m_Sessions.end ())
		{
		}	
		else 
		{
			// check pending sessions if it's SessionCreated
			auto it1 = m_PendingOutgoingSessions.find (senderEndpoint);
			if (it1 != m_PendingOutgoingSessions.end ())
			{
				if (it1->second->ProcessSessionCreated (buf, len))
					m_PendingOutgoingSessions.erase (it1);
			}
			else
			{
				// assume new incoming session
				auto session = std::make_shared<SSU2Session> (*this);
				session->SetRemoteEndpoint (senderEndpoint);
				session->ProcessSessionRequest (connID, buf, len);
			}	
		}	
	}	

	void SSU2Server::Send (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen, 
		const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to)
	{
		std::vector<boost::asio::const_buffer> bufs
		{
			boost::asio::buffer (header, headerLen),
			boost::asio::buffer (headerX, headerXLen),
			boost::asio::buffer (payload, payloadLen)
		};
		boost::system::error_code ec;
		m_Socket.send_to (bufs, to, 0, ec);
	}	

	bool SSU2Server::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address)
	{
		if (router && address)
			GetService ().post (
				[this, router, address]()
			    {
					auto session = std::make_shared<SSU2Session> (*this, router, address);
					session->Connect ();
				});               
		else
			return false;
		return true;
	}	
		
}
}
