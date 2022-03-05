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
		if (in_RemoteRouter && addr)
		{
			// outgoing
			InitNoiseXKState1 (*m_NoiseState, addr->s);
		}	
	}
	
	SSU2Session::~SSU2Session ()
	{	
	}

	void SSU2Session::SendSessionRequest ()
	{
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		m_NoiseState->MixHash (m_Address->s, 32); // h = SHA256(h || bpk)
		
		Header header;
		uint8_t headerX[48], payload[1200]; // TODO: correct payload size
		size_t payloadSize = 8;
		// fill packet
		RAND_bytes ((uint8_t *)&m_DestConnID, 8);
		header.h.connID = m_DestConnID; // dest id
		memset (header.h.h2.h.packetNum, 0, 4);
		header.h.h2.h.type = eSSU2SessionRequest;
		header.h.h2.h.flags[0] = 2; // ver
		header.h.h2.h.flags[1] = 2; // netID TODO:
		header.h.h2.h.flags[2] = 0; // flag
		RAND_bytes ((uint8_t *)&m_SourceConnID, 8); 
		memcpy (headerX, &m_SourceConnID, 8); // source id
		memset (headerX + 8, 0, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // X
		m_Server.AddPendingOutgoingSession (boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port), shared_from_this ());
		// KDF for session request 
		m_NoiseState->MixHash (header.buf, 16); // h = SHA256(h || header) TODO: long header
		m_NoiseState->MixHash (m_EphemeralKeys->GetPublicKey (), 32); // h = SHA256(h || aepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (m_Address->s, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// encrypt
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 12));
		const uint8_t nonce[12] = {0};
		i2p::crypto::ChaCha20 (headerX, 48, m_Address->i, nonce, headerX);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		// send
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port));
	}	

	bool SSU2Session::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		Header2 h2;
		memcpy (h2.buf, buf, 8);
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessCreateHeader", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
		h2.ll ^= CreateHeaderMask (kh2, buf + (len - 12));
		if (h2.h.type != eSSU2SessionCreated) 
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)h2.h.type);
			return false;
		}	
		return true;
	}	

	SSU2Server::SSU2Server (int port):
		m_Socket (m_Service), m_Endpoint (boost::asio::ip::udp::v6 (), port)
	{
	}

	void SSU2Server::OpenSocket ()
	{
		try
		{
			m_Socket.open (boost::asio::ip::udp::v6());
			m_Socket.set_option (boost::asio::socket_base::receive_buffer_size (SSU2_SOCKET_RECEIVE_BUFFER_SIZE));
			m_Socket.set_option (boost::asio::socket_base::send_buffer_size (SSU2_SOCKET_SEND_BUFFER_SIZE));
			m_Socket.bind (m_Endpoint);
			LogPrint (eLogInfo, "SSU2: Start listening port ", m_Endpoint.port());
		}
		catch (std::exception& ex )
		{
			LogPrint (eLogError, "SSU2: Failed to bind to port ", m_Endpoint.port(), ": ", ex.what());
			ThrowFatal ("Unable to start SSU2 transport at port ", m_Endpoint.port(), ": ", ex.what ());
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
	
}
}
