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
		m_NoiseState->MixHash (m_EphemeralKeys->GetPublicKey (), 32);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (m_Address->s, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);

		Header header;
		uint8_t headerX[48], payload[1200]; // TODO: correct payload size
		size_t payloadSize = 8;
		// fill packet
		RAND_bytes ((uint8_t *)&m_DestConnID, 8);
		header.h.connID = m_DestConnID; // dest id
		memset (header.h.packetNum, 0, 4);
		header.h.type = eSSU2SessionRequest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = 2; // netID TODO:
		header.h.flags[2] = 0; // flag
		RAND_bytes ((uint8_t *)&m_SourceConnID, 8); 
		memcpy (headerX, &m_SourceConnID, 8); // source id
		memset (headerX + 8, 0, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // X
		m_Server.AddPendingOutgoingSession (boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port), shared_from_this ());
		// encrypt
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		CreateHeaderMask (m_Address->i, payload + (payloadSize - 24), m_Address->i, payload + (payloadSize - 12));
		EncryptHeader (header);
		i2p::crypto::ChaCha20 (headerX, 48, m_Address->i, nonce, headerX);
		
	}	

	void SSU2Session::EncryptHeader (Header& h)
	{
		h.ll[0] ^= m_HeaderMask.ll[0];
		h.ll[1] ^= m_HeaderMask.ll[1];
	}	

	void SSU2Session::CreateHeaderMask (const uint8_t * kh1, const uint8_t * nonce1, const uint8_t * kh2, const uint8_t * nonce2)
	{
		// Header Encryption KDF
		uint8_t data[8] = {0};
		i2p::crypto::ChaCha20 (data, 8, kh1, nonce1, m_HeaderMask.buf);
		i2p::crypto::ChaCha20 (data, 8, kh2, nonce2, m_HeaderMask.buf + 8);
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
		uint64_t key = 0, connID;
		i2p::crypto::ChaCha20 ((uint8_t *)&key, 8, i2p::context.GetNTCP2IV (), buf + (len - 24), (uint8_t *)&key); // TODO: use SSU2 intro key
		memcpy (&connID, buf, 8);
		connID ^= key;
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
