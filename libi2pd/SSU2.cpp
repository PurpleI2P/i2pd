/*
* Copyright (c) 2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <openssl/rand.h>
#include "Transports.h"
#include "SSU2.h"

namespace i2p
{
namespace transport
{
	SSU2Session::SSU2Session (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr, bool peerTest):
		TransportSession (in_RemoteRouter, SSU2_TERMINATION_TIMEOUT),
		m_Address (addr)
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
		RAND_bytes (header.h.connID, 8);
		memset (header.h.packetNum, 0, 4);
		header.h.type = eSSU2SessionRequest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = 2; // netID TODO:
		header.h.flags[2] = 0; // flag
		RAND_bytes (headerX, 8); // source id
		memset (headerX + 8, 0, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // X
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
}
}
