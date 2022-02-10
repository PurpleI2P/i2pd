/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

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
		
		uint8_t packet[1200]; // TODO: correct packet size
		size_t packetSize = 64;
		// fill packet
		memcpy (packet + 32, m_EphemeralKeys->GetPublicKey (), 32); // X
		// encrypt
		CreateHeaderMask (m_Address->i, packet + (packetSize - 24), m_Address->i, packet + (packetSize - 12));
		EncryptHeader (*(i2p::crypto::ChipherBlock *)packet);
		uint8_t nonce[12] = {0};
		i2p::crypto::ChaCha20 (packet + 16, 48, m_Address->i, nonce, packet + 16);
		i2p::crypto::AEADChaCha20Poly1305 (packet + 64, packetSize - 64, m_NoiseState->m_H, 32, m_NoiseState->m_CK, nonce, packet + 64, packetSize - 48, true);
	}	

	void SSU2Session::EncryptHeader (i2p::crypto::ChipherBlock& header)
	{
		header ^= m_HeaderMask;
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
