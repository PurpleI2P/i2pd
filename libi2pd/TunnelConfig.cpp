/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
*/

#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "Log.h"
#include "Transports.h"
#include "Timestamp.h"
#include "I2PEndian.h"
#include "I2NPProtocol.h"
#include "TunnelConfig.h"

namespace i2p
{
namespace tunnel
{
	TunnelHopConfig::TunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r)
	{
		RAND_bytes (layerKey, 32);
		RAND_bytes (ivKey, 32);
		RAND_bytes (replyKey, 32);
		RAND_bytes (replyIV, 16);
		RAND_bytes ((uint8_t *)&tunnelID, 4);
		if (!tunnelID) tunnelID = 1; // tunnelID can't be zero
		isGateway = true;
		isEndpoint = true;
		ident = r;
		//nextRouter = nullptr;
		nextTunnelID = 0;

		next = nullptr;
		prev = nullptr;
	}

	void TunnelHopConfig::SetNextIdent (const i2p::data::IdentHash& ident)
	{
		nextIdent = ident;
		isEndpoint = false;
		RAND_bytes ((uint8_t *)&nextTunnelID, 4);
		if (!nextTunnelID) nextTunnelID = 1; // tunnelID can't be zero
	}

	void TunnelHopConfig::SetReplyHop (uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent)
	{
		nextIdent = replyIdent;
		nextTunnelID = replyTunnelID;
		isEndpoint = true;
	}

	void TunnelHopConfig::SetNext (TunnelHopConfig * n)
	{
		next = n;
		if (next)
		{
			next->prev = this;
			next->isGateway = false;
			isEndpoint = false;
			nextIdent = next->ident->GetIdentHash ();
			nextTunnelID = next->tunnelID;
		}
	}

	void TunnelHopConfig::SetPrev (TunnelHopConfig * p)
	{
		prev = p;
		if (prev)
		{
			prev->next = this;
			prev->isEndpoint = false;
			isGateway = false;
		}
	}
	
	void TunnelHopConfig::CreateBuildRequestRecord (uint8_t * record, uint32_t replyMsgID, BN_CTX * ctx)
	{
		uint8_t flag = 0;
		if (isGateway) flag |= 0x80;
		if (isEndpoint) flag |= 0x40;
		auto encryptor = ident->CreateEncryptor (nullptr);
		if (IsECIES ())
		{
			uint8_t clearText[ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
			htobe32buf (clearText + ECIES_BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET, tunnelID);
			htobe32buf (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET, nextTunnelID);
			memcpy (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET, nextIdent, 32);
			memcpy (clearText + ECIES_BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET, layerKey, 32);
			memcpy (clearText + ECIES_BUILD_REQUEST_RECORD_IV_KEY_OFFSET, ivKey, 32);
			memcpy (clearText + ECIES_BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET, replyKey, 32);
			memcpy (clearText + ECIES_BUILD_REQUEST_RECORD_REPLY_IV_OFFSET, replyIV, 16);
			clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] = flag;
			memset (clearText + ECIES_BUILD_REQUEST_RECORD_MORE_FLAGS_OFFSET, 0, 3); // set to 0 for compatibility
			htobe32buf (clearText + ECIES_BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET, i2p::util::GetMinutesSinceEpoch ());
			htobe32buf (clearText + ECIES_BUILD_REQUEST_RECORD_REQUEST_EXPIRATION_OFFSET, 600); // +10 minutes
			htobe32buf (clearText + ECIES_BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET, replyMsgID);
			memset (clearText + ECIES_BUILD_REQUEST_RECORD_PADDING_OFFSET, 0, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE - ECIES_BUILD_REQUEST_RECORD_PADDING_OFFSET);
			if (encryptor)
				EncryptECIES (encryptor, clearText, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, ctx);
		}
		else
		{	
			uint8_t clearText[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
			htobe32buf (clearText + BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET, tunnelID);
			memcpy (clearText + BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET, ident->GetIdentHash (), 32);
			htobe32buf (clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET, nextTunnelID);
			memcpy (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET, nextIdent, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET, layerKey, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_IV_KEY_OFFSET, ivKey, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET, replyKey, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_REPLY_IV_OFFSET, replyIV, 16);
			clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] = flag;
			htobe32buf (clearText + BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET, i2p::util::GetHoursSinceEpoch ());
			htobe32buf (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET, replyMsgID);
			RAND_bytes (clearText + BUILD_REQUEST_RECORD_PADDING_OFFSET, BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE - BUILD_REQUEST_RECORD_PADDING_OFFSET);
			if (encryptor)
				encryptor->Encrypt (clearText, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, ctx, false);
		}	
		memcpy (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)ident->GetIdentHash (), 16);
	}

	void TunnelHopConfig::EncryptECIES (std::shared_ptr<i2p::crypto::CryptoKeyEncryptor>& encryptor, 
			const uint8_t * plainText, uint8_t * encrypted, BN_CTX * ctx)
	{
		InitBuildRequestRecordNoiseState (*this);
		uint8_t hepk[32];
		encryptor->Encrypt (nullptr, hepk, nullptr, false); 
		MixHash (hepk, 32); // h = SHA256(h || hepk)
		auto ephemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		memcpy (encrypted, ephemeralKeys->GetPublicKey (), 32);  
		MixHash (encrypted, 32); // h = SHA256(h || sepk)
		encrypted += 32;
		uint8_t sharedSecret[32];
		ephemeralKeys->Agree (hepk, sharedSecret); // x25519(sesk, hepk)
		MixKey (sharedSecret); 
		uint8_t nonce[12];
		memset (nonce, 0, 12);
		if (!i2p::crypto::AEADChaCha20Poly1305 (plainText, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE, m_H, 32, 
			m_CK + 32, nonce, encrypted, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE + 16, true)) // encrypt
		{	
			LogPrint (eLogWarning, "Tunnel: Plaintext AEAD encryption failed");
			return;
		}	
		MixHash (encrypted, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE + 16); // h = SHA256(h || ciphertext)
	}	

	void InitBuildRequestRecordNoiseState (i2p::crypto::NoiseSymmetricState& state)
	{
		static const char protocolName[] = "Noise_N_25519_ChaChaPoly_SHA256"; // 31 chars
		static const uint8_t hh[32] =
		{
			0x69, 0x4d, 0x52, 0x44, 0x5a, 0x27, 0xd9, 0xad, 0xfa, 0xd2, 0x9c, 0x76, 0x32, 0x39, 0x5d, 0xc1, 
			0xe4, 0x35, 0x4c, 0x69, 0xb4, 0xf9, 0x2e, 0xac, 0x8a, 0x1e, 0xe4, 0x6a, 0x9e, 0xd2, 0x15, 0x54
		}; // SHA256 (protocol_name || 0)
		memcpy (state.m_CK, protocolName, 32);	// ck = h = protocol_name || 0
		memcpy (state.m_H, hh, 32); // h = SHA256(h)
	}	
}
}