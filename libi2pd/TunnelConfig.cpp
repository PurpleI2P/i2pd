/*
* Copyright (c) 2013-2021, The PurpleI2P Project
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

	void TunnelHopConfig::DecryptRecord (uint8_t * records, int index) const
	{
		uint8_t * record = records + index*TUNNEL_BUILD_RECORD_SIZE;
		i2p::crypto::CBCDecryption decryption;
		decryption.SetKey (replyKey);
		decryption.SetIV (replyIV);
		decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
	}

	void ECIESTunnelHopConfig::EncryptECIES (const uint8_t * plainText, size_t len, uint8_t * encrypted)
	{
		if (!ident) return;
		i2p::crypto::InitNoiseNState (*this, ident->GetEncryptionPublicKey ());
		auto ephemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		memcpy (encrypted, ephemeralKeys->GetPublicKey (), 32);
		MixHash (encrypted, 32); // h = SHA256(h || sepk)
		encrypted += 32;
		uint8_t sharedSecret[32];
		ephemeralKeys->Agree (ident->GetEncryptionPublicKey (), sharedSecret); // x25519(sesk, hepk)
		MixKey (sharedSecret);
		uint8_t nonce[12];
		memset (nonce, 0, 12);
		if (!i2p::crypto::AEADChaCha20Poly1305 (plainText, len, m_H, 32, m_CK + 32, nonce, encrypted, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Tunnel: Plaintext AEAD encryption failed");
			return;
		}
		MixHash (encrypted, len + 16); // h = SHA256(h || ciphertext)
	}

	bool ECIESTunnelHopConfig::DecryptECIES (const uint8_t * key, const uint8_t * nonce, const uint8_t * encrypted, size_t len, uint8_t * clearText) const
	{
		return i2p::crypto::AEADChaCha20Poly1305 (encrypted, len - 16, m_H, 32, key, nonce, clearText, len - 16, false); // decrypt
	}

	void LongECIESTunnelHopConfig::CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID)
	{
		// generate keys
		RAND_bytes (layerKey, 32);
		RAND_bytes (ivKey, 32);
		RAND_bytes (replyKey, 32);
		RAND_bytes (replyIV, 16);
		// fill clear text
		uint8_t flag = 0;
		if (isGateway) flag |= TUNNEL_BUILD_RECORD_GATEWAY_FLAG;
		if (isEndpoint) flag |= TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;
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
		// encrypt
		uint8_t * record = records + recordIndex*TUNNEL_BUILD_RECORD_SIZE;
		EncryptECIES (clearText, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET);
		memcpy (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)ident->GetIdentHash (), 16);
	}

	bool LongECIESTunnelHopConfig::DecryptBuildResponseRecord (uint8_t * records) const
	{
		uint8_t * record = records + recordIndex*TUNNEL_BUILD_RECORD_SIZE;
		uint8_t nonce[12];
		memset (nonce, 0, 12);
		if (!DecryptECIES (m_CK, nonce, record, TUNNEL_BUILD_RECORD_SIZE, record))
		{
			LogPrint (eLogWarning, "Tunnel: Response AEAD decryption failed");
			return false;
		}
		return true;
	}

	void ShortECIESTunnelHopConfig::CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID)
	{
		// fill clear text
		uint8_t flag = 0;
		if (isGateway) flag |= TUNNEL_BUILD_RECORD_GATEWAY_FLAG;
		if (isEndpoint) flag |= TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;
		uint8_t clearText[SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE ];
		htobe32buf (clearText + SHORT_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET, tunnelID);
		htobe32buf (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET, nextTunnelID);
		memcpy (clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, nextIdent, 32);
		clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] = flag;
		memset (clearText + SHORT_REQUEST_RECORD_MORE_FLAGS_OFFSET, 0, 2);
		clearText[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE] = 0; // AES
		htobe32buf (clearText + SHORT_REQUEST_RECORD_REQUEST_TIME_OFFSET, i2p::util::GetMinutesSinceEpoch ());
		htobe32buf (clearText + SHORT_REQUEST_RECORD_REQUEST_EXPIRATION_OFFSET , 600); // +10 minutes
		htobe32buf (clearText + SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET, replyMsgID);
		memset (clearText + SHORT_REQUEST_RECORD_PADDING_OFFSET, 0, SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE - SHORT_REQUEST_RECORD_PADDING_OFFSET);
		// encrypt
		uint8_t * record = records + recordIndex*SHORT_TUNNEL_BUILD_RECORD_SIZE;
		EncryptECIES (clearText, SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE, record + SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET);
		// derive keys
		i2p::crypto::HKDF (m_CK, nullptr, 0, "SMTunnelReplyKey", m_CK);
		memcpy (replyKey, m_CK + 32, 32);
		i2p::crypto::HKDF (m_CK, nullptr, 0, "SMTunnelLayerKey", m_CK);
		memcpy (layerKey, m_CK + 32, 32);
		if (isEndpoint)
		{
			i2p::crypto::HKDF (m_CK, nullptr, 0, "TunnelLayerIVKey", m_CK);
			memcpy (ivKey, m_CK + 32, 32);
			i2p::crypto::HKDF (m_CK, nullptr, 0, "RGarlicKeyAndTag", m_CK); // OTBRM garlic key m_CK + 32, tag first 8 bytes of m_CK
		}
		else
			memcpy (ivKey, m_CK, 32); // last HKDF
		memcpy (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)ident->GetIdentHash (), 16);
	}

	bool ShortECIESTunnelHopConfig::DecryptBuildResponseRecord (uint8_t * records) const
	{
		uint8_t * record = records + recordIndex*SHORT_TUNNEL_BUILD_RECORD_SIZE;
		uint8_t nonce[12];
		memset (nonce, 0, 12);
		nonce[4] = recordIndex; // nonce is record index
		if (!DecryptECIES (replyKey, nonce, record, SHORT_TUNNEL_BUILD_RECORD_SIZE, record))
		{
			LogPrint (eLogWarning, "Tunnel: Response AEAD decryption failed");
			return false;
		}
		return true;
	}

	void ShortECIESTunnelHopConfig::DecryptRecord (uint8_t * records, int index) const
	{
		uint8_t * record = records + index*SHORT_TUNNEL_BUILD_RECORD_SIZE;
		uint8_t nonce[12];
		memset (nonce, 0, 12);
		nonce[4] = index; // nonce is index
		i2p::crypto::ChaCha20 (record, SHORT_TUNNEL_BUILD_RECORD_SIZE, replyKey, nonce, record);
	}

	uint64_t ShortECIESTunnelHopConfig::GetGarlicKey (uint8_t * key) const
	{
		uint64_t tag;
		memcpy (&tag, m_CK, 8);
		memcpy (key, m_CK + 32, 32);
		return tag;
	}

	void TunnelConfig::CreatePeers (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers)
	{
		TunnelHopConfig * prev = nullptr;
		for (const auto& it: peers)
		{
			TunnelHopConfig * hop = nullptr;
			if (m_IsShort)
				hop = new ShortECIESTunnelHopConfig (it);
			else
			{
				if (it->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
					hop = new LongECIESTunnelHopConfig (it);
				else
					LogPrint (eLogError, "Tunnel: ElGamal router is not supported");
			}
			if (hop)
			{
				if (prev)
					prev->SetNext (hop);
				else
					m_FirstHop = hop;
				prev = hop;
			}
		}
		m_LastHop = prev;
	}
}
}