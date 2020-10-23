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
	
	void TunnelHopConfig::CreateBuildRequestRecord (uint8_t * record, uint32_t replyMsgID, BN_CTX * ctx) const
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
		uint8_t flag = 0;
		if (isGateway) flag |= 0x80;
		if (isEndpoint) flag |= 0x40;
		clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] = flag;
		htobe32buf (clearText + BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET, i2p::util::GetHoursSinceEpoch ());
		htobe32buf (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET, replyMsgID);
		RAND_bytes (clearText + BUILD_REQUEST_RECORD_PADDING_OFFSET, BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE - BUILD_REQUEST_RECORD_PADDING_OFFSET);
		auto encryptor = ident->CreateEncryptor (nullptr);
		if (encryptor)
		{
			if (ident->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET)
				EncryptECIES (encryptor, clearText, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, ctx);
			else	
				encryptor->Encrypt (clearText, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, ctx, false);
		}	
		memcpy (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)ident->GetIdentHash (), 16);
	}

	void TunnelHopConfig::EncryptECIES (std::shared_ptr<i2p::crypto::CryptoKeyEncryptor>& encryptor, 
			const uint8_t * clearText, uint8_t * encrypted, BN_CTX * ctx) const
	{
		memset (encrypted, 0, 512); // TODO: implement
	}	
}
}