/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <openssl/sha.h>
#include "Log.h"
#include "Crypto.h"
#include "Elligator.h"
#include "Tag.h"
#include "I2PEndian.h"
#include "Timestamp.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "Transports.h"
#include "ECIESX25519AEADRatchetSession.h"

namespace i2p
{
namespace garlic
{

	void RatchetTagSet::DHInitialize (const uint8_t * rootKey, const uint8_t * k)
	{
		// DH_INITIALIZE(rootKey, k)
		uint8_t keydata[64];
		i2p::crypto::HKDF (rootKey, k, 32, "KDFDHRatchetStep", keydata); // keydata = HKDF(rootKey, k, "KDFDHRatchetStep", 64)
		memcpy (m_NextRootKey, keydata, 32); // nextRootKey = keydata[0:31]
		i2p::crypto::HKDF (keydata + 32, nullptr, 0, "TagAndKeyGenKeys", m_KeyData.buf);
		// [sessTag_ck, symmKey_ck] = HKDF(keydata[32:63], ZEROLEN, "TagAndKeyGenKeys", 64)
		memcpy (m_SymmKeyCK, m_KeyData.buf + 32, 32);
		m_NextSymmKeyIndex = 0;
	}

	void RatchetTagSet::NextSessionTagRatchet ()
	{
		i2p::crypto::HKDF (m_KeyData.GetSessTagCK (), nullptr, 0, "STInitialization", m_KeyData.buf); // [sessTag_ck, sesstag_constant] = HKDF(sessTag_ck, ZEROLEN, "STInitialization", 64)
		memcpy (m_SessTagConstant, m_KeyData.GetSessTagConstant (), 32);
		m_NextIndex = 0;
	}

	uint64_t RatchetTagSet::GetNextSessionTag ()
	{
		i2p::crypto::HKDF (m_KeyData.GetSessTagCK (), m_SessTagConstant, 32, "SessionTagKeyGen", m_KeyData.buf); // [sessTag_ck, tag] = HKDF(sessTag_chainkey, SESSTAG_CONSTANT, "SessionTagKeyGen", 64)
		m_NextIndex++;
		if (m_NextIndex >= 65535)
		{
			LogPrint (eLogError, "Garlic: Tagset ", GetTagSetID (), " is empty");
			return 0;
		}
		return m_KeyData.GetTag ();
	}

	void RatchetTagSet::GetSymmKey (int index, uint8_t * key)
	{
		if (index >= m_NextSymmKeyIndex)
		{
			auto num = index + 1 - m_NextSymmKeyIndex;
			if (!m_NextSymmKeyIndex)
			{
				i2p::crypto::HKDF (m_SymmKeyCK, nullptr, 0, "SymmetricRatchet", m_CurrentSymmKeyCK); // keydata_0 = HKDF(symmKey_ck, SYMMKEY_CONSTANT, "SymmetricRatchet", 64)
				m_NextSymmKeyIndex = 1;
				num--;
			}
			for (int i = 0; i < num; i++)
			{
				i2p::crypto::HKDF (m_CurrentSymmKeyCK, nullptr, 0, "SymmetricRatchet", m_CurrentSymmKeyCK);
				if (i < num - 1)
					m_ItermediateSymmKeys.emplace (m_NextSymmKeyIndex + i, m_CurrentSymmKeyCK + 32);
			}
			m_NextSymmKeyIndex += num;
			memcpy (key, m_CurrentSymmKeyCK + 32, 32);
		}
		else
		{
			auto it = m_ItermediateSymmKeys.find (index);
			if (it != m_ItermediateSymmKeys.end ())
			{
				memcpy (key, it->second, 32);
				m_ItermediateSymmKeys.erase (it);
			}
			else
				LogPrint (eLogError, "Garlic: Missing symmetric key for index ", index);
		}
	}

	void RatchetTagSet::Expire ()
	{
		if (!m_ExpirationTimestamp)
			m_ExpirationTimestamp = i2p::util::GetSecondsSinceEpoch () + ECIESX25519_PREVIOUS_TAGSET_EXPIRATION_TIMEOUT;
	}

	ECIESX25519AEADRatchetSession::ECIESX25519AEADRatchetSession (GarlicDestination * owner, bool attachLeaseSet):
		GarlicRoutingSession (owner, attachLeaseSet)
	{
		RAND_bytes (m_PaddingSizes, 32); m_NextPaddingSize = 0;
		ResetKeys ();
	}

	ECIESX25519AEADRatchetSession::~ECIESX25519AEADRatchetSession ()
	{
	}

	void ECIESX25519AEADRatchetSession::ResetKeys ()
	{
		static const uint8_t protocolNameHash[32] =
		{
			0x4c, 0xaf, 0x11, 0xef, 0x2c, 0x8e, 0x36, 0x56, 0x4c, 0x53, 0xe8, 0x88, 0x85, 0x06, 0x4d, 0xba,
			0xac, 0xbe, 0x00, 0x54, 0xad, 0x17, 0x8f, 0x80, 0x79, 0xa6, 0x46, 0x82, 0x7e, 0x6e, 0xe4, 0x0c
		}; // SHA256("Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"), 40 bytes
		static const uint8_t hh[32] =
		{
			0x9c, 0xcf, 0x85, 0x2c, 0xc9, 0x3b, 0xb9, 0x50, 0x44, 0x41, 0xe9, 0x50, 0xe0, 0x1d, 0x52, 0x32,
			0x2e, 0x0d, 0x47, 0xad, 0xd1, 0xe9, 0xa5, 0x55, 0xf7, 0x55, 0xb5, 0x69, 0xae, 0x18, 0x3b, 0x5c
		}; // SHA256 (protocolNameHash)
		memcpy (m_CK, protocolNameHash, 32);
		memcpy (m_H, hh, 32);
	}

	void ECIESX25519AEADRatchetSession::MixHash (const uint8_t * buf, size_t len)
	{
		SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, m_H, 32);
		SHA256_Update (&ctx, buf, len);
		SHA256_Final (m_H, &ctx);
	}

	void ECIESX25519AEADRatchetSession::CreateNonce (uint64_t seqn, uint8_t * nonce)
	{
		memset (nonce, 0, 4);
		htole64buf (nonce + 4, seqn);
	}

	bool ECIESX25519AEADRatchetSession::GenerateEphemeralKeysAndEncode (uint8_t * buf)
	{
		bool ineligible = false;
		while (!ineligible)
		{	
			m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
			ineligible = m_EphemeralKeys->IsElligatorIneligible ();
			if (!ineligible) // we haven't tried it yet
			{	
				if (i2p::crypto::GetElligator ()->Encode (m_EphemeralKeys->GetPublicKey (), buf))
					return true; // success
				// otherwise return back
				m_EphemeralKeys->SetElligatorIneligible ();
				i2p::transport::transports.ReuseX25519KeysPair (m_EphemeralKeys);
			}
			else
				i2p::transport::transports.ReuseX25519KeysPair (m_EphemeralKeys);
		}	
		// we still didn't find elligator eligible pair
		for (int i = 0; i < 10; i++)
		{
			// create new
			m_EphemeralKeys = std::make_shared<i2p::crypto::X25519Keys>();
			m_EphemeralKeys->GenerateKeys ();
			if (i2p::crypto::GetElligator ()->Encode (m_EphemeralKeys->GetPublicKey (), buf))
				return true; // success
			else
			{
				// let NTCP2 use it
				m_EphemeralKeys->SetElligatorIneligible ();
				i2p::transport::transports.ReuseX25519KeysPair (m_EphemeralKeys);
			}	
		}
		LogPrint (eLogError, "Garlic: Can't generate elligator eligible x25519 keys");
		return false;
	}

	std::shared_ptr<RatchetTagSet> ECIESX25519AEADRatchetSession::CreateNewSessionTagset ()
	{
		uint8_t tagsetKey[32];
		i2p::crypto::HKDF (m_CK, nullptr, 0, "SessionReplyTags", tagsetKey, 32); // tagsetKey = HKDF(chainKey, ZEROLEN, "SessionReplyTags", 32)
		// Session Tag Ratchet
		auto tagsetNsr = (m_State == eSessionStateNewSessionReceived) ? std::make_shared<RatchetTagSet>(shared_from_this ()):
			std::make_shared<NSRatchetTagSet>(shared_from_this ());
		tagsetNsr->DHInitialize (m_CK, tagsetKey); // tagset_nsr = DH_INITIALIZE(chainKey, tagsetKey)
		tagsetNsr->NextSessionTagRatchet ();
		return tagsetNsr;
	}

	bool ECIESX25519AEADRatchetSession::HandleNewIncomingSession (const uint8_t * buf, size_t len)
	{
		if (!GetOwner ()) return false;
		// we are Bob
		// KDF1
		MixHash (GetOwner ()->GetEncryptionPublicKey (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET), 32); // h = SHA256(h || bpk)

		if (!i2p::crypto::GetElligator ()->Decode (buf, m_Aepk))
		{
			LogPrint (eLogError, "Garlic: Can't decode elligator");
			return false;
		}
		buf += 32; len -= 32;
		MixHash (m_Aepk, 32); // h = SHA256(h || aepk)

		uint8_t sharedSecret[32];
		GetOwner ()->Decrypt (m_Aepk, sharedSecret, nullptr, i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET); // x25519(bsk, aepk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)

		// decrypt flags/static
		uint8_t nonce[12], fs[32];
		CreateNonce (0, nonce);
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, 32, m_H, 32, m_CK + 32, nonce, fs, 32, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Flags/static section AEAD verification failed ");
			return false;
		}
		MixHash (buf, 48); // h = SHA256(h || ciphertext)
		buf += 48; len -= 48; // 32 data + 16 poly

		// KDF2 for payload
		bool isStatic = !i2p::data::Tag<32> (fs).IsZero ();
		if (isStatic)
		{
			// static key, fs is apk
			memcpy (m_RemoteStaticKey, fs, 32);
			GetOwner ()->Decrypt (fs, sharedSecret, nullptr, i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET); // x25519(bsk, apk)
			i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		}
		else // all zeros flags
			CreateNonce (1, nonce);

		// decrypt payload
		std::vector<uint8_t> payload (len - 16); // we must save original ciphertext
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, len - 16, m_H, 32, m_CK + 32, nonce, payload.data (), len - 16, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD verification failed");
			return false;
		}
		if (isStatic) MixHash (buf, len); // h = SHA256(h || ciphertext)
		m_State = eSessionStateNewSessionReceived;
		GetOwner ()->AddECIESx25519Session (m_RemoteStaticKey, shared_from_this ());

		HandlePayload (payload.data (), len - 16, nullptr, 0);

		return true;
	}

	void ECIESX25519AEADRatchetSession::HandlePayload (const uint8_t * buf, size_t len, const std::shared_ptr<RatchetTagSet>& receiveTagset, int index)
	{
		size_t offset = 0;
		while (offset < len)
		{
			uint8_t blk = buf[offset];
			offset++;
			auto size = bufbe16toh (buf + offset);
			offset += 2;
			LogPrint (eLogDebug, "Garlic: Block type ", (int)blk, " of size ", size);
			if (size > len)
			{
				LogPrint (eLogError, "Garlic: Unexpected block length ", size);
				break;
			}
			switch (blk)
			{
				case eECIESx25519BlkGalicClove:
					if (GetOwner ())
						GetOwner ()->HandleECIESx25519GarlicClove (buf + offset, size);
				break;
				case eECIESx25519BlkNextKey:
					LogPrint (eLogDebug, "Garlic: next key");
					HandleNextKey (buf + offset, size, receiveTagset);
				break;
				case eECIESx25519BlkAck:
				{
					LogPrint (eLogDebug, "Garlic: ack");
					int numAcks = size >> 2; // /4
					auto offset1 = offset;
					for (auto i = 0; i < numAcks; i++)
					{
						offset1 += 2; // tagsetid
						MessageConfirmed (bufbe16toh (buf + offset1)); offset1 += 2; // N
					}
					break;
				}
				case eECIESx25519BlkAckRequest:
				{
					LogPrint (eLogDebug, "Garlic: ack request");
					m_AckRequests.push_back ({receiveTagset->GetTagSetID (), index});
					break;
				}
				case eECIESx25519BlkTermination:
					LogPrint (eLogDebug, "Garlic: termination");
					if (GetOwner ())
						GetOwner ()->RemoveECIESx25519Session (m_RemoteStaticKey);
					if (receiveTagset) receiveTagset->Expire ();
				break;
				case eECIESx25519BlkDateTime:
					LogPrint (eLogDebug, "Garlic: datetime");
				break;
				case eECIESx25519BlkOptions:
					LogPrint (eLogDebug, "Garlic: options");
				break;
				case eECIESx25519BlkPadding:
					LogPrint (eLogDebug, "Garlic: padding");
				break;
				default:
					LogPrint (eLogWarning, "Garlic: Unknown block type ", (int)blk);
			}
			offset += size;
		}
	}

	void ECIESX25519AEADRatchetSession::HandleNextKey (const uint8_t * buf, size_t len, const std::shared_ptr<RatchetTagSet>& receiveTagset)
	{
		uint8_t flag = buf[0]; buf++; // flag
		if (flag & ECIESX25519_NEXT_KEY_REVERSE_KEY_FLAG)
		{
			if (!m_SendForwardKey || !m_NextSendRatchet) return;
			uint16_t keyID = bufbe16toh (buf); buf += 2; // keyID
			if (((!m_NextSendRatchet->newKey || !m_NextSendRatchet->keyID) && keyID == m_NextSendRatchet->keyID) ||
				(m_NextSendRatchet->newKey && keyID == m_NextSendRatchet->keyID -1))
			{
				if (flag & ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG)
					memcpy (m_NextSendRatchet->remote, buf, 32);
				uint8_t sharedSecret[32], tagsetKey[32];
				m_NextSendRatchet->key->Agree (m_NextSendRatchet->remote, sharedSecret);
				i2p::crypto::HKDF (sharedSecret, nullptr, 0, "XDHRatchetTagSet", tagsetKey, 32); // tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
				auto newTagset = std::make_shared<RatchetTagSet> (shared_from_this ());
				newTagset->SetTagSetID (1 + m_NextSendRatchet->keyID + keyID);
				newTagset->DHInitialize (m_SendTagset->GetNextRootKey (), tagsetKey);
				newTagset->NextSessionTagRatchet ();
				m_SendTagset = newTagset;
				m_SendForwardKey = false;
				LogPrint (eLogDebug, "Garlic: next send tagset ", newTagset->GetTagSetID (), " created");
			}
			else
				LogPrint (eLogDebug, "Garlic: Unexpected next key ", keyID);
		}
		else
		{
			uint16_t keyID = bufbe16toh (buf); buf += 2; // keyID
			bool newKey = flag & ECIESX25519_NEXT_KEY_REQUEST_REVERSE_KEY_FLAG;
			m_SendReverseKey = true;
			if (!m_NextReceiveRatchet)
				m_NextReceiveRatchet.reset (new DHRatchet ());
			else
			{
				if (keyID == m_NextReceiveRatchet->keyID && newKey == m_NextReceiveRatchet->newKey)
				{
					LogPrint (eLogDebug, "Garlic: Duplicate ", newKey ? "new" : "old", " key ", keyID, " received");
					return;
				}
				m_NextReceiveRatchet->keyID = keyID;
			}
			int tagsetID = 2*keyID;
			if (newKey)
			{
				m_NextReceiveRatchet->key = i2p::transport::transports.GetNextX25519KeysPair ();
				m_NextReceiveRatchet->newKey = true;
				tagsetID++;
			}
			else
				m_NextReceiveRatchet->newKey = false;
			if (flag & ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG)
				memcpy (m_NextReceiveRatchet->remote, buf, 32);

			uint8_t sharedSecret[32], tagsetKey[32];
			m_NextReceiveRatchet->key->Agree (m_NextReceiveRatchet->remote, sharedSecret);
			i2p::crypto::HKDF (sharedSecret, nullptr, 0, "XDHRatchetTagSet", tagsetKey, 32); // tagsetKey = HKDF(sharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)
			auto newTagset = std::make_shared<RatchetTagSet>(shared_from_this ());
			newTagset->SetTagSetID (tagsetID);
			newTagset->DHInitialize (receiveTagset->GetNextRootKey (), tagsetKey);
			newTagset->NextSessionTagRatchet ();
			GenerateMoreReceiveTags (newTagset, (GetOwner () && GetOwner ()->GetNumRatchetInboundTags () > 0) ?
				GetOwner ()->GetNumRatchetInboundTags () : ECIESX25519_MAX_NUM_GENERATED_TAGS);
			receiveTagset->Expire ();
			LogPrint (eLogDebug, "Garlic: next receive tagset ", tagsetID, " created");
		}
	}

	void ECIESX25519AEADRatchetSession::NewNextSendRatchet ()
	{
		if (m_NextSendRatchet)
		{
			if (!m_NextSendRatchet->newKey || !m_NextSendRatchet->keyID)
			{
				m_NextSendRatchet->keyID++;
				m_NextSendRatchet->newKey = true;
			}
			else
				m_NextSendRatchet->newKey = false;
		}
		else
			m_NextSendRatchet.reset (new DHRatchet ());
		if (m_NextSendRatchet->newKey)
			m_NextSendRatchet->key = i2p::transport::transports.GetNextX25519KeysPair ();

		m_SendForwardKey = true;
		LogPrint (eLogDebug, "Garlic: new send ratchet ", m_NextSendRatchet->newKey ? "new" : "old", " key ", m_NextSendRatchet->keyID, " created");
	}

	bool ECIESX25519AEADRatchetSession::NewOutgoingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen)
	{
		ResetKeys ();
		// we are Alice, bpk is m_RemoteStaticKey
		size_t offset = 0;
		if (!GenerateEphemeralKeysAndEncode (out + offset))
		{
			LogPrint (eLogError, "Garlic: Can't encode elligator");
			return false;
		}
		offset += 32;

		// KDF1
		MixHash (m_RemoteStaticKey, 32); // h = SHA256(h || bpk)
		MixHash (m_EphemeralKeys->GetPublicKey (), 32); // h = SHA256(h || aepk)
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (m_RemoteStaticKey, sharedSecret); // x25519(aesk, bpk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		// encrypt static key section
		uint8_t nonce[12];
		CreateNonce (0, nonce);
		if (!i2p::crypto::AEADChaCha20Poly1305 (GetOwner ()->GetEncryptionPublicKey (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET), 32, m_H, 32, m_CK + 32, nonce, out + offset, 48, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Static section AEAD encryption failed ");
			return false;
		}
		MixHash (out + offset, 48); // h = SHA256(h || ciphertext)
		offset += 48;
		// KDF2
		GetOwner ()->Decrypt (m_RemoteStaticKey, sharedSecret, nullptr, i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET); // x25519 (ask, bpk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		// encrypt payload
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len, m_H, 32, m_CK + 32, nonce, out + offset, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD encryption failed");
			return false;
		}
		MixHash (out + offset, len + 16); // h = SHA256(h || ciphertext)

		m_State = eSessionStateNewSessionSent;
		if (GetOwner ())
			GenerateMoreReceiveTags (CreateNewSessionTagset (), ECIESX25519_NSR_NUM_GENERATED_TAGS);

		return true;
	}

	bool ECIESX25519AEADRatchetSession::NewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen)
	{
		// we are Bob
		m_NSRSendTagset = CreateNewSessionTagset ();
		uint64_t tag = m_NSRSendTagset->GetNextSessionTag ();

		size_t offset = 0;
		memcpy (out + offset, &tag, 8);
		offset += 8;
		if (!GenerateEphemeralKeysAndEncode (out + offset)) // bepk
		{
			LogPrint (eLogError, "Garlic: Can't encode elligator");
			return false;
		}
		memcpy (m_NSREncodedKey, out + offset, 56); // for possible next NSR
		memcpy (m_NSRH, m_H, 32);
		offset += 32;
		// KDF for Reply Key Section
		MixHash ((const uint8_t *)&tag, 8); // h = SHA256(h || tag)
		MixHash (m_EphemeralKeys->GetPublicKey (), 32); // h = SHA256(h || bepk)
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (m_Aepk, sharedSecret); // sharedSecret = x25519(besk, aepk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK, 32); // chainKey = HKDF(chainKey, sharedSecret, "", 32)
		m_EphemeralKeys->Agree (m_RemoteStaticKey, sharedSecret); // sharedSecret = x25519(besk, apk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		uint8_t nonce[12];
		CreateNonce (0, nonce);
		// calculate hash for zero length
		if (!i2p::crypto::AEADChaCha20Poly1305 (nonce /* can be anything */, 0, m_H, 32, m_CK + 32, nonce, out + offset, 16, true)) // encrypt, ciphertext = ENCRYPT(k, n, ZEROLEN, ad)
		{
			LogPrint (eLogWarning, "Garlic: Reply key section AEAD encryption failed");
			return false;
		}
		MixHash (out + offset, 16); // h = SHA256(h || ciphertext)
		offset += 16;
		// KDF for payload
		uint8_t keydata[64];
		i2p::crypto::HKDF (m_CK, nullptr, 0, "", keydata); // keydata = HKDF(chainKey, ZEROLEN, "", 64)
		// k_ab = keydata[0:31], k_ba = keydata[32:63]
		auto receiveTagset = std::make_shared<RatchetTagSet>(shared_from_this ());
		receiveTagset->DHInitialize (m_CK, keydata); // tagset_ab = DH_INITIALIZE(chainKey, k_ab)
		receiveTagset->NextSessionTagRatchet ();
		m_SendTagset = std::make_shared<RatchetTagSet>(shared_from_this ());
		m_SendTagset->DHInitialize (m_CK, keydata + 32); // tagset_ba = DH_INITIALIZE(chainKey, k_ba)
		m_SendTagset->NextSessionTagRatchet ();
		GenerateMoreReceiveTags (receiveTagset, (GetOwner () && GetOwner ()->GetNumRatchetInboundTags () > 0) ?
			GetOwner ()->GetNumRatchetInboundTags () : ECIESX25519_MIN_NUM_GENERATED_TAGS);
		i2p::crypto::HKDF (keydata + 32, nullptr, 0, "AttachPayloadKDF", m_NSRKey, 32); // k = HKDF(k_ba, ZEROLEN, "AttachPayloadKDF", 32)
		// encrypt payload
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len, m_H, 32, m_NSRKey, nonce, out + offset, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: NSR payload section AEAD encryption failed");
			return false;
		}
		m_State = eSessionStateNewSessionReplySent;
		m_SessionCreatedTimestamp = i2p::util::GetSecondsSinceEpoch ();
		
		return true;
	}

	bool ECIESX25519AEADRatchetSession::NextNewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen)
	{
		// we are Bob and sent NSR already
		uint64_t tag = m_NSRSendTagset->GetNextSessionTag (); // next tag
		memcpy (out, &tag, 8);
		memcpy (out + 8, m_NSREncodedKey, 32);
		// recalculate h with new tag
		memcpy (m_H, m_NSRH, 32);
		MixHash ((const uint8_t *)&tag, 8); // h = SHA256(h || tag)
		MixHash (m_EphemeralKeys->GetPublicKey (), 32); // h = SHA256(h || bepk)
		uint8_t nonce[12];
		CreateNonce (0, nonce);
		if (!i2p::crypto::AEADChaCha20Poly1305 (nonce /* can be anything */, 0, m_H, 32, m_CK + 32, nonce, out + 40, 16, true)) // encrypt, ciphertext = ENCRYPT(k, n, ZEROLEN, ad)
		{
			LogPrint (eLogWarning, "Garlic: Reply key section AEAD encryption failed");
			return false;
		}
		MixHash (out + 40, 16); // h = SHA256(h || ciphertext)
		// encrypt payload
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len, m_H, 32, m_NSRKey, nonce, out + 56, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Next NSR payload section AEAD encryption failed");
			return false;
		}
		return true;
	}

	bool ECIESX25519AEADRatchetSession::HandleNewOutgoingSessionReply (uint8_t * buf, size_t len)
	{
		// we are Alice
		LogPrint (eLogDebug, "Garlic: reply received");
		const uint8_t * tag = buf;
		buf += 8; len -= 8; // tag
		uint8_t bepk[32]; // Bob's ephemeral key
		if (!i2p::crypto::GetElligator ()->Decode (buf, bepk))
		{
			LogPrint (eLogError, "Garlic: Can't decode elligator");
			return false;
		}
		buf += 32; len -= 32;
		// KDF for Reply Key Section
		uint8_t h[32]; memcpy (h, m_H, 32); // save m_H
		MixHash (tag, 8); // h = SHA256(h || tag)
		MixHash (bepk, 32); // h = SHA256(h || bepk)
		uint8_t sharedSecret[32];
		if (m_State == eSessionStateNewSessionSent)
		{
			// only fist time, we assume ephemeral keys the same
			m_EphemeralKeys->Agree (bepk, sharedSecret); // sharedSecret = x25519(aesk, bepk)
			i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK, 32); // chainKey = HKDF(chainKey, sharedSecret, "", 32)
			GetOwner ()->Decrypt (bepk, sharedSecret, nullptr, i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET); // x25519 (ask, bepk)
			i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		}
		uint8_t nonce[12];
		CreateNonce (0, nonce);
		// calculate hash for zero length
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, 0, m_H, 32, m_CK + 32, nonce, sharedSecret/* can be anything */, 0, false)) // decrypt, DECRYPT(k, n, ZEROLEN, ad) verification only
		{
			LogPrint (eLogWarning, "Garlic: Reply key section AEAD decryption failed");
			return false;
		}
		MixHash (buf, 16); // h = SHA256(h || ciphertext)
		buf += 16; len -= 16;
		// KDF for payload
		uint8_t keydata[64];
		i2p::crypto::HKDF (m_CK, nullptr, 0, "", keydata); // keydata = HKDF(chainKey, ZEROLEN, "", 64)
		if (m_State == eSessionStateNewSessionSent)
		{
			// k_ab = keydata[0:31], k_ba = keydata[32:63]
			m_SendTagset = std::make_shared<RatchetTagSet>(shared_from_this ());
			m_SendTagset->DHInitialize (m_CK, keydata); // tagset_ab = DH_INITIALIZE(chainKey, k_ab)
			m_SendTagset->NextSessionTagRatchet ();
			auto receiveTagset = std::make_shared<RatchetTagSet>(shared_from_this ());
			receiveTagset->DHInitialize (m_CK, keydata + 32); // tagset_ba = DH_INITIALIZE(chainKey, k_ba)
			receiveTagset->NextSessionTagRatchet ();
			GenerateMoreReceiveTags (receiveTagset, (GetOwner () && GetOwner ()->GetNumRatchetInboundTags () > 0) ?
				GetOwner ()->GetNumRatchetInboundTags () : ECIESX25519_MIN_NUM_GENERATED_TAGS);
		}
		i2p::crypto::HKDF (keydata + 32, nullptr, 0, "AttachPayloadKDF", keydata, 32); // k = HKDF(k_ba, ZEROLEN, "AttachPayloadKDF", 32)
		// decrypt payload
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, len - 16, m_H, 32, keydata, nonce, buf, len - 16, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD decryption failed");
			return false;
		}

		if (m_State == eSessionStateNewSessionSent)
		{
			m_State = eSessionStateEstablished;
			m_EphemeralKeys = nullptr;
			m_SessionCreatedTimestamp = i2p::util::GetSecondsSinceEpoch ();
			GetOwner ()->AddECIESx25519Session (m_RemoteStaticKey, shared_from_this ());
		}
		memcpy (m_H, h, 32); // restore m_H
		HandlePayload (buf, len - 16, nullptr, 0);

		// we have received reply to NS with LeaseSet in it
		SetLeaseSetUpdateStatus (eLeaseSetUpToDate);
		SetLeaseSetUpdateMsgID (0);

		return true;
	}

	bool ECIESX25519AEADRatchetSession::NewExistingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen)
	{
		uint8_t nonce[12];
		auto index = m_SendTagset->GetNextIndex ();
		CreateNonce (index, nonce); // tag's index
		uint64_t tag = m_SendTagset->GetNextSessionTag ();
		memcpy (out, &tag, 8);
		// ad = The session tag, 8 bytes
		// ciphertext = ENCRYPT(k, n, payload, ad)
		uint8_t key[32];
		m_SendTagset->GetSymmKey (index, key);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len, out, 8, key, nonce, out + 8, outLen - 8, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD encryption failed");
			return false;
		}
		if (index >= ECIESX25519_TAGSET_MAX_NUM_TAGS && !m_SendForwardKey)
			NewNextSendRatchet ();
		return true;
	}

	bool ECIESX25519AEADRatchetSession::HandleExistingSessionMessage (uint8_t * buf, size_t len,
		std::shared_ptr<RatchetTagSet> receiveTagset, int index)
	{
		uint8_t nonce[12];
		CreateNonce (index, nonce); // tag's index
		len -= 8; // tag
		uint8_t * payload = buf + 8;
		uint8_t key[32];
		receiveTagset->GetSymmKey (index, key);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 16, buf, 8, key, nonce, payload, len - 16, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD decryption failed");
			return false;
		}
		HandlePayload (payload, len - 16, receiveTagset, index);
		if (GetOwner ())
		{	
			int moreTags = 0;
			if (GetOwner ()->GetNumRatchetInboundTags () > 0) // override in settings?
			{
				if (receiveTagset->GetNextIndex () - index < GetOwner ()->GetNumRatchetInboundTags ()/2)
					moreTags = GetOwner ()->GetNumRatchetInboundTags ();
			}
			else
			{	
				moreTags = ECIESX25519_MIN_NUM_GENERATED_TAGS + (index >> 2); // N/4
				if (moreTags > ECIESX25519_MAX_NUM_GENERATED_TAGS) moreTags = ECIESX25519_MAX_NUM_GENERATED_TAGS;
				moreTags -= (receiveTagset->GetNextIndex () - index);
			}	
			if (moreTags > 0)
				GenerateMoreReceiveTags (receiveTagset, moreTags);
		}	
		return true;
	}

	bool ECIESX25519AEADRatchetSession::HandleNextMessage (uint8_t * buf, size_t len,
		std::shared_ptr<RatchetTagSet> receiveTagset, int index)
	{
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		switch (m_State)
		{
			case eSessionStateNewSessionReplySent:
				m_State = eSessionStateEstablished;
				m_NSRSendTagset = nullptr;
				m_EphemeralKeys = nullptr;
#if (__cplusplus >= 201703L) // C++ 17 or higher
				[[fallthrough]];
#endif
			case eSessionStateEstablished:
				if (HandleExistingSessionMessage (buf, len, receiveTagset, index)) return true;
				// check NSR just in case
				LogPrint (eLogDebug, "Garlic: check for out of order NSR with index ", index);
				if (receiveTagset->GetNextIndex () - index < ECIESX25519_NSR_NUM_GENERATED_TAGS/2)
					GenerateMoreReceiveTags (receiveTagset, ECIESX25519_NSR_NUM_GENERATED_TAGS);
				return HandleNewOutgoingSessionReply (buf, len);
			case eSessionStateNew:
				return HandleNewIncomingSession (buf, len);
			case eSessionStateNewSessionSent:
				receiveTagset->Expire (); // NSR tagset
				return HandleNewOutgoingSessionReply (buf, len);
			default:
				return false;
		}
		return true;
	}

	std::shared_ptr<I2NPMessage> ECIESX25519AEADRatchetSession::WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg)
	{
		auto payload = CreatePayload (msg, m_State != eSessionStateEstablished);
		size_t len = payload.size ();
		if (!len) return nullptr;
		auto m = NewI2NPMessage (len + 100); // 96 + 4
		m->Align (12); // in order to get buf aligned to 16 (12 + 4)
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length

		switch (m_State)
		{
			case eSessionStateEstablished:
				if (!NewExistingSessionMessage (payload.data (), payload.size (), buf, m->maxLen))
					return nullptr;
				len += 24;
			break;
			case eSessionStateNew:
				if (!NewOutgoingSessionMessage (payload.data (), payload.size (), buf, m->maxLen))
					return nullptr;
				len += 96;
			break;
			case eSessionStateNewSessionReceived:
				if (!NewSessionReplyMessage (payload.data (), payload.size (), buf, m->maxLen))
					return nullptr;
				len += 72;
			break;
			case eSessionStateNewSessionReplySent:
				if (!NextNewSessionReplyMessage (payload.data (), payload.size (), buf, m->maxLen))
					return nullptr;
				len += 72;
			break;
			default:
				return nullptr;
		}

		htobe32buf (m->GetPayload (), len);
		m->len += len + 4;
		m->FillI2NPMessageHeader (eI2NPGarlic);
		return m;
	}

	std::vector<uint8_t> ECIESX25519AEADRatchetSession::CreatePayload (std::shared_ptr<const I2NPMessage> msg, bool first)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();
		size_t payloadLen = 0;
		if (first) payloadLen += 7;// datatime
		if (msg)
		{	
			payloadLen += msg->GetPayloadLength () + 13;
			if (m_Destination) payloadLen += 32;
		}	
		auto leaseSet = (GetLeaseSetUpdateStatus () == eLeaseSetUpdated ||
			(GetLeaseSetUpdateStatus () == eLeaseSetSubmitted &&
				ts > GetLeaseSetSubmissionTime () + LEASET_CONFIRMATION_TIMEOUT)) ?
			GetOwner ()->GetLeaseSet () : nullptr;
		if (leaseSet)
		{
			payloadLen += leaseSet->GetBufferLen () + DATABASE_STORE_HEADER_SIZE + 13;
			if (!first)
			{
				// ack request
				SetLeaseSetUpdateStatus (eLeaseSetSubmitted);
				SetLeaseSetUpdateMsgID (m_SendTagset->GetNextIndex ());
				SetLeaseSetSubmissionTime (ts);
				payloadLen += 4;
			}
		}
		if (m_AckRequests.size () > 0)
			payloadLen += m_AckRequests.size ()*4 + 3;
		if (m_SendReverseKey)
		{
			payloadLen += 6;
			if (m_NextReceiveRatchet->newKey) payloadLen += 32;
		}
		if (m_SendForwardKey)
		{
			payloadLen += 6;
			if (m_NextSendRatchet->newKey) payloadLen += 32;
		}
		uint8_t paddingSize = 0;
		if (payloadLen || ts > m_LastSentTimestamp + ECIESX25519_SEND_INACTIVITY_TIMEOUT)
		{
			int delta = (int)ECIESX25519_OPTIMAL_PAYLOAD_SIZE - (int)payloadLen;
			if (delta < 0 || delta > 3) // don't create padding if we are close to optimal size
			{
				paddingSize = m_PaddingSizes[m_NextPaddingSize++] & 0x0F; // 0 - 15
				if (m_NextPaddingSize >= 32)
				{
					RAND_bytes (m_PaddingSizes, 32); 
					m_NextPaddingSize = 0;
				}	
				if (delta > 3)
				{
					delta -= 3;
					if (paddingSize >= delta) paddingSize %= delta;
				}
				paddingSize++;
				payloadLen += paddingSize + 3;
			}
		}
		std::vector<uint8_t> v(payloadLen);
		if (payloadLen)
		{	
			m_LastSentTimestamp = ts;
			size_t offset = 0;
			// DateTime
			if (first)
			{
				v[offset] = eECIESx25519BlkDateTime; offset++;
				htobe16buf (v.data () + offset, 4); offset += 2;
				htobe32buf (v.data () + offset, ts/1000); offset += 4; // in seconds
			}
			// LeaseSet
			if (leaseSet)
			{
				offset += CreateLeaseSetClove (leaseSet, ts, v.data () + offset, payloadLen - offset);
				if (!first)
				{
					// ack request
					v[offset] = eECIESx25519BlkAckRequest; offset++;
					htobe16buf (v.data () + offset, 1); offset += 2;
					v[offset] = 0; offset++; // flags
				}
			}
			// msg
			if (msg && m_Destination)
				offset += CreateGarlicClove (msg, v.data () + offset, payloadLen - offset);
			// ack
			if (m_AckRequests.size () > 0)
			{
				v[offset] = eECIESx25519BlkAck; offset++;
				htobe16buf (v.data () + offset, m_AckRequests.size () * 4); offset += 2;
				for (auto& it: m_AckRequests)
				{
					htobe16buf (v.data () + offset, it.first); offset += 2;
					htobe16buf (v.data () + offset, it.second); offset += 2;
				}
				m_AckRequests.clear ();
			}
			// next keys
			if (m_SendReverseKey)
			{
				v[offset] = eECIESx25519BlkNextKey; offset++;
				htobe16buf (v.data () + offset, m_NextReceiveRatchet->newKey ? 35 : 3); offset += 2;
				v[offset] = ECIESX25519_NEXT_KEY_REVERSE_KEY_FLAG;
				int keyID = m_NextReceiveRatchet->keyID - 1;
				if (m_NextReceiveRatchet->newKey)
				{
					v[offset] |= ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG;
					keyID++;
				}
				offset++; // flag
				htobe16buf (v.data () + offset, keyID); offset += 2; // keyid
				if (m_NextReceiveRatchet->newKey)
				{
					memcpy (v.data () + offset, m_NextReceiveRatchet->key->GetPublicKey (), 32);
					offset += 32; // public key
				}
				m_SendReverseKey = false;
			}
			if (m_SendForwardKey)
			{
				v[offset] = eECIESx25519BlkNextKey; offset++;
				htobe16buf (v.data () + offset, m_NextSendRatchet->newKey ? 35 : 3); offset += 2;
				v[offset] = m_NextSendRatchet->newKey ? ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG : ECIESX25519_NEXT_KEY_REQUEST_REVERSE_KEY_FLAG;
				if (!m_NextSendRatchet->keyID) v[offset] |= ECIESX25519_NEXT_KEY_REQUEST_REVERSE_KEY_FLAG; // for first key only
				offset++; // flag
				htobe16buf (v.data () + offset, m_NextSendRatchet->keyID); offset += 2; // keyid
				if (m_NextSendRatchet->newKey)
				{
					memcpy (v.data () + offset, m_NextSendRatchet->key->GetPublicKey (), 32);
					offset += 32; // public key
				}
			}
			// padding
			if (paddingSize)
			{
				v[offset] = eECIESx25519BlkPadding; offset++;
				htobe16buf (v.data () + offset, paddingSize); offset += 2;
				memset (v.data () + offset, 0, paddingSize); offset += paddingSize;
			}
		}	
		return v;
	}

	size_t ECIESX25519AEADRatchetSession::CreateGarlicClove (std::shared_ptr<const I2NPMessage> msg, uint8_t * buf, size_t len)
	{
		if (!msg) return 0;
		uint16_t cloveSize = msg->GetPayloadLength () + 9 + 1;
		if (m_Destination) cloveSize += 32;
		if ((int)len < cloveSize + 3) return 0;
		buf[0] = eECIESx25519BlkGalicClove; // clove type
		htobe16buf (buf + 1, cloveSize); // size
		buf += 3;
		if (m_Destination)
		{
			*buf = (eGarlicDeliveryTypeDestination << 5);
			memcpy (buf + 1, *m_Destination, 32); buf += 32;
		}
		else
			*buf = 0;
		buf++;	// flag and delivery instructions
		*buf = msg->GetTypeID (); // I2NP msg type
		htobe32buf (buf + 1, msg->GetMsgID ()); // msgID
		htobe32buf (buf + 5, msg->GetExpiration () / 1000); // expiration in seconds
		memcpy (buf + 9, msg->GetPayload (), msg->GetPayloadLength ());
		return cloveSize + 3;
	}

	size_t ECIESX25519AEADRatchetSession::CreateLeaseSetClove (std::shared_ptr<const i2p::data::LocalLeaseSet> ls, uint64_t ts, uint8_t * buf, size_t len)
	{
		if (!ls || ls->GetStoreType () != i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2)
		{
			LogPrint (eLogError, "Garlic: Incorrect LeasetSet type to send");
			return 0;
		}
		uint16_t cloveSize = 1 + 9 + DATABASE_STORE_HEADER_SIZE + ls->GetBufferLen (); // to local
		if ((int)len < cloveSize + 3) return 0;
		buf[0] = eECIESx25519BlkGalicClove; // clove type
		htobe16buf (buf + 1, cloveSize); // size
		buf += 3;
		*buf = 0; buf++; // flag and delivery instructions
		*buf = eI2NPDatabaseStore; buf++; // I2NP msg type
		RAND_bytes (buf, 4); buf += 4; // msgID
		htobe32buf (buf, (ts + I2NP_MESSAGE_EXPIRATION_TIMEOUT)/1000); buf += 4; // expiration
		// payload
		memcpy (buf + DATABASE_STORE_KEY_OFFSET, ls->GetStoreHash (), 32);
		buf[DATABASE_STORE_TYPE_OFFSET] = i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2;
		memset (buf + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0, 4); // replyToken = 0
		buf += DATABASE_STORE_HEADER_SIZE;
		memcpy (buf, ls->GetBuffer (), ls->GetBufferLen ());

		return cloveSize + 3;
	}

	void ECIESX25519AEADRatchetSession::GenerateMoreReceiveTags (std::shared_ptr<RatchetTagSet> receiveTagset, int numTags)
	{
		for (int i = 0; i < numTags; i++)
			GetOwner ()->AddECIESx25519SessionNextTag (receiveTagset);
	}

	bool ECIESX25519AEADRatchetSession::CheckExpired (uint64_t ts)
	{
		CleanupUnconfirmedLeaseSet (ts);
		return ts > m_LastActivityTimestamp + ECIESX25519_EXPIRATION_TIMEOUT;
	}

	std::shared_ptr<I2NPMessage> WrapECIESX25519AEADRatchetMessage (std::shared_ptr<const I2NPMessage> msg, const uint8_t * key, uint64_t tag)
	{
		auto m = NewI2NPMessage ();
		m->Align (12); // in order to get buf aligned to 16 (12 + 4)
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length
		uint8_t nonce[12];
		memset (nonce, 0, 12); // n = 0
		size_t offset = 0;
		memcpy (buf + offset, &tag, 8); offset += 8;
		auto payload = buf + offset;
		uint16_t cloveSize = msg->GetPayloadLength () + 9 + 1;
		size_t len = cloveSize + 3;
		payload[0] = eECIESx25519BlkGalicClove; // clove type
		htobe16buf (payload + 1, cloveSize); // size
		payload += 3;
		*payload = 0; payload++; // flag and delivery instructions
		*payload = msg->GetTypeID (); // I2NP msg type
		htobe32buf (payload + 1, msg->GetMsgID ()); // msgID
		htobe32buf (payload + 5, msg->GetExpiration () / 1000); // expiration in seconds
		memcpy (payload + 9, msg->GetPayload (), msg->GetPayloadLength ());

		if (!i2p::crypto::AEADChaCha20Poly1305 (buf + offset, len, buf, 8, key, nonce, buf + offset, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD encryption failed");
			return nullptr;
		}
		offset += len + 16;

		htobe32buf (m->GetPayload (), offset);
		m->len += offset + 4;
		m->FillI2NPMessageHeader (eI2NPGarlic);
		return m;
	}

}
}
