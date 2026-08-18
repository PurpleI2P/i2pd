/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstdint>
#include <zlib.h> // for crc32
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "Base.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2PEndian.h"
#include "Ed25519.h"
#include "Signature.h"
#include "Blinding.h"

namespace i2p
{
namespace data
{
	const uint8_t B33_TWO_BYTES_SIGTYPE_FLAG = 0x01;
	// const uint8_t B33_PER_SECRET_FLAG = 0x02; // not used for now
	const uint8_t B33_PER_CLIENT_AUTH_FLAG = 0x04;

	BlindedPublicKey::BlindedPublicKey (std::shared_ptr<const IdentityEx> identity, bool clientAuth):
		m_IsClientAuth (clientAuth)
	{
		if (!identity) return;
		m_SigType = identity->GetSigningKeyType ();
		m_BlindedSigType = i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519; // always 11
		if (m_SigType == i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 ||
			m_SigType == i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519)
			memcpy (m_PublicKey.data (), identity->GetSigningPublicKeyBuffer (), m_PublicKey.size ());
		else
			LogPrint (eLogError, "Blinding: Unsupported signature type ", (int)m_SigType);
	}

	BlindedPublicKey::BlindedPublicKey (std::string_view b33):
		m_SigType (0) // 0 means invalid, we can't blind DSA, set it later
	{
		uint8_t addr[40]; // TODO: define length from b33
		size_t l = i2p::data::Base32ToByteStream (b33, addr, 40);
		if (l < 32)
		{
			LogPrint (eLogError, "Blinding: Malformed b33 ", b33);
			return;
		}
		uint32_t checksum = crc32 (0, addr + 3, l - 3);
		// checksum is Little Endian
		addr[0] ^= checksum; addr[1] ^= (checksum >> 8); addr[2] ^= (checksum >> 16);
		uint8_t flags = addr[0];
		size_t offset = 1;
		if (flags & B33_TWO_BYTES_SIGTYPE_FLAG) // two bytes signatures
		{
			m_SigType = bufbe16toh (addr + offset); offset += 2;
			m_BlindedSigType = bufbe16toh (addr + offset); offset += 2;
		}
		else // one byte sig
		{
			m_SigType = addr[offset]; offset++;
			m_BlindedSigType = addr[offset]; offset++;
		}
		m_IsClientAuth = flags & B33_PER_CLIENT_AUTH_FLAG;

		std::unique_ptr<i2p::crypto::Verifier> blindedVerifier (i2p::data::IdentityEx::CreateVerifier (m_SigType));
		if (blindedVerifier)
		{
			if (offset + m_PublicKey.size () <= l)
				memcpy (m_PublicKey.data (), addr + offset, m_PublicKey.size ());
			else
				LogPrint (eLogError, "Blinding: Public key in b33 address is too short for signature type ", (int)m_SigType);
		}
		else
			LogPrint (eLogError, "Blinding: Unknown signature type ", (int)m_SigType, " in b33");
	}

	bool BlindedPublicKey::IsValid () const
	{
		switch (m_SigType)
		{
			case i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
			case i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
				return true;
			default:
				return false;
		}
	}

	std::string BlindedPublicKey::ToB33 () const
	{
		if (m_PublicKey.size () > 32) return ""; // assume 25519
		uint8_t addr[35];
		uint8_t flags = 0;
		if (m_IsClientAuth) flags |= B33_PER_CLIENT_AUTH_FLAG;
		addr[0] = flags; // flags
		addr[1] = m_SigType; // sig type
		addr[2] = m_BlindedSigType; // blinded sig type
		memcpy (addr + 3, m_PublicKey.data (), m_PublicKey.size ());
		uint32_t checksum = crc32 (0, addr + 3, m_PublicKey.size ());
		// checksum is Little Endian
		addr[0] ^= checksum; addr[1] ^= (checksum >> 8); addr[2] ^= (checksum >> 16);
		return ByteStreamToBase32 (addr, m_PublicKey.size () + 3);
	}

	void BlindedPublicKey::GetCredential (uint8_t * credential) const
	{
		// A = destination's signing public key
		// stA = signature type of A, 2 bytes big endian
		uint16_t stA = htobe16 (GetSigType ());
		// stA1 = signature type of blinded A, 2 bytes big endian
		uint16_t stA1 = htobe16 (GetBlindedSigType ());
		// credential = H("credential", A || stA || stA1)
		H ("credential", { {GetPublicKey (), GetPublicKeyLen ()}, {(const uint8_t *)&stA, 2}, {(const uint8_t *)&stA1, 2} }, credential);
	}

	void BlindedPublicKey::GetSubcredential (const uint8_t * blinded, size_t len, uint8_t * subcredential) const
	{
		uint8_t credential[32];
		GetCredential (credential);
		// subcredential = H("subcredential", credential || blindedPublicKey)
		H ("subcredential", { {credential, 32}, {blinded, len} }, subcredential);
	}

	void BlindedPublicKey::GenerateAlpha (const char * date, uint8_t * seed) const
	{
		uint16_t stA = htobe16 (GetSigType ()), stA1 = htobe16 (GetBlindedSigType ());
		uint8_t salt[32];
		//seed = HKDF(H("I2PGenerateAlpha", keydata), datestring || secret, "i2pblinding1", 64)
		H ("I2PGenerateAlpha", { {GetPublicKey (), GetPublicKeyLen ()}, {(const uint8_t *)&stA, 2}, {(const uint8_t *)&stA1, 2} }, salt);
		i2p::crypto::HKDF (salt, (const uint8_t *)date, 8, "i2pblinding1", seed);
	}

	size_t BlindedPublicKey::GetBlindedKey (const char * date, uint8_t * blindedKey) const
	{
		uint8_t seed[64];
		GenerateAlpha (date, seed);

		size_t publicKeyLength = 0;
		switch (m_SigType)
		{
			case i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
			case i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
				i2p::crypto::GetEd25519 ()->BlindPublicKey (GetPublicKey (), seed, blindedKey);
				publicKeyLength = i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH;
			break;
			default:
				LogPrint (eLogError, "Blinding: Can't blind signature type ", (int)m_SigType);
		}
		return publicKeyLength;
	}

	size_t BlindedPublicKey::BlindPrivateKey (const uint8_t * priv, const char * date, uint8_t * blindedPriv, uint8_t * blindedPub) const
	{
		uint8_t seed[64];
		GenerateAlpha (date, seed);
		size_t publicKeyLength = 0;
		switch (m_SigType)
		{
			case i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
				i2p::crypto::GetEd25519 ()->BlindPrivateKey (priv, seed, blindedPriv, blindedPub);
				publicKeyLength = i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH;
			break;
			case i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
			{
				uint8_t exp[64];
				i2p::crypto::Ed25519::ExpandPrivateKey (priv, exp);
				i2p::crypto::GetEd25519 ()->BlindPrivateKey (exp, seed, blindedPriv, blindedPub);
				publicKeyLength = i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH;
				break;
			}
			default:
				LogPrint (eLogError, "Blinding: Can't blind signature type ", (int)m_SigType);
		}
		return publicKeyLength;
	}

	void BlindedPublicKey::H (const std::string& p, const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * hash) const
	{
		EVP_MD_CTX *ctx = EVP_MD_CTX_new ();

		EVP_DigestInit_ex(ctx, EVP_sha256 (), NULL);
		EVP_DigestUpdate (ctx, p.c_str (), p.length ());
		for (const auto& it: bufs)
			EVP_DigestUpdate (ctx, it.first, it.second);
		EVP_DigestFinal_ex (ctx, (uint8_t * )hash, nullptr);
		EVP_MD_CTX_free (ctx);
	}

	i2p::data::IdentHash BlindedPublicKey::GetStoreHash (const char * date) const
	{
		i2p::data::IdentHash hash{};
		uint8_t blinded[i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH]; // 32 max
		size_t publicKeyLength = 0;
		if (date)
			publicKeyLength = GetBlindedKey (date, blinded);
		else
		{
			char currentDate[9];
			i2p::util::GetCurrentDate (currentDate);
			publicKeyLength = GetBlindedKey (currentDate, blinded);
		}
		if (publicKeyLength)
		{
			auto stA1 = htobe16 (m_BlindedSigType);
			EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
			EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
			EVP_DigestUpdate (ctx, (const uint8_t *)&stA1, 2);
			EVP_DigestUpdate (ctx, blinded, publicKeyLength);
			EVP_DigestFinal_ex (ctx, (uint8_t * )hash, nullptr);
			EVP_MD_CTX_free(ctx);
		}
		else
			LogPrint (eLogError, "Blinding: Blinded key type ", (int)m_BlindedSigType, " is not supported");
		return hash;
	}

}
}
