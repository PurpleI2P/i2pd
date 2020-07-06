/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "Log.h"
#include "Gost.h"
#include "CryptoKey.h"

namespace i2p
{
namespace crypto
{
	ElGamalEncryptor::ElGamalEncryptor (const uint8_t * pub)
	{
		memcpy (m_PublicKey, pub, 256);
	}

	void ElGamalEncryptor::Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding)
	{
		if (!ctx) return;
		ElGamalEncrypt (m_PublicKey, data, encrypted, ctx, zeroPadding);
	}

	ElGamalDecryptor::ElGamalDecryptor (const uint8_t * priv)
	{
		memcpy (m_PrivateKey, priv, 256);
	}

	bool ElGamalDecryptor::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding)
	{
		if (!ctx) return false;
		return ElGamalDecrypt (m_PrivateKey, encrypted, data, ctx, zeroPadding);
	}

	ECIESP256Encryptor::ECIESP256Encryptor (const uint8_t * pub)
	{
		m_Curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
		m_PublicKey = EC_POINT_new (m_Curve);
		BIGNUM * x = BN_bin2bn (pub, 32, nullptr);
		BIGNUM * y = BN_bin2bn (pub + 32, 32, nullptr);
		if (!EC_POINT_set_affine_coordinates_GFp (m_Curve, m_PublicKey, x, y, nullptr))
			LogPrint (eLogError, "ECICS P256 invalid public key");
		BN_free (x); BN_free (y);
	}

	ECIESP256Encryptor::~ECIESP256Encryptor ()
	{
		if (m_Curve) EC_GROUP_free (m_Curve);
		if (m_PublicKey) EC_POINT_free (m_PublicKey);
	}

	void ECIESP256Encryptor::Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding)
	{
		if (m_Curve && m_PublicKey)
			ECIESEncrypt (m_Curve, m_PublicKey, data, encrypted, ctx, zeroPadding);
	}

	ECIESP256Decryptor::ECIESP256Decryptor (const uint8_t * priv)
	{
		m_Curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
		m_PrivateKey = BN_bin2bn (priv, 32, nullptr);
	}

	ECIESP256Decryptor::~ECIESP256Decryptor ()
	{
		if (m_Curve) EC_GROUP_free (m_Curve);
		if (m_PrivateKey) BN_free (m_PrivateKey);
	}

	bool ECIESP256Decryptor::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding)
	{
		if (m_Curve && m_PrivateKey)
			return ECIESDecrypt (m_Curve, m_PrivateKey, encrypted, data, ctx, zeroPadding);
		return false;
	}

	void CreateECIESP256RandomKeys (uint8_t * priv, uint8_t * pub)
	{
		EC_GROUP * curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
		EC_POINT * p = nullptr;
		BIGNUM * key = nullptr;
		GenerateECIESKeyPair (curve, key, p);
		bn2buf (key, priv, 32);
		RAND_bytes (priv + 32, 224);
		BN_free (key);
		BIGNUM * x = BN_new (), * y = BN_new ();
		EC_POINT_get_affine_coordinates_GFp (curve, p, x, y, NULL);
		bn2buf (x, pub, 32);
		bn2buf (y, pub + 32, 32);
		RAND_bytes (pub + 64, 192);
		EC_POINT_free (p);
		BN_free (x); BN_free (y);
		EC_GROUP_free (curve);
	}

	ECIESGOSTR3410Encryptor::ECIESGOSTR3410Encryptor (const uint8_t * pub)
	{
		auto& curve = GetGOSTR3410Curve (eGOSTR3410CryptoProA);
		m_PublicKey = EC_POINT_new (curve->GetGroup ());
		BIGNUM * x = BN_bin2bn (pub, 32, nullptr);
		BIGNUM * y = BN_bin2bn (pub + 32, 32, nullptr);
		if (!EC_POINT_set_affine_coordinates_GFp (curve->GetGroup (), m_PublicKey, x, y, nullptr))
			LogPrint (eLogError, "ECICS GOST R 34.10 invalid public key");
		BN_free (x); BN_free (y);
	}

	ECIESGOSTR3410Encryptor::~ECIESGOSTR3410Encryptor ()
	{
		if (m_PublicKey) EC_POINT_free (m_PublicKey);
	}

	void ECIESGOSTR3410Encryptor::Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding)
	{
		if (m_PublicKey)
			ECIESEncrypt (GetGOSTR3410Curve (eGOSTR3410CryptoProA)->GetGroup (), m_PublicKey, data, encrypted, ctx, zeroPadding);
	}

	ECIESGOSTR3410Decryptor::ECIESGOSTR3410Decryptor (const uint8_t * priv)
	{
		m_PrivateKey = BN_bin2bn (priv, 32, nullptr);
	}

	ECIESGOSTR3410Decryptor::~ECIESGOSTR3410Decryptor ()
	{
		if (m_PrivateKey) BN_free (m_PrivateKey);
	}

	bool ECIESGOSTR3410Decryptor::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding)
	{
		if (m_PrivateKey)
			return ECIESDecrypt (GetGOSTR3410Curve (eGOSTR3410CryptoProA)->GetGroup (), m_PrivateKey, encrypted, data, ctx, zeroPadding);
		return false;
	}


	void CreateECIESGOSTR3410RandomKeys (uint8_t * priv, uint8_t * pub)
	{
		auto& curve = GetGOSTR3410Curve (eGOSTR3410CryptoProA);
		EC_POINT * p = nullptr;
		BIGNUM * key = nullptr;
		GenerateECIESKeyPair (curve->GetGroup (), key, p);
		bn2buf (key, priv, 32);
		RAND_bytes (priv + 32, 224);
		BN_free (key);
		BIGNUM * x = BN_new (), * y = BN_new ();
		EC_POINT_get_affine_coordinates_GFp (curve->GetGroup (), p, x, y, NULL);
		bn2buf (x, pub, 32);
		bn2buf (y, pub + 32, 32);
		RAND_bytes (pub + 64, 192);
		EC_POINT_free (p);
		BN_free (x); BN_free (y);
	}

	ECIESX25519AEADRatchetEncryptor::ECIESX25519AEADRatchetEncryptor (const uint8_t * pub)
	{
		memcpy (m_PublicKey, pub, 32);
	}

	void ECIESX25519AEADRatchetEncryptor::Encrypt (const uint8_t *, uint8_t * pub, BN_CTX *, bool)
	{
		memcpy (pub, m_PublicKey, 32);
	}

	ECIESX25519AEADRatchetDecryptor::ECIESX25519AEADRatchetDecryptor (const uint8_t * priv, bool calculatePublic)
	{
		m_StaticKeys.SetPrivateKey (priv, calculatePublic);
	}

	bool ECIESX25519AEADRatchetDecryptor::Decrypt (const uint8_t * epub, uint8_t * sharedSecret, BN_CTX * ctx, bool zeroPadding)
	{
		m_StaticKeys.Agree (epub, sharedSecret);
		return true;
	}

	void CreateECIESX25519AEADRatchetRandomKeys (uint8_t * priv, uint8_t * pub)
	{
		X25519Keys k;
		k.GenerateKeys ();
		k.GetPrivateKey (priv);
		memcpy (pub, k.GetPublicKey (), 32);
	}
}
}
