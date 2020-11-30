/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/crypto.h>
#include "TunnelBase.h"
#include <openssl/ssl.h>
#if OPENSSL_HKDF
#include <openssl/kdf.h>
#endif
#if !OPENSSL_AEAD_CHACHA20_POLY1305
#include "ChaCha20.h"
#include "Poly1305.h"
#endif
#include "Crypto.h"
#include "Ed25519.h"
#include "I2PEndian.h"
#include "Log.h"

namespace i2p
{
namespace crypto
{
	const uint8_t elgp_[256]=
	{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
		0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
		0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
		0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
		0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
		0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	const int elgg_ = 2;

	const uint8_t dsap_[128]=
	{
		0x9c, 0x05, 0xb2, 0xaa, 0x96, 0x0d, 0x9b, 0x97, 0xb8, 0x93, 0x19, 0x63, 0xc9, 0xcc, 0x9e, 0x8c,
		0x30, 0x26, 0xe9, 0xb8, 0xed, 0x92, 0xfa, 0xd0, 0xa6, 0x9c, 0xc8, 0x86, 0xd5, 0xbf, 0x80, 0x15,
		0xfc, 0xad, 0xae, 0x31, 0xa0, 0xad, 0x18, 0xfa, 0xb3, 0xf0, 0x1b, 0x00, 0xa3, 0x58, 0xde, 0x23,
		0x76, 0x55, 0xc4, 0x96, 0x4a, 0xfa, 0xa2, 0xb3, 0x37, 0xe9, 0x6a, 0xd3, 0x16, 0xb9, 0xfb, 0x1c,
		0xc5, 0x64, 0xb5, 0xae, 0xc5, 0xb6, 0x9a, 0x9f, 0xf6, 0xc3, 0xe4, 0x54, 0x87, 0x07, 0xfe, 0xf8,
		0x50, 0x3d, 0x91, 0xdd, 0x86, 0x02, 0xe8, 0x67, 0xe6, 0xd3, 0x5d, 0x22, 0x35, 0xc1, 0x86, 0x9c,
		0xe2, 0x47, 0x9c, 0x3b, 0x9d, 0x54, 0x01, 0xde, 0x04, 0xe0, 0x72, 0x7f, 0xb3, 0x3d, 0x65, 0x11,
		0x28, 0x5d, 0x4c, 0xf2, 0x95, 0x38, 0xd9, 0xe3, 0xb6, 0x05, 0x1f, 0x5b, 0x22, 0xcc, 0x1c, 0x93
	};

	const uint8_t dsaq_[20]=
	{
		0xa5, 0xdf, 0xc2, 0x8f, 0xef, 0x4c, 0xa1, 0xe2, 0x86, 0x74, 0x4c, 0xd8, 0xee, 0xd9, 0xd2, 0x9d,
		0x68, 0x40, 0x46, 0xb7
	};

	const uint8_t dsag_[128]=
	{
		0x0c, 0x1f, 0x4d, 0x27, 0xd4, 0x00, 0x93, 0xb4, 0x29, 0xe9, 0x62, 0xd7, 0x22, 0x38, 0x24, 0xe0,
		0xbb, 0xc4, 0x7e, 0x7c, 0x83, 0x2a, 0x39, 0x23, 0x6f, 0xc6, 0x83, 0xaf, 0x84, 0x88, 0x95, 0x81,
		0x07, 0x5f, 0xf9, 0x08, 0x2e, 0xd3, 0x23, 0x53, 0xd4, 0x37, 0x4d, 0x73, 0x01, 0xcd, 0xa1, 0xd2,
		0x3c, 0x43, 0x1f, 0x46, 0x98, 0x59, 0x9d, 0xda, 0x02, 0x45, 0x18, 0x24, 0xff, 0x36, 0x97, 0x52,
		0x59, 0x36, 0x47, 0xcc, 0x3d, 0xdc, 0x19, 0x7d, 0xe9, 0x85, 0xe4, 0x3d, 0x13, 0x6c, 0xdc, 0xfc,
		0x6b, 0xd5, 0x40, 0x9c, 0xd2, 0xf4, 0x50, 0x82, 0x11, 0x42, 0xa5, 0xe6, 0xf8, 0xeb, 0x1c, 0x3a,
		0xb5, 0xd0, 0x48, 0x4b, 0x81, 0x29, 0xfc, 0xf1, 0x7b, 0xce, 0x4f, 0x7f, 0x33, 0x32, 0x1c, 0x3c,
		0xb3, 0xdb, 0xb1, 0x4a, 0x90, 0x5e, 0x7b, 0x2b, 0x3e, 0x93, 0xbe, 0x47, 0x08, 0xcb, 0xcc, 0x82
	};

	const int rsae_ = 65537;

	struct CryptoConstants
	{
		// DH/ElGamal
		BIGNUM * elgp;
		BIGNUM * elgg;

		// DSA
		BIGNUM * dsap;
		BIGNUM * dsaq;
		BIGNUM * dsag;

		// RSA
		BIGNUM * rsae;

		CryptoConstants (const uint8_t * elgp_, int elgg_, const uint8_t * dsap_,
			const uint8_t * dsaq_, const uint8_t * dsag_, int rsae_)
		{
			elgp = BN_new ();
			BN_bin2bn (elgp_, 256, elgp);
			elgg = BN_new ();
			BN_set_word (elgg, elgg_);
			dsap = BN_new ();
			BN_bin2bn (dsap_, 128, dsap);
			dsaq = BN_new ();
			BN_bin2bn (dsaq_, 20, dsaq);
			dsag = BN_new ();
			BN_bin2bn (dsag_, 128, dsag);
			rsae = BN_new ();
			BN_set_word (rsae, rsae_);
		}

		~CryptoConstants ()
		{
			BN_free (elgp); BN_free (elgg); BN_free (dsap); BN_free (dsaq); BN_free (dsag); BN_free (rsae);
		}
	};

	static const CryptoConstants& GetCryptoConstants ()
	{
		static CryptoConstants cryptoConstants (elgp_, elgg_, dsap_, dsaq_, dsag_, rsae_);
		return cryptoConstants;
	}

	bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len)
	{
		int offset = len - BN_num_bytes (bn);
		if (offset < 0) return false;
		BN_bn2bin (bn, buf + offset);
		memset (buf, 0, offset);
		return true;
	}

// RSA
	#define rsae GetCryptoConstants ().rsae
	const BIGNUM * GetRSAE ()
	{
		return rsae;
	}

// DSA
	#define dsap GetCryptoConstants ().dsap
	#define dsaq GetCryptoConstants ().dsaq
	#define dsag GetCryptoConstants ().dsag
	DSA * CreateDSA ()
	{
		DSA * dsa = DSA_new ();
		DSA_set0_pqg (dsa, BN_dup (dsap), BN_dup (dsaq), BN_dup (dsag));
		DSA_set0_key (dsa, NULL, NULL);
		return dsa;
	}

// DH/ElGamal

	const int ELGAMAL_SHORT_EXPONENT_NUM_BITS = 226;
	const int ELGAMAL_SHORT_EXPONENT_NUM_BYTES = ELGAMAL_SHORT_EXPONENT_NUM_BITS/8+1;
	const int ELGAMAL_FULL_EXPONENT_NUM_BITS = 2048;
	const int ELGAMAL_FULL_EXPONENT_NUM_BYTES = ELGAMAL_FULL_EXPONENT_NUM_BITS/8;

	#define elgp GetCryptoConstants ().elgp
	#define elgg GetCryptoConstants ().elgg

	static BN_MONT_CTX * g_MontCtx = nullptr;
	static void PrecalculateElggTable (BIGNUM * table[][255], int len) // table is len's array of array of 255 bignums
	{
		if (len <= 0) return;
		BN_CTX * ctx = BN_CTX_new ();
		g_MontCtx = BN_MONT_CTX_new ();
		BN_MONT_CTX_set (g_MontCtx, elgp, ctx);
		auto montCtx = BN_MONT_CTX_new ();
		BN_MONT_CTX_copy (montCtx, g_MontCtx);
		for (int i = 0; i < len; i++)
		{
			table[i][0] = BN_new ();
			if (!i)
				BN_to_montgomery (table[0][0], elgg, montCtx, ctx);
			else
				BN_mod_mul_montgomery (table[i][0], table[i-1][254], table[i-1][0], montCtx, ctx);
			for (int j = 1; j < 255; j++)
			{
				table[i][j] = BN_new ();
				BN_mod_mul_montgomery (table[i][j], table[i][j-1], table[i][0], montCtx, ctx);
			}
		}
		BN_MONT_CTX_free (montCtx);
		BN_CTX_free (ctx);
	}

	static void DestroyElggTable (BIGNUM * table[][255], int len)
	{
		for (int i = 0; i < len; i++)
			for (int j = 0; j < 255; j++)
			{
				BN_free (table[i][j]);
				table[i][j] = nullptr;
			}
		BN_MONT_CTX_free (g_MontCtx);
	}

	static BIGNUM * ElggPow (const uint8_t * exp, int len, BIGNUM * table[][255], BN_CTX * ctx)
	// exp is in Big Endian
	{
		if (len <= 0) return nullptr;
		auto montCtx = BN_MONT_CTX_new ();
		BN_MONT_CTX_copy (montCtx, g_MontCtx);
		BIGNUM * res = nullptr;
		for (int i = 0; i < len; i++)
		{
			if (res)
			{
				if (exp[i])
					BN_mod_mul_montgomery (res, res, table[len-1-i][exp[i]-1], montCtx, ctx);
			}
			else if (exp[i])
				res = BN_dup (table[len-i-1][exp[i]-1]);
		}
		if (res)
			BN_from_montgomery (res, res, montCtx, ctx);
		BN_MONT_CTX_free (montCtx);
		return res;
	}

	static BIGNUM * ElggPow (const BIGNUM * exp, BIGNUM * table[][255], BN_CTX * ctx)
	{
		auto len = BN_num_bytes (exp);
		uint8_t * buf = new uint8_t[len];
		BN_bn2bin (exp, buf);
		auto ret = ElggPow (buf, len, table, ctx);
		delete[] buf;
		return ret;
	}

	static BIGNUM * (* g_ElggTable)[255] = nullptr;

// DH

	DHKeys::DHKeys ()
	{
		m_DH = DH_new ();
		DH_set0_pqg (m_DH, BN_dup (elgp), NULL, BN_dup (elgg));
		DH_set0_key (m_DH, NULL, NULL);
	}

	DHKeys::~DHKeys ()
	{
		DH_free (m_DH);
	}

	void DHKeys::GenerateKeys ()
	{
		BIGNUM * priv_key = NULL, * pub_key = NULL;
#if !defined(__x86_64__) // use short exponent for non x64
		priv_key = BN_new ();
		BN_rand (priv_key, ELGAMAL_SHORT_EXPONENT_NUM_BITS, 0, 1);
#endif
		if (g_ElggTable)
		{
#if defined(__x86_64__)
			priv_key = BN_new ();
			BN_rand (priv_key, ELGAMAL_FULL_EXPONENT_NUM_BITS, 0, 1);
#endif
			auto ctx = BN_CTX_new ();
			pub_key = ElggPow (priv_key, g_ElggTable, ctx);
			DH_set0_key (m_DH, pub_key, priv_key);
			BN_CTX_free (ctx);
		}
		else
		{
			DH_set0_key (m_DH, NULL, priv_key);
			DH_generate_key (m_DH);
			DH_get0_key (m_DH, (const BIGNUM **)&pub_key, (const BIGNUM **)&priv_key);
		}

		bn2buf (pub_key, m_PublicKey, 256);
	}

	void DHKeys::Agree (const uint8_t * pub, uint8_t * shared)
	{
		BIGNUM * pk = BN_bin2bn (pub, 256, NULL);
		DH_compute_key (shared, pk, m_DH);
		BN_free (pk);
	}

// x25519
	X25519Keys::X25519Keys ()
	{
#if OPENSSL_X25519
		m_Ctx = EVP_PKEY_CTX_new_id (NID_X25519, NULL);
		m_Pkey = nullptr;
#else
		m_Ctx = BN_CTX_new ();
#endif
	}

	X25519Keys::X25519Keys (const uint8_t * priv, const uint8_t * pub)
	{
#if OPENSSL_X25519
		m_Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, NULL, priv, 32);
		m_Ctx = EVP_PKEY_CTX_new (m_Pkey, NULL);
		if (pub)
			memcpy (m_PublicKey, pub, 32); // TODO: verify against m_Pkey
		else
		{
			size_t len = 32;
			EVP_PKEY_get_raw_public_key (m_Pkey, m_PublicKey, &len);
		}
#else
		m_Ctx = BN_CTX_new ();
		memcpy (m_PrivateKey, priv, 32);
		if (pub)
			memcpy (m_PublicKey, pub, 32);
		else
			GetEd25519 ()->ScalarMulB (m_PrivateKey, m_PublicKey, m_Ctx);
#endif
	}

	X25519Keys::~X25519Keys ()
	{
#if OPENSSL_X25519
		EVP_PKEY_CTX_free (m_Ctx);
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
#else
		BN_CTX_free (m_Ctx);
#endif
	}

	void X25519Keys::GenerateKeys ()
	{
#if OPENSSL_X25519
		if (m_Pkey)
		{
			EVP_PKEY_free (m_Pkey);
			m_Pkey = nullptr;
		}
		EVP_PKEY_keygen_init (m_Ctx);
		EVP_PKEY_keygen (m_Ctx, &m_Pkey);
		EVP_PKEY_CTX_free (m_Ctx);
		m_Ctx = EVP_PKEY_CTX_new (m_Pkey, NULL); // TODO: do we really need to re-create m_Ctx?
		size_t len = 32;
		EVP_PKEY_get_raw_public_key (m_Pkey, m_PublicKey, &len);
#else
		RAND_bytes (m_PrivateKey, 32);
		GetEd25519 ()->ScalarMulB (m_PrivateKey, m_PublicKey, m_Ctx);
#endif
	}

	void X25519Keys::Agree (const uint8_t * pub, uint8_t * shared)
	{
#if OPENSSL_X25519
		EVP_PKEY_derive_init (m_Ctx);
		auto pkey = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, NULL, pub, 32);
		EVP_PKEY_derive_set_peer (m_Ctx, pkey);
		size_t len = 32;
		EVP_PKEY_derive (m_Ctx, shared, &len);
		EVP_PKEY_free (pkey);
#else
		GetEd25519 ()->ScalarMul (pub, m_PrivateKey, shared, m_Ctx);
#endif
	}

	void X25519Keys::GetPrivateKey (uint8_t * priv) const
	{
#if OPENSSL_X25519
		size_t len = 32;
		EVP_PKEY_get_raw_private_key (m_Pkey, priv, &len);
#else
		memcpy (priv, m_PrivateKey, 32);
#endif
	}

	void X25519Keys::SetPrivateKey (const uint8_t * priv, bool calculatePublic)
	{
#if OPENSSL_X25519
		if (m_Ctx) EVP_PKEY_CTX_free (m_Ctx);
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
		m_Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, NULL, priv, 32);
		m_Ctx = EVP_PKEY_CTX_new (m_Pkey, NULL);
		if (calculatePublic)
		{
			size_t len = 32;
			EVP_PKEY_get_raw_public_key (m_Pkey, m_PublicKey, &len);
		}	
#else
		memcpy (m_PrivateKey, priv, 32);
		if (calculatePublic)
			GetEd25519 ()->ScalarMulB (m_PrivateKey, m_PublicKey, m_Ctx);
#endif
	}

// ElGamal
	void ElGamalEncrypt (const uint8_t * key, const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding)
	{
		BN_CTX_start (ctx);
		// everything, but a, because a might come from table
		BIGNUM * k = BN_CTX_get (ctx);
		BIGNUM * y = BN_CTX_get (ctx);
		BIGNUM * b1 = BN_CTX_get (ctx);
		BIGNUM * b = BN_CTX_get (ctx);
		// select random k
#if defined(__x86_64__)
		BN_rand (k, ELGAMAL_FULL_EXPONENT_NUM_BITS, -1, 1); // full exponent for x64
#else
		BN_rand (k, ELGAMAL_SHORT_EXPONENT_NUM_BITS, -1, 1); // short exponent of 226 bits
#endif
		// calculate a
		BIGNUM * a;
		if (g_ElggTable)
			a = ElggPow (k, g_ElggTable, ctx);
		else
		{
			a = BN_new ();
			BN_mod_exp (a, elgg, k, elgp, ctx);
		}

		// restore y from key
		BN_bin2bn (key, 256, y);
		// calculate b1
		BN_mod_exp (b1, y, k, elgp, ctx);
		// create m
		uint8_t m[255];
		m[0] = 0xFF;
		memcpy (m+33, data, 222);
		SHA256 (m+33, 222, m+1);
		// calculate b = b1*m mod p
		BN_bin2bn (m, 255, b);
		BN_mod_mul (b, b1, b, elgp, ctx);
		// copy a and b
		if (zeroPadding)
		{
			encrypted[0] = 0;
			bn2buf (a, encrypted + 1, 256);
			encrypted[257] = 0;
			bn2buf (b, encrypted + 258, 256);
		}
		else
		{
			bn2buf (a, encrypted, 256);
			bn2buf (b, encrypted + 256, 256);
		}
		BN_free (a);
		BN_CTX_end (ctx);
	}

	bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted,
		uint8_t * data, BN_CTX * ctx, bool zeroPadding)
	{
		BN_CTX_start (ctx);
		BIGNUM * x = BN_CTX_get (ctx), * a = BN_CTX_get (ctx), * b = BN_CTX_get (ctx);
		BN_bin2bn (key, 256, x);
		BN_sub (x, elgp, x); BN_sub_word (x, 1); // x = elgp - x- 1
		BN_bin2bn (zeroPadding ? encrypted + 1 : encrypted, 256, a);
		BN_bin2bn (zeroPadding ? encrypted + 258 : encrypted + 256, 256, b);
		// m = b*(a^x mod p) mod p
		BN_mod_exp (x, a, x, elgp, ctx);
		BN_mod_mul (b, b, x, elgp, ctx);
		uint8_t m[255];
		bn2buf (b, m, 255);
		BN_CTX_end (ctx);
		uint8_t hash[32];
		SHA256 (m + 33, 222, hash);
		if (memcmp (m + 1, hash, 32))
		{
			LogPrint (eLogError, "ElGamal decrypt hash doesn't match");
			return false;
		}
		memcpy (data, m + 33, 222);
		return true;
	}

	void GenerateElGamalKeyPair (uint8_t * priv, uint8_t * pub)
	{
#if defined(__x86_64__) || defined(__i386__) || defined(_MSC_VER)
		RAND_bytes (priv, 256);
#else
		// lower 226 bits (28 bytes and 2 bits) only. short exponent
		auto numBytes = (ELGAMAL_SHORT_EXPONENT_NUM_BITS)/8 + 1; // 29
		auto numZeroBytes = 256 - numBytes;
		RAND_bytes (priv + numZeroBytes, numBytes);
		memset (priv, 0, numZeroBytes);
		priv[numZeroBytes] &= 0x03;
#endif
		BN_CTX * ctx = BN_CTX_new ();
		BIGNUM * p = BN_new ();
		BN_bin2bn (priv, 256, p);
		BN_mod_exp (p, elgg, p, elgp, ctx);
		bn2buf (p, pub, 256);
		BN_free (p);
		BN_CTX_free (ctx);
	}

// ECIES
	void ECIESEncrypt (const EC_GROUP * curve, const EC_POINT * key, const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding)
	{
		BN_CTX_start (ctx);
		BIGNUM * q = BN_CTX_get (ctx);
		EC_GROUP_get_order(curve, q, ctx);
		int len = BN_num_bytes (q);
		BIGNUM * k = BN_CTX_get (ctx);
		BN_rand_range (k, q); // 0 < k < q
		// point for shared secret
		auto p = EC_POINT_new (curve);
		EC_POINT_mul (curve, p, k, nullptr, nullptr, ctx);
		BIGNUM * x = BN_CTX_get (ctx), * y = BN_CTX_get (ctx);
		EC_POINT_get_affine_coordinates_GFp (curve, p, x, y, nullptr);
		if (zeroPadding)
		{
			encrypted[0] = 0;
			bn2buf (x, encrypted + 1, len);
			bn2buf (y, encrypted + 1 + len, len);
			RAND_bytes (encrypted + 1 + 2*len, 256 - 2*len);
		}
		else
		{
			bn2buf (x, encrypted, len);
			bn2buf (y, encrypted + len, len);
			RAND_bytes (encrypted + 2*len, 256 - 2*len);
		}
		// encryption key and iv
		EC_POINT_mul (curve, p, nullptr, key, k, ctx);
		EC_POINT_get_affine_coordinates_GFp (curve, p, x, y, nullptr);
		uint8_t keyBuf[64], iv[64], shared[32];
		bn2buf (x, keyBuf, len);
		bn2buf (y, iv, len);
		SHA256 (keyBuf, len, shared);
		// create buffer
		uint8_t m[256];
		m[0] = 0xFF; m[255] = 0xFF;
		memcpy (m+33, data, 222);
		SHA256 (m+33, 222, m+1);
		// encrypt
		CBCEncryption encryption;
		encryption.SetKey (shared);
		encryption.SetIV (iv);
		if (zeroPadding)
		{
			encrypted[257] = 0;
			encryption.Encrypt (m, 256, encrypted + 258);
		}
		else
			encryption.Encrypt (m, 256, encrypted + 256);
		EC_POINT_free (p);
		BN_CTX_end (ctx);
	}

	bool ECIESDecrypt (const EC_GROUP * curve, const BIGNUM * key, const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding)
	{
		bool ret = true;
		BN_CTX_start (ctx);
		BIGNUM * q = BN_CTX_get (ctx);
		EC_GROUP_get_order(curve, q, ctx);
		int len = BN_num_bytes (q);
		// point for shared secret
		BIGNUM * x = BN_CTX_get (ctx), * y = BN_CTX_get (ctx);
		if (zeroPadding)
		{
			BN_bin2bn (encrypted + 1, len, x);
			BN_bin2bn (encrypted + 1 + len, len, y);
		}
		else
		{
			BN_bin2bn (encrypted, len, x);
			BN_bin2bn (encrypted + len, len, y);
		}
		auto p = EC_POINT_new (curve);
		if (EC_POINT_set_affine_coordinates_GFp (curve, p, x, y, nullptr))
		{
			auto s = EC_POINT_new (curve);
			EC_POINT_mul (curve, s, nullptr, p, key, ctx);
			EC_POINT_get_affine_coordinates_GFp (curve, s, x, y, nullptr);
			EC_POINT_free (s);
			uint8_t keyBuf[64], iv[64], shared[32];
			bn2buf (x, keyBuf, len);
			bn2buf (y, iv, len);
			SHA256 (keyBuf, len, shared);
			// decrypt
			uint8_t m[256];
			CBCDecryption decryption;
			decryption.SetKey (shared);
			decryption.SetIV (iv);
			if (zeroPadding)
				decryption.Decrypt (encrypted + 258, 256, m);
			else
				decryption.Decrypt (encrypted + 256, 256, m);
			// verify and copy
			uint8_t hash[32];
			SHA256 (m + 33, 222, hash);
			if (!memcmp (m + 1, hash, 32))
				memcpy (data, m + 33, 222);
			else
			{
				LogPrint (eLogError, "ECIES decrypt hash doesn't match");
				ret = false;
			}
		}
		else
		{
			LogPrint (eLogError, "ECIES decrypt point is invalid");
			ret = false;
		}

		EC_POINT_free (p);
		BN_CTX_end (ctx);
		return ret;
	}

	void GenerateECIESKeyPair (const EC_GROUP * curve, BIGNUM *& priv, EC_POINT *& pub)
	{
		BN_CTX * ctx = BN_CTX_new ();
		BIGNUM * q = BN_new ();
		EC_GROUP_get_order(curve, q, ctx);
		priv = BN_new ();
		BN_rand_range (priv, q);
		pub = EC_POINT_new (curve);
		EC_POINT_mul (curve, pub, priv, nullptr, nullptr, ctx);
		BN_free (q);
		BN_CTX_free (ctx);
	}

// HMAC
	const uint64_t IPAD = 0x3636363636363636;
	const uint64_t OPAD = 0x5C5C5C5C5C5C5C5C;


	static const uint64_t ipads[] = { IPAD, IPAD, IPAD, IPAD };
	static const uint64_t opads[] = { OPAD, OPAD, OPAD, OPAD };

	void HMACMD5Digest (uint8_t * msg, size_t len, const MACKey& key, uint8_t * digest)
	// key is 32 bytes
	// digest is 16 bytes
	// block size is 64 bytes
	{
		uint64_t buf[256];
		uint64_t hash[12]; // 96 bytes
#if defined(__x86_64__) || defined(__i386__)
		if(i2p::cpu::avx)
		{
			__asm__
				(
					"vmovups %[key], %%ymm0 \n"
					"vmovups %[ipad], %%ymm1 \n"
					"vmovups %%ymm1, 32(%[buf]) \n"
					"vxorps %%ymm0, %%ymm1, %%ymm1 \n"
					"vmovups %%ymm1, (%[buf]) \n"
					"vmovups %[opad], %%ymm1 \n"
					"vmovups %%ymm1, 32(%[hash]) \n"
					"vxorps %%ymm0, %%ymm1, %%ymm1 \n"
					"vmovups %%ymm1, (%[hash]) \n"
					"vzeroall \n" // end of AVX
					"movups %%xmm0, 80(%[hash]) \n" // zero last 16 bytes
					:
					: [key]"m"(*(const uint8_t *)key), [ipad]"m"(*ipads), [opad]"m"(*opads),
						[buf]"r"(buf), [hash]"r"(hash)
					: "memory", "%xmm0" // TODO: change to %ymm0 later
					);
		}
		else
#endif
		{
			// ikeypad
			buf[0] = key.GetLL ()[0] ^ IPAD;
			buf[1] = key.GetLL ()[1] ^ IPAD;
			buf[2] = key.GetLL ()[2] ^ IPAD;
			buf[3] = key.GetLL ()[3] ^ IPAD;
			buf[4] = IPAD;
			buf[5] = IPAD;
			buf[6] = IPAD;
			buf[7] = IPAD;
			// okeypad
			hash[0] = key.GetLL ()[0] ^ OPAD;
			hash[1] = key.GetLL ()[1] ^ OPAD;
			hash[2] = key.GetLL ()[2] ^ OPAD;
			hash[3] = key.GetLL ()[3] ^ OPAD;
			hash[4] = OPAD;
			hash[5] = OPAD;
			hash[6] = OPAD;
			hash[7] = OPAD;
			// fill last 16 bytes with zeros (first hash size assumed 32 bytes in I2P)
			memset (hash + 10, 0, 16);
		}

		// concatenate with msg
		memcpy (buf + 8, msg, len);
		// calculate first hash
		MD5((uint8_t *)buf, len + 64, (uint8_t *)(hash + 8)); // 16 bytes

		// calculate digest
		MD5((uint8_t *)hash, 96, digest);
	}

// AES
#ifdef __AES__
	#define KeyExpansion256(round0,round1) \
		"pshufd $0xff, %%xmm2, %%xmm2 \n" \
		"movaps %%xmm1, %%xmm4 \n" \
		"pslldq $4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm1 \n" \
		"pslldq $4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm1 \n" \
		"pslldq $4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm1 \n" \
		"pxor %%xmm2, %%xmm1 \n" \
		"movaps %%xmm1, "#round0"(%[sched]) \n" \
		"aeskeygenassist $0, %%xmm1, %%xmm4 \n" \
		"pshufd $0xaa, %%xmm4, %%xmm2 \n" \
		"movaps %%xmm3, %%xmm4 \n" \
		"pslldq $4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm3 \n" \
		"pslldq $4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm3 \n" \
		"pslldq $4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm3 \n" \
		"pxor %%xmm2, %%xmm3 \n" \
		"movaps %%xmm3, "#round1"(%[sched]) \n"
#endif

#ifdef __AES__
	void ECBCryptoAESNI::ExpandKey (const AESKey& key)
	{
		__asm__
		(
			"movups (%[key]), %%xmm1 \n"
			"movups 16(%[key]), %%xmm3 \n"
			"movaps %%xmm1, (%[sched]) \n"
			"movaps %%xmm3, 16(%[sched]) \n"
			"aeskeygenassist $1, %%xmm3, %%xmm2 \n"
			KeyExpansion256(32,48)
			"aeskeygenassist $2, %%xmm3, %%xmm2 \n"
			KeyExpansion256(64,80)
			"aeskeygenassist $4, %%xmm3, %%xmm2 \n"
			KeyExpansion256(96,112)
			"aeskeygenassist $8, %%xmm3, %%xmm2 \n"
			KeyExpansion256(128,144)
			"aeskeygenassist $16, %%xmm3, %%xmm2 \n"
			KeyExpansion256(160,176)
			"aeskeygenassist $32, %%xmm3, %%xmm2 \n"
			KeyExpansion256(192,208)
			"aeskeygenassist $64, %%xmm3, %%xmm2 \n"
			// key expansion final
			"pshufd $0xff, %%xmm2, %%xmm2 \n"
			"movaps %%xmm1, %%xmm4 \n"
			"pslldq $4, %%xmm4 \n"
			"pxor %%xmm4, %%xmm1 \n"
			"pslldq $4, %%xmm4 \n"
			"pxor %%xmm4, %%xmm1 \n"
			"pslldq $4, %%xmm4 \n"
			"pxor %%xmm4, %%xmm1 \n"
			"pxor %%xmm2, %%xmm1 \n"
			"movups %%xmm1, 224(%[sched]) \n"
			: // output
			: [key]"r"((const uint8_t *)key), [sched]"r"(GetKeySchedule ()) // input
			: "%xmm1", "%xmm2", "%xmm3", "%xmm4", "memory" // clogged
		);
	}
#endif


#ifdef __AES__
	#define EncryptAES256(sched) \
		"pxor (%["#sched"]), %%xmm0 \n" \
		"aesenc	16(%["#sched"]), %%xmm0 \n" \
		"aesenc	32(%["#sched"]), %%xmm0 \n" \
		"aesenc	48(%["#sched"]), %%xmm0 \n" \
		"aesenc	64(%["#sched"]), %%xmm0 \n" \
		"aesenc	80(%["#sched"]), %%xmm0 \n" \
		"aesenc	96(%["#sched"]), %%xmm0 \n" \
		"aesenc	112(%["#sched"]), %%xmm0 \n" \
		"aesenc	128(%["#sched"]), %%xmm0 \n" \
		"aesenc	144(%["#sched"]), %%xmm0 \n" \
		"aesenc	160(%["#sched"]), %%xmm0 \n" \
		"aesenc	176(%["#sched"]), %%xmm0 \n" \
		"aesenc	192(%["#sched"]), %%xmm0 \n" \
		"aesenc	208(%["#sched"]), %%xmm0 \n" \
		"aesenclast	224(%["#sched"]), %%xmm0 \n"
#endif

	void ECBEncryption::Encrypt (const ChipherBlock * in, ChipherBlock * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					"movups (%[in]), %%xmm0 \n"
					EncryptAES256(sched)
					"movups %%xmm0, (%[out]) \n"
					: : [sched]"r"(GetKeySchedule ()), [in]"r"(in), [out]"r"(out) : "%xmm0", "memory"
					);
		}
		else
#endif
		{
			AES_encrypt (in->buf, out->buf, &m_Key);
		}
	}

#ifdef __AES__
	#define DecryptAES256(sched) \
		"pxor 224(%["#sched"]), %%xmm0 \n" \
		"aesdec	208(%["#sched"]), %%xmm0 \n" \
		"aesdec	192(%["#sched"]), %%xmm0 \n" \
		"aesdec	176(%["#sched"]), %%xmm0 \n" \
		"aesdec	160(%["#sched"]), %%xmm0 \n" \
		"aesdec	144(%["#sched"]), %%xmm0 \n" \
		"aesdec	128(%["#sched"]), %%xmm0 \n" \
		"aesdec	112(%["#sched"]), %%xmm0 \n" \
		"aesdec	96(%["#sched"]), %%xmm0 \n" \
		"aesdec	80(%["#sched"]), %%xmm0 \n" \
		"aesdec	64(%["#sched"]), %%xmm0 \n" \
		"aesdec	48(%["#sched"]), %%xmm0 \n" \
		"aesdec	32(%["#sched"]), %%xmm0 \n" \
		"aesdec	16(%["#sched"]), %%xmm0 \n" \
		"aesdeclast (%["#sched"]), %%xmm0 \n"
#endif

	void ECBDecryption::Decrypt (const ChipherBlock * in, ChipherBlock * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					"movups (%[in]), %%xmm0 \n"
					DecryptAES256(sched)
					"movups %%xmm0, (%[out]) \n"
					: : [sched]"r"(GetKeySchedule ()), [in]"r"(in), [out]"r"(out) : "%xmm0", "memory"
					);
		}
		else
#endif
		{
			AES_decrypt (in->buf, out->buf, &m_Key);
		}
	}

#ifdef __AES__
	#define CallAESIMC(offset) \
		"movaps "#offset"(%[shed]), %%xmm0 \n" \
		"aesimc %%xmm0, %%xmm0 \n" \
		"movaps %%xmm0, "#offset"(%[shed]) \n"
#endif

	void ECBEncryption::SetKey (const AESKey& key)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			ExpandKey (key);
		}
		else
#endif
		{
			AES_set_encrypt_key (key, 256, &m_Key);
		}
	}

	void ECBDecryption::SetKey (const AESKey& key)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			ExpandKey (key); // expand encryption key first
			// then invert it using aesimc
			__asm__
				(
					CallAESIMC(16)
					CallAESIMC(32)
					CallAESIMC(48)
					CallAESIMC(64)
					CallAESIMC(80)
					CallAESIMC(96)
					CallAESIMC(112)
					CallAESIMC(128)
					CallAESIMC(144)
					CallAESIMC(160)
					CallAESIMC(176)
					CallAESIMC(192)
					CallAESIMC(208)
					: : [shed]"r"(GetKeySchedule ()) : "%xmm0", "memory"
					);
		}
		else
#endif
		{
			AES_set_decrypt_key (key, 256, &m_Key);
		}
	}

	void CBCEncryption::Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					"movups (%[iv]), %%xmm1 \n"
					"1: \n"
					"movups (%[in]), %%xmm0 \n"
					"pxor %%xmm1, %%xmm0 \n"
					EncryptAES256(sched)
					"movaps %%xmm0, %%xmm1 \n"
					"movups %%xmm0, (%[out]) \n"
					"add $16, %[in] \n"
					"add $16, %[out] \n"
					"dec %[num] \n"
					"jnz 1b \n"
					"movups %%xmm1, (%[iv]) \n"
					:
					: [iv]"r"((uint8_t *)m_LastBlock), [sched]"r"(m_ECBEncryption.GetKeySchedule ()),
						[in]"r"(in), [out]"r"(out), [num]"r"(numBlocks)
					: "%xmm0", "%xmm1", "cc", "memory"
					);
		}
		else
#endif
		{
			for (int i = 0; i < numBlocks; i++)
			{
				*m_LastBlock.GetChipherBlock () ^= in[i];
				m_ECBEncryption.Encrypt (m_LastBlock.GetChipherBlock (), m_LastBlock.GetChipherBlock ());
				out[i] = *m_LastBlock.GetChipherBlock ();
			}
		}
	}

	void CBCEncryption::Encrypt (const uint8_t * in, std::size_t len, uint8_t * out)
	{
		// len/16
		int numBlocks = len >> 4;
		if (numBlocks > 0)
			Encrypt (numBlocks, (const ChipherBlock *)in, (ChipherBlock *)out);
	}

	void CBCEncryption::Encrypt (const uint8_t * in, uint8_t * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					"movups (%[iv]), %%xmm1 \n"
					"movups (%[in]), %%xmm0 \n"
					"pxor %%xmm1, %%xmm0 \n"
					EncryptAES256(sched)
					"movups %%xmm0, (%[out]) \n"
					"movups %%xmm0, (%[iv]) \n"
					:
					: [iv]"r"((uint8_t *)m_LastBlock), [sched]"r"(m_ECBEncryption.GetKeySchedule ()),
						[in]"r"(in), [out]"r"(out)
					: "%xmm0", "%xmm1", "memory"
					);
		}
		else
#endif
			Encrypt (1, (const ChipherBlock *)in, (ChipherBlock *)out);
	}

	void CBCDecryption::Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					"movups (%[iv]), %%xmm1 \n"
					"1: \n"
					"movups (%[in]), %%xmm0 \n"
					"movaps %%xmm0, %%xmm2 \n"
					DecryptAES256(sched)
					"pxor %%xmm1, %%xmm0 \n"
					"movups %%xmm0, (%[out]) \n"
					"movaps %%xmm2, %%xmm1 \n"
					"add $16, %[in] \n"
					"add $16, %[out] \n"
					"dec %[num] \n"
					"jnz 1b \n"
					"movups %%xmm1, (%[iv]) \n"
					:
					: [iv]"r"((uint8_t *)m_IV), [sched]"r"(m_ECBDecryption.GetKeySchedule ()),
						[in]"r"(in), [out]"r"(out), [num]"r"(numBlocks)
					: "%xmm0", "%xmm1", "%xmm2", "cc", "memory"
					);
		}
		else
#endif
		{
			for (int i = 0; i < numBlocks; i++)
			{
				ChipherBlock tmp = in[i];
				m_ECBDecryption.Decrypt (in + i, out + i);
				out[i] ^= *m_IV.GetChipherBlock ();
				*m_IV.GetChipherBlock () = tmp;
			}
		}
	}

	void CBCDecryption::Decrypt (const uint8_t * in, std::size_t len, uint8_t * out)
	{
		int numBlocks = len >> 4;
		if (numBlocks > 0)
			Decrypt (numBlocks, (const ChipherBlock *)in, (ChipherBlock *)out);
	}

	void CBCDecryption::Decrypt (const uint8_t * in, uint8_t * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					"movups (%[iv]), %%xmm1 \n"
					"movups (%[in]), %%xmm0 \n"
					"movups %%xmm0, (%[iv]) \n"
					DecryptAES256(sched)
					"pxor %%xmm1, %%xmm0 \n"
					"movups %%xmm0, (%[out]) \n"
					:
					: [iv]"r"((uint8_t *)m_IV), [sched]"r"(m_ECBDecryption.GetKeySchedule ()),
						[in]"r"(in), [out]"r"(out)
					: "%xmm0", "%xmm1", "memory"
					);
		}
		else
#endif
			Decrypt (1, (const ChipherBlock *)in, (ChipherBlock *)out);
	}

	void TunnelEncryption::Encrypt (const uint8_t * in, uint8_t * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					// encrypt IV
					"movups (%[in]), %%xmm0 \n"
					EncryptAES256(sched_iv)
					"movaps %%xmm0, %%xmm1 \n"
					// double IV encryption
					EncryptAES256(sched_iv)
					"movups %%xmm0, (%[out]) \n"
					// encrypt data, IV is xmm1
					"1: \n"
					"add $16, %[in] \n"
					"add $16, %[out] \n"
					"movups (%[in]), %%xmm0 \n"
					"pxor %%xmm1, %%xmm0 \n"
					EncryptAES256(sched_l)
					"movaps %%xmm0, %%xmm1 \n"
					"movups %%xmm0, (%[out]) \n"
					"dec %[num] \n"
					"jnz 1b \n"
					:
					: [sched_iv]"r"(m_IVEncryption.GetKeySchedule ()), [sched_l]"r"(m_LayerEncryption.ECB().GetKeySchedule ()),
						[in]"r"(in), [out]"r"(out), [num]"r"(63) // 63 blocks = 1008 bytes
					: "%xmm0", "%xmm1", "cc", "memory"
					);
		}
		else
#endif
		{
			m_IVEncryption.Encrypt ((const ChipherBlock *)in, (ChipherBlock *)out); // iv
			m_LayerEncryption.SetIV (out);
			m_LayerEncryption.Encrypt (in + 16, i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE, out + 16); // data
			m_IVEncryption.Encrypt ((ChipherBlock *)out, (ChipherBlock *)out); // double iv
		}
	}

	void TunnelDecryption::Decrypt (const uint8_t * in, uint8_t * out)
	{
#ifdef __AES__
		if(i2p::cpu::aesni)
		{
			__asm__
				(
					// decrypt IV
					"movups	(%[in]), %%xmm0 \n"
					DecryptAES256(sched_iv)
					"movaps %%xmm0, %%xmm1 \n"
					// double IV encryption
					DecryptAES256(sched_iv)
					"movups %%xmm0, (%[out]) \n"
					// decrypt data, IV is xmm1
					"1: \n"
					"add $16, %[in] \n"
					"add $16, %[out] \n"
					"movups (%[in]), %%xmm0 \n"
					"movaps %%xmm0, %%xmm2 \n"
					DecryptAES256(sched_l)
					"pxor %%xmm1, %%xmm0 \n"
					"movups %%xmm0, (%[out]) \n"
					"movaps %%xmm2, %%xmm1 \n"
					"dec %[num] \n"
					"jnz 1b \n"
					:
					: [sched_iv]"r"(m_IVDecryption.GetKeySchedule ()), [sched_l]"r"(m_LayerDecryption.ECB().GetKeySchedule ()),
						[in]"r"(in), [out]"r"(out), [num]"r"(63) // 63 blocks = 1008 bytes
					: "%xmm0", "%xmm1", "%xmm2", "cc", "memory"
					);
		}
		else
#endif
		{
			m_IVDecryption.Decrypt ((const ChipherBlock *)in, (ChipherBlock *)out); // iv
			m_LayerDecryption.SetIV (out);
			m_LayerDecryption.Decrypt (in + 16, i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE, out + 16); // data
			m_IVDecryption.Decrypt ((ChipherBlock *)out, (ChipherBlock *)out); // double iv
		}
	}

// AEAD/ChaCha20/Poly1305

	bool AEADChaCha20Poly1305 (const uint8_t * msg, size_t msgLen, const uint8_t * ad, size_t adLen, const uint8_t * key, const uint8_t * nonce, uint8_t * buf, size_t len, bool encrypt)
	{
		if (len < msgLen) return false;
		if (encrypt && len < msgLen + 16) return false;
		bool ret = true;
#if OPENSSL_AEAD_CHACHA20_POLY1305
		int outlen = 0;
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
		if (encrypt)
		{
			EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), 0, 0, 0);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, 0);
			EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
			EVP_EncryptUpdate(ctx, NULL, &outlen, ad, adLen);
			EVP_EncryptUpdate(ctx, buf, &outlen, msg, msgLen);
			EVP_EncryptFinal_ex(ctx, buf, &outlen);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, buf + msgLen);
		}
		else
		{
			EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), 0, 0, 0);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, 0);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (uint8_t *)(msg + msgLen));
			EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
			EVP_DecryptUpdate(ctx, NULL, &outlen, ad, adLen);
			EVP_DecryptUpdate(ctx, buf, &outlen, msg, msgLen);
			ret = EVP_DecryptFinal_ex(ctx, buf + outlen, &outlen) > 0;
		}

		EVP_CIPHER_CTX_free (ctx);
#else
		chacha::Chacha20State state;
		// generate one time poly key
		chacha::Chacha20Init (state, nonce, key, 0);
		uint64_t polyKey[8];
		memset(polyKey, 0, sizeof(polyKey));
		chacha::Chacha20Encrypt (state, (uint8_t *)polyKey, 64);
		// create Poly1305 hash
		Poly1305 polyHash (polyKey);
		if (!ad) adLen = 0;
		uint8_t padding[16]; memset (padding, 0, 16);
		if (ad)
		{
			polyHash.Update (ad, adLen);// additional authenticated data
			auto rem = adLen & 0x0F; // %16
			if (rem)
			{
				// padding1
				rem = 16 - rem;
				polyHash.Update (padding, rem);
			}
		}
		// encrypt/decrypt data and add to hash
		Chacha20SetCounter (state, 1);
		if (buf != msg)
			memcpy (buf, msg, msgLen);
		if (encrypt)
		{
			chacha::Chacha20Encrypt (state, buf, msgLen); // encrypt
			polyHash.Update (buf, msgLen); // after encryption
		}
		else
		{
			polyHash.Update (buf, msgLen); // before decryption
			chacha::Chacha20Encrypt (state, buf, msgLen); // decrypt
		}

		auto rem = msgLen & 0x0F; // %16
		if (rem)
		{
			// padding2
			rem = 16 - rem;
			polyHash.Update (padding, rem);
		}
		// adLen and msgLen
		htole64buf (padding, adLen);
		htole64buf (padding + 8, msgLen);
		polyHash.Update (padding, 16);

		if (encrypt)
			// calculate Poly1305 tag and write in after encrypted data
			polyHash.Finish ((uint64_t *)(buf + msgLen));
		else
		{
			uint64_t tag[4];
			// calculate Poly1305 tag
			polyHash.Finish (tag);
			if (memcmp (tag, msg + msgLen, 16)) ret = false; // compare with provided
		}
#endif
		return ret;
	}

	void AEADChaCha20Poly1305Encrypt (const std::vector<std::pair<uint8_t *, size_t> >& bufs, const uint8_t * key, const uint8_t * nonce, uint8_t * mac)
	{
		if (bufs.empty ()) return;
#if OPENSSL_AEAD_CHACHA20_POLY1305
		int outlen = 0;
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
		EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), 0, 0, 0);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, 0);
		EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
		for (const auto& it: bufs)
			EVP_EncryptUpdate(ctx, it.first, &outlen, it.first, it.second);
		EVP_EncryptFinal_ex(ctx, NULL, &outlen);
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac);
		EVP_CIPHER_CTX_free (ctx);
#else
		chacha::Chacha20State state;
		// generate one time poly key
		chacha::Chacha20Init (state, nonce, key, 0);
		uint64_t polyKey[8];
		memset(polyKey, 0, sizeof(polyKey));
		chacha::Chacha20Encrypt (state, (uint8_t *)polyKey, 64);
		Poly1305 polyHash (polyKey);
		// encrypt buffers
		Chacha20SetCounter (state, 1);
		size_t size = 0;
		for (const auto& it: bufs)
		{
			chacha::Chacha20Encrypt (state, it.first, it.second);
			polyHash.Update (it.first, it.second); // after encryption
			size += it.second;
		}
		// padding
		uint8_t padding[16];
		memset (padding, 0, 16);
		auto rem = size & 0x0F; // %16
		if (rem)
		{
			// padding2
			rem = 16 - rem;
			polyHash.Update (padding, rem);
		}
		// adLen and msgLen
		// adLen is always zero
		htole64buf (padding + 8, size);
		polyHash.Update (padding, 16);
		// MAC
		polyHash.Finish ((uint64_t *)mac);
#endif
	}

	void ChaCha20 (const uint8_t * msg, size_t msgLen, const uint8_t * key, const uint8_t * nonce, uint8_t * out)
	{
#if OPENSSL_AEAD_CHACHA20_POLY1305
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new ();
		uint32_t iv[4];
		iv[0] = htole32 (1); memcpy (iv + 1, nonce, 12); // counter | nonce
		EVP_EncryptInit_ex(ctx, EVP_chacha20 (), NULL, key, (const uint8_t *)iv);
		int outlen = 0;
		EVP_EncryptUpdate(ctx, out, &outlen, msg, msgLen);
		EVP_EncryptFinal_ex(ctx, NULL, &outlen);
		EVP_CIPHER_CTX_free (ctx);
#else
		chacha::Chacha20State state;
		chacha::Chacha20Init (state, nonce, key, 1);
		if (out != msg) memcpy (out, msg, msgLen);
		chacha::Chacha20Encrypt (state, out, msgLen);
#endif
	}

	void HKDF (const uint8_t * salt, const uint8_t * key, size_t keyLen, const std::string& info,
		uint8_t * out, size_t outLen)
	{
#if OPENSSL_HKDF
		EVP_PKEY_CTX * pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_HKDF, nullptr);
		EVP_PKEY_derive_init (pctx);
		EVP_PKEY_CTX_set_hkdf_md (pctx, EVP_sha256());
		if (key && keyLen)
		{
			EVP_PKEY_CTX_set1_hkdf_salt (pctx, salt, 32);
			EVP_PKEY_CTX_set1_hkdf_key (pctx, key, keyLen);
		}
		else
		{
			// zerolen
			EVP_PKEY_CTX_hkdf_mode (pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
			uint8_t tempKey[32]; unsigned int len;
			HMAC(EVP_sha256(), salt, 32, nullptr, 0, tempKey, &len);
			EVP_PKEY_CTX_set1_hkdf_key (pctx, tempKey, len);
		}
		if (info.length () > 0)
			EVP_PKEY_CTX_add1_hkdf_info (pctx, info.c_str (), info.length ());
		EVP_PKEY_derive (pctx, out, &outLen);
		EVP_PKEY_CTX_free (pctx);
#else
		uint8_t prk[32]; unsigned int len;
		HMAC(EVP_sha256(), salt, 32, key, keyLen, prk, &len);
		auto l = info.length ();
		memcpy (out, info.c_str (), l); out[l] = 0x01;
		HMAC(EVP_sha256(), prk, 32, out, l + 1, out, &len);
		if (outLen > 32) // 64
		{
			memcpy (out + 32, info.c_str (), l); out[l + 32] = 0x02;
			HMAC(EVP_sha256(), prk, 32, out, l + 33, out + 32, &len);
		}
#endif
	}

	void NoiseSymmetricState::MixHash (const uint8_t * buf, size_t len)
	{
		SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, m_H, 32);
		SHA256_Update (&ctx, buf, len);
		SHA256_Final (m_H, &ctx);
	}

	void NoiseSymmetricState::MixKey (const uint8_t * sharedSecret)
	{
		HKDF (m_CK, sharedSecret, 32, "", m_CK);
		// new ck is m_CK[0:31], key is m_CK[32:63]
	}

// init and terminate

/*	std::vector <std::unique_ptr<std::mutex> > m_OpenSSLMutexes;
	static void OpensslLockingCallback(int mode, int type, const char * file, int line)
	{
		if (type > 0 && (size_t)type < m_OpenSSLMutexes.size ())
		{
			if (mode & CRYPTO_LOCK)
				m_OpenSSLMutexes[type]->lock ();
			else
				m_OpenSSLMutexes[type]->unlock ();
		}
	}*/

	void InitCrypto (bool precomputation, bool aesni, bool avx, bool force)
	{
		i2p::cpu::Detect (aesni, avx, force);
#if LEGACY_OPENSSL
		SSL_library_init ();
#endif
/*		auto numLocks = CRYPTO_num_locks();
		for (int i = 0; i < numLocks; i++)
			m_OpenSSLMutexes.emplace_back (new std::mutex);
		CRYPTO_set_locking_callback (OpensslLockingCallback);*/
		if (precomputation)
		{
#if defined(__x86_64__)
			g_ElggTable = new BIGNUM * [ELGAMAL_FULL_EXPONENT_NUM_BYTES][255];
			PrecalculateElggTable (g_ElggTable, ELGAMAL_FULL_EXPONENT_NUM_BYTES);
#else
			g_ElggTable = new BIGNUM * [ELGAMAL_SHORT_EXPONENT_NUM_BYTES][255];
			PrecalculateElggTable (g_ElggTable, ELGAMAL_SHORT_EXPONENT_NUM_BYTES);
#endif
		}
	}

	void TerminateCrypto ()
	{
		if (g_ElggTable)
		{
			DestroyElggTable (g_ElggTable,
#if defined(__x86_64__)
				ELGAMAL_FULL_EXPONENT_NUM_BYTES
#else
				ELGAMAL_SHORT_EXPONENT_NUM_BYTES
#endif
			);
			delete[] g_ElggTable; g_ElggTable = nullptr;
		}
/*		CRYPTO_set_locking_callback (nullptr);
		m_OpenSSLMutexes.clear ();*/
	}
}
}
