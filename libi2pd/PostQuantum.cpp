/*
* Copyright (c) 2025-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "PostQuantum.h"

#if OPENSSL_MLKEM

#include <string.h>

#if defined(LIBRESSL_VERSION_NUMBER)
#include <cstdlib>
#include <openssl/mlkem.h>
#else
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

namespace i2p
{
namespace crypto
{
	MLKEMKeys::MLKEMKeys (MLKEMTypes type):
		m_Name (type == eMLKEM512 ? "ML-KEM-512" : type == eMLKEM768 ? "ML-KEM-768" : "ML-KEM-1024"),
#if defined(LIBRESSL_VERSION_NUMBER)
		m_Rank (type == eMLKEM768 ? MLKEM768_RANK : type == eMLKEM1024 ? MLKEM1024_RANK : 0),
#endif
		m_KeyLen (
#if defined(LIBRESSL_VERSION_NUMBER)
			type == eMLKEM768 ? MLKEM768_KEY_LENGTH : type == eMLKEM1024 ? MLKEM1024_KEY_LENGTH : 0
#else
			type == eMLKEM512 ? MLKEM512_KEY_LENGTH : type == eMLKEM768 ? MLKEM768_KEY_LENGTH : MLKEM1024_KEY_LENGTH
#endif
		),
		m_CTLen (
#if defined(LIBRESSL_VERSION_NUMBER)
			type == eMLKEM768 ? MLKEM768_CIPHER_TEXT_LENGTH : type == eMLKEM1024 ? MLKEM1024_CIPHER_TEXT_LENGTH : 0
#else
			type == eMLKEM512 ? MLKEM512_CIPHER_TEXT_LENGTH : type == eMLKEM768 ? MLKEM768_CIPHER_TEXT_LENGTH : MLKEM1024_CIPHER_TEXT_LENGTH
#endif
		)
#if defined(LIBRESSL_VERSION_NUMBER)
		, m_PrivateKey (nullptr), m_PublicKey (nullptr)
#else
		, m_Pkey (nullptr)
#endif
	{
		m_PublicKeyEncoded.fill (0);
	}

	MLKEMKeys::~MLKEMKeys ()
	{
#if defined(LIBRESSL_VERSION_NUMBER)
		if (m_PrivateKey) MLKEM_private_key_free (m_PrivateKey);
		if (m_PublicKey) MLKEM_public_key_free (m_PublicKey);
#else
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
#endif
	}

	void MLKEMKeys::GenerateKeys ()
	{
#if defined(LIBRESSL_VERSION_NUMBER)
		m_PublicKeyEncoded.fill (0);
		if (!m_Rank)
		{
			LogPrint (eLogError, "MLKEM ", m_Name, " is not supported by LibreSSL");
			return;
		}
		if (m_PrivateKey) MLKEM_private_key_free (m_PrivateKey);
		if (m_PublicKey) MLKEM_public_key_free (m_PublicKey);
		m_PrivateKey = nullptr;
		m_PublicKey = nullptr;
		m_PrivateKey = MLKEM_private_key_new (m_Rank);
		m_PublicKey = MLKEM_public_key_new (m_Rank);
		if (!m_PrivateKey || !m_PublicKey)
		{
			LogPrint (eLogError, "MLKEM can't create native key objects");
			if (m_PrivateKey) MLKEM_private_key_free (m_PrivateKey);
			if (m_PublicKey) MLKEM_public_key_free (m_PublicKey);
			m_PrivateKey = nullptr;
			m_PublicKey = nullptr;
			return;
		}
		uint8_t * pub = nullptr, * seed = nullptr;
		size_t pubLen = 0, seedLen = 0;
		if (!MLKEM_generate_key (m_PrivateKey, &pub, &pubLen, &seed, &seedLen) || !pub || pubLen != m_KeyLen)
		{
			LogPrint (eLogError, "MLKEM native key generation failed");
			if (pub) OPENSSL_free (pub);
			if (seed) OPENSSL_free (seed);
			MLKEM_private_key_free (m_PrivateKey);
			MLKEM_public_key_free (m_PublicKey);
			m_PrivateKey = nullptr;
			m_PublicKey = nullptr;
			return;
		}
		if (!MLKEM_parse_public_key (m_PublicKey, pub, pubLen))
		{
			LogPrint (eLogError, "MLKEM can't parse generated public key");
			OPENSSL_free (pub);
			if (seed) OPENSSL_free (seed);
			MLKEM_private_key_free (m_PrivateKey);
			MLKEM_public_key_free (m_PublicKey);
			m_PrivateKey = nullptr;
			m_PublicKey = nullptr;
			return;
		}
		memcpy (m_PublicKeyEncoded.data (), pub, pubLen);
		OPENSSL_free (pub);
		if (seed) OPENSSL_free (seed);
		LogPrint (eLogDebug, "MLKEM: ", m_Name, " native key generation succeeded");
#else
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
		m_Pkey = EVP_PKEY_Q_keygen (NULL, NULL, m_Name.c_str ());
		if (!m_Pkey)
		{
			LogPrint (eLogError, "MLKEM can't generate keypair");
			return;
		}
		size_t len = m_KeyLen;
		if (!EVP_PKEY_get_octet_string_param (m_Pkey, OSSL_PKEY_PARAM_PUB_KEY,
			m_PublicKeyEncoded.data (), m_PublicKeyEncoded.size (), &len) || len != m_KeyLen)
			LogPrint (eLogError, "MLKEM can't read generated public key");
#endif
	}

	void MLKEMKeys::GetPublicKey (uint8_t * pub) const
	{
		if (m_KeyLen)
			memcpy (pub, m_PublicKeyEncoded.data (), m_KeyLen);
	}

	void MLKEMKeys::SetPublicKey (const uint8_t * pub)
	{
#if defined(LIBRESSL_VERSION_NUMBER)
		if (!m_Rank)
		{
			LogPrint (eLogError, "MLKEM ", m_Name, " is not supported by LibreSSL");
			return;
		}
		if (m_PublicKey) MLKEM_public_key_free (m_PublicKey);
		m_PublicKey = MLKEM_public_key_new (m_Rank);
		if (!m_PublicKey)
		{
			LogPrint (eLogError, "MLKEM can't create native public key");
			return;
		}
		if (!MLKEM_parse_public_key (m_PublicKey, pub, m_KeyLen))
		{
			LogPrint (eLogError, "MLKEM can't parse native public key");
			MLKEM_public_key_free (m_PublicKey);
			m_PublicKey = nullptr;
			return;
		}
		memcpy (m_PublicKeyEncoded.data (), pub, m_KeyLen);
#else
		if (m_Pkey)
		{
			EVP_PKEY_free (m_Pkey);
			m_Pkey = nullptr;
		}
		memcpy (m_PublicKeyEncoded.data (), pub, m_KeyLen);
		OSSL_PARAM params[] =
		{
			OSSL_PARAM_octet_string (OSSL_PKEY_PARAM_PUB_KEY, (uint8_t *)pub, m_KeyLen),
			OSSL_PARAM_END
		};
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, m_Name.c_str (), NULL);
		if (ctx)
		{
			if (EVP_PKEY_fromdata_init (ctx) <= 0 ||
				EVP_PKEY_fromdata (ctx, &m_Pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params) <= 0)
					LogPrint (eLogError, "MLKEM can't create PKEY from params");
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
#endif
	}

	void MLKEMKeys::Encaps (uint8_t * ciphertext, uint8_t * shared)
	{
#if defined(LIBRESSL_VERSION_NUMBER)
		if (!m_PublicKey) return;
		uint8_t * ct = nullptr, * secret = nullptr;
		size_t ctLen = 0, sharedLen = 0;
		if (!MLKEM_encap (m_PublicKey, &ct, &ctLen, &secret, &sharedLen) || !ct || !secret ||
			ctLen != m_CTLen || sharedLen != MLKEM_SHARED_SECRET_LENGTH)
		{
			LogPrint (eLogError, "MLKEM native encapsulation failed");
			if (ct) OPENSSL_free (ct);
			if (secret) OPENSSL_free (secret);
			return;
		}
		memcpy (ciphertext, ct, ctLen);
		memcpy (shared, secret, sharedLen);
		OPENSSL_free (ct);
		OPENSSL_free (secret);
		LogPrint (eLogDebug, "MLKEM: ", m_Name, " native encapsulation succeeded");
#else
		if (!m_Pkey) return;
		auto ctx = EVP_PKEY_CTX_new_from_pkey (NULL, m_Pkey, NULL);
		if (ctx)
		{
			EVP_PKEY_encapsulate_init (ctx, NULL);
			size_t len = m_CTLen, sharedLen = 32;
			EVP_PKEY_encapsulate (ctx, ciphertext, &len, shared, &sharedLen);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
#endif
	}

	void MLKEMKeys::Decaps (const uint8_t * ciphertext, uint8_t * shared)
	{
#if defined(LIBRESSL_VERSION_NUMBER)
		if (!m_PrivateKey) return;
		uint8_t * secret = nullptr;
		size_t sharedLen = 0;
		if (!MLKEM_decap (m_PrivateKey, ciphertext, m_CTLen, &secret, &sharedLen) || !secret ||
			sharedLen != MLKEM_SHARED_SECRET_LENGTH)
		{
			LogPrint (eLogError, "MLKEM native decapsulation failed");
			if (secret) OPENSSL_free (secret);
			return;
		}
		memcpy (shared, secret, sharedLen);
		OPENSSL_free (secret);
		LogPrint (eLogDebug, "MLKEM: ", m_Name, " native decapsulation succeeded");
#else
		if (!m_Pkey) return;
		auto ctx = EVP_PKEY_CTX_new_from_pkey (NULL, m_Pkey, NULL);
		if (ctx)
		{
			EVP_PKEY_decapsulate_init (ctx, NULL);
			size_t sharedLen = 32;
			EVP_PKEY_decapsulate (ctx, shared, &sharedLen, ciphertext, m_CTLen);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
#endif
	}

	std::unique_ptr<MLKEMKeys> CreateMLKEMKeys (i2p::data::CryptoKeyType type)
	{
		switch (type)
		{
#if !defined(LIBRESSL_VERSION_NUMBER)
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM512_X25519_AEAD:
				return std::make_unique<MLKEMKeys> (eMLKEM512);
#endif
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD:
				return std::make_unique<MLKEMKeys> (eMLKEM768);
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM1024_X25519_AEAD:
				return std::make_unique<MLKEMKeys> (eMLKEM1024);
			default:
				return nullptr;
		}
	}

	static constexpr std::array NoiseIKInitMLKEMKeys =
	{
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0xb0, 0x8f, 0xb1, 0x73, 0x92, 0x66, 0xc9, 0x90, 0x45, 0x7f, 0xdd, 0xc6, 0x4e, 0x55, 0x40, 0xd8,
				0x0a, 0x37, 0x99, 0x06, 0x92, 0x2a, 0x78, 0xc4, 0xb1, 0xef, 0x86, 0x06, 0xd0, 0x15, 0x9f, 0x4d
			}, // SHA256("Noise_IKhfselg2_25519+MLKEM512_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x95, 0x8d, 0xf6, 0x6c, 0x95, 0xce, 0xa9, 0xf7, 0x42, 0xfc, 0xfa, 0x62, 0x71, 0x36, 0x1e, 0xa7,
				0xdc, 0x7a, 0xc0, 0x75, 0x01, 0xcf, 0xf9, 0xfc, 0x9f, 0xdb, 0x4c, 0x68, 0x3a, 0x53, 0x49, 0xeb
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x36, 0x03, 0x90, 0x2d, 0xf9, 0xa2, 0x2a, 0x5e, 0xc9, 0x3d, 0xdb, 0x8f, 0xa8, 0x1b, 0xdb, 0x4b,
				0xae, 0x9d, 0x93, 0x9c, 0xdf, 0xaf, 0xde, 0x55, 0x49, 0x13, 0xfe, 0x98, 0xf8, 0x4a, 0xd4, 0xbd
			}, // SHA256("Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256")
		 	std::array<uint8_t, 32>
		 	{
				0x15, 0x44, 0x89, 0xbf, 0x30, 0xf0, 0xc9, 0x77, 0x66, 0x10, 0xcb, 0xb1, 0x57, 0x3f, 0xab, 0x68,
				0x79, 0x57, 0x39, 0x57, 0x0a, 0xe7, 0xc0, 0x31, 0x8a, 0xa2, 0x96, 0xef, 0xbf, 0xa9, 0x6a, 0xbb
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x86, 0xa5, 0x36, 0x44, 0xc6, 0x12, 0xd5, 0x71, 0xa1, 0x2d, 0xd8, 0xb6, 0x0a, 0x00, 0x9f, 0x2c,
				0x1a, 0xa8, 0x7d, 0x22, 0xa4, 0xff, 0x2b, 0xcd, 0x61, 0x34, 0x97, 0x6d, 0xa1, 0x49, 0xeb, 0x4a
			}, // SHA256("Noise_IKhfselg2_25519+MLKEM1024_ChaChaPoly_SHA256")
		 	std::array<uint8_t, 32>
		 	{
				0x42, 0x0d, 0xc2, 0x1c, 0x7b, 0x18, 0x61, 0xb7, 0x4a, 0x04, 0x3d, 0xae, 0x0f, 0xdc, 0xf2, 0x71,
				0xb9, 0xba, 0x19, 0xbb, 0xbd, 0x5f, 0xd4, 0x9c, 0x3f, 0x4b, 0x01, 0xed, 0x6d, 0x13, 0x1d, 0xa2
			} // SHA256 (first)
		)
	};

	void InitNoiseIKStateMLKEM (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub)
	{
		auto ind = GetMLKEMIndex (type);
		if (ind < 0) return;
		state.Init (NoiseIKInitMLKEMKeys[ind].first.data(), NoiseIKInitMLKEMKeys[ind].second.data(), pub);
	}

	static constexpr std::array NoiseXKInitMLKEMKeys =
	{
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0xf9, 0x9f, 0x6c, 0x60, 0xea, 0x06, 0x78, 0x7f, 0x8d, 0xc2, 0x3f, 0xa3, 0xe9, 0xf7, 0xc0, 0xa5,
				0x34, 0x77, 0x10, 0xc1, 0x1d, 0x99, 0xe0, 0xe9, 0x9c, 0xe3, 0x90, 0x2b, 0x92, 0x32, 0x07, 0x20
			}, // SHA256("Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x6a, 0xc4, 0x2c, 0xd8, 0x31, 0xeb, 0xd3, 0x0c, 0xdf, 0x90, 0x2e, 0x67, 0xf4, 0x66, 0x39, 0xab,
				0x85, 0xcf, 0xac, 0x0f, 0x77, 0xba, 0x79, 0x58, 0x61, 0xe9, 0x56, 0x97, 0x44, 0x99, 0xad, 0xe1
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0xb9, 0xc3, 0x44, 0x56, 0x11, 0xcc, 0x80, 0xec, 0xca, 0x15, 0xde, 0x37, 0xa4, 0x1a, 0xb6, 0xc6,
				0xfb, 0x59, 0xdb, 0x83, 0xeb, 0x1e, 0x9d, 0x7e, 0x27, 0x63, 0xa8, 0xa5, 0x34, 0xec, 0x53, 0xd1
			}, // SHA256("Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x0b, 0xcd, 0x38, 0xaf, 0xcf, 0xb7, 0xaa, 0xeb, 0x25, 0x73, 0xb8, 0x4f, 0x74, 0x83, 0x02, 0x94,
				0x8b, 0x53, 0xf5, 0x42, 0xce, 0x3f, 0x23, 0xdc, 0xcc, 0x9a, 0xe9, 0xb0, 0x21, 0xab, 0x48, 0xff
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x97, 0xe6, 0x8d, 0x27, 0x49, 0x41, 0x50, 0xea, 0x80, 0x54, 0x8e, 0x73, 0x04, 0x45, 0x3f, 0x61,
				0x29, 0xbc, 0x07, 0x8b, 0x14, 0x05, 0x13, 0xbe, 0x9a, 0x55, 0xb2, 0x07, 0xa2, 0xda, 0x37, 0x0c
			}, // SHA256("Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM1024_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x59, 0x50, 0x1a, 0x59, 0x87, 0x82, 0x65, 0x55, 0x58, 0x09, 0x9b, 0xec, 0xab, 0x2a, 0x64, 0x1d,
				0xf1, 0x7b, 0xca, 0xe7, 0xb3, 0x5d, 0x6d, 0xa7, 0x8c, 0x6e, 0x79, 0x7e, 0xab, 0xf3, 0x57, 0x3f
			} // SHA256 (first)
		)
	};

	void InitNoiseXKStateMLKEM (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub)
	{
		auto ind = GetMLKEMIndex (type);
		if (ind < 0) return;
		state.Init (NoiseXKInitMLKEMKeys[ind].first.data(), NoiseXKInitMLKEMKeys[ind].second.data(), pub);
	}

	static constexpr std::array NoiseXKInitMLKEMKeys1 =
	{
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x16, 0x22, 0x45, 0x4d, 0xbe, 0xa3, 0xf7, 0x7b, 0xcf, 0x5a, 0x0b, 0x60, 0xf8, 0x56, 0xe0, 0x54,
				0xa6, 0x79, 0x72, 0x74, 0x2a, 0xb7, 0x1a, 0xdf, 0x39, 0x38, 0x7d, 0x35, 0xf8, 0x90, 0x41, 0x68
			}, // SHA256("Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0xb1, 0x84, 0xaf, 0x89, 0xb5, 0xd2, 0x7f, 0xbd, 0xa4, 0x62, 0xbe, 0x35, 0xa4, 0xc0, 0x17, 0x77,
				0xfb, 0x70, 0xc7, 0x39, 0x28, 0x72, 0xcf, 0x74, 0x4a, 0xbf, 0x3c, 0xc5, 0xb8, 0x6c, 0xaf, 0xcf
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x06, 0x45, 0x8d, 0x7f, 0x4a, 0x0e, 0x53, 0xd3, 0x7b, 0xdb, 0xbb, 0x74, 0x77, 0x99, 0xa1, 0x04,
				0xc7, 0x52, 0x00, 0x0b, 0xe0, 0xd1, 0x2a, 0x83, 0x03, 0x7b, 0xe3, 0xd1, 0xdb, 0x77, 0xf2, 0x90
			}, // SHA256("Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0xd6, 0xae, 0x20, 0x15, 0x44, 0x5f, 0x61, 0xa5, 0xa7, 0xe2, 0x87, 0xcf, 0x64, 0xe0, 0x0c, 0xcc,
				0x97, 0xeb, 0xea, 0x1c, 0x5d, 0xd0, 0x8c, 0x26, 0x34, 0x32, 0x06, 0xf5, 0x5e, 0x28, 0xad, 0x12
			} // SHA256 (first)
		)
		// no ML-KEM-1024
	};

	void InitNoiseXKStateMLKEM1 (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub)
	{
		auto ind = GetMLKEMIndex (type);
		if (ind < 0 || ind >= (int)NoiseXKInitMLKEMKeys1.size ()) return;
		state.Init (NoiseXKInitMLKEMKeys1[ind].first.data(), NoiseXKInitMLKEMKeys1[ind].second.data(), pub);
	}
}
}

#endif
