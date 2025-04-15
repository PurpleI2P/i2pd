/*
* Copyright (c) 2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "PostQuantum.h"

#if OPENSSL_PQ

#include <openssl/param_build.h>
#include <openssl/core_names.h>

namespace i2p
{
namespace crypto
{
	MLKEMKeys::MLKEMKeys (MLKEMTypes type):
		m_Name (std::get<0>(MLKEMS[type])), m_KeyLen (std::get<1>(MLKEMS[type])), 
		m_CTLen (std::get<2>(MLKEMS[type])), m_Pkey (nullptr)
	{
	}
	
	MLKEMKeys::~MLKEMKeys ()
	{
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
	}	

	void MLKEMKeys::GenerateKeys ()
	{
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
		m_Pkey = EVP_PKEY_Q_keygen(NULL, NULL, m_Name.c_str ());
	}

	void MLKEMKeys::GetPublicKey (uint8_t * pub) const
	{	
		if (m_Pkey)
		{	
			size_t len = m_KeyLen;
		    EVP_PKEY_get_octet_string_param (m_Pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, m_KeyLen, &len);
		}	
	}

	void MLKEMKeys::SetPublicKey (const uint8_t * pub)
	{
		if (m_Pkey)
		{	
			EVP_PKEY_free (m_Pkey);
			m_Pkey = nullptr;
		}	
		OSSL_PARAM params[] =
		{
			OSSL_PARAM_octet_string (OSSL_PKEY_PARAM_PUB_KEY, (uint8_t *)pub, m_KeyLen),
			OSSL_PARAM_END
		};		
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, m_Name.c_str (), NULL);
		if (ctx)
		{
			EVP_PKEY_fromdata_init (ctx);
			EVP_PKEY_fromdata (ctx, &m_Pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
	}

	void MLKEMKeys::Encaps (uint8_t * ciphertext, uint8_t * shared)
	{
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
	}	

	void MLKEMKeys::Decaps (const uint8_t * ciphertext, uint8_t * shared)
	{
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
	}	

	std::unique_ptr<MLKEMKeys> CreateMLKEMKeys (i2p::data::CryptoKeyType type)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)MLKEMS.size ()) return nullptr;
		return std::make_unique<MLKEMKeys>((MLKEMTypes)(type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1));
	}	

	static constexpr std::array<std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 32> >, 3> NoiseIKInitMLKEMKeys =
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
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)NoiseIKInitMLKEMKeys.size ()) return;
		auto ind = type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1;
		state.Init (NoiseIKInitMLKEMKeys[ind].first.data(), NoiseIKInitMLKEMKeys[ind].second.data(), pub);
	}		
}	
}	

#endif