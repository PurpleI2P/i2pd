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
			LogPrint (eLogError, "MLKEM512 can't create PKEY context");
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
			LogPrint (eLogError, "MLKEM512 can't create PKEY context");
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
			LogPrint (eLogError, "MLKEM512 can't create PKEY context");
	}	

	std::unique_ptr<MLKEMKeys> CreateMLKEMKeys (i2p::data::CryptoKeyType type)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)MLKEMS.size ()) return nullptr;
		return std::make_unique<MLKEMKeys>((MLKEMTypes)(type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1));
	}	
}	
}	

#endif