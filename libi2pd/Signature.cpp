/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <memory>
#include <openssl/evp.h>
#if (OPENSSL_VERSION_NUMBER >= 0x030000000) // since 3.0.0
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif
#include "Log.h"
#include "Signature.h"

namespace i2p
{
namespace crypto
{
#if (OPENSSL_VERSION_NUMBER >= 0x030000000) // since 3.0.0
	DSAVerifier::DSAVerifier ():
		m_PublicKey (nullptr)
	{
	}

	DSAVerifier::~DSAVerifier ()
	{
		if (m_PublicKey)
			EVP_PKEY_free (m_PublicKey);
	}

	void DSAVerifier::SetPublicKey (const uint8_t * signingKey)
	{
		if (m_PublicKey)
			EVP_PKEY_free (m_PublicKey);
		BIGNUM * pub = BN_bin2bn (signingKey, DSA_PUBLIC_KEY_LENGTH, NULL);
		m_PublicKey = CreateDSA (pub);
		BN_free (pub);
	}
	
	bool DSAVerifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		// signature
		DSA_SIG * sig = DSA_SIG_new();
		DSA_SIG_set0 (sig, BN_bin2bn (signature, DSA_SIGNATURE_LENGTH/2, NULL), BN_bin2bn (signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2, NULL));
		// to DER format
		uint8_t sign[DSA_SIGNATURE_LENGTH + 8];
		uint8_t * s = sign;
		auto l = i2d_DSA_SIG (sig, &s);
		DSA_SIG_free(sig);
		// verify
		EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
		EVP_DigestVerifyInit (ctx, NULL, EVP_sha1(), NULL, m_PublicKey);
		auto ret = EVP_DigestVerify (ctx, sign, l, buf, len) == 1;
		EVP_MD_CTX_destroy (ctx);
		return ret;
	}

	DSASigner::DSASigner (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
	{
		BIGNUM * priv = BN_bin2bn (signingPrivateKey, DSA_PRIVATE_KEY_LENGTH, NULL);
		m_PrivateKey = CreateDSA (nullptr, priv);
		BN_free (priv);
	}

	DSASigner::~DSASigner ()
	{
		if (m_PrivateKey)
			EVP_PKEY_free (m_PrivateKey);
	}

	void DSASigner::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		uint8_t sign[DSA_SIGNATURE_LENGTH + 8];
		size_t l = DSA_SIGNATURE_LENGTH + 8;
		EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
		EVP_DigestSignInit (ctx, NULL, EVP_sha1(), NULL, m_PrivateKey);
		EVP_DigestSign (ctx, sign, &l, buf, len);
		EVP_MD_CTX_destroy (ctx);
		// decode r and s
		const uint8_t * s1 = sign;
    	DSA_SIG * sig = d2i_DSA_SIG (NULL, &s1, l);
		const BIGNUM * r, * s;
		DSA_SIG_get0 (sig, &r, &s);
		bn2buf (r, signature, DSA_SIGNATURE_LENGTH/2);
		bn2buf (s, signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2);
		DSA_SIG_free(sig);
	}
	
	void CreateDSARandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		EVP_PKEY * paramskey = CreateDSA();
		EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new_from_pkey(NULL, paramskey, NULL);
		EVP_PKEY_keygen_init(ctx);
		EVP_PKEY * pkey = nullptr;
		EVP_PKEY_keygen(ctx, &pkey);
		BIGNUM * pub = NULL, * priv = NULL;
		EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub);
		bn2buf (pub, signingPublicKey, DSA_PUBLIC_KEY_LENGTH);
		EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv);
		bn2buf (priv, signingPrivateKey, DSA_PRIVATE_KEY_LENGTH);
		BN_free (pub); BN_free (priv);
		EVP_PKEY_free (pkey);
		EVP_PKEY_free (paramskey);
		EVP_PKEY_CTX_free (ctx);
	}	
#else	
	
	DSAVerifier::DSAVerifier ()
	{
		m_PublicKey = CreateDSA ();
	}

	DSAVerifier::~DSAVerifier ()
	{
		DSA_free (m_PublicKey);
	}

	void DSAVerifier::SetPublicKey (const uint8_t * signingKey)
	{
		DSA_set0_key (m_PublicKey, BN_bin2bn (signingKey, DSA_PUBLIC_KEY_LENGTH, NULL), NULL);
	}
	
	bool DSAVerifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		// calculate SHA1 digest
		uint8_t digest[20];
		SHA1 (buf, len, digest);
		// signature
		DSA_SIG * sig = DSA_SIG_new();
		DSA_SIG_set0 (sig, BN_bin2bn (signature, DSA_SIGNATURE_LENGTH/2, NULL), BN_bin2bn (signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2, NULL));
		// DSA verification
		int ret = DSA_do_verify (digest, 20, sig, m_PublicKey) == 1;
		DSA_SIG_free(sig);
		return ret;
	}

	DSASigner::DSASigner (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
	{
		m_PrivateKey = CreateDSA ();
		DSA_set0_key (m_PrivateKey, BN_bin2bn (signingPublicKey, DSA_PUBLIC_KEY_LENGTH, NULL), BN_bin2bn (signingPrivateKey, DSA_PRIVATE_KEY_LENGTH, NULL));
	}

	DSASigner::~DSASigner ()
	{
		DSA_free (m_PrivateKey);
	}

	void DSASigner::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		uint8_t digest[20];
		SHA1 (buf, len, digest);
		DSA_SIG * sig = DSA_do_sign (digest, 20, m_PrivateKey);
		const BIGNUM * r, * s;
		DSA_SIG_get0 (sig, &r, &s);
		bn2buf (r, signature, DSA_SIGNATURE_LENGTH/2);
		bn2buf (s, signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2);
		DSA_SIG_free(sig);
	}

	void CreateDSARandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		DSA * dsa = CreateDSA ();
		DSA_generate_key (dsa);
		const BIGNUM * pub_key, * priv_key;
		DSA_get0_key(dsa, &pub_key, &priv_key);
		bn2buf (priv_key, signingPrivateKey, DSA_PRIVATE_KEY_LENGTH);
		bn2buf (pub_key, signingPublicKey, DSA_PUBLIC_KEY_LENGTH);
		DSA_free (dsa);
	}
#endif	

#if (OPENSSL_VERSION_NUMBER >= 0x030000000) // since 3.0.0
	ECDSAVerifier::ECDSAVerifier (int curve, size_t keyLen, const EVP_MD * hash):
		m_Curve(curve), m_KeyLen (keyLen), m_Hash (hash), m_PublicKey (nullptr)
	{
	}

	ECDSAVerifier::~ECDSAVerifier ()
	{
		if (m_PublicKey)
			EVP_PKEY_free (m_PublicKey);
	}	

	void ECDSAVerifier::SetPublicKey (const uint8_t * signingKey)
	{
		if (m_PublicKey)
		{	
			EVP_PKEY_free (m_PublicKey);
			m_PublicKey = nullptr;
		}	
		auto plen = GetPublicKeyLen ();
		std::vector<uint8_t> pub(plen + 1);
		pub[0] = POINT_CONVERSION_UNCOMPRESSED;
		memcpy (pub.data() + 1, signingKey, plen); // 0x04|x|y
		OSSL_PARAM_BLD * paramBld = OSSL_PARAM_BLD_new ();	
		OSSL_PARAM_BLD_push_utf8_string (paramBld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2ln(m_Curve), 0);
		OSSL_PARAM_BLD_push_octet_string (paramBld, OSSL_PKEY_PARAM_PUB_KEY, pub.data (), pub.size ());
		OSSL_PARAM * params = OSSL_PARAM_BLD_to_param(paramBld);

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
		if (ctx)
		{
			if (EVP_PKEY_fromdata_init (ctx) <= 0 ||
				EVP_PKEY_fromdata (ctx, &m_PublicKey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
					LogPrint (eLogError, "ECDSA can't create PKEY from params");
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "ECDSA can't create PKEY context");
		
		OSSL_PARAM_free (params);	
		OSSL_PARAM_BLD_free (paramBld);
	}	

	bool ECDSAVerifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		// signature
		ECDSA_SIG * sig = ECDSA_SIG_new();
		ECDSA_SIG_set0 (sig, BN_bin2bn (signature, GetSignatureLen ()/2, NULL), 
			BN_bin2bn (signature + GetSignatureLen ()/2, GetSignatureLen ()/2, NULL));
		// to DER format
		std::vector<uint8_t> sign(GetSignatureLen () + 8);
		uint8_t * s = sign.data ();
		auto l = i2d_ECDSA_SIG (sig, &s);
		ECDSA_SIG_free(sig);
		// verify
		EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
		EVP_DigestVerifyInit (ctx, NULL, m_Hash, NULL, m_PublicKey);
		auto ret = EVP_DigestVerify (ctx, sign.data (), l, buf, len) == 1;
		EVP_MD_CTX_destroy (ctx);
		return ret;
	}	

	ECDSASigner::ECDSASigner (int curve, size_t keyLen, const EVP_MD * hash, const uint8_t * signingPrivateKey):
		m_KeyLen (keyLen), m_Hash(hash), m_PrivateKey (nullptr)
	{
		BIGNUM * priv = BN_bin2bn (signingPrivateKey, keyLen/2, NULL);
		OSSL_PARAM_BLD * paramBld = OSSL_PARAM_BLD_new ();	
		OSSL_PARAM_BLD_push_utf8_string (paramBld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2ln(curve), 0);
		OSSL_PARAM_BLD_push_BN (paramBld, OSSL_PKEY_PARAM_PRIV_KEY, priv);	
		OSSL_PARAM * params = OSSL_PARAM_BLD_to_param(paramBld);	
		
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
		if (ctx)
		{
			if (EVP_PKEY_fromdata_init (ctx) <= 0 ||
				EVP_PKEY_fromdata (ctx, &m_PrivateKey, EVP_PKEY_KEYPAIR, params) <= 0)
					LogPrint (eLogError, "ECDSA can't create PKEY from params");
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "ECDSA can't create PKEY context");

		OSSL_PARAM_free (params);	
		OSSL_PARAM_BLD_free (paramBld);	
		BN_free (priv);	
	}
		
	ECDSASigner::~ECDSASigner ()
	{
		if (m_PrivateKey)
			EVP_PKEY_free (m_PrivateKey);
	}

	void ECDSASigner::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		std::vector<uint8_t> sign(m_KeyLen + 8);
		size_t l = sign.size ();
		EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
		EVP_DigestSignInit (ctx, NULL, m_Hash, NULL, m_PrivateKey);
		EVP_DigestSign (ctx, sign.data(), &l, buf, len);
		EVP_MD_CTX_destroy (ctx);
		// decode r and s	
		const uint8_t * s1 = sign.data ();
		ECDSA_SIG * sig = d2i_ECDSA_SIG (NULL, &s1, l);
		const BIGNUM * r, * s;
		ECDSA_SIG_get0 (sig, &r, &s);
		bn2buf (r, signature, m_KeyLen/2);
		bn2buf (s, signature + m_KeyLen/2, m_KeyLen/2);
		ECDSA_SIG_free(sig);
	}	
		
	void CreateECDSARandomKeys (int curve, size_t keyLen, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		EVP_PKEY * pkey = EVP_EC_gen (OBJ_nid2ln(curve));
		// private
		BIGNUM * priv = BN_new ();
		EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv);
		bn2buf (priv, signingPrivateKey, keyLen/2);
		BN_free (priv);
		// public
		BIGNUM * x = BN_new (), * y = BN_new ();
		EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x);
		EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
		bn2buf (x, signingPublicKey, keyLen/2);
		bn2buf (y, signingPublicKey + keyLen/2, keyLen/2);
		BN_free (x); BN_free (y);
		EVP_PKEY_free (pkey);
	}	
		
#endif		
		
	EDDSA25519Verifier::EDDSA25519Verifier ():
		m_Pkey (nullptr)
	{
	}

	EDDSA25519Verifier::~EDDSA25519Verifier ()
	{
		EVP_PKEY_free (m_Pkey);
	}

	void EDDSA25519Verifier::SetPublicKey (const uint8_t * signingKey)
	{
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
		m_Pkey = EVP_PKEY_new_raw_public_key (EVP_PKEY_ED25519, NULL, signingKey, 32);
	}

	bool EDDSA25519Verifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		if (m_Pkey)
		{	
			EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
			EVP_DigestVerifyInit (ctx, NULL, NULL, NULL, m_Pkey);
			auto ret = EVP_DigestVerify (ctx, signature, 64, buf, len) == 1;
			EVP_MD_CTX_destroy (ctx);	
			return ret;	
		}	
		else
			LogPrint (eLogError, "EdDSA verification key is not set");
		return false;
	}

	EDDSA25519SignerCompat::EDDSA25519SignerCompat (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
	{
		// expand key
		Ed25519::ExpandPrivateKey (signingPrivateKey, m_ExpandedPrivateKey);
		// generate and encode public key
		BN_CTX * ctx = BN_CTX_new ();
		auto publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
		GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);

		if (signingPublicKey && memcmp (m_PublicKeyEncoded, signingPublicKey, EDDSA25519_PUBLIC_KEY_LENGTH))
		{
			// keys don't match, it means older key with 0x1F
			LogPrint (eLogWarning, "Older EdDSA key detected");
			m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] &= 0xDF; // drop third bit
			publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
			GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);
		}
		BN_CTX_free (ctx);
	}

	EDDSA25519SignerCompat::~EDDSA25519SignerCompat ()
	{
	}

	void EDDSA25519SignerCompat::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		GetEd25519 ()->Sign (m_ExpandedPrivateKey, m_PublicKeyEncoded, buf, len, signature);
	}

	EDDSA25519Signer::EDDSA25519Signer (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey):
		m_Pkey (nullptr), m_Fallback (nullptr)
	{
		m_Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_ED25519, NULL, signingPrivateKey, 32);
		uint8_t publicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
		size_t len = EDDSA25519_PUBLIC_KEY_LENGTH;
		EVP_PKEY_get_raw_public_key (m_Pkey, publicKey, &len);
		if (signingPublicKey && memcmp (publicKey, signingPublicKey, EDDSA25519_PUBLIC_KEY_LENGTH))
		{
			LogPrint (eLogWarning, "EdDSA public key mismatch. Fallback");
			m_Fallback = new EDDSA25519SignerCompat (signingPrivateKey, signingPublicKey);
			EVP_PKEY_free (m_Pkey);
			m_Pkey = nullptr;
		}
	}

	EDDSA25519Signer::~EDDSA25519Signer ()
	{
		if (m_Fallback) delete m_Fallback;
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
	}

	void EDDSA25519Signer::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		if (m_Fallback) 
			return m_Fallback->Sign (buf, len, signature);
		else if (m_Pkey)
		{
				
			EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
			size_t l = 64;
			uint8_t sig[64]; // temporary buffer for signature. openssl issue #7232
			EVP_DigestSignInit (ctx, NULL, NULL, NULL, m_Pkey);
			if (!EVP_DigestSign (ctx, sig, &l, buf, len))
				LogPrint (eLogError, "EdDSA signing failed");
			memcpy (signature, sig, 64);
			EVP_MD_CTX_destroy (ctx);
		}
		else
			LogPrint (eLogError, "EdDSA signing key is not set");
	}

#if (OPENSSL_VERSION_NUMBER >= 0x030000000)
	static const OSSL_PARAM EDDSA25519phParams[] =
	{
		OSSL_PARAM_utf8_string ("instance", (char *)"Ed25519ph", 9),
		OSSL_PARAM_END
	};
		
	bool EDDSA25519phVerifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		auto pkey = GetPkey ();
		if (pkey)
		{	
			uint8_t digest[64];
			SHA512 (buf, len, digest);
			EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
			EVP_DigestVerifyInit_ex (ctx, NULL, NULL, NULL, NULL, pkey, EDDSA25519phParams);
			auto ret = EVP_DigestVerify (ctx, signature, 64, digest, 64);
			EVP_MD_CTX_destroy (ctx);	
			return ret;	
		}	
		else
			LogPrint (eLogError, "EdDSA verification key is not set");
		return false;
	}

	EDDSA25519phSigner::EDDSA25519phSigner (const uint8_t * signingPrivateKey): 
		EDDSA25519Signer (signingPrivateKey)
	{		
	}
		
	void EDDSA25519phSigner::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		auto pkey = GetPkey ();
		if (pkey)
		{	
			uint8_t digest[64];
			SHA512 (buf, len, digest);
			EVP_MD_CTX * ctx = EVP_MD_CTX_create ();
			size_t l = 64;
			uint8_t sig[64];
			EVP_DigestSignInit_ex (ctx, NULL, NULL, NULL, NULL, pkey, EDDSA25519phParams);
			if (!EVP_DigestSign (ctx, sig, &l, digest, 64))
				LogPrint (eLogError, "EdDSA signing failed");
			memcpy (signature, sig, 64);
			EVP_MD_CTX_destroy (ctx);
		}
		else
			LogPrint (eLogError, "EdDSA signing key is not set");
	}		
#endif	
		
#if OPENSSL_PQ
		
	MLDSA44Verifier::MLDSA44Verifier ():
		m_Pkey (nullptr)
	{
	}

	MLDSA44Verifier::~MLDSA44Verifier ()
	{
		EVP_PKEY_free (m_Pkey);
	}

	void MLDSA44Verifier::SetPublicKey (const uint8_t * signingKey)
	{
		if (m_Pkey) 
		{ 
			EVP_PKEY_free (m_Pkey);
			m_Pkey = nullptr;
		}	
		OSSL_PARAM params[] =
		{
			OSSL_PARAM_octet_string (OSSL_PKEY_PARAM_PUB_KEY, (uint8_t *)signingKey, GetPublicKeyLen ()),
			OSSL_PARAM_END
		};		
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "ML-DSA-44", NULL);
		if (ctx)
		{
			EVP_PKEY_fromdata_init (ctx);
			EVP_PKEY_fromdata (ctx, &m_Pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLDSA44 can't create PKEY context");
	}

	bool MLDSA44Verifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		bool ret = false;
		if (m_Pkey)
		{	
			EVP_PKEY_CTX * vctx = EVP_PKEY_CTX_new_from_pkey (NULL, m_Pkey, NULL);
			if (vctx)
			{
				EVP_SIGNATURE * sig = EVP_SIGNATURE_fetch (NULL, "ML-DSA-44", NULL);
				if (sig)
				{
					int encode = 1;
					OSSL_PARAM params[] =
					{
						OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode),
						OSSL_PARAM_END
					};		
					EVP_PKEY_verify_message_init (vctx, sig, params);
					ret = EVP_PKEY_verify (vctx, signature, GetSignatureLen (), buf, len) == 1;
					EVP_SIGNATURE_free (sig);
				}	
				EVP_PKEY_CTX_free (vctx);
			}	
			else
				LogPrint (eLogError, "MLDSA44 can't obtain context from PKEY");
		}	
		else
			LogPrint (eLogError, "MLDSA44 verification key is not set");
		return ret;
	}

	MLDSA44Signer::MLDSA44Signer (const uint8_t * signingPrivateKey):
		m_Pkey (nullptr)
	{
		OSSL_PARAM params[] =
		{
			OSSL_PARAM_octet_string (OSSL_PKEY_PARAM_PRIV_KEY, (uint8_t *)signingPrivateKey, MLDSA44_PRIVATE_KEY_LENGTH),
			OSSL_PARAM_END
		};		
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, "ML-DSA-44", NULL);
		if (ctx)
		{
			EVP_PKEY_fromdata_init (ctx);
			EVP_PKEY_fromdata (ctx, &m_Pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLDSA44 can't create PKEY context");
	}

	MLDSA44Signer::~MLDSA44Signer ()
	{
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
	}

	void MLDSA44Signer::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		if (m_Pkey)
		{	
			EVP_PKEY_CTX * sctx = EVP_PKEY_CTX_new_from_pkey (NULL, m_Pkey, NULL);
			if (sctx)
			{
				EVP_SIGNATURE * sig = EVP_SIGNATURE_fetch (NULL, "ML-DSA-44", NULL);
				if (sig)
				{
					int encode = 1;
					OSSL_PARAM params[] =
					{
						OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode),
						OSSL_PARAM_END
					};		
					EVP_PKEY_sign_message_init (sctx, sig, params);
					size_t siglen = MLDSA44_SIGNATURE_LENGTH;
					EVP_PKEY_sign (sctx, signature, &siglen, buf, len);
					EVP_SIGNATURE_free (sig);
				}	
				EVP_PKEY_CTX_free (sctx);
			}	
			else
				LogPrint (eLogError, "MLDSA44 can't obtain context from PKEY");
		}	
		else
			LogPrint (eLogError, "MLDSA44 signing key is not set");
	}	
		
#endif		
}
}
