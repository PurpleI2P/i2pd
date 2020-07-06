/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SIGNATURE_H__
#define SIGNATURE_H__

#include <inttypes.h>
#include <string.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include "Crypto.h"
#include "Ed25519.h"
#include "Gost.h"

namespace i2p
{
namespace crypto
{
	class Verifier
	{
		public:

			virtual ~Verifier () {};
			virtual bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const = 0;
			virtual size_t GetPublicKeyLen () const = 0;
			virtual size_t GetSignatureLen () const = 0;
			virtual size_t GetPrivateKeyLen () const { return GetSignatureLen ()/2; };
			virtual void SetPublicKey (const uint8_t * signingKey) = 0;
	};

	class Signer
	{
		public:

			virtual ~Signer () {};
			virtual void Sign (const uint8_t * buf, int len, uint8_t * signature) const = 0;
	};

	const size_t DSA_PUBLIC_KEY_LENGTH = 128;
	const size_t DSA_SIGNATURE_LENGTH = 40;
	const size_t DSA_PRIVATE_KEY_LENGTH = DSA_SIGNATURE_LENGTH/2;
	class DSAVerifier: public Verifier
	{
		public:

			DSAVerifier ()
			{
				m_PublicKey = CreateDSA ();
			}

			void SetPublicKey (const uint8_t * signingKey)
			{
				DSA_set0_key (m_PublicKey, BN_bin2bn (signingKey, DSA_PUBLIC_KEY_LENGTH, NULL), NULL);
			}

			~DSAVerifier ()
			{
				DSA_free (m_PublicKey);
			}

			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				// calculate SHA1 digest
				uint8_t digest[20];
				SHA1 (buf, len, digest);
				// signature
				DSA_SIG * sig = DSA_SIG_new();
				DSA_SIG_set0 (sig, BN_bin2bn (signature, DSA_SIGNATURE_LENGTH/2, NULL), BN_bin2bn (signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2, NULL));
				// DSA verification
				int ret = DSA_do_verify (digest, 20, sig, m_PublicKey);
				DSA_SIG_free(sig);
				return ret;
			}

			size_t GetPublicKeyLen () const { return DSA_PUBLIC_KEY_LENGTH; };
			size_t GetSignatureLen () const { return DSA_SIGNATURE_LENGTH; };

		private:

			DSA * m_PublicKey;
	};

	class DSASigner: public Signer
	{
		public:

			DSASigner (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
			// openssl 1.1 always requires DSA public key even for signing
			{
				m_PrivateKey = CreateDSA ();
				DSA_set0_key (m_PrivateKey, BN_bin2bn (signingPublicKey, DSA_PUBLIC_KEY_LENGTH, NULL), BN_bin2bn (signingPrivateKey, DSA_PRIVATE_KEY_LENGTH, NULL));
			}

			~DSASigner ()
			{
				DSA_free (m_PrivateKey);
			}

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
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

		private:

			DSA * m_PrivateKey;
	};

	inline void CreateDSARandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		DSA * dsa = CreateDSA ();
		DSA_generate_key (dsa);
		const BIGNUM * pub_key, * priv_key;
		DSA_get0_key(dsa, &pub_key, &priv_key);
		bn2buf (priv_key, signingPrivateKey, DSA_PRIVATE_KEY_LENGTH);
		bn2buf (pub_key, signingPublicKey, DSA_PUBLIC_KEY_LENGTH);
		DSA_free (dsa);
	}

	struct SHA256Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			SHA256 (buf, len, digest);
		}

		enum { hashLen = 32 };
	};

	struct SHA384Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			SHA384 (buf, len, digest);
		}

		enum { hashLen = 48 };
	};

	struct SHA512Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			SHA512 (buf, len, digest);
		}

		enum { hashLen = 64 };
	};

	// EcDSA
	template<typename Hash, int curve, size_t keyLen>
	class ECDSAVerifier: public Verifier
	{
		public:

			ECDSAVerifier ()
			{
				m_PublicKey = EC_KEY_new_by_curve_name (curve);
			}

			void SetPublicKey (const uint8_t * signingKey)
			{
				BIGNUM * x = BN_bin2bn (signingKey, keyLen/2, NULL);
				BIGNUM * y = BN_bin2bn (signingKey + keyLen/2, keyLen/2, NULL);
				EC_KEY_set_public_key_affine_coordinates (m_PublicKey, x, y);
				BN_free (x); BN_free (y);
			}

			~ECDSAVerifier ()
			{
				EC_KEY_free (m_PublicKey);
			}

			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				ECDSA_SIG * sig = ECDSA_SIG_new();
				auto r = BN_bin2bn (signature, GetSignatureLen ()/2, NULL);
				auto s = BN_bin2bn (signature + GetSignatureLen ()/2, GetSignatureLen ()/2, NULL);
				ECDSA_SIG_set0(sig, r, s);
				// ECDSA verification
				int ret = ECDSA_do_verify (digest, Hash::hashLen, sig, m_PublicKey);
				ECDSA_SIG_free(sig);
				return ret;
			}

			size_t GetPublicKeyLen () const { return keyLen; };
			size_t GetSignatureLen () const { return keyLen; }; // signature length = key length


		private:

			EC_KEY * m_PublicKey;
	};

	template<typename Hash, int curve, size_t keyLen>
	class ECDSASigner: public Signer
	{
		public:

			ECDSASigner (const uint8_t * signingPrivateKey)
			{
				m_PrivateKey = EC_KEY_new_by_curve_name (curve);
				EC_KEY_set_private_key (m_PrivateKey, BN_bin2bn (signingPrivateKey, keyLen/2, NULL));
			}

			~ECDSASigner ()
			{
				EC_KEY_free (m_PrivateKey);
			}

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				ECDSA_SIG * sig = ECDSA_do_sign (digest, Hash::hashLen, m_PrivateKey);
				const BIGNUM * r, * s;
				ECDSA_SIG_get0 (sig, &r, &s);
				// signatureLen = keyLen
				bn2buf (r, signature, keyLen/2);
				bn2buf (s, signature + keyLen/2, keyLen/2);
				ECDSA_SIG_free(sig);
			}

		private:

			EC_KEY * m_PrivateKey;
	};

	inline void CreateECDSARandomKeys (int curve, size_t keyLen, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		EC_KEY * signingKey = EC_KEY_new_by_curve_name (curve);
		EC_KEY_generate_key (signingKey);
		bn2buf (EC_KEY_get0_private_key (signingKey), signingPrivateKey, keyLen/2);
		BIGNUM * x = BN_new(), * y = BN_new();
		EC_POINT_get_affine_coordinates_GFp (EC_KEY_get0_group(signingKey),
			EC_KEY_get0_public_key (signingKey), x, y, NULL);
		bn2buf (x, signingPublicKey, keyLen/2);
		bn2buf (y, signingPublicKey + keyLen/2, keyLen/2);
		BN_free (x); BN_free (y);
		EC_KEY_free (signingKey);
	}

// ECDSA_SHA256_P256
	const size_t ECDSAP256_KEY_LENGTH = 64;
	typedef ECDSAVerifier<SHA256Hash, NID_X9_62_prime256v1, ECDSAP256_KEY_LENGTH> ECDSAP256Verifier;
	typedef ECDSASigner<SHA256Hash, NID_X9_62_prime256v1, ECDSAP256_KEY_LENGTH> ECDSAP256Signer;

	inline void CreateECDSAP256RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		CreateECDSARandomKeys (NID_X9_62_prime256v1, ECDSAP256_KEY_LENGTH, signingPrivateKey, signingPublicKey);
	}

// ECDSA_SHA384_P384
	const size_t ECDSAP384_KEY_LENGTH = 96;
	typedef ECDSAVerifier<SHA384Hash, NID_secp384r1, ECDSAP384_KEY_LENGTH> ECDSAP384Verifier;
	typedef ECDSASigner<SHA384Hash, NID_secp384r1, ECDSAP384_KEY_LENGTH> ECDSAP384Signer;

	inline void CreateECDSAP384RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		CreateECDSARandomKeys (NID_secp384r1, ECDSAP384_KEY_LENGTH, signingPrivateKey, signingPublicKey);
	}

// ECDSA_SHA512_P521
	const size_t ECDSAP521_KEY_LENGTH = 132;
	typedef ECDSAVerifier<SHA512Hash, NID_secp521r1, ECDSAP521_KEY_LENGTH> ECDSAP521Verifier;
	typedef ECDSASigner<SHA512Hash, NID_secp521r1, ECDSAP521_KEY_LENGTH> ECDSAP521Signer;

	inline void CreateECDSAP521RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		CreateECDSARandomKeys (NID_secp521r1, ECDSAP521_KEY_LENGTH, signingPrivateKey, signingPublicKey);
	}


	// EdDSA
	class EDDSA25519Verifier: public Verifier
	{
		public:

			EDDSA25519Verifier ();
			void SetPublicKey (const uint8_t * signingKey);
			~EDDSA25519Verifier ();

			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const;

			size_t GetPublicKeyLen () const { return EDDSA25519_PUBLIC_KEY_LENGTH; };
			size_t GetSignatureLen () const { return EDDSA25519_SIGNATURE_LENGTH; };

		private:

#if OPENSSL_EDDSA
			EVP_PKEY * m_Pkey;
			EVP_MD_CTX * m_MDCtx;
#else
			EDDSAPoint m_PublicKey;
			uint8_t m_PublicKeyEncoded[EDDSA25519_PUBLIC_KEY_LENGTH];
#endif
	};

	class EDDSA25519SignerCompat: public Signer
	{
		public:

			EDDSA25519SignerCompat (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey = nullptr);
			// we pass signingPublicKey to check if it matches private key
			~EDDSA25519SignerCompat ();

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;
			const uint8_t * GetPublicKey () const { return m_PublicKeyEncoded; }; // for keys creation

		private:

			uint8_t m_ExpandedPrivateKey[64];
			uint8_t m_PublicKeyEncoded[EDDSA25519_PUBLIC_KEY_LENGTH];
	};

#if OPENSSL_EDDSA
	class EDDSA25519Signer: public Signer
	{
		public:

			EDDSA25519Signer (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey = nullptr);
			// we pass signingPublicKey to check if it matches private key
			~EDDSA25519Signer ();

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;

		private:
			EVP_PKEY * m_Pkey;
			EVP_MD_CTX * m_MDCtx;
			EDDSA25519SignerCompat * m_Fallback;
	};
#else

	typedef EDDSA25519SignerCompat EDDSA25519Signer;

#endif

	inline void CreateEDDSA25519RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
#if OPENSSL_EDDSA
		EVP_PKEY *pkey = NULL;
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_ED25519, NULL);
		EVP_PKEY_keygen_init (pctx);
		EVP_PKEY_keygen (pctx, &pkey);
		EVP_PKEY_CTX_free (pctx);
		size_t len = EDDSA25519_PUBLIC_KEY_LENGTH;
		EVP_PKEY_get_raw_public_key (pkey, signingPublicKey, &len);
		len = EDDSA25519_PRIVATE_KEY_LENGTH;
		EVP_PKEY_get_raw_private_key (pkey, signingPrivateKey, &len);
		EVP_PKEY_free (pkey);
#else
		RAND_bytes (signingPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH);
		EDDSA25519Signer signer (signingPrivateKey);
		memcpy (signingPublicKey, signer.GetPublicKey (), EDDSA25519_PUBLIC_KEY_LENGTH);
#endif
	}


	// ГОСТ Р 34.11
	struct GOSTR3411_256_Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			GOSTR3411_2012_256 (buf, len, digest);
		}

		enum { hashLen = 32 };
	};

	struct GOSTR3411_512_Hash
	{
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			GOSTR3411_2012_512 (buf, len, digest);
		}

		enum { hashLen = 64 };
	};

	// ГОСТ Р 34.10
	const size_t GOSTR3410_256_PUBLIC_KEY_LENGTH = 64;
	const size_t GOSTR3410_512_PUBLIC_KEY_LENGTH = 128;

	template<typename Hash>
	class GOSTR3410Verifier: public Verifier
	{
		public:

			enum { keyLen = Hash::hashLen };

			GOSTR3410Verifier (GOSTR3410ParamSet paramSet):
				m_ParamSet (paramSet), m_PublicKey (nullptr)
			{
			}

			void SetPublicKey (const uint8_t * signingKey)
			{
				BIGNUM * x = BN_bin2bn (signingKey, GetPublicKeyLen ()/2, NULL);
				BIGNUM * y = BN_bin2bn (signingKey + GetPublicKeyLen ()/2, GetPublicKeyLen ()/2, NULL);
				m_PublicKey = GetGOSTR3410Curve (m_ParamSet)->CreatePoint (x, y);
				BN_free (x); BN_free (y);
			}
			~GOSTR3410Verifier ()
			{
				if (m_PublicKey) EC_POINT_free (m_PublicKey);
			}

			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				BIGNUM * d = BN_bin2bn (digest, Hash::hashLen, nullptr);
				BIGNUM * r = BN_bin2bn (signature, GetSignatureLen ()/2, NULL);
				BIGNUM * s = BN_bin2bn (signature + GetSignatureLen ()/2, GetSignatureLen ()/2, NULL);
				bool ret = GetGOSTR3410Curve (m_ParamSet)->Verify (m_PublicKey, d, r, s);
				BN_free (d); BN_free (r); BN_free (s);
				return ret;
			}

			size_t GetPublicKeyLen () const { return keyLen*2; }
			size_t GetSignatureLen () const { return keyLen*2; }

		private:

			GOSTR3410ParamSet m_ParamSet;
			EC_POINT * m_PublicKey;
	};

	template<typename Hash>
	class GOSTR3410Signer: public Signer
	{
		public:

			enum { keyLen = Hash::hashLen };

			GOSTR3410Signer (GOSTR3410ParamSet paramSet, const uint8_t * signingPrivateKey):
				m_ParamSet (paramSet)
			{
				m_PrivateKey = BN_bin2bn (signingPrivateKey, keyLen, nullptr);
			}
			~GOSTR3410Signer () { BN_free (m_PrivateKey); }

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				BIGNUM * d = BN_bin2bn (digest, Hash::hashLen, nullptr);
				BIGNUM * r = BN_new (), * s = BN_new ();
				GetGOSTR3410Curve (m_ParamSet)->Sign (m_PrivateKey, d, r, s);
				bn2buf (r, signature, keyLen);
				bn2buf (s, signature + keyLen, keyLen);
				BN_free (d); BN_free (r); BN_free (s);
			}

		private:

			GOSTR3410ParamSet m_ParamSet;
			BIGNUM * m_PrivateKey;
	};

	inline void CreateGOSTR3410RandomKeys (GOSTR3410ParamSet paramSet, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		const auto& curve = GetGOSTR3410Curve (paramSet);
		auto keyLen = curve->GetKeyLen ();
		RAND_bytes (signingPrivateKey, keyLen);
		BIGNUM * priv = BN_bin2bn (signingPrivateKey, keyLen, nullptr);

		auto pub = curve->MulP (priv);
		BN_free (priv);
		BIGNUM * x = BN_new (), * y = BN_new ();
		curve->GetXY (pub, x, y);
		EC_POINT_free (pub);
		bn2buf (x, signingPublicKey, keyLen);
		bn2buf (y, signingPublicKey + keyLen, keyLen);
		BN_free (x); BN_free (y);
	}

	typedef GOSTR3410Verifier<GOSTR3411_256_Hash> GOSTR3410_256_Verifier;
	typedef GOSTR3410Signer<GOSTR3411_256_Hash> GOSTR3410_256_Signer;
	typedef GOSTR3410Verifier<GOSTR3411_512_Hash> GOSTR3410_512_Verifier;
	typedef GOSTR3410Signer<GOSTR3411_512_Hash> GOSTR3410_512_Signer;

	// RedDSA
	typedef EDDSA25519Verifier RedDSA25519Verifier;
	class RedDSA25519Signer: public Signer
	{
		public:

			RedDSA25519Signer (const uint8_t * signingPrivateKey)
			{
				memcpy (m_PrivateKey, signingPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH);
				BN_CTX * ctx = BN_CTX_new ();
				auto publicKey = GetEd25519 ()->GeneratePublicKey (m_PrivateKey, ctx);
				GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);
				BN_CTX_free (ctx);
			}
			~RedDSA25519Signer () {};

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				GetEd25519 ()->SignRedDSA (m_PrivateKey, m_PublicKeyEncoded, buf, len, signature);
			}

			const uint8_t * GetPublicKey () const { return m_PublicKeyEncoded; }; // for keys creation

		private:

			uint8_t m_PrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH];
			uint8_t m_PublicKeyEncoded[EDDSA25519_PUBLIC_KEY_LENGTH];
	};

	inline void CreateRedDSA25519RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		GetEd25519 ()->CreateRedDSAPrivateKey (signingPrivateKey);
		RedDSA25519Signer signer (signingPrivateKey);
		memcpy (signingPublicKey, signer.GetPublicKey (), EDDSA25519_PUBLIC_KEY_LENGTH);
	}
}
}

#endif
