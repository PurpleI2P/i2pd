/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef CRYPTO_H__
#define CRYPTO_H__

#include <inttypes.h>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/opensslv.h>

#include "Base.h"
#include "Tag.h"
#include "CPU.h"

// recognize openssl version and features
#if ((OPENSSL_VERSION_NUMBER < 0x010100000) || defined(LIBRESSL_VERSION_NUMBER)) // 1.0.2 and below or LibreSSL
#   define LEGACY_OPENSSL 1
#   define X509_getm_notBefore X509_get_notBefore
#   define X509_getm_notAfter X509_get_notAfter
#else
#   define LEGACY_OPENSSL 0
#   if (OPENSSL_VERSION_NUMBER >= 0x010101000) // 1.1.1
#       define OPENSSL_HKDF 1
#       define OPENSSL_EDDSA 1
#       define OPENSSL_X25519 1
#       define OPENSSL_SIPHASH 1
#   endif
#   if !defined OPENSSL_NO_CHACHA && !defined OPENSSL_NO_POLY1305 // some builds might not include them
#       define OPENSSL_AEAD_CHACHA20_POLY1305 1
#   endif
#endif

namespace i2p
{
namespace crypto
{
	bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len);

	// DSA
	DSA * CreateDSA ();

	// RSA
	const BIGNUM * GetRSAE ();

	// DH
	class DHKeys
	{
		public:

			DHKeys ();
			~DHKeys ();

			void GenerateKeys ();
			const uint8_t * GetPublicKey () const { return m_PublicKey; };
			void Agree (const uint8_t * pub, uint8_t * shared);

		private:

			DH * m_DH;
			uint8_t m_PublicKey[256];
	};

	// x25519
	class X25519Keys
	{
		public:

			X25519Keys ();
			X25519Keys (const uint8_t * priv, const uint8_t * pub); // if pub is null, derive from priv
			~X25519Keys ();

			void GenerateKeys ();
			const uint8_t * GetPublicKey () const { return m_PublicKey; };
			void GetPrivateKey (uint8_t * priv) const;
			void SetPrivateKey (const uint8_t * priv, bool calculatePublic = false);
			void Agree (const uint8_t * pub, uint8_t * shared);

			bool IsElligatorIneligible () const { return m_IsElligatorIneligible; }
			void SetElligatorIneligible () { m_IsElligatorIneligible = true; }
			
		private:

			uint8_t m_PublicKey[32];
#if OPENSSL_X25519
			EVP_PKEY_CTX * m_Ctx;
			EVP_PKEY * m_Pkey;
#else
			BN_CTX * m_Ctx;
			uint8_t m_PrivateKey[32];
#endif
			bool m_IsElligatorIneligible = false; // true if definitly ineligible
	};

	// ElGamal
	void ElGamalEncrypt (const uint8_t * key, const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding = false);
	bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding = false);
	void GenerateElGamalKeyPair (uint8_t * priv, uint8_t * pub);

	// ECIES
	void ECIESEncrypt (const EC_GROUP * curve, const EC_POINT * key, const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding = false); // 222 bytes data, 514 bytes encrypted with zeropadding, 512 without
	bool ECIESDecrypt (const EC_GROUP * curve, const BIGNUM * key, const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding = false);
	void GenerateECIESKeyPair (const EC_GROUP * curve, BIGNUM *& priv, EC_POINT *& pub);

	// HMAC
	typedef i2p::data::Tag<32> MACKey;
	void HMACMD5Digest (uint8_t * msg, size_t len, const MACKey& key, uint8_t * digest);

	// AES
	struct ChipherBlock
	{
		uint8_t buf[16];

		void operator^=(const ChipherBlock& other) // XOR
		{
			if (!(((size_t)buf | (size_t)other.buf) & 0x03)) // multiple of 4 ?
			{
				for (int i = 0; i < 4; i++)
					reinterpret_cast<uint32_t *>(buf)[i] ^= reinterpret_cast<const uint32_t *>(other.buf)[i];
			}
			else
			{
				for (int i = 0; i < 16; i++)
					buf[i] ^= other.buf[i];
			}
		}
	};

	typedef i2p::data::Tag<32> AESKey;

	template<size_t sz>
	class AESAlignedBuffer // 16 bytes alignment
	{
		public:

			AESAlignedBuffer ()
			{
				m_Buf = m_UnalignedBuffer;
				uint8_t rem = ((size_t)m_Buf) & 0x0f;
				if (rem)
					m_Buf += (16 - rem);
			}

			operator uint8_t * () { return m_Buf; };
			operator const uint8_t * () const { return m_Buf; };
			ChipherBlock * GetChipherBlock () { return (ChipherBlock *)m_Buf; };
			const ChipherBlock * GetChipherBlock () const { return (const ChipherBlock *)m_Buf; };

		private:

			uint8_t m_UnalignedBuffer[sz + 15]; // up to 15 bytes alignment
			uint8_t * m_Buf;
	};


#ifdef __AES__
	#ifdef ARM64AES
		void init_aesenc(void) __attribute__((constructor));
	#endif
	class ECBCryptoAESNI
	{
		public:

			uint8_t * GetKeySchedule () { return m_KeySchedule; };

		protected:

			void ExpandKey (const AESKey& key);

		private:

			AESAlignedBuffer<240> m_KeySchedule;	// 14 rounds for AES-256, 240 bytes
	};
#endif

#ifdef __AES__
	class ECBEncryption: public ECBCryptoAESNI
#else
	class ECBEncryption
#endif
	{
		public:

		void SetKey (const AESKey& key);

		void Encrypt(const ChipherBlock * in, ChipherBlock * out);

	private:
		AES_KEY m_Key;
	};

#ifdef __AES__
	class ECBDecryption: public ECBCryptoAESNI
#else
	class ECBDecryption
#endif
	{
		public:

			void SetKey (const AESKey& key);
			void Decrypt (const ChipherBlock * in, ChipherBlock * out);
		private:
			AES_KEY m_Key;
	};

	class CBCEncryption
	{
		public:

			CBCEncryption () { memset ((uint8_t *)m_LastBlock, 0, 16); };

			void SetKey (const AESKey& key) { m_ECBEncryption.SetKey (key); }; // 32 bytes
			void SetIV (const uint8_t * iv) { memcpy ((uint8_t *)m_LastBlock, iv, 16); }; // 16 bytes
			void GetIV (uint8_t * iv) const { memcpy (iv, (const uint8_t *)m_LastBlock, 16); };

			void Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out);
			void Encrypt (const uint8_t * in, std::size_t len, uint8_t * out);
			void Encrypt (const uint8_t * in, uint8_t * out); // one block

			ECBEncryption & ECB() { return m_ECBEncryption; }

		private:

			AESAlignedBuffer<16> m_LastBlock;

			ECBEncryption m_ECBEncryption;
	};

	class CBCDecryption
	{
		public:

			CBCDecryption () { memset ((uint8_t *)m_IV, 0, 16); };

			void SetKey (const AESKey& key) { m_ECBDecryption.SetKey (key); }; // 32 bytes
			void SetIV (const uint8_t * iv) { memcpy ((uint8_t *)m_IV, iv, 16); }; // 16 bytes
			void GetIV (uint8_t * iv) const { memcpy (iv, (const uint8_t *)m_IV, 16); };

			void Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out);
			void Decrypt (const uint8_t * in, std::size_t len, uint8_t * out);
			void Decrypt (const uint8_t * in, uint8_t * out); // one block

			ECBDecryption & ECB() { return m_ECBDecryption; }

		private:

			AESAlignedBuffer<16> m_IV;
			ECBDecryption m_ECBDecryption;
	};

	class TunnelEncryption // with double IV encryption
	{
		public:

			void SetKeys (const AESKey& layerKey, const AESKey& ivKey)
			{
				m_LayerEncryption.SetKey (layerKey);
				m_IVEncryption.SetKey (ivKey);
			}

			void Encrypt (const uint8_t * in, uint8_t * out); // 1024 bytes (16 IV + 1008 data)

		private:

			ECBEncryption m_IVEncryption;
			CBCEncryption m_LayerEncryption;
	};

	class TunnelDecryption // with double IV encryption
	{
		public:

			void SetKeys (const AESKey& layerKey, const AESKey& ivKey)
			{
				m_LayerDecryption.SetKey (layerKey);
				m_IVDecryption.SetKey (ivKey);
			}

			void Decrypt (const uint8_t * in, uint8_t * out); // 1024 bytes (16 IV + 1008 data)

		private:

			ECBDecryption m_IVDecryption;
			CBCDecryption m_LayerDecryption;
	};

// AEAD/ChaCha20/Poly1305
	bool AEADChaCha20Poly1305 (const uint8_t * msg, size_t msgLen, const uint8_t * ad, size_t adLen, const uint8_t * key, const uint8_t * nonce, uint8_t * buf, size_t len, bool encrypt); // msgLen is len without tag

	void AEADChaCha20Poly1305Encrypt (const std::vector<std::pair<uint8_t *, size_t> >& bufs, const uint8_t * key, const uint8_t * nonce, uint8_t * mac); // encrypt multiple buffers with zero ad

// ChaCha20
	void ChaCha20 (const uint8_t * msg, size_t msgLen, const uint8_t * key, const uint8_t * nonce, uint8_t * out);

// HKDF

	void HKDF (const uint8_t * salt, const uint8_t * key, size_t keyLen, const std::string& info, uint8_t * out, size_t outLen = 64); // salt - 32, out - 32 or 64, info <= 32

// init and terminate
	void InitCrypto (bool precomputation);
	void TerminateCrypto ();
}
}

// take care about openssl below 1.1.0
#if LEGACY_OPENSSL
// define getters and setters introduced in 1.1.0
inline int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
	{
		if (d->p) BN_free (d->p);
		if (d->q) BN_free (d->q);
		if (d->g) BN_free (d->g);
		d->p = p; d->q = q; d->g = g; return 1;
	}
inline int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
	{
		if (d->pub_key) BN_free (d->pub_key);
		if (d->priv_key) BN_free (d->priv_key);
		d->pub_key = pub_key; d->priv_key = priv_key; return 1;
	}
inline void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key)
	{ *pub_key = d->pub_key; *priv_key = d->priv_key; }
inline int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
	{
		if (sig->r) BN_free (sig->r);
		if (sig->s) BN_free (sig->s);
		sig->r = r; sig->s = s; return 1;
	}
inline void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
	{ *pr = sig->r; *ps = sig->s; }

inline int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
	{
		if (sig->r) BN_free (sig->r);
		if (sig->s) BN_free (sig->s);
		sig->r = r; sig->s = s; return 1;
	}
inline void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
	{ *pr = sig->r; *ps = sig->s; }

inline int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
	{
		if (r->n) BN_free (r->n);
		if (r->e) BN_free (r->e);
		if (r->d) BN_free (r->d);
		r->n = n; r->e = e; r->d = d; return 1;
	}
inline void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
	{ *n = r->n; *e = r->e; *d = r->d; }

inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
	{
		if (dh->p) BN_free (dh->p);
		if (dh->q) BN_free (dh->q);
		if (dh->g) BN_free (dh->g);
		dh->p = p; dh->q = q; dh->g = g;  return 1;
	}
inline int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
	{
		if (dh->pub_key) BN_free (dh->pub_key);
		if (dh->priv_key) BN_free (dh->priv_key);
		dh->pub_key = pub_key; dh->priv_key = priv_key; return 1;
	}
inline void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
	{ *pub_key = dh->pub_key; *priv_key = dh->priv_key; }

inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
	{ return pkey->pkey.rsa; }

inline EVP_MD_CTX *EVP_MD_CTX_new ()
	{ return EVP_MD_CTX_create(); }
inline void EVP_MD_CTX_free (EVP_MD_CTX *ctx)
	{ EVP_MD_CTX_destroy (ctx); }

// ssl
#define TLS_method TLSv1_method

#endif

#endif
