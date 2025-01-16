/*
* Copyright (c) 2013-2025, The PurpleI2P Project
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
#include <openssl/opensslv.h>

#include "Base.h"
#include "Tag.h"

// recognize openssl version and features
#if (OPENSSL_VERSION_NUMBER >= 0x010101000) // 1.1.1
#	define OPENSSL_HKDF 1
#	define OPENSSL_EDDSA 1
#	if (!defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER != 0x030000000)) // 3.0.0, regression in SipHash, not implemented in LibreSSL
#		define OPENSSL_SIPHASH 1
#	endif
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
			bool Agree (const uint8_t * pub, uint8_t * shared);

			bool IsElligatorIneligible () const { return m_IsElligatorIneligible; }
			void SetElligatorIneligible () { m_IsElligatorIneligible = true; }

		private:

			uint8_t m_PublicKey[32];
			EVP_PKEY_CTX * m_Ctx;
			EVP_PKEY * m_Pkey;
			bool m_IsElligatorIneligible = false; // true if definitely ineligible
	};

	// ElGamal
	void ElGamalEncrypt (const uint8_t * key, const uint8_t * data, uint8_t * encrypted); // 222 bytes data, 514 bytes encrypted
	bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted, uint8_t * data); // 514 bytes encrypted, 222 data
	void GenerateElGamalKeyPair (uint8_t * priv, uint8_t * pub);

	// ECIES
	void ECIESEncrypt (const EC_GROUP * curve, const EC_POINT * key, const uint8_t * data, uint8_t * encrypted); // 222 bytes data, 514 bytes encrypted
	bool ECIESDecrypt (const EC_GROUP * curve, const BIGNUM * key, const uint8_t * encrypted, uint8_t * data); // 514 bytes encrypted, 222 data
	void GenerateECIESKeyPair (const EC_GROUP * curve, BIGNUM *& priv, EC_POINT *& pub);

	// AES
	typedef i2p::data::Tag<32> AESKey;
	
	class ECBEncryption
	{
		public:

			ECBEncryption ();
			~ECBEncryption ();
			
			void SetKey (const uint8_t * key) { m_Key = key; };
			void Encrypt(const uint8_t * in, uint8_t * out);

		private:

			AESKey m_Key;
			EVP_CIPHER_CTX * m_Ctx;	
	};

	class ECBDecryption
	{
		public:

			ECBDecryption ();
			~ECBDecryption ();
			
			void SetKey (const uint8_t * key) { m_Key = key; };
			void Decrypt (const uint8_t * in, uint8_t * out);
			
		private:
			
			AESKey m_Key;
			EVP_CIPHER_CTX * m_Ctx;	
	};

	class CBCEncryption
	{
		public:

			CBCEncryption ();
			~CBCEncryption ();

			void SetKey (const uint8_t * key) { m_Key = key; }; // 32 bytes		
			void Encrypt (const uint8_t * in, size_t len, const uint8_t * iv, uint8_t * out);
			
		private:

			AESKey m_Key;
			EVP_CIPHER_CTX * m_Ctx;	
	};

	class CBCDecryption
	{
		public:

			CBCDecryption ();
			~CBCDecryption ();
			
			void SetKey (const uint8_t * key) { m_Key = key; }; // 32 bytes
			void Decrypt (const uint8_t * in, size_t len, const uint8_t * iv, uint8_t * out);

		private:

			AESKey m_Key;
			EVP_CIPHER_CTX * m_Ctx;	
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

	class AEADChaCha20Poly1305Encryptor
	{
		public:

			AEADChaCha20Poly1305Encryptor ();
			~AEADChaCha20Poly1305Encryptor ();

			bool Encrypt (const uint8_t * msg, size_t msgLen, const uint8_t * ad, size_t adLen,
				const uint8_t * key, const uint8_t * nonce, uint8_t * buf, size_t len); // msgLen is len without tag

			void Encrypt (const std::vector<std::pair<uint8_t *, size_t> >& bufs, const uint8_t * key, const uint8_t * nonce, uint8_t * mac); // encrypt multiple buffers with zero ad
			
		private:

			EVP_CIPHER_CTX * m_Ctx;	
	};	

	class AEADChaCha20Poly1305Decryptor
	{
		public:

			AEADChaCha20Poly1305Decryptor ();
			~AEADChaCha20Poly1305Decryptor ();

			bool Decrypt (const uint8_t * msg, size_t msgLen, const uint8_t * ad, size_t adLen,
				const uint8_t * key, const uint8_t * nonce, uint8_t * buf, size_t len); // msgLen is len without tag
			
		private:

			EVP_CIPHER_CTX * m_Ctx;	
	};	
	
	bool AEADChaCha20Poly1305 (const uint8_t * msg, size_t msgLen, const uint8_t * ad, size_t adLen,
		const uint8_t * key, const uint8_t * nonce, uint8_t * buf, size_t len, bool encrypt); // msgLen is len without tag
	
// ChaCha20
	void ChaCha20 (const uint8_t * msg, size_t msgLen, const uint8_t * key, const uint8_t * nonce, uint8_t * out);

	class ChaCha20Context
	{
		public:

			ChaCha20Context ();
			~ChaCha20Context ();
			void operator ()(const uint8_t * msg, size_t msgLen, const uint8_t * key, const uint8_t * nonce, uint8_t * out);
			
		private:

			EVP_CIPHER_CTX * m_Ctx;	
	};
	
// HKDF

	void HKDF (const uint8_t * salt, const uint8_t * key, size_t keyLen, const std::string& info, uint8_t * out, size_t outLen = 64); // salt - 32, out - 32 or 64, info <= 32

// Noise

	struct NoiseSymmetricState
	{
		uint8_t m_H[32] /*h*/, m_CK[64] /*[ck, k]*/;

		void MixHash (const uint8_t * buf, size_t len);
		void MixHash (const std::vector<std::pair<uint8_t *, size_t> >& bufs);
		void MixKey (const uint8_t * sharedSecret);
	};

	void InitNoiseNState (NoiseSymmetricState& state, const uint8_t * pub); // Noise_N (tunnels, router)
	void InitNoiseXKState (NoiseSymmetricState& state, const uint8_t * pub); // Noise_XK (NTCP2)
	void InitNoiseXKState1 (NoiseSymmetricState& state, const uint8_t * pub); // Noise_XK (SSU2)
	void InitNoiseIKState (NoiseSymmetricState& state, const uint8_t * pub); // Noise_IK (ratchets)

// init and terminate
	void InitCrypto (bool precomputation);
	void TerminateCrypto ();
}
}

#endif
