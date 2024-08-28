/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
#include "CPU.h"

// recognize openssl version and features
#if (OPENSSL_VERSION_NUMBER >= 0x010101000) // 1.1.1
#	define OPENSSL_HKDF 1
#	define OPENSSL_EDDSA 1
#	define OPENSSL_X25519 1
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
#if OPENSSL_X25519
			EVP_PKEY_CTX * m_Ctx;
			EVP_PKEY * m_Pkey;
#else
			BN_CTX * m_Ctx;
			uint8_t m_PrivateKey[32];
#endif
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


#if SUPPORTS_AES
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

#if SUPPORTS_AES
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

#if SUPPORTS_AES
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
	void InitCrypto (bool precomputation, bool aesni, bool force);
	void TerminateCrypto ();
}
}

#endif
