/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef CRYPTO_KEY_H__
#define CRYPTO_KEY_H__

#include <inttypes.h>
#include "Crypto.h"

namespace i2p
{
namespace crypto
{
	class CryptoKeyEncryptor
	{
		public:

			virtual ~CryptoKeyEncryptor () {};
			virtual void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding) = 0; // 222 bytes data, 512/514 bytes encrypted
	};

	class CryptoKeyDecryptor
	{
		public:

			virtual ~CryptoKeyDecryptor () {};
			virtual bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding) = 0; // 512/514 bytes encrypted, 222 bytes data
			virtual size_t GetPublicKeyLen () const = 0; // we need it to set key in LS2
	};

// ElGamal
	class ElGamalEncryptor: public CryptoKeyEncryptor // for destination
	{
		public:

			ElGamalEncryptor (const uint8_t * pub);
			void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding);

		private:

			uint8_t m_PublicKey[256];
	};

	class ElGamalDecryptor: public CryptoKeyDecryptor // for destination
	{
		public:

			ElGamalDecryptor (const uint8_t * priv);
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding);
			size_t GetPublicKeyLen () const { return 256; };

		private:

			uint8_t m_PrivateKey[256];
	};

// ECIES P256

	class ECIESP256Encryptor: public CryptoKeyEncryptor
	{
		public:

			ECIESP256Encryptor (const uint8_t * pub);
			~ECIESP256Encryptor ();
			void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding);

		private:

			EC_GROUP * m_Curve;
			EC_POINT * m_PublicKey;
	};


	class ECIESP256Decryptor: public CryptoKeyDecryptor
	{
		public:

			ECIESP256Decryptor (const uint8_t * priv);
			~ECIESP256Decryptor ();
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding);
			size_t GetPublicKeyLen () const { return 64; };

		private:

			EC_GROUP * m_Curve;
			BIGNUM * m_PrivateKey;
	};

	void CreateECIESP256RandomKeys (uint8_t * priv, uint8_t * pub);

// ECIES GOST R 34.10

	class ECIESGOSTR3410Encryptor: public CryptoKeyEncryptor
	{
		public:

			ECIESGOSTR3410Encryptor (const uint8_t * pub);
			~ECIESGOSTR3410Encryptor ();
			void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding);

		private:

			EC_POINT * m_PublicKey;
	};


	class ECIESGOSTR3410Decryptor: public CryptoKeyDecryptor
	{
		public:

			ECIESGOSTR3410Decryptor (const uint8_t * priv);
			~ECIESGOSTR3410Decryptor ();
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding);
			size_t GetPublicKeyLen () const { return 64; };

		private:

			BIGNUM * m_PrivateKey;
	};

	void CreateECIESGOSTR3410RandomKeys (uint8_t * priv, uint8_t * pub);

// ECIES-X25519-AEAD-Ratchet

	class ECIESX25519AEADRatchetEncryptor: public CryptoKeyEncryptor
	{
		public:

			ECIESX25519AEADRatchetEncryptor (const uint8_t * pub);
			~ECIESX25519AEADRatchetEncryptor () {};
			void Encrypt (const uint8_t *, uint8_t * pub, BN_CTX *, bool);
			// copies m_PublicKey to pub

		private:

			uint8_t m_PublicKey[32];
	};

	class ECIESX25519AEADRatchetDecryptor: public CryptoKeyDecryptor
	{
		public:

			ECIESX25519AEADRatchetDecryptor (const uint8_t * priv, bool calculatePublic = false);
			~ECIESX25519AEADRatchetDecryptor () {};
			bool Decrypt (const uint8_t * epub, uint8_t * sharedSecret, BN_CTX * ctx, bool zeroPadding);
			// agree with static and return in sharedSecret (32 bytes)
			size_t GetPublicKeyLen () const { return 32; };
			const uint8_t * GetPubicKey () const { return m_StaticKeys.GetPublicKey (); };

		private:

			X25519Keys m_StaticKeys;
	};

	void CreateECIESX25519AEADRatchetRandomKeys (uint8_t * priv, uint8_t * pub);
}
}

#endif
