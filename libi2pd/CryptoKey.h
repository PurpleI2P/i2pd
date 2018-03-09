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

		private:

			BIGNUM * m_PrivateKey;
	};

	void CreateECIESGOSTR3410RandomKeys (uint8_t * priv, uint8_t * pub);
}
}

#endif

