/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef IDENTITY_H__
#define IDENTITY_H__

#include <inttypes.h>
#include <string.h>
#include <string>
#include <memory>
#include <atomic>
#include <vector>
#include <mutex>
#include "Base.h"
#include "Signature.h"
#include "CryptoKey.h"

namespace i2p
{
namespace data
{
	typedef Tag<32> IdentHash;
	inline std::string GetIdentHashAbbreviation (const IdentHash& ident)
	{
		return ident.ToBase64 ().substr (0, 4);
	}

	struct Keys
	{
		uint8_t privateKey[256];
		uint8_t signingPrivateKey[20];
		uint8_t publicKey[256];
		uint8_t signingKey[128];
	};

	const uint8_t CERTIFICATE_TYPE_NULL = 0;
	const uint8_t CERTIFICATE_TYPE_HASHCASH = 1;
	const uint8_t CERTIFICATE_TYPE_HIDDEN = 2;
	const uint8_t CERTIFICATE_TYPE_SIGNED = 3;
	const uint8_t CERTIFICATE_TYPE_MULTIPLE = 4;
	const uint8_t CERTIFICATE_TYPE_KEY = 5;

	struct Identity
	{
		uint8_t publicKey[256];
		uint8_t signingKey[128];
		uint8_t certificate[3];	// byte 1 - type, bytes 2-3 - length

		Identity () = default;
		Identity (const Keys& keys) { *this = keys; };
		Identity& operator=(const Keys& keys);
		size_t FromBuffer (const uint8_t * buf, size_t len);
		IdentHash Hash () const;
	};

	Keys CreateRandomKeys ();

	const size_t DEFAULT_IDENTITY_SIZE = sizeof (Identity); // 387 bytes

	const uint16_t CRYPTO_KEY_TYPE_ELGAMAL = 0;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC = 1;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET = 4;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC_TEST = 65280; // TODO: remove later
	const uint16_t CRYPTO_KEY_TYPE_ECIES_GOSTR3410_CRYPTO_PRO_A_SHA256_AES256CBC = 65281; // TODO: use GOST R 34.11 instead SHA256 and GOST 28147-89 instead AES

	const uint16_t SIGNING_KEY_TYPE_DSA_SHA1 = 0;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA256_P256 = 1;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA384_P384 = 2;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA512_P521 = 3;
	const uint16_t SIGNING_KEY_TYPE_RSA_SHA256_2048 = 4;
	const uint16_t SIGNING_KEY_TYPE_RSA_SHA384_3072 = 5;
	const uint16_t SIGNING_KEY_TYPE_RSA_SHA512_4096 = 6;
	const uint16_t SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 = 7;
	const uint16_t SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph = 8; // not implemented
	const uint16_t SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256 = 9;
	const uint16_t SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512 = 10; // approved by FSB
	const uint16_t SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 = 11; // for LeaseSet2 only

	typedef uint16_t SigningKeyType;
	typedef uint16_t CryptoKeyType;

	class IdentityEx
	{
		public:

			IdentityEx ();
			IdentityEx (const uint8_t * publicKey, const uint8_t * signingKey,
				SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1, CryptoKeyType cryptoType = CRYPTO_KEY_TYPE_ELGAMAL);
			IdentityEx (const uint8_t * buf, size_t len);
			IdentityEx (const IdentityEx& other);
			IdentityEx (const Identity& standard);
			~IdentityEx ();
			IdentityEx& operator=(const IdentityEx& other);
			IdentityEx& operator=(const Identity& standard);

			size_t FromBuffer (const uint8_t * buf, size_t len);
			size_t ToBuffer (uint8_t * buf, size_t len) const;
			size_t FromBase64(const std::string& s);
			std::string ToBase64 () const;
			const Identity& GetStandardIdentity () const { return m_StandardIdentity; };

			const IdentHash& GetIdentHash () const { return m_IdentHash; };
			const uint8_t * GetEncryptionPublicKey () const { return m_StandardIdentity.publicKey; };
			uint8_t * GetEncryptionPublicKeyBuffer () { return m_StandardIdentity.publicKey; };
			std::shared_ptr<i2p::crypto::CryptoKeyEncryptor> CreateEncryptor (const uint8_t * key) const;
			size_t GetFullLen () const { return m_ExtendedLen + DEFAULT_IDENTITY_SIZE; };
			size_t GetSigningPublicKeyLen () const;
			const uint8_t * GetSigningPublicKeyBuffer () const; // returns NULL for P521
			size_t GetSigningPrivateKeyLen () const;
			size_t GetSignatureLen () const;
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const;
			SigningKeyType GetSigningKeyType () const;
			bool IsRSA () const; // signing key type
			CryptoKeyType GetCryptoKeyType () const;
			void DropVerifier () const; // to save memory

  			bool operator == (const IdentityEx & other) const { return GetIdentHash() == other.GetIdentHash(); }
			void RecalculateIdentHash(uint8_t * buff=nullptr);

			static i2p::crypto::Verifier * CreateVerifier (SigningKeyType keyType);
			static std::shared_ptr<i2p::crypto::CryptoKeyEncryptor> CreateEncryptor (CryptoKeyType keyType, const uint8_t * key);

		private:

			void CreateVerifier () const;
			void UpdateVerifier (i2p::crypto::Verifier * verifier) const;

		private:

			Identity m_StandardIdentity;
			IdentHash m_IdentHash;
			mutable i2p::crypto::Verifier * m_Verifier = nullptr;
			mutable std::mutex m_VerifierMutex;
			size_t m_ExtendedLen;
			uint8_t * m_ExtendedBuffer;
	};

	class PrivateKeys // for eepsites
	{
		public:

			PrivateKeys () = default;
			PrivateKeys (const PrivateKeys& other) { *this = other; };
			PrivateKeys (const Keys& keys) { *this = keys; };
			PrivateKeys& operator=(const Keys& keys);
			PrivateKeys& operator=(const PrivateKeys& other);
			~PrivateKeys () = default;

			std::shared_ptr<const IdentityEx> GetPublic () const { return m_Public; };
			const uint8_t * GetPrivateKey () const { return m_PrivateKey; };
			const uint8_t * GetSigningPrivateKey () const { return m_SigningPrivateKey; };
			size_t GetSignatureLen () const; // might not match identity
			bool IsOfflineSignature () const { return m_TransientSignatureLen > 0; };
			uint8_t * GetPadding();
			void RecalculateIdentHash(uint8_t * buf=nullptr) { m_Public->RecalculateIdentHash(buf); }
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;

			size_t GetFullLen () const;
			size_t FromBuffer (const uint8_t * buf, size_t len);
			size_t ToBuffer (uint8_t * buf, size_t len) const;

			size_t FromBase64(const std::string& s);
			std::string ToBase64 () const;

			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> CreateDecryptor (const uint8_t * key) const;

			static std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> CreateDecryptor (CryptoKeyType cryptoType, const uint8_t * key);
			static PrivateKeys CreateRandomKeys (SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1, CryptoKeyType cryptoType = CRYPTO_KEY_TYPE_ELGAMAL);
			static void GenerateSigningKeyPair (SigningKeyType type, uint8_t * priv, uint8_t * pub);
			static void GenerateCryptoKeyPair (CryptoKeyType type, uint8_t * priv, uint8_t * pub); // priv and pub are 256 bytes long
			static i2p::crypto::Signer * CreateSigner (SigningKeyType keyType, const uint8_t * priv);

			// offline keys
			PrivateKeys CreateOfflineKeys (SigningKeyType type, uint32_t expires) const;
			const std::vector<uint8_t>& GetOfflineSignature () const { return m_OfflineSignature; };

		private:

			void CreateSigner () const;
			void CreateSigner (SigningKeyType keyType) const;

		private:

			std::shared_ptr<IdentityEx> m_Public;
			uint8_t m_PrivateKey[256];
			uint8_t m_SigningPrivateKey[128]; // assume private key doesn't exceed 128 bytes
			mutable std::unique_ptr<i2p::crypto::Signer> m_Signer;
			std::vector<uint8_t> m_OfflineSignature; // non zero length, if applicable
			size_t m_TransientSignatureLen = 0;
			size_t m_TransientSigningPrivateKeyLen = 0;
	};

	// kademlia
	struct XORMetric
	{
		union
		{
			uint8_t metric[32];
			uint64_t metric_ll[4];
		};

		void SetMin () { memset (metric, 0, 32); };
		void SetMax () { memset (metric, 0xFF, 32); };
		bool operator< (const XORMetric& other) const { return memcmp (metric, other.metric, 32) < 0; };
	};

	IdentHash CreateRoutingKey (const IdentHash& ident);
	XORMetric operator^(const IdentHash& key1, const IdentHash& key2);

	// destination for delivery instructions
	class RoutingDestination
	{
		public:

			RoutingDestination () {};
			virtual ~RoutingDestination () {};

			virtual std::shared_ptr<const IdentityEx> GetIdentity ()  const = 0;
			virtual void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const = 0; // encrypt data for
			virtual bool IsDestination () const = 0; // for garlic

			const IdentHash& GetIdentHash () const { return GetIdentity ()->GetIdentHash (); };
			virtual CryptoKeyType GetEncryptionType () const { return GetIdentity ()->GetCryptoKeyType (); }; // override in LeaseSet2
	};

	class LocalDestination
	{
		public:

			virtual ~LocalDestination() {};
			virtual bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, CryptoKeyType preferredCrypto = CRYPTO_KEY_TYPE_ELGAMAL) const = 0;
			virtual std::shared_ptr<const IdentityEx> GetIdentity () const = 0;

			const IdentHash& GetIdentHash () const { return GetIdentity ()->GetIdentHash (); };
			virtual bool SupportsEncryptionType (CryptoKeyType keyType) const { return GetIdentity ()->GetCryptoKeyType () == keyType; }; // override for LeaseSet
			virtual const uint8_t * GetEncryptionPublicKey (CryptoKeyType keyType) const { return GetIdentity ()->GetEncryptionPublicKey (); }; // override for LeaseSet
	};
}
}

#endif
