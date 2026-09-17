/*
* Copyright (c) 2013-2026, The PurpleI2P Project
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
#include <string_view>
#include <memory>
#include <vector>
#include "Base.h"
#include "I2PEndian.h"
#include "Signature.h"
#include "Tag.h"

namespace i2p
{
namespace crypto
{
	class CryptoKeyEncryptor;
	class CryptoKeyDecryptor;
}
namespace data
{
	typedef Tag<32> IdentHash;
	inline std::string GetIdentHashAbbreviation (const IdentHash& ident)
	{
		return ident.ToBase64 ().substr (0, 4);
	}

	std::vector<IdentHash> ExtractIdentHashes (std::string_view hashes);

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
		operator uint8_t * () { return reinterpret_cast<uint8_t *>(this); }
		operator const uint8_t * () const { return reinterpret_cast<const uint8_t *>(this); }
	};

	Keys CreateRandomKeys ();

	const size_t DEFAULT_IDENTITY_SIZE = sizeof (Identity); // 387 bytes

	const uint16_t CRYPTO_KEY_TYPE_ELGAMAL = 0;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC = 1;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_X25519_AEAD = 4;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_MLKEM512_X25519_AEAD = 5;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD = 6;
	const uint16_t CRYPTO_KEY_TYPE_ECIES_MLKEM1024_X25519_AEAD = 7;

	const uint16_t SIGNING_KEY_TYPE_DSA_SHA1 = 0;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA256_P256 = 1;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA384_P384 = 2;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA512_P521 = 3;
	const uint16_t SIGNING_KEY_TYPE_RSA_SHA256_2048 = 4;
	const uint16_t SIGNING_KEY_TYPE_RSA_SHA384_3072 = 5;
	const uint16_t SIGNING_KEY_TYPE_RSA_SHA512_4096 = 6;
	const uint16_t SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 = 7;
	const uint16_t SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph = 8; // since openssl 3.0.0
	const uint16_t SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256 = 9;
	const uint16_t SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512 = 10; // approved by FSB
	const uint16_t SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 = 11; // for LeaseSet2 only

	typedef uint16_t SigningKeyType;
	typedef uint16_t CryptoKeyType;

	const size_t MAX_EXTENDED_BUFFER_SIZE = 8; // cryptoKeyType + signingKeyType + 4 extra bytes of P521
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
			size_t FromBase64(std::string_view s);
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

			bool operator == (const IdentityEx & other) const { return GetIdentHash() == other.GetIdentHash(); }
			void RecalculateIdentHash(uint8_t * buff=nullptr);

			static i2p::crypto::Verifier * CreateVerifier (SigningKeyType keyType);
			static std::shared_ptr<i2p::crypto::CryptoKeyEncryptor> CreateEncryptor (CryptoKeyType keyType, const uint8_t * key);

		private:

			void CreateVerifier ();

		private:

			Identity m_StandardIdentity;
			IdentHash m_IdentHash;
			std::unique_ptr<i2p::crypto::Verifier> m_Verifier;
			size_t m_ExtendedLen;
			union
			{
				uint8_t m_ExtendedBuffer[MAX_EXTENDED_BUFFER_SIZE];
				uint8_t * m_ExtendedBufferPtr;
			};
	};

	size_t GetIdentityBufferLen (const uint8_t * buf, size_t len); // return actual identity length in buffer

	const size_t OFFLINE_SIGNATURE_HEADER_LENGTH = 4 + 2; // expires, transient signature type

	// expires || transient signature type || transient public key || signature by the authority,
	// then the transient private key. The authority is the destination itself, or the blinded key
	// of the day for an encrypted LeaseSet
	class OfflineSigner: public i2p::crypto::Signer
	{
		public:

			// implements Signer
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const override { m_Signer->Sign (buf, len, signature); };
			size_t GetSignatureLen () const override { return m_SignatureLen; };

			const std::vector<uint8_t>& GetOfflineSignature () const { return m_OfflineSignature; };
			uint32_t GetExpires () const { return bufbe32toh (m_OfflineSignature.data ()); };
			size_t GetFullLen () const { return m_OfflineSignature.size () + m_TransientPrivateKey.size (); };
			size_t ToBuffer (uint8_t * buf, size_t len) const;
			size_t FromBuffer (const uint8_t * buf, size_t len, size_t authoritySignatureLen); // returns length taken, 0 if invalid

			template<typename Authority>
			bool Verify (const Authority& authority) const // the authority must be the one the transient key was signed by
			{
				size_t signatureLen = authority->GetSignatureLen ();
				if (m_OfflineSignature.size () <= signatureLen) return false;
				size_t signedLen = m_OfflineSignature.size () - signatureLen;
				return authority->Verify (m_OfflineSignature.data (), signedLen, m_OfflineSignature.data () + signedLen);
			}

		private:

			size_t m_SignatureLen = 0;
			std::vector<uint8_t> m_OfflineSignature, m_TransientPrivateKey;
			std::unique_ptr<i2p::crypto::Signer> m_Signer;
	};

	// the transient key of an offline signature, verifying on behalf of the destination
	class OfflineVerifier: public i2p::crypto::Verifier
	{
		public:

			// implements Verifier
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const override { return m_TransientVerifier->Verify (buf, len, signature); };
			size_t GetPublicKeyLen () const override { return m_TransientVerifier->GetPublicKeyLen (); };
			size_t GetSignatureLen () const override { return m_TransientVerifier->GetSignatureLen (); };
			void SetPublicKey (const uint8_t * signingKey) override { m_TransientVerifier->SetPublicKey (signingKey); };

			// offset points to the offline signature inside a LeaseSet, a stream packet or a datagram
			template<typename Authority>
			static std::shared_ptr<OfflineVerifier> FromBuffer (const uint8_t * buf, size_t len, const Authority& authority, size_t& offset)
			{
				if (offset + OFFLINE_SIGNATURE_HEADER_LENGTH >= len) return nullptr;
				const uint8_t * signedData = buf + offset;
				uint32_t expires = bufbe32toh (signedData);
				if (IsExpired (expires)) return nullptr;
				SigningKeyType keyType = bufbe16toh (signedData + 4);
				std::unique_ptr<i2p::crypto::Verifier> transientVerifier (IdentityEx::CreateVerifier (keyType));
				if (!transientVerifier) return nullptr;
				size_t signedLen = OFFLINE_SIGNATURE_HEADER_LENGTH + transientVerifier->GetPublicKeyLen ();
				if (offset + signedLen + authority->GetSignatureLen () >= len) return nullptr;
				transientVerifier->SetPublicKey (signedData + OFFLINE_SIGNATURE_HEADER_LENGTH);
				if (!authority->Verify (signedData, signedLen, signedData + signedLen)) return nullptr;
				offset += signedLen + authority->GetSignatureLen ();
				auto verifier = std::make_shared<OfflineVerifier>();
				verifier->m_TransientVerifier = std::move (transientVerifier);
				return verifier;
			}

		private:

			static bool IsExpired (uint32_t expires);

		private:

			std::unique_ptr<i2p::crypto::Verifier> m_TransientVerifier;
	};

	const uint8_t B33_OFFLINE_KEYS_VERSION = 1;
	const size_t B33_OFFLINE_KEYS_HEADER_LENGTH = 1 + IdentHash::len + 2; // version, ident hash, number of keys
	const uint64_t SECONDS_PER_DAY = 24*60*60;

	// a transient key per day for an encrypted LeaseSet, authorized by the blinded key of its own day.
	// version || ident hash || number of keys, then an offline signature per day. Appended to the keys
	// file, where a router without b33 offline keys does not look for it
	class B33OfflineKeys
	{
		public:

			size_t GetLen () const { return m_Buf.size (); };
			const uint8_t * GetBuffer () const { return m_Buf.data (); };
			bool operator== (const B33OfflineKeys& other) const { return m_Buf == other.m_Buf; };
			size_t FromBuffer (const uint8_t * buf, size_t len, const IdentHash& ident); // the keys are the tail of the keys file
			size_t ToBuffer (uint8_t * buf, size_t len) const;

		private:

			std::vector<uint8_t> m_Buf;
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
			const uint8_t * GetSigningPrivateKey () const { return m_SigningPrivateKey.data (); };
			size_t GetSignatureLen () const; // might not match identity
			bool IsOfflineSignature () const { return m_OfflineSigner != nullptr; };
			uint8_t * GetPadding();
			void RecalculateIdentHash(uint8_t * buf=nullptr) { m_Public->RecalculateIdentHash(buf); }
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;

			size_t GetFullLen () const;
			size_t FromBuffer (const uint8_t * buf, size_t len);
			size_t ToBuffer (uint8_t * buf, size_t len) const;

			size_t FromBase64(std::string_view s);
			std::string ToBase64 () const;

			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> CreateDecryptor (const uint8_t * key) const;

			static std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> CreateDecryptor (CryptoKeyType cryptoType, const uint8_t * key);
			static PrivateKeys CreateRandomKeys (SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1, CryptoKeyType cryptoType = CRYPTO_KEY_TYPE_ELGAMAL, bool isDestination = false);
			static void GenerateSigningKeyPair (SigningKeyType type, uint8_t * priv, uint8_t * pub);
			static void GenerateCryptoKeyPair (CryptoKeyType type, uint8_t * priv, uint8_t * pub); // priv and pub are 256 bytes long
			static i2p::crypto::Signer * CreateSigner (SigningKeyType keyType, const uint8_t * priv);

			const B33OfflineKeys& GetB33OfflineKeys () const { return m_B33OfflineKeys; };

			// offline keys
			PrivateKeys CreateOfflineKeys (SigningKeyType type, uint32_t expires) const;
			const std::vector<uint8_t>& GetOfflineSignature () const;
			void UpdateOfflineSignature (const PrivateKeys& other); // refresh transient material, keep identity

		private:

			void CreateSigner () const;
			void CreateSigner (SigningKeyType keyType) const;
			size_t GetPrivateKeyLen () const;

		private:

			std::shared_ptr<IdentityEx> m_Public;
			uint8_t m_PrivateKey[256];
			std::vector<uint8_t> m_SigningPrivateKey;
			mutable std::unique_ptr<i2p::crypto::Signer> m_Signer;
			std::shared_ptr<OfflineSigner> m_OfflineSigner; // signs instead of m_Signer, if applicable
			B33OfflineKeys m_B33OfflineKeys; // non zero length, if applicable
	};

	// destination for delivery instructions
	class RoutingDestination
	{
		public:

			RoutingDestination () {};
			virtual ~RoutingDestination () {};

			virtual std::shared_ptr<const IdentityEx> GetIdentity () const = 0;
			virtual void Encrypt (const uint8_t * data, uint8_t * encrypted) const = 0; // encrypt data for
			virtual bool IsDestination () const = 0; // for garlic

			const IdentHash& GetIdentHash () const { return GetIdentity ()->GetIdentHash (); };
			virtual CryptoKeyType GetEncryptionType () const { return GetIdentity ()->GetCryptoKeyType (); }; // override in LeaseSet2
	};

	class LocalDestination
	{
		public:

			virtual ~LocalDestination() {};
			virtual bool Decrypt (const uint8_t * encrypted, uint8_t * data, CryptoKeyType preferredCrypto = CRYPTO_KEY_TYPE_ELGAMAL) const = 0;
			virtual std::shared_ptr<const IdentityEx> GetIdentity () const = 0;

			const IdentHash& GetIdentHash () const { return GetIdentity ()->GetIdentHash (); };
			virtual bool SupportsEncryptionType (CryptoKeyType keyType) const { return GetIdentity ()->GetCryptoKeyType () == keyType; }; // override for LeaseSet
			virtual const uint8_t * GetEncryptionPublicKey (CryptoKeyType keyType) const { return GetIdentity ()->GetEncryptionPublicKey (); }; // override for LeaseSet
	};
}
}

#endif
