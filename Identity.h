#ifndef IDENTITY_H__
#define IDENTITY_H__

#include <inttypes.h>
#include <string.h>
#include <string>
#include "base64.h"
#include "ElGamal.h"
#include "Signature.h"

namespace i2p
{
namespace data
{
	template<int sz>
	class Tag
	{
		public:

			Tag (const uint8_t * buf) { memcpy (m_Buf, buf, sz); };
			Tag (const Tag<sz>& ) = default;
#ifndef _WIN32 // FIXME!!! msvs 2013 can't compile it
			Tag (Tag<sz>&& ) = default;
#endif
			Tag () = default;
			
			Tag<sz>& operator= (const Tag<sz>& ) = default;
#ifndef _WIN32
			Tag<sz>& operator= (Tag<sz>&& ) = default;
#endif
			
			uint8_t * operator()() { return m_Buf; };
			const uint8_t * operator()() const { return m_Buf; };

			operator uint8_t * () { return m_Buf; };
			operator const uint8_t * () const { return m_Buf; };
			
			bool operator== (const Tag<sz>& other) const { return !memcmp (m_Buf, other.m_Buf, sz); };
			bool operator< (const Tag<sz>& other) const { return memcmp (m_Buf, other.m_Buf, sz) < 0; };

			std::string ToBase64 () const
			{
				char str[sz*2];
				int l = i2p::data::ByteStreamToBase64 (m_Buf, sz, str, sz*2);
				str[l] = 0;
				return std::string (str);
			}

			std::string ToBase32 () const
			{
				char str[sz*2];
				int l = i2p::data::ByteStreamToBase32 (m_Buf, sz, str, sz*2);
				str[l] = 0;
				return std::string (str);
			}

		private:

			union // 8 bytes alignment
			{	
				uint8_t m_Buf[sz];
				uint64_t ll[sz/8];
			};		
	};	
	typedef Tag<32> IdentHash;

#pragma pack(1)

	struct DHKeysPair // transient keys for transport sessions
	{
		uint8_t publicKey[256];
		uint8_t privateKey[256];
	};	

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
		struct
		{
			uint8_t type;
			uint16_t length;
		} certificate;	

		Identity () = default;
		Identity (const Keys& keys) { *this = keys; };
		Identity& operator=(const Keys& keys);
		bool FromBase64(const std::string& );
		size_t FromBuffer (const uint8_t * buf, size_t len);
		IdentHash Hash() const;
	};	
	const size_t DEFAULT_IDENTITY_SIZE = sizeof (Identity); // 387 bytes

	const uint16_t CRYPTO_KEY_TYPE_ELGAMAL = 0;
	const uint16_t SIGNING_KEY_TYPE_DSA_SHA1 = 0;
	const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA256_P256 = 1;
	typedef uint16_t SigningKeyType;
	
	class IdentityEx
	{
		public:

			IdentityEx ();
			IdentityEx (const uint8_t * publicKey, const uint8_t * signingKey,
				SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1);
			IdentityEx (const uint8_t * buf, size_t len);
			IdentityEx (const IdentityEx& other);
			~IdentityEx ();
			IdentityEx& operator=(const IdentityEx& other);
			IdentityEx& operator=(const Identity& standard);
			
			size_t FromBuffer (const uint8_t * buf, size_t len);
			size_t ToBuffer (uint8_t * buf, size_t len) const;
			const Identity& GetStandardIdentity () const { return m_StandardIdentity; };
			const IdentHash& GetIdentHash () const { return m_IdentHash; };
			size_t GetFullLen () const { return m_ExtendedLen + DEFAULT_IDENTITY_SIZE; };
			size_t GetSigningPublicKeyLen () const;
			size_t GetSignatureLen () const;
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const;
			SigningKeyType GetSigningKeyType () const;
			
		private:

			void CreateVerifier ();
			
		private:

			Identity m_StandardIdentity;
			IdentHash m_IdentHash;
			i2p::crypto::Verifier * m_Verifier;
			size_t m_ExtendedLen;
			uint8_t * m_ExtendedBuffer;
	};	
	
	class PrivateKeys // for eepsites
	{
		public:
			
			PrivateKeys (): m_Signer (nullptr) {};
			PrivateKeys (const PrivateKeys& other): m_Signer (nullptr) { *this = other; };
			PrivateKeys (const Keys& keys): m_Signer (nullptr) { *this = keys; };
			PrivateKeys& operator=(const Keys& keys);
			PrivateKeys& operator=(const PrivateKeys& other);
			~PrivateKeys () { delete m_Signer; };
			
			const IdentityEx& GetPublic () const { return m_Public; };
			const uint8_t * GetPrivateKey () const { return m_PrivateKey; };
			const uint8_t * GetSigningPrivateKey () const { return m_SigningPrivateKey; };
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;

			size_t GetFullLen () const { return m_Public.GetFullLen () + 256 + m_Public.GetSignatureLen ()/2; };			
			size_t FromBuffer (const uint8_t * buf, size_t len);
			size_t ToBuffer (uint8_t * buf, size_t len) const;

			static PrivateKeys CreateRandomKeys (SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1);
	
		private:

			void CreateSigner ();
			
		private:

			IdentityEx m_Public;
			uint8_t m_PrivateKey[256];
			uint8_t m_SigningPrivateKey[128]; // assume private key doesn't exceed 128 bytes
			i2p::crypto::Signer * m_Signer;
	};
	
#pragma pack()
		
	Keys CreateRandomKeys ();
	void CreateRandomDHKeysPair (DHKeysPair * keys); // for transport sessions

	// kademlia
	union RoutingKey
	{
		uint8_t hash[32];
		uint64_t hash_ll[4];
	};	

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

	RoutingKey CreateRoutingKey (const IdentHash& ident);
	XORMetric operator^(const RoutingKey& key1, const RoutingKey& key2); 	
	
	// destination for delivery instuctions
	class RoutingDestination
	{
		public:

			RoutingDestination (): m_ElGamalEncryption (nullptr) {};
			virtual ~RoutingDestination () { delete m_ElGamalEncryption; };
			
			virtual const IdentHash& GetIdentHash () const = 0;
			virtual const uint8_t * GetEncryptionPublicKey () const = 0;
			virtual bool IsDestination () const = 0; // for garlic 

			i2p::crypto::ElGamalEncryption * GetElGamalEncryption () const
			{
				if (!m_ElGamalEncryption)
					m_ElGamalEncryption = new i2p::crypto::ElGamalEncryption (GetEncryptionPublicKey ());
				return m_ElGamalEncryption;
			}
			
		private:

			mutable i2p::crypto::ElGamalEncryption * m_ElGamalEncryption; // use lazy initialization
	};	

	class LocalDestination 
	{
		public:

			virtual ~LocalDestination() {};
			virtual const PrivateKeys& GetPrivateKeys () const = 0;
			virtual const uint8_t * GetEncryptionPrivateKey () const = 0; 
			virtual const uint8_t * GetEncryptionPublicKey () const = 0; 
			virtual void SetLeaseSetUpdated () = 0;

			const IdentityEx& GetIdentity () const { return GetPrivateKeys ().GetPublic (); };
			const IdentHash& GetIdentHash () const { return GetIdentity ().GetIdentHash (); };  
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const 
			{ 
				GetPrivateKeys ().Sign (buf, len, signature); 
			};
	};	
}
}


#endif
