#ifndef IDENTITY_H__
#define IDENTITY_H__

#include <inttypes.h>
#include <string.h>
#include <string>
#include "base64.h"
#include "ElGamal.h"

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
	
	struct Identity
	{
		uint8_t publicKey[256];
		uint8_t signingKey[128];
		uint8_t certificate[3];

		Identity& operator=(const Keys& keys);
		bool FromBase64(const std::string& );
		IdentHash Hash() const;
	};	
	
	struct PrivateKeys // for eepsites
	{
		Identity pub;
		uint8_t privateKey[256];
		uint8_t signingPrivateKey[20];	

		PrivateKeys () = default;
		PrivateKeys (const PrivateKeys& ) = default;
		PrivateKeys (const Keys& keys) { *this = keys; };
		
		PrivateKeys& operator=(const Keys& keys);
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
			virtual const IdentHash& GetIdentHash () const = 0;
			virtual const Identity& GetIdentity () const = 0;
			virtual const uint8_t * GetEncryptionPrivateKey () const = 0; 
			virtual const uint8_t * GetEncryptionPublicKey () const = 0; 
			virtual void Sign (const uint8_t * buf, int len, uint8_t * signature) const = 0;
	};	
}
}


#endif
