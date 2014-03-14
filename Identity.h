#ifndef IDENTITY_H__
#define IDENTITY_H__

#include <inttypes.h>
#include <string.h>
#include "ElGamal.h"

namespace i2p
{
namespace data
{
#pragma pack(1)

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
	};	
	
#pragma pack()

	class IdentHash
	{
		public:

			IdentHash (const uint8_t * hash) { memcpy (m_Hash, hash, 32); };
			IdentHash (const IdentHash& ) = default;
#ifndef _WIN32 // FIXME!!! msvs 2013 can't compile it
			IdentHash (IdentHash&& ) = default;
#endif
			IdentHash () = default;
			
			IdentHash& operator= (const IdentHash& ) = default;
#ifndef _WIN32
			IdentHash& operator= (IdentHash&& ) = default;
#endif
			
			uint8_t * operator()() { return m_Hash; };
			const uint8_t * operator()() const { return m_Hash; };

			operator uint8_t * () { return m_Hash; };
			operator const uint8_t * () const { return m_Hash; };
			
			bool operator== (const IdentHash& other) const { return !memcmp (m_Hash, other.m_Hash, 32); };
			bool operator< (const IdentHash& other) const { return memcmp (m_Hash, other.m_Hash, 32) < 0; };
			
		private:

			uint8_t m_Hash[32];
	};	

	IdentHash CalculateIdentHash (const Identity& identity);
	Keys CreateRandomKeys ();

	// kademlia
	struct RoutingKey
	{
		uint8_t hash[32];
	};	

	struct XORMetric
	{
		uint8_t metric[32];

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

			virtual void UpdateLeaseSet () = 0; // LeaseSet must be update
	};	
}
}


#endif
