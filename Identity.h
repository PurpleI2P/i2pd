#ifndef IDENTITY_H__
#define IDENTITY_H__

#include <inttypes.h>
#include <string.h>

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
	};	
	
#pragma pack()

	class IdentHash
	{
		public:

			IdentHash (const uint8_t * hash) { memcpy (m_Hash, hash, 32); };
			IdentHash (const IdentHash& ) = default;
			IdentHash (IdentHash&& ) = default;
			IdentHash () = default;
			
			IdentHash& operator= (const IdentHash& ) = default;
			IdentHash& operator= (IdentHash&& ) = default;
			
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
	
	class RoutingDestination
	{
		public:
			virtual const IdentHash& GetIdentHash () const = 0;
			virtual const uint8_t * GetEncryptionPublicKey () const = 0;
			virtual bool IsDestination () const = 0; // for garlic 
	};	
}
}


#endif
