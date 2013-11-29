#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
#include <string.h>
#include <list>

namespace i2p
{
namespace data
{	
	
#pragma pack(1)
	struct Lease
	{
		uint8_t tunnelGateway[32];
		uint32_t tunnelID;
		uint64_t endDate;
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
	
	class RoutingDestination  // TODO: move to separate file later
	{
		public:
			virtual const IdentHash& GetIdentHash () const = 0;
			virtual const uint8_t * GetEncryptionPublicKey () const = 0;
			virtual bool IsDestination () const = 0; // for garlic 
	};	
	
	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, int len);

			// implements RoutingDestination
			const IdentHash& GetIdentHash () const { return m_IdentHash; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionKey; };
			bool IsDestination () const { return true; };
			
		private:

			std::list<Lease> m_Leases;
			IdentHash m_IdentHash;
			uint8_t m_EncryptionKey[256];
	};	
}		
}	

#endif
