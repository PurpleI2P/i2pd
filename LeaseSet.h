#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
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

	class RoutingDestination  // TODO: move to separate file later
	{
		public:
			virtual const uint8_t * GetIdentHash () const = 0;
			virtual const uint8_t * GetEncryptionPublicKey () const = 0;
			virtual bool IsDestination () const = 0; // for garlic 
	};	
	
	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, int len);

			// implements RoutingDestination
			const uint8_t * GetIdentHash () const { return m_IdentHash; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionKey; };
			bool IsDestination () const { return true; };
			
		private:

			std::list<Lease> m_Leases;
			uint8_t m_IdentHash[32];
			uint8_t m_EncryptionKey[256];
	};	
}		
}	

#endif
