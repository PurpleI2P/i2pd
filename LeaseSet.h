#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
#include <string.h>
#include <vector>
#include "Identity.h"

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

	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, int len);
			LeaseSet (const LeaseSet& ) = default;
			LeaseSet& operator=(const LeaseSet& ) = default;
			
			// implements RoutingDestination
			const Identity& GetIdentity () const { return m_Identity; };
			const IdentHash& GetIdentHash () const { return m_IdentHash; };
			const std::vector<Lease>& GetLeases () const { return m_Leases; };
			std::vector<Lease> GetNonExpiredLeases () const;
			bool HasExpiredLeases () const;
			bool HasNonExpiredLeases () const;
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionKey; };
			bool IsDestination () const { return true; };
			
		private:

			std::vector<Lease> m_Leases;
			Identity m_Identity;
			IdentHash m_IdentHash;
			uint8_t m_EncryptionKey[256];
	};	
}		
}	

#endif
