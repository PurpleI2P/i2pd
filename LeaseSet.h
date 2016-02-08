#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
#include <string.h>
#include <vector>
#include "Identity.h"

namespace i2p
{

namespace tunnel
{
	class TunnelPool;
}

namespace data
{	
	struct Lease
	{
		IdentHash tunnelGateway;
		uint32_t tunnelID;
		uint64_t endDate;

		bool operator< (const Lease& other) const 
		{
			if (endDate != other.endDate)
				return endDate > other.endDate;
			else
				return tunnelID < other.tunnelID; 
		}	
	};	

	const int MAX_LS_BUFFER_SIZE = 3072;
	const uint8_t MAX_NUM_LEASES = 16;		
	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, size_t len, bool storeLeases = true);
			LeaseSet (std::shared_ptr<const i2p::tunnel::TunnelPool> pool);
			~LeaseSet () { delete[] m_Buffer; };
			void Update (const uint8_t * buf, size_t len);
			void PopulateLeases (); /// from buffer
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_Identity; };			

			const uint8_t * GetBuffer () const { return m_Buffer; };
			size_t GetBufferLen () const { return m_BufferLen; };	
			bool IsValid () const { return m_IsValid; };

			// implements RoutingDestination
			const IdentHash& GetIdentHash () const { return m_Identity->GetIdentHash (); };
			const std::vector<Lease>& GetLeases () const { return m_Leases; };
			const std::vector<Lease> GetNonExpiredLeases (bool withThreshold = true) const;
			bool HasExpiredLeases () const;
			bool IsExpired () const;
			uint64_t GetExpirationTime () const { return m_ExpirationTime; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionKey; };
			bool IsDestination () const { return true; };

		private:

			void ReadFromBuffer (bool readIdentity = true);
			
		private:

			bool m_IsValid, m_StoreLeases; // we don't need to store leases for floodfill
			std::vector<Lease> m_Leases;
			uint64_t m_ExpirationTime; // in milliseconds
			std::shared_ptr<const IdentityEx> m_Identity;
			uint8_t m_EncryptionKey[256];
			uint8_t * m_Buffer;
			size_t m_BufferLen;
	};	
}		
}	

#endif
