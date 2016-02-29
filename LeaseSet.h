#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
#include <string.h>
#include <vector>
#include <memory>
#include "Identity.h"

namespace i2p
{

namespace tunnel
{
	class TunnelPool;
}

namespace data
{	
	const int LEASE_ENDDATE_THRESHOLD = 51000; // in milliseconds
	struct Lease
	{
		IdentHash tunnelGateway;
		uint32_t tunnelID;
		uint64_t endDate; // 0 means invalid
		bool isUpdated; // trasient 
	};	

	struct LeaseCmp
	{
		bool operator() (std::shared_ptr<const Lease> l1, std::shared_ptr<const Lease> l2) const
  		{	
			if (l1->tunnelID != l2->tunnelID)
				return l1->tunnelID < l2->tunnelID; 
			else
				return l1->tunnelGateway < l2->tunnelGateway; 
		};
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
			bool IsNewer (const uint8_t * buf, size_t len) const;
			void PopulateLeases (); // from buffer
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_Identity; };			

			const uint8_t * GetBuffer () const { return m_Buffer; };
			size_t GetBufferLen () const { return m_BufferLen; };	
			bool IsValid () const { return m_IsValid; };
			const std::vector<std::shared_ptr<const Lease> > GetNonExpiredLeases (bool withThreshold = true) const;
			bool HasExpiredLeases () const;
			bool IsExpired () const;
			bool IsEmpty () const { return m_Leases.empty (); };
			uint64_t GetExpirationTime () const { return m_ExpirationTime; };
			bool operator== (const LeaseSet& other) const 
			{ return m_BufferLen == other.m_BufferLen && !memcmp (m_Buffer, other.m_Buffer, m_BufferLen); }; 

			// implements RoutingDestination
			const IdentHash& GetIdentHash () const { return m_Identity->GetIdentHash (); };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionKey; };
			bool IsDestination () const { return true; };

		private:

			void ReadFromBuffer (bool readIdentity = true);
			uint64_t ExtractTimestamp (const uint8_t * buf, size_t len) const; // min expiration time
			
		private:

			bool m_IsValid, m_StoreLeases; // we don't need to store leases for floodfill
			std::set<std::shared_ptr<Lease>, LeaseCmp> m_Leases;
			uint64_t m_ExpirationTime; // in milliseconds
			std::shared_ptr<const IdentityEx> m_Identity;
			uint8_t m_EncryptionKey[256];
			uint8_t * m_Buffer;
			size_t m_BufferLen;
	};	
}		
}	

#endif
