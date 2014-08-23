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
	
#pragma pack(1)

	struct Lease
	{
		uint8_t tunnelGateway[32];
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
	
#pragma pack()	

	const int MAX_LS_BUFFER_SIZE = 2048;	
	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, int len, bool unsolicited = false);
			LeaseSet (const LeaseSet& ) = default;
			LeaseSet (const i2p::tunnel::TunnelPool& pool);
			LeaseSet& operator=(const LeaseSet& ) = default;
			void Update (const uint8_t * buf, int len);
			
			const uint8_t * GetBuffer () const { return m_Buffer; };
			size_t GetBufferLen () const { return m_BufferLen; };	

			bool IsUnsolicited () const { return m_IsUnsolicited; };
			void SetUnsolicited (bool unsolicited) { m_IsUnsolicited = unsolicited; };

			// implements RoutingDestination
			const Identity& GetIdentity () const { return m_Identity.GetStandardIdentity (); };
			const IdentHash& GetIdentHash () const { return m_Identity.GetIdentHash (); };
			const std::vector<Lease>& GetLeases () const { return m_Leases; };
			const std::vector<Lease> GetNonExpiredLeases () const;
			bool HasExpiredLeases () const;
			bool HasNonExpiredLeases () const;
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionKey; };
			bool IsDestination () const { return true; };

		private:

			void ReadFromBuffer ();
			
		private:

			std::vector<Lease> m_Leases;
			IdentityEx m_Identity;
			uint8_t m_EncryptionKey[256];
			uint8_t m_Buffer[MAX_LS_BUFFER_SIZE];
			size_t m_BufferLen;
			bool m_IsUnsolicited;
	};	
}		
}	

#endif
