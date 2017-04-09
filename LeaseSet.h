#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
#include <string.h>
#include <vector>
#include <set>
#include <memory>
#include "Identity.h"
#include "Timestamp.h"

namespace i2p
{

namespace tunnel
{
	class InboundTunnel;	
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
		/* return true if this lease expires within t millisecond + fudge factor */
		bool ExpiresWithin( const uint64_t t, const uint64_t fudge = 1000 ) const {
			auto expire = i2p::util::GetMillisecondsSinceEpoch ();
			if(fudge) expire += rand() % fudge;
			if (endDate < expire) return true;
			return (endDate - expire) < t;
		}
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

  typedef std::function<bool(const Lease & l)> LeaseInspectFunc;
  
	const size_t MAX_LS_BUFFER_SIZE = 3072;
	const size_t LEASE_SIZE = 44; // 32 + 4 + 8
	const uint8_t MAX_NUM_LEASES = 16;		
	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, size_t len, bool storeLeases = true);
			~LeaseSet () { delete[] m_Buffer; };
			void Update (const uint8_t * buf, size_t len);
			bool IsNewer (const uint8_t * buf, size_t len) const;
			void PopulateLeases (); // from buffer
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_Identity; };			

			const uint8_t * GetBuffer () const { return m_Buffer; };
			size_t GetBufferLen () const { return m_BufferLen; };	
			bool IsValid () const { return m_IsValid; };
			const std::vector<std::shared_ptr<const Lease> > GetNonExpiredLeases (bool withThreshold = true) const;
      const std::vector<std::shared_ptr<const Lease> > GetNonExpiredLeasesExcluding (LeaseInspectFunc exclude, bool withThreshold = true)  const;
			bool HasExpiredLeases () const;
			bool IsExpired () const;
			bool IsEmpty () const { return m_Leases.empty (); };
			uint64_t GetExpirationTime () const { return m_ExpirationTime; };
			bool ExpiresSoon(const uint64_t dlt=1000 * 5, const uint64_t fudge = 0) const ;
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

	class LocalLeaseSet
	{
		public:

			LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * encryptionPublicKey, std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels);
			LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len);
			~LocalLeaseSet () { delete[] m_Buffer; };

			const uint8_t * GetBuffer () const { return m_Buffer; };
			uint8_t * GetSignature () { return m_Buffer + m_BufferLen - GetSignatureLen (); }; 
			size_t GetBufferLen () const { return m_BufferLen; };	
			size_t GetSignatureLen () const { return m_Identity->GetSignatureLen (); };
			uint8_t * GetLeases () { return m_Leases; }; 
			
			const IdentHash& GetIdentHash () const { return m_Identity->GetIdentHash (); };
			bool IsExpired () const;
			uint64_t GetExpirationTime () const { return m_ExpirationTime; };
			void SetExpirationTime (uint64_t expirationTime) { m_ExpirationTime = expirationTime; };
			bool operator== (const LeaseSet& other) const 
			{ return m_BufferLen == other.GetBufferLen ()  && !memcmp (other.GetBuffer (), other.GetBuffer (), m_BufferLen); }; 


		private:
			
			uint64_t m_ExpirationTime; // in milliseconds
			std::shared_ptr<const IdentityEx> m_Identity;
			uint8_t * m_Buffer, * m_Leases;
			size_t m_BufferLen;
	}; 
}		
}	

#endif
