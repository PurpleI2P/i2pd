#include <string.h>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "NetDb.hpp"
#include "Tunnel.h"
#include "LeaseSet.h"

namespace i2p
{
namespace data
{
	
	LeaseSet::LeaseSet (const uint8_t * buf, size_t len, bool storeLeases):
		m_IsValid (true), m_StoreLeases (storeLeases), m_ExpirationTime (0)
	{
		m_Buffer = new uint8_t[len];
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
	}

	void LeaseSet::Update (const uint8_t * buf, size_t len)
	{	
		if (len > m_BufferLen)
		{
			auto oldBuffer = m_Buffer;
			m_Buffer = new uint8_t[len];
			delete[] oldBuffer;
		}	
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer (false);
	}

	void LeaseSet::PopulateLeases ()
	{
		m_StoreLeases = true;
		ReadFromBuffer (false);
	}	
		
	void LeaseSet::ReadFromBuffer (bool readIdentity)	
	{	
		if (readIdentity || !m_Identity)
			m_Identity = std::make_shared<IdentityEx>(m_Buffer, m_BufferLen);
		size_t size = m_Identity->GetFullLen ();
		if (size > m_BufferLen)
		{
			LogPrint (eLogError, "LeaseSet: identity length ", size, " exceeds buffer size ", m_BufferLen);
			m_IsValid = false;
			return;
		}
		memcpy (m_EncryptionKey, m_Buffer + size, 256);
		size += 256; // encryption key
		size += m_Identity->GetSigningPublicKeyLen (); // unused signing key
		uint8_t num = m_Buffer[size];
		size++; // num
		LogPrint (eLogDebug, "LeaseSet: read num=", (int)num);
		if (!num || num > MAX_NUM_LEASES)
		{	  
			LogPrint (eLogError, "LeaseSet: incorrect number of leases", (int)num);
			m_IsValid = false;
			return;
		}	

		// reset existing leases
		if (m_StoreLeases)
			for (auto& it: m_Leases)
				it->isUpdated = false;
		else	
			m_Leases.clear ();

		// process leases
		m_ExpirationTime = 0;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		const uint8_t * leases = m_Buffer + size;
		for (int i = 0; i < num; i++)
		{
			Lease lease;
			lease.tunnelGateway = leases;
			leases += 32; // gateway
			lease.tunnelID = bufbe32toh (leases);
			leases += 4; // tunnel ID
			lease.endDate = bufbe64toh (leases); 
			leases += 8; // end date
			if (ts < lease.endDate + LEASE_ENDDATE_THRESHOLD)
			{	
				if (lease.endDate > m_ExpirationTime)
					m_ExpirationTime = lease.endDate;
				if (m_StoreLeases)
				{	
					auto ret = m_Leases.insert (std::make_shared<Lease>(lease));
					if (!ret.second) (*ret.first)->endDate = lease.endDate; // update existing
					(*ret.first)->isUpdated = true;
					// check if lease's gateway is in our netDb
					if (!netdb.FindRouter (lease.tunnelGateway))
					{
						// if not found request it
						LogPrint (eLogInfo, "LeaseSet: Lease's tunnel gateway not found, requesting");
						netdb.RequestDestination (lease.tunnelGateway);
					}
				}	
			}
			else
				LogPrint (eLogWarning, "LeaseSet: Lease is expired already ");
		}	
		if (!m_ExpirationTime)
		{
			LogPrint (eLogWarning, "LeaseSet: all leases are expired. Dropped");
			m_IsValid = false;
			return;
		}	
		m_ExpirationTime += LEASE_ENDDATE_THRESHOLD;
		// delete old leases	
		if (m_StoreLeases)
		{	
			for (auto it = m_Leases.begin (); it != m_Leases.end ();)
			{	
				if (!(*it)->isUpdated)
				{
					(*it)->endDate = 0; // somebody might still hold it
					m_Leases.erase (it++);
				}	
				else
					++it;
			}
		}

		// verify
		if (!m_Identity->Verify (m_Buffer, leases - m_Buffer, leases))
		{
			LogPrint (eLogWarning, "LeaseSet: verification failed");
			m_IsValid = false;
		}
	}				

	uint64_t LeaseSet::ExtractTimestamp (const uint8_t * buf, size_t len) const 
	{
		if (!m_Identity) return 0;
		size_t size = m_Identity->GetFullLen ();
		if (size > len) return 0;
		size += 256; // encryption key
		size += m_Identity->GetSigningPublicKeyLen (); // unused signing key
		if (size > len) return 0;
		uint8_t num = buf[size];
		size++; // num
		if (size + num*LEASE_SIZE > len) return 0;
		uint64_t timestamp= 0 ;
		for (int i = 0; i < num; i++)
		{
			size += 36; // gateway (32) + tunnelId(4)
			auto endDate = bufbe64toh (buf + size); 
			size += 8; // end date
			if (!timestamp || endDate < timestamp)
				timestamp = endDate;
		}	
		return timestamp;
	}	

	bool LeaseSet::IsNewer (const uint8_t * buf, size_t len) const
	{
		return ExtractTimestamp (buf, len) > ExtractTimestamp (m_Buffer, m_BufferLen);
	}	

	bool LeaseSet::ExpiresSoon(const uint64_t dlt, const uint64_t fudge) const
	{
		auto now = i2p::util::GetMillisecondsSinceEpoch ();
		if (fudge) now += rand() % fudge;
		if (now >= m_ExpirationTime) return true;
		return	m_ExpirationTime - now <= dlt;
	}

  const std::vector<std::shared_ptr<const Lease> > LeaseSet::GetNonExpiredLeases (bool withThreshold) const
  {
    return GetNonExpiredLeasesExcluding( [] (const Lease & l) -> bool { return false; }, withThreshold);
  }
  
	const std::vector<std::shared_ptr<const Lease> > LeaseSet::GetNonExpiredLeasesExcluding (LeaseInspectFunc exclude, bool withThreshold) const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		std::vector<std::shared_ptr<const Lease> > leases;
		for (const auto& it: m_Leases)
		{
			auto endDate = it->endDate;
			if (withThreshold)
				endDate += LEASE_ENDDATE_THRESHOLD;
			else
				endDate -= LEASE_ENDDATE_THRESHOLD;
			if (ts < endDate && !exclude(*it))
				leases.push_back (it);
		}	
		return leases;	
	}	

	bool LeaseSet::HasExpiredLeases () const
 	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (const auto& it: m_Leases)
			if (ts >= it->endDate) return true;
		return false;
 	}	

	bool LeaseSet::IsExpired () const
	{
		if (m_StoreLeases && IsEmpty ()) return true;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		return ts > m_ExpirationTime;
	}

	LocalLeaseSet::LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * encryptionPublicKey, std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels):
		m_ExpirationTime (0), m_Identity (identity)
	{
		int num = tunnels.size ();
		if (num > MAX_NUM_LEASES) num = MAX_NUM_LEASES;
		// identity
		auto signingKeyLen = m_Identity->GetSigningPublicKeyLen ();
		m_BufferLen = m_Identity->GetFullLen () + 256 + signingKeyLen + 1 + num*LEASE_SIZE + m_Identity->GetSignatureLen ();	
		m_Buffer = new uint8_t[m_BufferLen];	
		auto offset = m_Identity->ToBuffer (m_Buffer, m_BufferLen);
		memcpy (m_Buffer + offset, encryptionPublicKey, 256);
		offset += 256;
		memset (m_Buffer + offset, 0, signingKeyLen);
		offset += signingKeyLen;
		// num leases
		m_Buffer[offset] = num; 
		offset++;
		// leases
		m_Leases = m_Buffer + offset;
		auto currentTime = i2p::util::GetMillisecondsSinceEpoch ();
		for (int i = 0; i < num; i++)
		{
			memcpy (m_Buffer + offset, tunnels[i]->GetNextIdentHash (), 32);
			offset += 32; // gateway id
			htobe32buf (m_Buffer + offset, tunnels[i]->GetNextTunnelID ());
			offset += 4; // tunnel id
			uint64_t ts = tunnels[i]->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			if (ts > m_ExpirationTime) m_ExpirationTime = ts;
			// make sure leaseset is newer than previous, but adding some time to expiration date
			ts += (currentTime - tunnels[i]->GetCreationTime ()*1000LL)*2/i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT; // up to 2 secs
			htobe64buf (m_Buffer + offset, ts);
			offset += 8; // end date
		}
		//  we don't sign it yet. must be signed later on
	}

	LocalLeaseSet::LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len):
		m_ExpirationTime (0), m_Identity (identity)
	{
		m_BufferLen = len;
		m_Buffer = new uint8_t[m_BufferLen];
		memcpy (m_Buffer, buf, len);		
	}

	bool LocalLeaseSet::IsExpired () const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		return ts > m_ExpirationTime;
	}	
}		
}	
