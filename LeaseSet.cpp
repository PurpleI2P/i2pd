#include <string.h>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "NetDb.h"
#include "Tunnel.h"
#include "TunnelPool.h"
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

	LeaseSet::LeaseSet (std::shared_ptr<const i2p::tunnel::TunnelPool> pool):
		m_IsValid (true), m_StoreLeases (true), m_ExpirationTime (0)
	{	
		if (!pool) return;
		// header
		auto localDestination = pool->GetLocalDestination ();
		if (!localDestination)
		{
			m_Buffer = nullptr;
			m_BufferLen = 0;
			m_IsValid = false;
			LogPrint (eLogError, "LeaseSet: Destination for local LeaseSet doesn't exist");
			return;
		}	
		m_Buffer = new uint8_t[MAX_LS_BUFFER_SIZE];
		m_BufferLen = localDestination->GetIdentity ()->ToBuffer (m_Buffer, MAX_LS_BUFFER_SIZE);
		memcpy (m_Buffer + m_BufferLen, localDestination->GetEncryptionPublicKey (), 256);
		m_BufferLen += 256;
		auto signingKeyLen = localDestination->GetIdentity ()->GetSigningPublicKeyLen ();
		memset (m_Buffer + m_BufferLen, 0, signingKeyLen);
		m_BufferLen += signingKeyLen;
		int numTunnels = pool->GetNumInboundTunnels () + 2; // 2 backup tunnels 
		if (numTunnels > 16) numTunnels = 16; // 16 tunnels maximum 
		auto tunnels = pool->GetInboundTunnels (numTunnels);
		m_Buffer[m_BufferLen] = tunnels.size (); // num leases
		m_BufferLen++;
		// leases
		auto currentTime = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it: tunnels)
		{	
			memcpy (m_Buffer + m_BufferLen, it->GetNextIdentHash (), 32);
			m_BufferLen += 32; // gateway id
			htobe32buf (m_Buffer + m_BufferLen, it->GetNextTunnelID ());
			m_BufferLen += 4; // tunnel id
			uint64_t ts = it->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			if (ts > m_ExpirationTime) m_ExpirationTime = ts;
			// make sure leaseset is newer than previous, but adding some time to expiration date
			ts += (currentTime - it->GetCreationTime ()*1000LL)*2/i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT; // up to 2 secs
			htobe64buf (m_Buffer + m_BufferLen, ts);
			m_BufferLen += 8; // end date
		}
		// signature
		localDestination->Sign (m_Buffer, m_BufferLen, m_Buffer + m_BufferLen);
		m_BufferLen += localDestination->GetIdentity ()->GetSignatureLen (); 
		LogPrint (eLogDebug, "LeaseSet: Local LeaseSet of ", tunnels.size (), " leases created");

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
			for (auto it: m_Leases)
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
					if (!ret.second) *(*ret.first) = lease; // update existing
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
					it++;
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
		
	const std::vector<std::shared_ptr<const Lease> > LeaseSet::GetNonExpiredLeases (bool withThreshold) const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		std::vector<std::shared_ptr<const Lease> > leases;
		for (auto it: m_Leases)
		{
			auto endDate = it->endDate;
			if (withThreshold)
				endDate += LEASE_ENDDATE_THRESHOLD;
			else
				endDate -= LEASE_ENDDATE_THRESHOLD;
			if (ts < endDate)
				leases.push_back (it);
		}	
		return leases;	
	}	

	bool LeaseSet::HasExpiredLeases () const
 	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it: m_Leases)
			if (ts >= it->endDate) return true;
		return false;
 	}	

	bool LeaseSet::IsExpired () const
	{
		if (IsEmpty ()) return true;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		return ts > m_ExpirationTime;
	}

	LocalLeaseSet::LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * encryptionPublicKey, std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels):
		m_Identity (identity)
	{
		int num = tunnels.size ();
		if (num > MAX_NUM_LEASES) num = MAX_NUM_LEASES;
		// identity
		m_BufferLen = m_Identity->GetFullLen () + 256 + num*LEASE_SIZE + m_Identity->GetSignatureLen ();	
		m_Buffer = new uint8_t[m_BufferLen];	
		auto offset = m_Identity->ToBuffer (m_Buffer, m_BufferLen);
		memcpy (m_Buffer + offset, encryptionPublicKey, 256);
		offset += 256;
		auto signingKeyLen = m_Identity->GetSigningPublicKeyLen ();
		memset (m_Buffer + offset, 0, signingKeyLen);
		offset += signingKeyLen;
		// num leases
		m_Buffer[offset] = num; 
		offset++;
		// leases
		auto currentTime = i2p::util::GetMillisecondsSinceEpoch ();
		for (int i = 0; i < num; i++)
		{
			memcpy (m_Buffer + offset, tunnels[i]->GetNextIdentHash (), 32);
			offset += 32; // gateway id
			htobe32buf (m_Buffer + offset, tunnels[i]->GetNextTunnelID ());
			offset += 4; // tunnel id
			uint64_t ts = tunnels[i]->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			// make sure leaseset is newer than previous, but adding some time to expiration date
			ts += (currentTime - tunnels[i]->GetCreationTime ()*1000LL)*2/i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT; // up to 2 secs
			htobe64buf (m_Buffer + offset, ts);
			offset += 8; // end date
		}
		//  we don't sign it yet. must be signed later on
	}	

	void LocalLeaseSet::SetSignature (const uint8_t * signature)
	{
		auto signatureLen = GetSignatureLen ();
		memcpy (m_Buffer + m_BufferLen - signatureLen, signature, signatureLen);
	}
}		
}	
