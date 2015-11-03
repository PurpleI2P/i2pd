#include <string.h>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "NetDb.h"
#include "TunnelPool.h"
#include "LeaseSet.h"

namespace i2p
{
namespace data
{
	
	LeaseSet::LeaseSet (const uint8_t * buf, size_t len):
		m_IsValid (true)
	{
		m_Buffer = new uint8_t[len];
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
	}

	LeaseSet::LeaseSet (const i2p::tunnel::TunnelPool& pool):
		m_IsValid (true)
	{	
		// header
		const i2p::data::LocalDestination * localDestination = pool.GetLocalDestination ();
		if (!localDestination)
		{
			m_Buffer = nullptr;
			m_BufferLen = 0;
			m_IsValid = false;
			LogPrint (eLogError, "Destination for local LeaseSet doesn't exist");
			return;
		}	
		m_Buffer = new uint8_t[MAX_LS_BUFFER_SIZE];
		m_BufferLen = localDestination->GetIdentity ()->ToBuffer (m_Buffer, MAX_LS_BUFFER_SIZE);
		memcpy (m_Buffer + m_BufferLen, localDestination->GetEncryptionPublicKey (), 256);
		m_BufferLen += 256;
		auto signingKeyLen = localDestination->GetIdentity ()->GetSigningPublicKeyLen ();
		memset (m_Buffer + m_BufferLen, 0, signingKeyLen);
		m_BufferLen += signingKeyLen;
		auto tunnels = pool.GetInboundTunnels (5); // 5 tunnels maximum
		m_Buffer[m_BufferLen] = tunnels.size (); // num leases
		m_BufferLen++;
		// leases
		for (auto it: tunnels)
		{	
			memcpy (m_Buffer + m_BufferLen, it->GetNextIdentHash (), 32);
			m_BufferLen += 32; // gateway id
			htobe32buf (m_Buffer + m_BufferLen, it->GetNextTunnelID ());
			m_BufferLen += 4; // tunnel id
			uint64_t ts = it->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			ts += rand () % 6; // + random milliseconds 0-5
			htobe64buf (m_Buffer + m_BufferLen, ts);
			m_BufferLen += 8; // end date
		}
		// signature
		localDestination->Sign (m_Buffer, m_BufferLen, m_Buffer + m_BufferLen);
		m_BufferLen += localDestination->GetIdentity ()->GetSignatureLen (); 
		LogPrint ("Local LeaseSet of ", tunnels.size (), " leases created");

		ReadFromBuffer ();
	}

	void LeaseSet::Update (const uint8_t * buf, size_t len)
	{	
		m_Leases.clear ();
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
	
	void LeaseSet::ReadFromBuffer (bool readIdentity)	
	{	
		if (readIdentity || !m_Identity)
			m_Identity = std::make_shared<IdentityEx>(m_Buffer, m_BufferLen);
		size_t size = m_Identity->GetFullLen ();
		memcpy (m_EncryptionKey, m_Buffer + size, 256);
		size += 256; // encryption key
		size += m_Identity->GetSigningPublicKeyLen (); // unused signing key
		uint8_t num = m_Buffer[size];
		size++; // num
		LogPrint ("LeaseSet num=", (int)num);
		if (!num)  m_IsValid = false;

		// process leases
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
			m_Leases.push_back (lease);

			// check if lease's gateway is in our netDb
			if (!netdb.FindRouter (lease.tunnelGateway))
			{
				// if not found request it
				LogPrint (eLogInfo, "Lease's tunnel gateway not found. Requested");
				netdb.RequestDestination (lease.tunnelGateway);
			}	
		}	
		
		// verify
		if (!m_Identity->Verify (m_Buffer, leases - m_Buffer, leases))
		{
			LogPrint (eLogWarning, "LeaseSet verification failed");
			m_IsValid = false;
		}
	}				
	
	const std::vector<Lease> LeaseSet::GetNonExpiredLeases (bool withThreshold) const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		std::vector<Lease> leases;
		for (auto& it: m_Leases)
		{
			auto endDate = it.endDate;
			if (!withThreshold)
				endDate -= i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD*1000;
			if (ts < endDate)
				leases.push_back (it);
		}	
		return leases;	
	}	

	bool LeaseSet::HasExpiredLeases () const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto& it: m_Leases)
			if (ts >= it.endDate) return true;
		return false;
	}	

	bool LeaseSet::HasNonExpiredLeases () const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto& it: m_Leases)
			if (ts < it.endDate) return true;
		return false;
	}	
}		
}	
