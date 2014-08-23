#include "I2PEndian.h"
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "Log.h"
#include "Timestamp.h"
#include "NetDb.h"
#include "TunnelPool.h"
#include "LeaseSet.h"

namespace i2p
{
namespace data
{
	
	LeaseSet::LeaseSet (const uint8_t * buf, int len, bool unsolicited): 
		m_IsUnsolicited (unsolicited)
	{
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
	}

	LeaseSet::LeaseSet (const i2p::tunnel::TunnelPool& pool):
		m_IsUnsolicited (false)
	{	
		// header
		const i2p::data::LocalDestination& localDestination = pool.GetLocalDestination ();
		m_BufferLen = localDestination.GetIdentity ().ToBuffer (m_Buffer, MAX_LS_BUFFER_SIZE);
		memcpy (m_Buffer + m_BufferLen, localDestination.GetEncryptionPublicKey (), 256);
		m_BufferLen += 256;
		auto signingKeyLen = localDestination.GetIdentity ().GetSigningPublicKeyLen ();
		memset (m_Buffer + m_BufferLen, 0, signingKeyLen);
		m_BufferLen += signingKeyLen;
		auto tunnels = pool.GetInboundTunnels (5); // 5 tunnels maximum
		m_Buffer[m_BufferLen] = tunnels.size (); // num leases
		m_BufferLen++;
		// leases
		for (auto it: tunnels)
		{	
			Lease * lease = (Lease *)(m_Buffer + m_BufferLen);
			memcpy (lease->tunnelGateway, it->GetNextIdentHash (), 32);
			lease->tunnelID = htobe32 (it->GetNextTunnelID ());
			uint64_t ts = it->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - 60; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			lease->endDate = htobe64 (ts);
			m_BufferLen += sizeof (Lease);
		}	
		// signature
		localDestination.Sign (m_Buffer, m_BufferLen, m_Buffer + m_BufferLen);
		m_BufferLen += localDestination.GetIdentity ().GetSignatureLen (); 
		LogPrint ("Local LeaseSet of ", tunnels.size (), " leases created");

		ReadFromBuffer ();
	}

	void LeaseSet::Update (const uint8_t * buf, int len)
	{	
		m_Leases.clear ();
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
	}
	
	void LeaseSet::ReadFromBuffer ()	
	{	
		size_t size = m_Identity.FromBuffer (m_Buffer, m_BufferLen);
		memcpy (m_EncryptionKey, m_Buffer + size, 256);
		size += 256; // encryption key
		size += m_Identity.GetSigningPublicKeyLen (); // unused signing key
		uint8_t num = m_Buffer[size];
		size++; // num
		LogPrint ("LeaseSet num=", (int)num);

		// process leases
		const uint8_t * leases = m_Buffer + size;
		for (int i = 0; i < num; i++)
		{
			Lease lease = *(Lease *)leases;
			lease.tunnelID = be32toh (lease.tunnelID);
			lease.endDate = be64toh (lease.endDate);
			m_Leases.push_back (lease);
			leases += sizeof (Lease);

			// check if lease's gateway is in our netDb
			if (!netdb.FindRouter (lease.tunnelGateway))
			{
				// if not found request it
				LogPrint ("Lease's tunnel gateway not found. Requested");
				netdb.RequestDestination (lease.tunnelGateway);
			}	
		}	
		
		// verify
		if (!m_Identity.Verify (m_Buffer, leases - m_Buffer, leases))
			LogPrint ("LeaseSet verification failed");
	}				
	
	const std::vector<Lease> LeaseSet::GetNonExpiredLeases () const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		std::vector<Lease> leases;
		for (auto& it: m_Leases)
			if (ts < it.endDate)
				leases.push_back (it);
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
