#include <string.h>
#include "I2PEndian.h"
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
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
	
	LeaseSet::LeaseSet (const uint8_t * buf, int len)
	{
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
	}

	LeaseSet::LeaseSet (const i2p::tunnel::TunnelPool& pool)
	{	
		// header
		const i2p::data::LocalDestination * localDestination = pool.GetLocalDestination ();
		if (!localDestination)
		{
			m_BufferLen = 0;
			LogPrint (eLogError, "Destination for local LeaseSet doesn't exist");
			return;
		}	
		m_BufferLen = localDestination->GetIdentity ().ToBuffer (m_Buffer, MAX_LS_BUFFER_SIZE);
		memcpy (m_Buffer + m_BufferLen, localDestination->GetEncryptionPublicKey (), 256);
		m_BufferLen += 256;
		auto signingKeyLen = localDestination->GetIdentity ().GetSigningPublicKeyLen ();
		memset (m_Buffer + m_BufferLen, 0, signingKeyLen);
		m_BufferLen += signingKeyLen;
		auto tunnels = pool.GetInboundTunnels (5); // 5 tunnels maximum
		m_Buffer[m_BufferLen] = tunnels.size (); // num leases
		m_BufferLen++;
		// leases
		CryptoPP::AutoSeededRandomPool rnd;	
		for (auto it: tunnels)
		{	
			memcpy (m_Buffer + m_BufferLen, it->GetNextIdentHash (), 32);
			m_BufferLen += 32; // gateway id
			htobe32buf (m_Buffer + m_BufferLen, it->GetNextTunnelID ());
			m_BufferLen += 4; // tunnel id
			uint64_t ts = it->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - 60; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			ts += rnd.GenerateWord32 (0, 5); // + random milliseconds
			htobe64buf (m_Buffer + m_BufferLen, ts);
			m_BufferLen += 8; // end date
		}
		// signature
		localDestination->Sign (m_Buffer, m_BufferLen, m_Buffer + m_BufferLen);
		m_BufferLen += localDestination->GetIdentity ().GetSignatureLen (); 
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
