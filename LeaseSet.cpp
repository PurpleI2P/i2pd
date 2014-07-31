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
		m_BufferLen = 0;	
		// header
		const i2p::data::LocalDestination& localDestination = pool.GetLocalDestination ();
		LeaseSetHeader * header = (LeaseSetHeader *)m_Buffer;
		header->destination = localDestination.GetIdentity ();
		memcpy (header->encryptionKey, localDestination.GetEncryptionPublicKey (), 256);
		memset (header->signingKey, 0, 128);
		auto tunnels = pool.GetInboundTunnels (5); // 5 tunnels maximum
		header->num = tunnels.size (); // num leases
		m_BufferLen += sizeof (LeaseSetHeader);	
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
		m_BufferLen += 40;
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
		const LeaseSetHeader * header = (const LeaseSetHeader *)m_Buffer;
		m_Identity = header->destination;
		m_IdentHash = m_Identity.Hash();
		memcpy (m_EncryptionKey, header->encryptionKey, 256);
		LogPrint ("LeaseSet num=", (int)header->num);

		// process leases
		const uint8_t * leases = m_Buffer + sizeof (LeaseSetHeader);
		for (int i = 0; i < header->num; i++)
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
		CryptoPP::DSA::PublicKey pubKey;
		pubKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Identity.signingKey, 128));
		CryptoPP::DSA::Verifier verifier (pubKey);
		if (!verifier.VerifyMessage (m_Buffer, leases - m_Buffer, leases, 40))
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
