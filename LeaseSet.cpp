#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "Log.h"
#include "LeaseSet.h"

namespace i2p
{
namespace data
{
	
	LeaseSet::LeaseSet (const uint8_t * buf, int len)
	{
#pragma pack(1)
		struct H
		{
			Identity destination;
			uint8_t encryptionKey[256];
			uint8_t signingKey[128];
			uint8_t num;
		};		
#pragma pack ()	

		const H * header = (const H *)buf;
		m_Identity = header->destination;
		m_IdentHash = CalculateIdentHash (m_Identity);
		memcpy (m_EncryptionKey, header->encryptionKey, 256);
		LogPrint ("LeaseSet num=", (int)header->num);

		const uint8_t * leases = buf + sizeof (H);
		for (int i = 0; i < header->num; i++)
		{
			Lease lease = *(Lease *)leases;
			lease.tunnelID = be32toh (lease.tunnelID);
			m_Leases.push_back (lease);
			leases += sizeof (Lease);
		}	

		// verify
		CryptoPP::DSA::PublicKey pubKey;
		pubKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Identity.signingKey, 128));
		CryptoPP::DSA::Verifier verifier (pubKey);
		if (!verifier.VerifyMessage (buf, leases - buf, leases, 40))
			LogPrint ("LeaseSet verification failed");
	}	
}		
}	
