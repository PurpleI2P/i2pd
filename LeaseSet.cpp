#include <cryptopp/sha.h>
#include "Log.h"
#include "RouterInfo.h"
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
			RouterIdentity destination;
			uint8_t encryptionKey[256];
			uint8_t signingKey[128];
			uint8_t num;
		};		
#pragma pack ()	

		const H * header = (const H *)buf;
		CryptoPP::SHA256().CalculateDigest(m_IdentHash, (uint8_t *)&header->destination, sizeof (RouterIdentity));
		memcpy (m_EncryptionKey, header->encryptionKey, 256);
		LogPrint ("LeaseSet num=", (int)header->num);

		for (int i = 0; i < header->num; i++)
		{
			m_Leases.push_back (*(Lease *)(buf + sizeof (H)));
		}	
	}	
}		
}	
