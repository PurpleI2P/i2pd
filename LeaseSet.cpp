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

		for (int i = 0; i < header->num; i++)
		{
			m_Leases.push_back (*(Lease *)(buf + sizeof (H)));
		}	
	}	
}		
}	
