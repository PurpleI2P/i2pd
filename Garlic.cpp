#include <inttypes.h>
#include <endian.h>
#include <map>
#include <string>
#include "ElGamal.h"
#include "RouterContext.h"
#include "Timestamp.h"
#include "Streaming.h"
#include "Garlic.h"

namespace i2p
{
namespace garlic
{	
	GarlicRoutingSession::GarlicRoutingSession (const i2p::data::RoutingDestination * destination, int numTags):
		m_Destination (destination), m_NumTags (numTags), m_NextTag (-1), m_SessionTags (0)
	{
		m_Rnd.GenerateBlock (m_SessionKey, 32);
		if (m_NumTags > 0)
		{	
			m_SessionTags = new uint8_t[m_NumTags*32];
			for (int i = 0; i < m_NumTags; i++)
				m_Rnd.GenerateBlock (m_SessionTags + i*32, 32);
		}	
	}	

	GarlicRoutingSession::~GarlicRoutingSession	()
	{	
		delete[] m_SessionTags;
	}
		
	I2NPMessage * GarlicRoutingSession::WrapSingleMessage (I2NPMessage * msg)
	{
		I2NPMessage * m = NewI2NPMessage ();
		size_t len = 0;
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length
		if (m_NextTag < 0) // new session
		{
			// create ElGamal block
			ElGamalBlock elGamal;
			memcpy (elGamal.sessionKey, m_SessionKey, 32); 
			m_Rnd.GenerateBlock (elGamal.preIV, 32); // Pre-IV
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32); 
			i2p::crypto::ElGamalEncrypt (m_Destination->GetEncryptionPublicKey (), (uint8_t *)&elGamal, sizeof(elGamal), buf, true);
			buf += 514;
			// AES block
			m_Encryption.SetKeyWithIV (m_SessionKey, 32, iv);
			len += 514 + CreateAESBlock (buf, msg);	
		}
		else // existing session
		{	
			// session tag
			memcpy (buf, m_SessionTags + m_NextTag*32, 32);
			buf += 32;
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, m_SessionTags + m_NextTag*32, 32);
			m_Encryption.SetKeyWithIV (m_SessionKey, 32, iv);
			// AES block
			len += 32 + CreateAESBlock (buf, msg);
		}	
		m_NextTag++;
		*(uint32_t *)(m->GetPayload ()) = htobe32 (len);
		m->len += len + 4;
		FillI2NPMessageHeader (m, eI2NPGarlic);
		DeleteI2NPMessage (msg);
		return m;
	}	

	size_t GarlicRoutingSession::CreateAESBlock (uint8_t * buf, I2NPMessage * msg)
	{
		size_t blockSize = 0;
		*(uint16_t *)buf = htobe16 (m_NumTags); // tag count
		blockSize += 2;
		memcpy (buf + blockSize, m_SessionTags, m_NumTags*32); // tags
		blockSize += m_NumTags*32;
		uint32_t * payloadSize = (uint32_t *)(buf + blockSize);
		blockSize += 4;
		uint8_t * payloadHash = buf + blockSize;
		blockSize += 32;
		buf[blockSize] = 0; // flag
		blockSize++;
		size_t len = CreateGarlicPayload (buf + blockSize, msg);
		*payloadSize = htobe32 (len);
		CryptoPP::SHA256().CalculateDigest(payloadHash, buf + blockSize, len);
		blockSize += len;
		size_t rem = blockSize % 16;
		if (rem)
			blockSize += (16-rem); //padding
		m_Encryption.ProcessData(buf, buf, blockSize);
		return blockSize;
	}	

	size_t GarlicRoutingSession::CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
		size_t size = 0;
		payload[size] = 1; // 1 clove
		size++;
		if (m_Destination->IsDestination ())
		{
			payload[size] = eGarlicDeliveryTypeDestination << 5;//  delivery instructions flag destination
			size++;
			memcpy (payload + size, m_Destination->GetIdentHash (), 32);
			size += 32;
		}	
		else	
		{	
			payload[size] = 0;//  delivery instructions flag local
			size++;
		}
		memcpy (payload + size, msg->GetBuffer (), msg->GetLength ());
		size += msg->GetLength ();
		*(uint32_t *)(payload + size) = htobe32 (m_Rnd.GenerateWord32 ()); // CloveID
		size += 4;
		*(uint64_t *)(payload + size) = htobe64 (ts); // Expiration of clove
		size += 8;
		memset (payload + size, 0, 3); // certificate of clove
		size += 3;
		memset (payload + size, 0, 3); // certificate of message
		size += 3;
		*(uint32_t *)(payload + size) = htobe32 (m_Rnd.GenerateWord32 ()); // MessageID
		size += 4;
		*(uint64_t *)(payload + size) = htobe64 (ts); // Expiration of message
		size += 8;
		return size;
	}	

	GarlicRouting routing;	
	GarlicRouting::GarlicRouting ()
	{
	}
	
	GarlicRouting::~GarlicRouting ()
	{
		for (auto it: m_Sessions)
			delete it.second;
		m_Sessions.clear ();
	}	

	I2NPMessage * GarlicRouting::WrapSingleMessage (const i2p::data::RoutingDestination * destination, I2NPMessage * msg)
	{
		if (!destination) return nullptr;
		auto it = m_Sessions.find (destination->GetIdentHash ());
		GarlicRoutingSession * session = nullptr;
		if (it != m_Sessions.end ())
			session = it->second;
		if (!session)
		{
			session = new GarlicRoutingSession (destination, 4); // TODO: change it later
			m_Sessions[destination->GetIdentHash ()] = session;
		}	

		I2NPMessage * ret = session->WrapSingleMessage (msg);
		if (session->GetNumRemainingSessionTags () <= 0)
		{
			m_Sessions.erase (destination->GetIdentHash ());
			delete session;
		}	
		return ret;
	}	

	void GarlicRouting::HandleGarlicMessage (uint8_t * buf, size_t len)
	{
		uint32_t length = be32toh (*(uint32_t *)buf);
		buf += 4;
		std::string sessionTag((const char *)buf, 32);
		if (m_SessionTags.count (sessionTag) > 0)
		{
			// existing session
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, buf, 32);
			m_Decryption.SetKeyWithIV (m_SessionKey, 32, iv);
			m_Decryption.ProcessData(buf + 32, buf + 32, length - 32);
			HandleAESBlock (buf + 32, length - 32);
		}
		else
		{
			// new session
			ElGamalBlock elGamal;
			i2p::crypto::ElGamalDecrypt (i2p::context.GetLeaseSetPrivateKey (), buf, (uint8_t *)&elGamal, true);
			memcpy (m_SessionKey, elGamal.sessionKey, 32);
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32); 
			m_Decryption.SetKeyWithIV (m_SessionKey, 32, iv);
			m_Decryption.ProcessData(buf + 514, buf + 514, length - 514);
			HandleAESBlock (buf + 514, length - 514);
		}	
		
	}	

	void GarlicRouting::HandleAESBlock (uint8_t * buf, size_t len)
	{
		uint16_t tagCount = be16toh (*(uint16_t *)buf);
		buf += 2;
		for (int i = 0; i < tagCount; i++)
			m_SessionTags.insert (std::string ((const char *)(buf + i*32), 32));
		buf += tagCount*32;
		uint32_t payloadSize = be32toh (*(uint32_t *)buf);
		buf += 4;
		buf += 32;// payload hash. TODO: verify it
		if (*buf) // session key?
			buf += 32; // new session key
		buf++; // flag
		// payload
		HandleGarlicPayload (buf, payloadSize);
	}	

	void GarlicRouting::HandleGarlicPayload (uint8_t * buf, size_t len)
	{
		int numCloves = buf[0];
		LogPrint (numCloves," cloves");
		buf++;
		for (int i = 0; i < numCloves; i++)
		{
			// delivery instructions
			uint8_t flag = buf[0];
			buf++; // flag
			if (flag & 0x80) // encrypted?
			{
				// TODO: implement
				LogPrint ("Clove encrypted");
				buf += 32; 
			}	
			GarlicDeliveryType deliveryType = (GarlicDeliveryType)((flag >> 5) & 0x03);
			switch (deliveryType)
			{
				case eGarlicDeliveryTypeLocal:
					LogPrint ("Garlic type local");
					i2p::HandleI2NPMessage (buf, len);
				break;	
				case eGarlicDeliveryTypeDestination:
				{	
					LogPrint ("Garlic type destination");
					i2p::data::IdentHash destination (buf);	
					buf += 32;
					// we assume streaming protocol for destination
					// later on we should let destination decide
					I2NPHeader * header = (I2NPHeader *)buf;
					if (header->typeID == eI2NPData)
						i2p::stream::HandleDataMessage (&destination, buf + sizeof (I2NPHeader), be16toh (header->size));
					else
						LogPrint ("Unexpected I2NP garlic message ", (int)header->typeID);
					break;
				}	
				case eGarlicDeliveryTypeRouter:
					LogPrint ("Garlic type router not implemented");
					// TODO: implement
					buf += 32;
				break;
				case eGarlicDeliveryTypeTunnel:
					LogPrint ("Garlic type tunnel not implemented");
					// TODO: implement
					buf += 4;
					buf += 32;
				break;
				default:
					LogPrint ("Unknow garlic delivery type ", (int)deliveryType);
			}
			buf += GetI2NPMessageLength (buf); //  I2NP
			buf += 4; // CloveID
			buf += 8; // Date
			buf += 3; // Certificate
		}	
	}	
}	
}
