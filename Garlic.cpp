#include <inttypes.h>
#include "I2PEndian.h"
#include <map>
#include <string>
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "Streaming.h"
#include "Garlic.h"

namespace i2p
{
namespace garlic
{	
	GarlicRoutingSession::GarlicRoutingSession (const i2p::data::RoutingDestination& destination, int numTags):
		m_Destination (destination), m_FirstMsgID (0), m_IsAcknowledged (false), 
		m_NumTags (numTags), m_NextTag (-1), m_SessionTags (0),
		m_ElGamalEncryption (m_Destination.GetEncryptionPublicKey (), true)
	{
		// create new session tags and session key
		m_Rnd.GenerateBlock (m_SessionKey, 32);
		if (m_NumTags > 0)
		{
			m_SessionTags = new uint8_t[m_NumTags*32];
			GenerateSessionTags ();
		}	
		else
			m_SessionTags = nullptr;
	}	

	GarlicRoutingSession::~GarlicRoutingSession	()
	{	
		delete[] m_SessionTags;
	}
	
	void GarlicRoutingSession::GenerateSessionTags ()
	{
		if (m_SessionTags)
		{
			for (int i = 0; i < m_NumTags; i++)
				m_Rnd.GenerateBlock (m_SessionTags + i*32, 32);
		}
	}
	
	I2NPMessage * GarlicRoutingSession::WrapSingleMessage (I2NPMessage * msg, I2NPMessage * leaseSet)
	{
		I2NPMessage * m = NewI2NPMessage ();
		size_t len = 0;
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length
		if (m_NextTag < 0 || !m_NumTags) // new session
		{
			// create ElGamal block
			ElGamalBlock elGamal;
			memcpy (elGamal.sessionKey, m_SessionKey, 32); 
			m_Rnd.GenerateBlock (elGamal.preIV, 32); // Pre-IV
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32); 
			m_ElGamalEncryption.Encrypt ((uint8_t *)&elGamal, sizeof(elGamal), buf);			
			m_Encryption.SetKeyWithIV (m_SessionKey, 32, iv);
			buf += 514;
			len += 514;	
		}
		else // existing session
		{	
			// session tag
			memcpy (buf, m_SessionTags + m_NextTag*32, 32);			
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, m_SessionTags + m_NextTag*32, 32);
			m_Encryption.SetKeyWithIV (m_SessionKey, 32, iv);
			buf += 32;
			len += 32;

			// re-create session tags if necessary				
			if (m_NextTag >= m_NumTags - 1) // we have used last tag
			{
				GenerateSessionTags ();
				m_NextTag = -1;
			}			
		}	
		// AES block
		len += CreateAESBlock (buf, msg, leaseSet);
		m_NextTag++;
		*(uint32_t *)(m->GetPayload ()) = htobe32 (len);
		m->len += len + 4;
		FillI2NPMessageHeader (m, eI2NPGarlic);
		if (msg)
			DeleteI2NPMessage (msg);
		return m;
	}	

	size_t GarlicRoutingSession::CreateAESBlock (uint8_t * buf, I2NPMessage * msg, I2NPMessage * leaseSet)
	{
		size_t blockSize = 0;
		*(uint16_t *)buf = m_NextTag < 0 ? htobe16 (m_NumTags) : 0; // tag count
		blockSize += 2;
		if (m_NextTag < 0) // session tags recreated
		{	
			memcpy (buf + blockSize, m_SessionTags, m_NumTags*32); // tags
			blockSize += m_NumTags*32;
		}	
		uint32_t * payloadSize = (uint32_t *)(buf + blockSize);
		blockSize += 4;
		uint8_t * payloadHash = buf + blockSize;
		blockSize += 32;
		buf[blockSize] = 0; // flag
		blockSize++;
		size_t len = CreateGarlicPayload (buf + blockSize, msg, leaseSet);
		*payloadSize = htobe32 (len);
		CryptoPP::SHA256().CalculateDigest(payloadHash, buf + blockSize, len);
		blockSize += len;
		size_t rem = blockSize % 16;
		if (rem)
			blockSize += (16-rem); //padding
		m_Encryption.ProcessData(buf, buf, blockSize);
		return blockSize;
	}	

	size_t GarlicRoutingSession::CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg, I2NPMessage * leaseSet)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
		uint32_t msgID = m_Rnd.GenerateWord32 ();	
		size_t size = 0;
		uint8_t * numCloves = payload + size;
		*numCloves = 0;
		size++;

		if (m_NextTag < 0) // new session
		{
			// clove is DeliveryStatus 
			size += CreateDeliveryStatusClove (payload + size, msgID);
			(*numCloves)++;
			m_FirstMsgID = msgID;
		}	
		if (leaseSet) 
		{
			// clove is our leaseSet if presented
			size += CreateGarlicClove (payload + size, leaseSet, false);
			(*numCloves)++;
		}	
		if (msg) // clove message ifself if presented
		{	
			size += CreateGarlicClove (payload + size, msg, m_Destination.IsDestination ());
			(*numCloves)++;
		}	
		
		memset (payload + size, 0, 3); // certificate of message
		size += 3;
		*(uint32_t *)(payload + size) = htobe32 (msgID); // MessageID
		size += 4;
		*(uint64_t *)(payload + size) = htobe64 (ts); // Expiration of message
		size += 8;
		return size;
	}	

	size_t GarlicRoutingSession::CreateGarlicClove (uint8_t * buf, I2NPMessage * msg, bool isDestination)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
		size_t size = 0;
		if (isDestination)
		{
			buf[size] = eGarlicDeliveryTypeDestination << 5;//  delivery instructions flag destination
			size++;
			memcpy (buf + size, m_Destination.GetIdentHash (), 32);
			size += 32;
		}	
		else	
		{	
			buf[size] = 0;//  delivery instructions flag local
			size++;
		}
		
		memcpy (buf + size, msg->GetBuffer (), msg->GetLength ());
		size += msg->GetLength ();
		*(uint32_t *)(buf + size) = htobe32 (m_Rnd.GenerateWord32 ()); // CloveID
		size += 4;
		*(uint64_t *)(buf + size) = htobe64 (ts); // Expiration of clove
		size += 8;
		memset (buf + size, 0, 3); // certificate of clove
		size += 3;
		return size;
	}	

	size_t GarlicRoutingSession::CreateDeliveryStatusClove (uint8_t * buf, uint32_t msgID)
	{		
		size_t size = 0;
		auto tunnel = i2p::tunnel::tunnels.GetNextInboundTunnel ();
		if (tunnel)
		{	
			buf[size] = eGarlicDeliveryTypeTunnel << 5; // delivery instructions flag tunnel
			size++;
			// hash and tunnelID sequence is reversed for Garlic
			memcpy (buf + size, tunnel->GetNextIdentHash (), 32); // To Hash
			size += 32;
			*(uint32_t *)(buf + size) = htobe32 (tunnel->GetNextTunnelID ()); // tunnelID
			size += 4; 	
		}
		else	
		{	
			LogPrint ("No reply tunnels for garlic DeliveryStatus found");
			buf[size] = 0;//  delivery instructions flag local
			size++;
		}
			
		
		I2NPMessage * msg = CreateDeliveryStatusMsg (msgID);
		memcpy (buf + size, msg->GetBuffer (), msg->GetLength ());
		size += msg->GetLength ();
		DeleteI2NPMessage (msg);
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
		*(uint32_t *)(buf + size) = htobe32 (m_Rnd.GenerateWord32 ()); // CloveID
		size += 4;
		*(uint64_t *)(buf + size) = htobe64 (ts); // Expiration of clove
		size += 8;
		memset (buf + size, 0, 3); // certificate of clove
		size += 3;
		
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

	I2NPMessage * GarlicRouting::WrapSingleMessage (const i2p::data::RoutingDestination& destination, I2NPMessage * msg)
	{
		auto it = m_Sessions.find (destination.GetIdentHash ());
		if (it != m_Sessions.end ())
		{
			delete it->second;
			m_Sessions.erase (it);
		}
		GarlicRoutingSession * session = new GarlicRoutingSession (destination, 0); // not follow-on messages expected
		m_Sessions[destination.GetIdentHash ()] = session;

		return session->WrapSingleMessage (msg, nullptr);
	}	

	I2NPMessage * GarlicRouting::WrapMessage (const i2p::data::RoutingDestination& destination, 
		I2NPMessage * msg, I2NPMessage * leaseSet)
	{
		auto it = m_Sessions.find (destination.GetIdentHash ());
		GarlicRoutingSession * session = nullptr;
		if (it != m_Sessions.end ())
			session = it->second;
		if (!session)
		{
			session = new GarlicRoutingSession (destination, 4); // TODO: change it later
			m_Sessions[destination.GetIdentHash ()] = session;
		}	

		I2NPMessage * ret = session->WrapSingleMessage (msg, leaseSet);
		if (!session->GetNextTag ()) // tags have beed recreated
			m_CreatedSessions[session->GetFirstMsgID ()] = session;
		return ret;
	}

	void GarlicRouting::HandleGarlicMessage (uint8_t * buf, size_t len, bool isFromTunnel)
	{
		uint32_t length = be32toh (*(uint32_t *)buf);
		buf += 4;
		std::string sessionTag((const char *)buf, 32);
		auto it = m_SessionTags.find (sessionTag);
		if (it != m_SessionTags.end ())
		{
			// existing session
			std::string sessionKey (it->second);
			m_SessionTags.erase (it); // tag might be used only once
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, buf, 32);
			m_Decryption.SetKeyWithIV ((uint8_t *)sessionKey.c_str (), 32, iv); // tag is mapped to 32 bytes key
			m_Decryption.ProcessData(buf + 32, buf + 32, length - 32);
			HandleAESBlock (buf + 32, length - 32, (uint8_t *)sessionKey.c_str ());
		}
		else
		{
			// new session
			ElGamalBlock elGamal;
			if (i2p::crypto::ElGamalDecrypt (
			   	isFromTunnel ? i2p::context.GetLeaseSetPrivateKey () : i2p::context.GetPrivateKey (), 
				buf, (uint8_t *)&elGamal, true))
			{	
				uint8_t iv[32]; // IV is first 16 bytes
				CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32); 
				m_Decryption.SetKeyWithIV (elGamal.sessionKey, 32, iv);
				m_Decryption.ProcessData(buf + 514, buf + 514, length - 514);
				HandleAESBlock (buf + 514, length - 514, elGamal.sessionKey);
			}	
			else
				LogPrint ("Failed to decrypt garlic");
		}	
		
	}	

	void GarlicRouting::HandleAESBlock (uint8_t * buf, size_t len, uint8_t * sessionKey)
	{
		uint16_t tagCount = be16toh (*(uint16_t *)buf);
		buf += 2;
		for (int i = 0; i < tagCount; i++)
			m_SessionTags[std::string ((const char *)(buf + i*32), 32)] = std::string ((const char *)sessionKey, 32);
		buf += tagCount*32;
		uint32_t payloadSize = be32toh (*(uint32_t *)buf);
		if (payloadSize > len)
		{
			LogPrint ("Unexpected payload size ", payloadSize);
			return;
		}	
		buf += 4;
		uint8_t * payloadHash = buf;
		buf += 32;// payload hash. 
		if (*buf) // session key?
			buf += 32; // new session key
		buf++; // flag

		// payload
		uint8_t hash[32];
		CryptoPP::SHA256().CalculateDigest(hash, buf, payloadSize);
		if (memcmp (hash, payloadHash, 32)) // payload hash doesn't match
		{
			LogPrint ("Wrong payload hash");
			return;
		}		    
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
					i2p::HandleI2NPMessage (buf, len, false);
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
				case eGarlicDeliveryTypeTunnel:
				{	
					LogPrint ("Garlic type tunnel");
					// gwHash and gwTunnel sequence is reverted
					uint8_t * gwHash = buf;
					buf += 32;
					uint32_t gwTunnel = be32toh (*(uint32_t *)buf);
					buf += 4;
					auto tunnel = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
					if (tunnel) // we have send it through an outbound tunnel
					{	
						I2NPMessage * msg = CreateI2NPMessage (buf, len - 36);
						tunnel->SendTunnelDataMsg (gwHash, gwTunnel, msg);
					}	
					else
						LogPrint ("No outbound tunnels available for garlic clove");
					break;
				}
				case eGarlicDeliveryTypeRouter:
					LogPrint ("Garlic type router not supported");
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

	void GarlicRouting::HandleDeliveryStatusMessage (uint8_t * buf, size_t len)
	{
		I2NPDeliveryStatusMsg * msg = (I2NPDeliveryStatusMsg *)buf;
		auto it = m_CreatedSessions.find (be32toh (msg->msgID));
		if (it != m_CreatedSessions.end ())			
		{
			it->second->SetAcknowledged (true);
			m_CreatedSessions.erase (it);
			LogPrint ("Garlic message ", be32toh (msg->msgID), " acknowledged");
		}	
	}	
}	
}
