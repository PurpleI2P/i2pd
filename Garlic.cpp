#include <inttypes.h>
#include "I2PEndian.h"
#include <map>
#include <string>
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "Timestamp.h"
#include "Destination.h"
#include "Garlic.h"

namespace i2p
{
namespace garlic
{
	GarlicRoutingSession::GarlicRoutingSession (GarlicDestination * owner, 
	    const i2p::data::RoutingDestination * destination, int numTags):
		m_Owner (owner), m_Destination (destination), m_NumTags (numTags), 
		m_LeaseSetUpdated (numTags > 0)
	{
		// create new session tags and session key
		m_Rnd.GenerateBlock (m_SessionKey, 32);
		m_Encryption.SetKey (m_SessionKey);
	}	

	GarlicRoutingSession::GarlicRoutingSession (const uint8_t * sessionKey, const SessionTag& sessionTag):
		m_Owner (nullptr), m_Destination (nullptr), m_NumTags (1), m_LeaseSetUpdated (false)
	{
		memcpy (m_SessionKey, sessionKey, 32);
		m_Encryption.SetKey (m_SessionKey);
		m_SessionTags.push_back (sessionTag);
		m_SessionTags.back ().creationTime = i2p::util::GetSecondsSinceEpoch ();
	}	

	GarlicRoutingSession::~GarlicRoutingSession	()
	{	
		for (auto it: m_UnconfirmedTagsMsgs)	
			delete it.second;
		m_UnconfirmedTagsMsgs.clear ();
	}
	
	GarlicRoutingSession::UnconfirmedTags * GarlicRoutingSession::GenerateSessionTags ()
	{
		auto tags = new UnconfirmedTags (m_NumTags);
		tags->tagsCreationTime = i2p::util::GetSecondsSinceEpoch ();		
		for (int i = 0; i < m_NumTags; i++)
		{
			m_Rnd.GenerateBlock (tags->sessionTags[i], 32);
			tags->sessionTags[i].creationTime = tags->tagsCreationTime;
		}			
		return tags;	
	}
	
	void GarlicRoutingSession::TagsConfirmed (uint32_t msgID) 
	{ 
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		auto it = m_UnconfirmedTagsMsgs.find (msgID);	
		if (it != m_UnconfirmedTagsMsgs.end ())
		{
			UnconfirmedTags * tags = it->second;
			if (ts < tags->tagsCreationTime + OUTGOING_TAGS_EXPIRATION_TIMEOUT)
			{	
				for (int i = 0; i < tags->numTags; i++)
					m_SessionTags.push_back (tags->sessionTags[i]);
			}	
			m_UnconfirmedTagsMsgs.erase (it);
			delete tags;
		}
		// delete expired unconfirmed tags
		for (auto it = m_UnconfirmedTagsMsgs.begin (); it != m_UnconfirmedTagsMsgs.end ();)
		{
			if (ts >= it->second->tagsCreationTime + OUTGOING_TAGS_EXPIRATION_TIMEOUT)
			{
				delete it->second;
				it = m_UnconfirmedTagsMsgs.erase (it);
			}	
			else
				it++;
		}	
	}

	I2NPMessage * GarlicRoutingSession::WrapSingleMessage (I2NPMessage * msg)
	{
		I2NPMessage * m = NewI2NPMessage ();
		m->Align (12); // in order to get buf aligned to 16 (12 + 4)
		size_t len = 0;
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length

		// find non-expired tag
		bool tagFound = false;	
		SessionTag tag; 
		if (m_NumTags > 0)
		{	
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			while (!m_SessionTags.empty ())
			{
				if (ts < m_SessionTags.front ().creationTime + OUTGOING_TAGS_EXPIRATION_TIMEOUT)
				{
					tag = m_SessionTags.front ();
					m_SessionTags.pop_front (); // use same tag only once
					tagFound = true;
					break;
				}	
				else
					m_SessionTags.pop_front (); // remove expired tag
			}
		}	
		// create message
		if (!tagFound) // new session
		{
			LogPrint ("No garlic tags available. Use ElGamal");
			if (!m_Destination)
			{
				LogPrint ("Can't use ElGamal for unknown destination");
				return nullptr;
			}
			// create ElGamal block
			ElGamalBlock elGamal;
			memcpy (elGamal.sessionKey, m_SessionKey, 32); 
			m_Rnd.GenerateBlock (elGamal.preIV, 32); // Pre-IV
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32); 
			m_Destination->GetElGamalEncryption ()->Encrypt ((uint8_t *)&elGamal, sizeof(elGamal), buf, true);			
			m_Encryption.SetIV (iv);
			buf += 514;
			len += 514;	
		}
		else // existing session
		{	
			// session tag
			memcpy (buf, tag, 32);	
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, tag, 32);
			m_Encryption.SetIV (iv);
			buf += 32;
			len += 32;		
		}	
		// AES block
		len += CreateAESBlock (buf, msg);
		htobe32buf (m->GetPayload (), len);
		m->len += len + 4;
		FillI2NPMessageHeader (m, eI2NPGarlic);
		if (msg)
			DeleteI2NPMessage (msg);
		return m;
	}	

	size_t GarlicRoutingSession::CreateAESBlock (uint8_t * buf, const I2NPMessage * msg)
	{
		size_t blockSize = 0;
		bool createNewTags = m_Owner && m_NumTags && ((int)m_SessionTags.size () <= m_NumTags/2);
		UnconfirmedTags * newTags = createNewTags ? GenerateSessionTags () : nullptr;
		htobuf16 (buf, newTags ? htobe16 (newTags->numTags) : 0); // tag count
		blockSize += 2;
		if (newTags) // session tags recreated
		{	
			for (int i = 0; i < newTags->numTags; i++)
			{
				memcpy (buf + blockSize, newTags->sessionTags[i], 32); // tags
				blockSize += 32;
			}
		}	
		uint32_t * payloadSize = (uint32_t *)(buf + blockSize);
		blockSize += 4;
		uint8_t * payloadHash = buf + blockSize;
		blockSize += 32;
		buf[blockSize] = 0; // flag
		blockSize++;
		size_t len = CreateGarlicPayload (buf + blockSize, msg, newTags);
		htobe32buf (payloadSize, len);
		CryptoPP::SHA256().CalculateDigest(payloadHash, buf + blockSize, len);
		blockSize += len;
		size_t rem = blockSize % 16;
		if (rem)
			blockSize += (16-rem); //padding
		m_Encryption.Encrypt(buf, blockSize, buf);
		return blockSize;
	}	

	size_t GarlicRoutingSession::CreateGarlicPayload (uint8_t * payload, const I2NPMessage * msg, UnconfirmedTags * newTags)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
		uint32_t msgID = m_Rnd.GenerateWord32 ();	
		size_t size = 0;
		uint8_t * numCloves = payload + size;
		*numCloves = 0;
		size++;

		if (m_Owner)
		{	
			if (newTags) // new session
			{
				// clove is DeliveryStatus 
				size += CreateDeliveryStatusClove (payload + size, msgID);
				if (size > 0) // successive?
				{
					(*numCloves)++;
					m_UnconfirmedTagsMsgs[msgID] = newTags;
					m_Owner->DeliveryStatusSent (this, msgID);
				}
				else
					LogPrint ("DeliveryStatus clove was not created");
			}	
			if (m_LeaseSetUpdated) 
			{
				m_LeaseSetUpdated = false;
				// clove if our leaseSet must be attached
				auto leaseSet = CreateDatabaseStoreMsg (m_Owner->GetLeaseSet ());
				size += CreateGarlicClove (payload + size, leaseSet, false);
				DeleteI2NPMessage (leaseSet);
				(*numCloves)++;
			}
		}	
		if (msg) // clove message ifself if presented
		{	
			size += CreateGarlicClove (payload + size, msg, m_Destination ? m_Destination->IsDestination () : false);
			(*numCloves)++;
		}	
		
		memset (payload + size, 0, 3); // certificate of message
		size += 3;
		htobe32buf (payload + size, msgID); // MessageID
		size += 4;
		htobe64buf (payload + size, ts); // Expiration of message
		size += 8;
		return size;
	}	

	size_t GarlicRoutingSession::CreateGarlicClove (uint8_t * buf, const I2NPMessage * msg, bool isDestination)
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
		size_t size = 0;
		if (isDestination && m_Destination)
		{
			buf[size] = eGarlicDeliveryTypeDestination << 5;//  delivery instructions flag destination
			size++;
			memcpy (buf + size, m_Destination->GetIdentHash (), 32);
			size += 32;
		}	
		else	
		{	
			buf[size] = 0;//  delivery instructions flag local
			size++;
		}
		
		memcpy (buf + size, msg->GetBuffer (), msg->GetLength ());
		size += msg->GetLength ();
		htobe32buf (buf + size, m_Rnd.GenerateWord32 ()); // CloveID
		size += 4;
		htobe64buf (buf + size, ts); // Expiration of clove
		size += 8;
		memset (buf + size, 0, 3); // certificate of clove
		size += 3;
		return size;
	}	

	size_t GarlicRoutingSession::CreateDeliveryStatusClove (uint8_t * buf, uint32_t msgID)
	{		
		size_t size = 0;
		if (m_Owner)
		{
			auto leases = m_Owner->GetLeaseSet ()->GetNonExpiredLeases ();
			if (!leases.empty ())
			{	
				buf[size] = eGarlicDeliveryTypeTunnel << 5; // delivery instructions flag tunnel
				size++;
				uint32_t i = m_Rnd.GenerateWord32 (0, leases.size () - 1);
				// hash and tunnelID sequence is reversed for Garlic 
				memcpy (buf + size, leases[i].tunnelGateway, 32); // To Hash
				size += 32;
				htobe32buf (buf + size, leases[i].tunnelID); // tunnelID
				size += 4; 	
				// create msg 
				I2NPMessage * msg = CreateDeliveryStatusMsg (msgID);
				if (m_Owner)
				{
					//encrypt 
					uint8_t key[32], tag[32];
					m_Rnd.GenerateBlock (key, 32); // random session key 
					m_Rnd.GenerateBlock (tag, 32); // random session tag
					m_Owner->SubmitSessionKey (key, tag);
					GarlicRoutingSession garlic (key, tag);
					msg = garlic.WrapSingleMessage (msg);		
				}
				memcpy (buf + size, msg->GetBuffer (), msg->GetLength ());
				size += msg->GetLength ();
				DeleteI2NPMessage (msg);
				// fill clove
				uint64_t ts = i2p::util::GetMillisecondsSinceEpoch () + 5000; // 5 sec
				htobe32buf (buf + size, m_Rnd.GenerateWord32 ()); // CloveID
				size += 4;
				htobe64buf (buf + size, ts); // Expiration of clove
				size += 8;
				memset (buf + size, 0, 3); // certificate of clove
				size += 3;
			}
			else	
				LogPrint ("All tunnels of local LeaseSet expired");	
		}
		else
			LogPrint ("Missing local LeaseSet");

		return size;
	}
	
	GarlicDestination::~GarlicDestination ()
	{
		for (auto it: m_Sessions)
			delete it.second;
		m_Sessions.clear ();
	}

	void GarlicDestination::AddSessionKey (const uint8_t * key, const uint8_t * tag)
	{
		if (key)
		{
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			auto decryption = std::make_shared<i2p::crypto::CBCDecryption>();
			decryption->SetKey (key);
			m_Tags[SessionTag(tag, ts)] = decryption;
		}
	}

	bool GarlicDestination::SubmitSessionKey (const uint8_t * key, const uint8_t * tag) 
	{
		AddSessionKey (key, tag);
		return true;
	}

	void GarlicDestination::HandleGarlicMessage (I2NPMessage * msg)
	{
		uint8_t * buf = msg->GetPayload ();
		uint32_t length = bufbe32toh (buf);
		buf += 4; // length
		auto it = m_Tags.find (SessionTag(buf));
		if (it != m_Tags.end ())
		{
			// tag found. Use AES
			uint8_t iv[32]; // IV is first 16 bytes
			CryptoPP::SHA256().CalculateDigest(iv, buf, 32);
			it->second->SetIV (iv);
			it->second->Decrypt (buf + 32, length - 32, buf + 32);
			HandleAESBlock (buf + 32, length - 32, it->second, msg->from);
			m_Tags.erase (it); // tag might be used only once
		}
		else
		{
			// tag not found. Use ElGamal
			ElGamalBlock elGamal;
			if (i2p::crypto::ElGamalDecrypt (GetEncryptionPrivateKey (), buf, (uint8_t *)&elGamal, true))
			{	
				auto decryption = std::make_shared<i2p::crypto::CBCDecryption>();
				decryption->SetKey (elGamal.sessionKey);
				uint8_t iv[32]; // IV is first 16 bytes
				CryptoPP::SHA256().CalculateDigest(iv, elGamal.preIV, 32); 
				decryption->SetIV (iv);
				decryption->Decrypt(buf + 514, length - 514, buf + 514);
				HandleAESBlock (buf + 514, length - 514, decryption, msg->from);
			}	
			else
				LogPrint ("Failed to decrypt garlic");
		}
		DeleteI2NPMessage (msg);

		// cleanup expired tags
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		if (ts > m_LastTagsCleanupTime + INCOMING_TAGS_EXPIRATION_TIMEOUT)
		{
			if (m_LastTagsCleanupTime)
			{
				int numExpiredTags = 0;
				for (auto it = m_Tags.begin (); it != m_Tags.end ();)
				{
					if (ts > it->first.creationTime + INCOMING_TAGS_EXPIRATION_TIMEOUT)
					{
						numExpiredTags++;
						it = m_Tags.erase (it);
					}	
					else
						it++;
				}
				LogPrint (numExpiredTags, " tags expired for ", GetIdentHash().ToBase64 ());
			}	
			m_LastTagsCleanupTime = ts;
		}	
	}	

	void GarlicDestination::HandleAESBlock (uint8_t * buf, size_t len, std::shared_ptr<i2p::crypto::CBCDecryption> decryption,
		i2p::tunnel::InboundTunnel * from)
	{
		uint16_t tagCount = bufbe16toh (buf);
		buf += 2; len -= 2;	
		if (tagCount > 0)
		{	
			if (tagCount*32 > len) 
			{
				LogPrint (eLogError, "Tag count ", tagCount, " exceeds length ", len);
				return ;
			}	
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			for (int i = 0; i < tagCount; i++)
				m_Tags[SessionTag(buf + i*32, ts)] = decryption;	
		}	
		buf += tagCount*32;
		len -= tagCount*32;
		uint32_t payloadSize = bufbe32toh (buf);
		if (payloadSize > len)
		{
			LogPrint (eLogError, "Unexpected payload size ", payloadSize);
			return;
		}	
		buf += 4;
		uint8_t * payloadHash = buf;
		buf += 32;// payload hash. 
		if (*buf) // session key?
			buf += 32; // new session key
		buf++; // flag

		// payload
		if (!CryptoPP::SHA256().VerifyDigest (payloadHash, buf, payloadSize)) // payload hash doesn't match
		{
			LogPrint ("Wrong payload hash");
			return;
		}		    
		HandleGarlicPayload (buf, payloadSize, from);
	}	

	void GarlicDestination::HandleGarlicPayload (uint8_t * buf, size_t len, i2p::tunnel::InboundTunnel * from)
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
					HandleI2NPMessage (buf, len, from);
				break;	
				case eGarlicDeliveryTypeDestination:	
					LogPrint ("Garlic type destination");
					buf += 32; // destination. check it later or for multiple destinations
					HandleI2NPMessage (buf, len, from);
				break;
				case eGarlicDeliveryTypeTunnel:
				{	
					LogPrint ("Garlic type tunnel");
					// gwHash and gwTunnel sequence is reverted
					uint8_t * gwHash = buf;
					buf += 32;
					uint32_t gwTunnel = bufbe32toh (buf);
					buf += 4;
					i2p::tunnel::OutboundTunnel * tunnel = nullptr;
					if (from && from->GetTunnelPool ())
						tunnel = from->GetTunnelPool ()->GetNextOutboundTunnel ();
					if (tunnel) // we have send it through an outbound tunnel
					{	
						I2NPMessage * msg = CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from);
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
	
	I2NPMessage * GarlicDestination::WrapMessage (const i2p::data::RoutingDestination& destination, 
		I2NPMessage * msg, bool attachLeaseSet)	
	{
		if (attachLeaseSet) // we should maintain this session
		{	
			auto session = GetRoutingSession (destination, 32);  // 32 tags by default
			return session->WrapSingleMessage (msg);	
		}
		else // one time session
		{
			GarlicRoutingSession session (this, &destination, 0); // don't use tag if no LeaseSet
			return session.WrapSingleMessage (msg);
		}	
	}

	GarlicRoutingSession * GarlicDestination::GetRoutingSession (
		const i2p::data::RoutingDestination& destination, int numTags)
	{
		auto it = m_Sessions.find (destination.GetIdentHash ());
		GarlicRoutingSession * session = nullptr;
		if (it != m_Sessions.end ())
			session = it->second;
		if (!session)
		{
			session = new GarlicRoutingSession (this, &destination, numTags); 
			std::unique_lock<std::mutex> l(m_SessionsMutex);
			m_Sessions[destination.GetIdentHash ()] = session;
		}	
		return session;
	}	
		
	void GarlicDestination::DeliveryStatusSent (GarlicRoutingSession * session, uint32_t msgID)
	{
		m_CreatedSessions[msgID] = session;
	}		

	void GarlicDestination::HandleDeliveryStatusMessage (I2NPMessage * msg)
	{
		uint32_t msgID = bufbe32toh (msg->GetPayload ());
		{
			auto it = m_CreatedSessions.find (msgID);
			if (it != m_CreatedSessions.end ())			
			{
				it->second->TagsConfirmed (msgID);
				m_CreatedSessions.erase (it);
				LogPrint ("Garlic message ", msgID, " acknowledged");
			}	
		}
		DeleteI2NPMessage (msg);	
	}

	void GarlicDestination::SetLeaseSetUpdated ()
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);	
		for (auto it: m_Sessions)
			it.second->SetLeaseSetUpdated ();
	}

	void GarlicDestination::ProcessGarlicMessage (I2NPMessage * msg)
	{
		HandleGarlicMessage (msg);
	}

	void GarlicDestination::ProcessDeliveryStatusMessage (I2NPMessage * msg)
	{
		HandleDeliveryStatusMessage (msg);
	}

}	
}
