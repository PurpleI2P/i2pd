#include "Log.h"
#include "SSU.h"
#include "SSUData.h"

namespace i2p
{
namespace ssu
{
	SSUData::SSUData (SSUSession& session):
		m_Session (session)
	{
	}

	SSUData::~SSUData ()
	{
		for (auto it: m_IncomleteMessages)
			if (it.second)
			{
				DeleteI2NPMessage (it.second->msg);
				delete it.second;
			}	
		for (auto it: m_SentMessages)
		{
			for (auto f: it.second)
			delete[] f;
		}	
	}

	void SSUData::ProcessSentMessageAck (uint32_t msgID)
	{
		auto it = m_SentMessages.find (msgID);
		if (it != m_SentMessages.end ())
		{
			// delete all ack-ed message's fragments
			for (auto f: it->second)
				delete[] f;
			m_SentMessages.erase (it);	
		}
	}		

	void SSUData::ProcessMessage (uint8_t * buf, size_t len)
	{
		//uint8_t * start = buf;
		uint8_t flag = *buf;
		buf++;
		LogPrint ("Process SSU data flags=", (int)flag);
		if (flag & DATA_FLAG_EXPLICIT_ACKS_INCLUDED)
		{
			// explicit ACKs
			uint8_t numAcks =*buf;
			buf++;
			for (int i = 0; i < numAcks; i++)
				ProcessSentMessageAck (be32toh (((uint32_t *)buf)[i]));
			buf += numAcks*4;
		}
		if (flag & DATA_FLAG_ACK_BITFIELDS_INCLUDED)
		{
			// explicit ACK bitfields
			uint8_t numBitfields =*buf;
			buf++;
			for (int i = 0; i < numBitfields; i++)
			{
				buf += 4; // msgID
				// TODO: process individual Ack bitfields
				while (*buf & 0x80) // not last
					buf++;
				buf++; // last byte
			}	
		}	
		uint8_t numFragments = *buf; // number of fragments
		buf++;
		for (int i = 0; i < numFragments; i++)
		{	
			uint32_t msgID = be32toh (*(uint32_t *)buf); // message ID
			buf += 4;
			uint8_t frag[4];
			frag[0] = 0;
			memcpy (frag + 1, buf, 3);
			buf += 3;
			uint32_t fragmentInfo = be32toh (*(uint32_t *)frag); // fragment info
			uint16_t fragmentSize = fragmentInfo & 0x1FFF; // bits 0 - 13
			bool isLast = fragmentInfo & 0x010000; // bit 16	
			uint8_t fragmentNum = fragmentInfo >> 17; // bits 23 - 17
			LogPrint ("SSU data fragment ", (int)fragmentNum, " of message ", msgID, " size=", (int)fragmentSize, isLast ? " last" : " non-last"); 		

			//  find message with msgID
			I2NPMessage * msg = nullptr;
			IncompleteMessage * incompleteMessage = nullptr;
			auto it = m_IncomleteMessages.find (msgID);
			if (it != m_IncomleteMessages.end ()) 
			{	
				// message exists
				incompleteMessage = it->second;
				msg = incompleteMessage->msg;
			}	
			else
			{
				// create new message
				msg = NewI2NPMessage ();
				msg->len -= sizeof (I2NPHeaderShort);
				incompleteMessage = new IncompleteMessage (msg);
				m_IncomleteMessages[msgID] = incompleteMessage;
			}	

			// handle current fragment
			if (fragmentNum == incompleteMessage->nextFragmentNum)
			{
				// expected fragment
				memcpy (msg->buf + msg->len, buf, fragmentSize);
				msg->len += fragmentSize;
				incompleteMessage->nextFragmentNum++;
				if (!isLast && !incompleteMessage->savedFragments.empty ())
				{
					// try saved fragments
					for (auto it1 = incompleteMessage->savedFragments.begin (); it1 != incompleteMessage->savedFragments.end ();)
					{
						auto savedFragment = *it1;
						if (savedFragment->fragmentNum == incompleteMessage->nextFragmentNum)
						{
							memcpy (msg->buf + msg->len, savedFragment->buf, savedFragment->len);
							msg->len += savedFragment->len;
							isLast = savedFragment->isLast;
							incompleteMessage->nextFragmentNum++;
							incompleteMessage->savedFragments.erase (it1++);
							delete savedFragment;
						}
						else
							break;
					}	
				}	
			}	
			else
			{	
				if (fragmentNum < incompleteMessage->nextFragmentNum)
					// duplicate fragment
					LogPrint ("Duplicate fragment ", (int)fragmentNum, " of message ", msgID, ". Ignored");	
				else
				{
					// missing fragment
					LogPrint ("Missing fragments from ", (int)incompleteMessage->nextFragmentNum, " to ", fragmentNum - 1, " of message ", msgID);	
					incompleteMessage->savedFragments.insert (new Fragment (fragmentNum, buf, fragmentSize, isLast));
				}
				isLast = false;
			}	

			if (isLast)
			{
				// delete incomplete message
				delete incompleteMessage;
				m_IncomleteMessages.erase (msgID);				
				// process message
				SendMsgAck (msgID);
				msg->FromSSU (msgID);
				if (m_Session.GetState () == eSessionStateEstablished)
					i2p::HandleI2NPMessage (msg);
				else
				{
					// we expect DeliveryStatus
					if (msg->GetHeader ()->typeID == eI2NPDeliveryStatus)
					{
						LogPrint ("SSU session established");
						m_Session.Established ();
					}	
					else
						LogPrint ("SSU unexpected message ", (int)msg->GetHeader ()->typeID);
					DeleteI2NPMessage (msg);
				}	
			}				
			buf += fragmentSize;
		}	
	}

	void SSUData::Send (i2p::I2NPMessage * msg)
	{
		uint32_t msgID = msg->ToSSU ();
		if (m_SentMessages.count (msgID) > 0)
		{
			LogPrint ("SSU message ", msgID, " already sent");
			DeleteI2NPMessage (msg);
			return;
		}		
		auto fragments = m_SentMessages[msgID];
		msgID = htobe32 (msgID);	
		size_t payloadSize = SSU_MTU - sizeof (SSUHeader) - 9; // 9  =  flag + #frg(1) + messageID(4) + frag info (3) 
		size_t len = msg->GetLength ();
		uint8_t * msgBuf = msg->GetSSUHeader ();

		uint32_t fragmentNum = 0;
		while (len > 0)
		{	
			uint8_t * buf = new uint8_t[SSU_MTU + 18];
			fragments.push_back (buf);
			uint8_t	* payload = buf + sizeof (SSUHeader);
			*payload = DATA_FLAG_WANT_REPLY; // for compatibility
			payload++;
			*payload = 1; // always 1 message fragment per message
			payload++;
			*(uint32_t *)payload = msgID;
			payload += 4;
			bool isLast = (len <= payloadSize);
			size_t size = isLast ? len : payloadSize;
			uint32_t fragmentInfo = (fragmentNum << 17);
			if (isLast)
				fragmentInfo |= 0x010000;
			
			fragmentInfo |= size;
			fragmentInfo = htobe32 (fragmentInfo);
			memcpy (payload, (uint8_t *)(&fragmentInfo) + 1, 3);
			payload += 3;
			memcpy (payload, msgBuf, size);
			
			size += payload - buf;
			if (size & 0x0F) // make sure 16 bytes boundary
				size = ((size >> 4) + 1) << 4; // (/16 + 1)*16
			
			// encrypt message with session key
			m_Session.FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, size);
			m_Session.Send (buf, size);

			if (!isLast)
			{	
				len -= payloadSize;
				msgBuf += payloadSize;
			}	
			else
				len = 0;
			fragmentNum++;
		}	
		DeleteI2NPMessage (msg);
	}		

	void SSUData::SendMsgAck (uint32_t msgID)
	{
		uint8_t buf[48 + 18]; // actual length is 44 = 37 + 7 but pad it to multiple of 16
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = DATA_FLAG_EXPLICIT_ACKS_INCLUDED; // flag
		payload++;
		*payload = 1; // number of ACKs
		payload++;
		*(uint32_t *)(payload) = htobe32 (msgID); // msgID	
		payload += 4;
		*payload = 0; // number of fragments

		// encrypt message with session key
		m_Session.FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, 48);
		m_Session.Send (buf, 48);
	}
}
}

