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
			// TODO: process ACKs
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
				// TODO: process ACH bitfields
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
			I2NPMessage * msg = nullptr;
			if (fragmentNum > 0) // follow-up fragment
			{
				auto it = m_IncomleteMessages.find (msgID);
				if (it != m_IncomleteMessages.end ())
				{
					if (fragmentNum == it->second->nextFragmentNum)
					{
						// expected fragment
						msg = it->second->msg;
						memcpy (msg->buf + msg->len, buf, fragmentSize);
						msg->len += fragmentSize;
						it->second->nextFragmentNum++;
					}	
					else if (fragmentNum < it->second->nextFragmentNum)
						// duplicate fragment
						LogPrint ("Duplicate fragment ", fragmentNum, " of message ", msgID, ". Ignored");	
					else
					{
						// missing fragment
						LogPrint ("Missing fragments from ", it->second->nextFragmentNum, " to ", fragmentNum - 1, " of message ", msgID);	
						//TODO
					}	
 						
					if (isLast)
					{
						if (!msg)
							DeleteI2NPMessage (it->second->msg);
						delete it->second;
						m_IncomleteMessages.erase (it);
					}	
				}
				else
					// TODO:
					LogPrint ("Unexpected follow-on fragment ", fragmentNum, " of message ", msgID);	
			}
			else // first fragment
			{
				msg = NewI2NPMessage ();
				memcpy (msg->GetSSUHeader (), buf, fragmentSize);
				msg->len += fragmentSize - sizeof (I2NPHeaderShort);
			}

			if (msg)
			{					
				if (!fragmentNum && !isLast)
					m_IncomleteMessages[msgID] = new IncompleteMessage (msg);
				if (isLast)
				{
					m_Session.SendMsgAck (msgID);
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
			}
			buf += fragmentSize;
		}	
	}

}
}

