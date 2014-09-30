#include <stdlib.h>
#include <boost/bind.hpp>
#include "Log.h"
#include "Timestamp.h"
#include "NetDb.h"
#include "SSU.h"
#include "SSUData.h"

namespace i2p
{
namespace ssu
{
	SSUData::SSUData (SSUSession& session):
		m_Session (session), m_ResendTimer (session.m_Server.GetService ())
	{
		m_PacketSize = SSU_MAX_PACKET_SIZE;
		auto remoteRouter = session.GetRemoteRouter ();
		if (remoteRouter)
			AdjustPacketSize (*remoteRouter);
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
			delete it.second;
	}

	void SSUData::AdjustPacketSize (const i2p::data::RouterInfo& remoteRouter)
	{
		auto ssuAddress = remoteRouter.GetSSUAddress ();
		if (ssuAddress && ssuAddress->mtu)
		{
			m_PacketSize = ssuAddress->mtu - IPV4_HEADER_SIZE - UDP_HEADER_SIZE;
			if (m_PacketSize > 0)
			{
				// make sure packet size multiple of 16
				m_PacketSize >>= 4;
				m_PacketSize <<= 4;
				if (m_PacketSize > (int)SSU_MAX_PACKET_SIZE) m_PacketSize = SSU_MAX_PACKET_SIZE;
				LogPrint ("MTU=", ssuAddress->mtu, " packet size=", m_PacketSize); 
			}
			else
			{	
				LogPrint ("Unexpected MTU ", ssuAddress->mtu);
				m_PacketSize = SSU_MAX_PACKET_SIZE;
			}	
		}		
	}

	void SSUData::UpdatePacketSize (const i2p::data::IdentHash& remoteIdent)
	{
 		auto routerInfo = i2p::data::netdb.FindRouter (remoteIdent);
		if (routerInfo)
			AdjustPacketSize (*routerInfo);
	}

	void SSUData::ProcessSentMessageAck (uint32_t msgID)
	{
		auto it = m_SentMessages.find (msgID);
		if (it != m_SentMessages.end ())
		{
			delete it->second;
			m_SentMessages.erase (it);	
			if (m_SentMessages.empty ())
				m_ResendTimer.cancel ();
		}
	}		

	void SSUData::ProcessAcks (uint8_t *& buf, uint8_t flag)
	{
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
				uint32_t msgID = be32toh (*(uint32_t *)buf);
				buf += 4; // msgID
				auto it = m_SentMessages.find (msgID);		
				// process individual Ack bitfields
				bool isNonLast = false;
				int fragment = 0;
				do
				{
					uint8_t bitfield = *buf;
					isNonLast = bitfield & 0x80;
					bitfield &= 0x7F; // clear MSB
					if (bitfield && it != m_SentMessages.end ())
					{	
						int numSentFragments = it->second->fragments.size ();		
						// process bits
						uint8_t mask = 0x01;
						for (int j = 0; j < 7; j++)
						{			
							if (bitfield & mask)
							{
								if (fragment < numSentFragments)
								{
									delete it->second->fragments[fragment];
									it->second->fragments[fragment] = nullptr;
								}	
							}				
							fragment++;
							mask <<= 1;
						}
					}	
					buf++;
				}
				while (isNonLast); 
			}	
		}		
	}

	void SSUData::ProcessFragments (uint8_t * buf)
	{
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
					if (isLast)
						LogPrint ("Message ", msgID, " complete");
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
					auto savedFragment = new Fragment (fragmentNum, buf, fragmentSize, isLast);
					if (!incompleteMessage->savedFragments.insert (savedFragment).second)
					{
						LogPrint ("Fragment ", (int)fragmentNum, " of message ", msgID, " already saved");
						delete savedFragment;
					}	
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
				{
					if (!m_ReceivedMessages.count (msgID))
					{	
						if (m_ReceivedMessages.size () > 100) m_ReceivedMessages.clear ();
						m_ReceivedMessages.insert (msgID);
						i2p::HandleI2NPMessage (msg);
					}	
					else
					{
						LogPrint ("SSU message ", msgID, " already received");						
						i2p::DeleteI2NPMessage (msg);
					}	
				}	
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
			else
				SendFragmentAck (msgID, fragmentNum);			
			buf += fragmentSize;
		}	
	}

	void SSUData::ProcessMessage (uint8_t * buf, size_t len)
	{
		//uint8_t * start = buf;
		uint8_t flag = *buf;
		buf++;
		LogPrint ("Process SSU data flags=", (int)flag);
		// process acks if presented
		if (flag & (DATA_FLAG_ACK_BITFIELDS_INCLUDED | DATA_FLAG_EXPLICIT_ACKS_INCLUDED))
			ProcessAcks (buf, flag);
		// extended data if presented
		if (flag & DATA_FLAG_EXTENDED_DATA_INCLUDED)
		{
			uint8_t extendedDataSize = *buf;
			buf++; // size
			LogPrint ("SSU extended data of ", extendedDataSize, " bytes presented");
			buf += extendedDataSize;
		}
		// process data
		ProcessFragments (buf);
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
		if (m_SentMessages.empty ()) // schedule resend at first message only
			ScheduleResend ();
		SentMessage * sentMessage = new SentMessage;
		m_SentMessages[msgID] = sentMessage; 
		sentMessage->nextResendTime = i2p::util::GetSecondsSinceEpoch () + RESEND_INTERVAL;
		sentMessage->numResends = 0;
		auto& fragments = sentMessage->fragments;
		msgID = htobe32 (msgID);	
		size_t payloadSize = m_PacketSize - sizeof (SSUHeader) - 9; // 9  =  flag + #frg(1) + messageID(4) + frag info (3) 
		size_t len = msg->GetLength ();
		uint8_t * msgBuf = msg->GetSSUHeader ();

		uint32_t fragmentNum = 0;
		while (len > 0)
		{	
			Fragment * fragment = new Fragment;
			fragment->fragmentNum = fragmentNum;
			uint8_t * buf = fragment->buf;
			fragments.push_back (fragment);
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
			fragment->len = size; 
			
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

	void SSUData::SendFragmentAck (uint32_t msgID, int fragmentNum)
	{
		if (fragmentNum > 64)
		{
			LogPrint ("Fragment number ", fragmentNum, " exceeds 64");
			return;
		}
		uint8_t buf[64 + 18];
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = DATA_FLAG_ACK_BITFIELDS_INCLUDED; // flag
		payload++;	
		*payload = 1; // number of ACK bitfields
		payload++;
		// one ack
		*(uint32_t *)(payload) = htobe32 (msgID); // msgID	
		payload += 4;
		div_t d = div (fragmentNum, 7);
		memset (payload, 0x80, d.quot); // 0x80 means non-last
		payload += d.quot;		
		*payload = 0x01 << d.rem; // set corresponding bit
		payload++;
		*payload = 0; // number of fragments

		size_t len = d.quot < 4 ? 48 : 64; // 48 = 37 + 7 + 4 (3+1)			
		// encrypt message with session key
		m_Session.FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, len);
		m_Session.Send (buf, len);
	}	

	void SSUData::ScheduleResend()
	{		
		m_ResendTimer.cancel ();
		m_ResendTimer.expires_from_now (boost::posix_time::seconds(RESEND_INTERVAL));
		m_ResendTimer.async_wait (boost::bind (&SSUData::HandleResendTimer,
			this, boost::asio::placeholders::error));
	}
		
	void SSUData::HandleResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it : m_SentMessages)
			{
				if (ts >= it.second->nextResendTime && it.second->numResends < MAX_NUM_RESENDS)
				{	
					for (auto f: it.second->fragments)
						if (f) m_Session.Send (f->buf, f->len); // resend

					it.second->numResends++;
					it.second->nextResendTime += it.second->numResends*RESEND_INTERVAL;
				}	
			}
			ScheduleResend ();	
		}	
	}	
}
}

