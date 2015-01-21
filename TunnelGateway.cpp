#include <string.h>
#include "I2PEndian.h"
#include <cryptopp/sha.h>
#include "Log.h"
#include "RouterContext.h"
#include "Transports.h"
#include "TunnelGateway.h"

namespace i2p
{
namespace tunnel
{
	void TunnelGatewayBuffer::PutI2NPMsg (const TunnelMessageBlock& block)
	{
		bool messageCreated = false;
		if (!m_CurrentTunnelDataMsg)
		{	
			CreateCurrentTunnelDataMessage ();
			messageCreated = true;
		}	

		// create delivery instructions
		uint8_t di[43]; // max delivery instruction length is 43 for tunnel
		size_t diLen = 1;// flag
		if (block.deliveryType != eDeliveryTypeLocal) // tunnel or router
		{	
			if (block.deliveryType == eDeliveryTypeTunnel)
			{
				htobe32buf (di + diLen, block.tunnelID);
				diLen += 4; // tunnelID
			}
			
			memcpy (di + diLen, block.hash, 32);
			diLen += 32; //len
		}	
		di[0] = block.deliveryType << 5; // set delivery type

		// create fragments
		I2NPMessage * msg = block.data;
		auto fullMsgLen = diLen + msg->GetLength () + 2; // delivery instructions + payload + 2 bytes length
		if (fullMsgLen <= m_RemainingSize)
		{
			// message fits. First and last fragment
			htobe16buf (di + diLen, msg->GetLength ());
			diLen += 2; // size
			memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len, di, diLen);
			memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + diLen, msg->GetBuffer (), msg->GetLength ());
			m_CurrentTunnelDataMsg->len += diLen + msg->GetLength ();
			m_RemainingSize -= diLen + msg->GetLength ();
			if (!m_RemainingSize)
				CompleteCurrentTunnelDataMessage ();
			DeleteI2NPMessage (msg);
		}	
		else
		{
			if (!messageCreated) // check if we should complete previous message
			{	
				auto numFollowOnFragments = fullMsgLen / TUNNEL_DATA_MAX_PAYLOAD_SIZE;
				// length of bytes don't fit full tunnel message
				// every follow-on fragment adds 7 bytes
				auto nonFit = (fullMsgLen + numFollowOnFragments*7) % TUNNEL_DATA_MAX_PAYLOAD_SIZE; 
				if (!nonFit || nonFit > m_RemainingSize)
				{
					CompleteCurrentTunnelDataMessage ();
					CreateCurrentTunnelDataMessage ();
				}	
			}	
			if (diLen + 6 <= m_RemainingSize)
			{
				// delivery instructions fit
				uint32_t msgID;
				memcpy (&msgID, msg->GetHeader () + I2NP_HEADER_MSGID_OFFSET, 4); // in network bytes order
				size_t size = m_RemainingSize - diLen - 6; // 6 = 4 (msgID) + 2 (size)

				// first fragment
				di[0] |= 0x08; // fragmented
				htobuf32 (di + diLen, msgID);
				diLen += 4; // Message ID
				htobe16buf (di + diLen, size);
				diLen += 2; // size
				memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len, di, diLen);
				memcpy (m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + diLen, msg->GetBuffer (), size);
				m_CurrentTunnelDataMsg->len += diLen + size;
				CompleteCurrentTunnelDataMessage ();
				// follow on fragments
				int fragmentNumber = 1;
				while (size < msg->GetLength ())
				{	
					CreateCurrentTunnelDataMessage ();
					uint8_t * buf = m_CurrentTunnelDataMsg->GetBuffer ();
					buf[0] = 0x80 | (fragmentNumber << 1); // frag
					bool isLastFragment = false;
					size_t s = msg->GetLength () - size;
					if (s > TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7) // 7 follow on instructions
						s = TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7;	
					else // last fragment
					{	
						buf[0] |= 0x01;
						isLastFragment = true;
					}
					htobuf32 (buf + 1, msgID); //Message ID
					htobe16buf (buf + 5, s); // size
					memcpy (buf + 7, msg->GetBuffer () + size, s);
					m_CurrentTunnelDataMsg->len += s+7;
					if (isLastFragment)
					{
						m_RemainingSize -= s+7; 
						if (!m_RemainingSize)
							CompleteCurrentTunnelDataMessage ();
					}
					else
						CompleteCurrentTunnelDataMessage ();
					size += s;
					fragmentNumber++;
				}
				DeleteI2NPMessage (msg);
			}	
			else
			{
				// delivery instructions don't fit. Create new message
				CompleteCurrentTunnelDataMessage ();
				PutI2NPMsg (block);
				// don't delete msg because it's taken care inside
			}	
		}			
	}
	
	void TunnelGatewayBuffer::ClearTunnelDataMsgs ()
	{
		m_TunnelDataMsgs.clear ();
	}

	void TunnelGatewayBuffer::CreateCurrentTunnelDataMessage ()
	{
		m_CurrentTunnelDataMsg = NewI2NPMessage ();
		m_CurrentTunnelDataMsg->Align (12);
		// we reserve space for padding
		m_CurrentTunnelDataMsg->offset += TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE;
		m_CurrentTunnelDataMsg->len = m_CurrentTunnelDataMsg->offset;
		m_RemainingSize = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
	}	
	
	void TunnelGatewayBuffer::CompleteCurrentTunnelDataMessage ()
	{
		if (!m_CurrentTunnelDataMsg) return;
		uint8_t * payload = m_CurrentTunnelDataMsg->GetBuffer ();
		size_t size = m_CurrentTunnelDataMsg->len - m_CurrentTunnelDataMsg->offset;
		
		m_CurrentTunnelDataMsg->offset = m_CurrentTunnelDataMsg->len - TUNNEL_DATA_MSG_SIZE - I2NP_HEADER_SIZE;
		uint8_t * buf = m_CurrentTunnelDataMsg->GetPayload ();
		htobe32buf (buf, m_TunnelID);
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (buf + 4, 16); // original IV	
		memcpy (payload + size, buf + 4, 16); // copy IV for checksum 
		uint8_t hash[32];
		CryptoPP::SHA256().CalculateDigest (hash, payload, size+16);
		memcpy (buf+20, hash, 4); // checksum		
		payload[-1] = 0; // zero	
		ptrdiff_t paddingSize = payload - buf - 25; // 25  = 24 + 1 
		if (paddingSize > 0)
			memset (buf + 24, 1, paddingSize); // padding TODO: fill with random data

		// we can't fill message header yet because encryption is required
		m_TunnelDataMsgs.push_back (m_CurrentTunnelDataMsg);
		m_CurrentTunnelDataMsg = nullptr;
	}	
	
	void TunnelGateway::SendTunnelDataMsg (const TunnelMessageBlock& block)
	{
		if (block.data)
		{	
			PutTunnelDataMsg (block);
			SendBuffer ();
		}	
	}	

	void TunnelGateway::PutTunnelDataMsg (const TunnelMessageBlock& block)
	{
		if (block.data)
			m_Buffer.PutI2NPMsg (block);
	}	

	void TunnelGateway::SendBuffer ()
	{
		m_Buffer.CompleteCurrentTunnelDataMessage ();
		auto tunnelMsgs = m_Buffer.GetTunnelDataMsgs ();
		for (auto tunnelMsg : tunnelMsgs)
		{	
			m_Tunnel->EncryptTunnelMsg (tunnelMsg);
			FillI2NPMessageHeader (tunnelMsg, eI2NPTunnelData);
			m_NumSentBytes += TUNNEL_DATA_MSG_SIZE;
		}	
		i2p::transport::transports.SendMessages (m_Tunnel->GetNextIdentHash (), tunnelMsgs);
		m_Buffer.ClearTunnelDataMsgs ();
	}	
}		
}	

