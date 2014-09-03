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
		if (!m_CurrentTunnelDataMsg)
			CreateCurrentTunnelDataMessage ();

		// create delivery instructions
		uint8_t di[43]; // max delivery instruction length is 43 for tunnel
		size_t diLen = 1;// flag
		if (block.deliveryType != eDeliveryTypeLocal) // tunnel or router
		{	
			if (block.deliveryType == eDeliveryTypeTunnel)
			{
				*(uint32_t *)(di + diLen) = htobe32 (block.tunnelID);
				diLen += 4; // tunnelID
			}
			
			memcpy (di + diLen, block.hash, 32);
			diLen += 32; //len
		}	
		di[0] = block.deliveryType << 5; // set delivery type

		// create fragments
		I2NPMessage * msg = block.data;
		if (diLen + msg->GetLength () + 2<= m_RemainingSize)
		{
			// message fits. First and last fragment
			*(uint16_t *)(di + diLen) = htobe16 (msg->GetLength ());
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
			if (diLen + 6 <= m_RemainingSize)
			{
				// delivery instructions fit
				uint32_t msgID = msg->GetHeader ()->msgID; // in network bytes order
				size_t size = m_RemainingSize - diLen - 6; // 6 = 4 (msgID) + 2 (size)

				// first fragment
				di[0] |= 0x08; // fragmented
				*(uint32_t *)(di + diLen) = msgID;
				diLen += 4; // Message ID
				*(uint16_t *)(di + diLen) = htobe16 (size);
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
					*(uint32_t *)(buf + 1) = msgID; //Message ID
					*(uint16_t *)(buf + 5) = htobe16 (s); // size
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
		// we reserve space for padding
		m_CurrentTunnelDataMsg->offset += TUNNEL_DATA_MSG_SIZE + sizeof (I2NPHeader);
		m_CurrentTunnelDataMsg->len = m_CurrentTunnelDataMsg->offset;
		m_RemainingSize = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
	}	
	
	void TunnelGatewayBuffer::CompleteCurrentTunnelDataMessage ()
	{
		if (!m_CurrentTunnelDataMsg) return;
		uint8_t * payload = m_CurrentTunnelDataMsg->GetBuffer ();
		size_t size = m_CurrentTunnelDataMsg->len - m_CurrentTunnelDataMsg->offset;
		
		m_CurrentTunnelDataMsg->offset = m_CurrentTunnelDataMsg->len - TUNNEL_DATA_MSG_SIZE - sizeof (I2NPHeader);
		uint8_t * buf = m_CurrentTunnelDataMsg->GetPayload ();
		*(uint32_t *)(buf) = htobe32 (m_TunnelID);
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
			i2p::transports.SendMessage (m_Tunnel->GetNextIdentHash (), tunnelMsg);
			m_NumSentBytes += TUNNEL_DATA_MSG_SIZE;
		}	
		m_Buffer.ClearTunnelDataMsgs ();
	}	
}		
}	

