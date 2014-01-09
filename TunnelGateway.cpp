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
	void TunnelGatewayBuffer::PutI2NPMsg (const uint8_t * gwHash, uint32_t gwTunnel, I2NPMessage * msg)
	{
		TunnelMessageBlockExt * block = new TunnelMessageBlockExt;
		block->deliveryInstructionsLen = 1; // flag
		if (gwHash)
		{	
			block->deliveryInstructionsLen += 32; // hash
			memcpy (block->hash, gwHash, 32);
			if (gwTunnel)
			{	
				block->deliveryType = eDeliveryTypeTunnel;
				block->deliveryInstructionsLen += 4; // tunnelID
				block->tunnelID = gwTunnel;
			}	
			else
				block->deliveryType = eDeliveryTypeRouter;
		}	
		else	
			block->deliveryType = eDeliveryTypeLocal;
		block->deliveryInstructionsLen += 2; // size
		// we don't reserve 4 bytes for msgID yet
		block->totalLen = block->deliveryInstructionsLen + msg->GetLength ();
		block->data = msg;
		m_I2NPMsgs.push_back (block);

		if (!m_Remaining) m_Remaining = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
		if (block->totalLen <= m_Remaining) // message fits
		{
			block->isFragmented = false;
			m_Remaining -= block->totalLen;
		}	
		else // message doesn't fit
		{
			if (block->deliveryInstructionsLen + 4 <= m_Remaining)
			{
				// delivery instructions of first fragment fits
				block->isFragmented = true;
				block->deliveryInstructionsLen += 4;
				block->totalLen += 4;
				m_Remaining = m_Remaining + TUNNEL_DATA_MAX_PAYLOAD_SIZE - block->totalLen - 7; // TODO: handle case if more than two fragments
			}	
			else
			{
				// delivery instructions of first fragment don't fit
				block->isFragmented = false;
				m_Remaining = 0;
			}	
		}	
	}	

	std::vector<I2NPMessage *> TunnelGatewayBuffer::GetTunnelDataMsgs () 
	{ 
		m_Remaining = 0;
		m_NextOffset = 0;
		std::vector<I2NPMessage *> res;
		int cnt = m_I2NPMsgs.size ();
		if (cnt > 0)
		{	
			int ind = 0;
			while (ind < cnt)
			{
				auto tunnelMsg = CreateNextTunnelMessage (ind);
				if (!tunnelMsg) break;
				res.push_back (tunnelMsg);
			}
			for (auto msg: m_I2NPMsgs)
				delete msg;
			m_I2NPMsgs.clear ();
		}	
		
		return res; 
	}

	size_t TunnelGatewayBuffer::CreateFirstFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len)
	{
		size_t ret = 1;
		buf[0] = block->deliveryType << 5; // flag
		if (block->deliveryType == eDeliveryTypeTunnel)
		{
			*(uint32_t *)(buf + ret) = htobe32 (block->tunnelID);
			ret += 4;
		}
		if (block->deliveryType == eDeliveryTypeTunnel || block->deliveryType == eDeliveryTypeRouter)
		{
			memcpy (buf + ret, block->hash, 32);
			ret += 32;
		}	
		size_t size = block->data->GetLength ();
		if (block->totalLen > len) // entire message doesn't fit
		{	
			buf[0] |= 0x08; // set fragmented bit
			m_NextMsgID = block->data->GetHeader ()->msgID;
			*(uint32_t *)(buf + ret) = m_NextMsgID;
			ret += 4; // msgID
			m_NextSeqn = 1;
			size = len - ret - 2; // 2 bytes for size field
			m_NextOffset = size;
		}	
		*(uint16_t *)(buf + ret) = htobe16 (size); // size
		ret += 2;
		memcpy (buf + ret, block->data->GetBuffer (), size);
		ret += size;
		return ret;	
	}	

	size_t TunnelGatewayBuffer::CreateFollowOnFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len)
	{
		int ret = 0;
		buf[0] = 0x80 | (m_NextSeqn << 1);// follow-on flag and seqn
		size_t fragmentLen = len - 7; // 7 bytes of header
		if (fragmentLen >= block->data->GetLength () - m_NextOffset)
		{
			// fragment fits
			fragmentLen = block->data->GetLength () - m_NextOffset;
			buf[0] |= 0x01; // last fragment
		}
		else
			m_NextSeqn++;

		*(uint32_t *)(buf + 1) = m_NextMsgID; // msgID
		*(uint16_t *)(buf + 5) = htobe16 (fragmentLen); // size
		memcpy (buf + 7, block->data->GetBuffer () + m_NextOffset, fragmentLen);

		m_NextOffset += fragmentLen;
		ret += fragmentLen + 7;
		
		return ret;
	}	

	I2NPMessage * TunnelGatewayBuffer::CreateNextTunnelMessage (int& ind)
	{
		int cnt = m_I2NPMsgs.size ();
		if (ind > cnt - 1) return nullptr; // no more messages
		// calculate payload size
		size_t size = 0;
		int i = ind;
		if (m_NextOffset)
		{	
			size = m_I2NPMsgs[i]->data->GetLength () - m_NextOffset + 7; // including follow-on header
			i++;
		}	
		while (i < cnt)
		{	
			auto msg = m_I2NPMsgs[i];
			size += msg->totalLen;
			if (size >= TUNNEL_DATA_MAX_PAYLOAD_SIZE)
			{
				size = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
				break;
			}	
			if (msg->isFragmented) break;
			i++;
		}
		
		I2NPMessage * tunnelMsg = NewI2NPMessage ();
		uint8_t * buf = tunnelMsg->GetPayload ();
		*(uint32_t *)(buf) = htobe32 (m_TunnelID);
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (buf + 4, 16); // original IV	
		memcpy (buf + TUNNEL_DATA_MSG_SIZE, buf + 4, 16); // copy IV for checksum 	
		size_t zero  = TUNNEL_DATA_MSG_SIZE - size -1;
		buf[zero] = 0; // zero
		size_t s = 0;
		while (ind < cnt)
		{
			auto msg = m_I2NPMsgs[ind];
			if (m_NextOffset)	
			{	
				s += CreateFollowOnFragment (msg, buf + zero + 1 + s, size - s);
				m_NextOffset = 0; // TODO:
			}	
			else
			{	
				s += CreateFirstFragment (msg, buf + zero + 1 + s, size - s);
				if (msg->isFragmented) break; // payload is full, but we stay at the same message
			}
			ind++;
			if (s >= size) break; //  payload is full but we moved to next message
		}

		if (s != size)
		{	
			LogPrint ("TunnelData payload size mismatch ", s, "!=", size);
			return nullptr;
		}	
		
		uint8_t hash[32];
		CryptoPP::SHA256().CalculateDigest(hash, buf+zero+1, size+16);
		memcpy (buf+20, hash, 4); // checksum
		if (zero > 24)
			memset (buf+24, 1, zero-24); // padding TODO: fill with random data
		tunnelMsg->len += TUNNEL_DATA_MSG_SIZE;
		// we can't fill message header yet because encryption is required
		return tunnelMsg;
	}	
	
	void TunnelGateway::SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg)
	{
		PutTunnelDataMsg (gwHash, gwTunnel, msg);
		SendBuffer ();
	}	

	void TunnelGateway::PutTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg)
	{
		m_Buffer.PutI2NPMsg (gwHash, gwTunnel, msg);
	}	

	void TunnelGateway::SendBuffer ()
	{
		auto tunnelMsgs = m_Buffer.GetTunnelDataMsgs ();
		for (auto tunnelMsg : tunnelMsgs)
		{	
			m_Tunnel->EncryptTunnelMsg (tunnelMsg);
			FillI2NPMessageHeader (tunnelMsg, eI2NPTunnelData);
			i2p::transports.SendMessage (m_Tunnel->GetNextIdentHash (), tunnelMsg);
			m_NumSentBytes += TUNNEL_DATA_MSG_SIZE;
		}	
	}	
}		
}	

