#include <string.h>
#include <endian.h>
#include <cryptopp/sha.h>
#include "RouterContext.h"
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
			block->deliveryInstructionsLen = 32; // hash
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
		// we don't reserve 4 bytes for msgID because we don't if it fits
		block->totalLen = block->deliveryInstructionsLen + msg->GetLength ();
		block->data = msg;
		m_I2NPMsgs.push_back (block);
	}	

	std::vector<I2NPMessage *> TunnelGatewayBuffer::GetTunnelDataMsgs (uint32_t tunnelID) 
	{ 
		std::vector<I2NPMessage *> res;
		int cnt = m_I2NPMsgs.size (), pos = 0, prev = 0;
		m_NextOffset = 0;
		if (cnt > 0)
		{	
			size_t size = 0;
			while (pos < cnt)
			{
				TunnelMessageBlockExt * block = m_I2NPMsgs[pos];
				if (size + block->totalLen >= 1003) // 1003  = 1008 - checksum - zero  
				{
					// we have to make sure if we can put delivery instructions + msgID of last message
					if (size + block->deliveryInstructionsLen + 4 > 1003)
					{	
						// we have to exclude last message
						pos--;
					}
					else
						size = 1003;
					res.push_back (CreateNextTunnelMessage (tunnelID, prev, pos, size));
					prev = pos;
				}
				else
					size += block->totalLen;
				pos++;
			}	
			res.push_back (CreateNextTunnelMessage (tunnelID, prev, pos, size)); // last message
			for (auto m: m_I2NPMsgs)
				delete m;
			m_I2NPMsgs.clear ();
		}
		
		return res; 
	}

	size_t TunnelGatewayBuffer::CreateFirstFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len)
	{
		if (block->deliveryInstructionsLen > len) return 0; // can't put even delivery instructions
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
			if (ret + 4 > len) return 0; // can't put delivery instructions with msgID
			buf[0] |= 0x08; // set fragmented bit
			m_NextMsgID = block->data->GetHeader ()->msgID;
			*(uint32_t *)(buf + ret) = m_NextMsgID;
			ret += 4; // msgID
			m_NextSeqn = 1;
			size -= (block->totalLen - len);
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
		if (fragmentLen >= block->totalLen - m_NextOffset)
		{
			// fragment fits
			fragmentLen = block->totalLen - m_NextOffset;
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

	I2NPMessage * TunnelGatewayBuffer::CreateNextTunnelMessage (uint32_t tunnelID, 
		int from, int to, size_t size)
	{
		I2NPMessage * tunnelMsg = NewI2NPMessage ();
		uint8_t * buf = tunnelMsg->GetPayload ();
		*(uint32_t *)(buf) = htobe32 (tunnelID);
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (buf + 4, 16); // original IV	
		memcpy (buf + 1028, buf + 4, 16); // copy IV for checksum 	
		size_t zero  = 1028 - size;
		buf[zero] = 0; // zero
		buf += zero;
		for (int i = from; i <= to; i++)
		{
			TunnelMessageBlockExt * block = m_I2NPMsgs[i];
			size_t s = CreateFirstFragment (block, buf, size);
			if (s < size)
			{	
				size -= s;
				buf += s;
			}	
			else
				break;
		}	
		uint8_t hash[32];
		CryptoPP::SHA256().CalculateDigest(hash, buf+zero+1, size+16);
		memcpy (buf+20, hash, 4); // checksum
		if (zero > 25)
			memset (buf+24, 1, zero-25); // padding
		
		// we can't fill message header yet because encryption is required
		return tunnelMsg;
	}	
}		
}	

