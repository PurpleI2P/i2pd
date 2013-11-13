#include <string.h>
#include <endian.h>
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
		block->deliveryInstructionsLen += 2; // size
		// we don't reserve 4 bytes for msgID because we don't if it fits
		block->totalLen = block->deliveryInstructionsLen + msg->GetLength ();
		block->data = msg;
		m_I2NPMsgs.push_back (block);
	}	

	std::vector<I2NPMessage *> TunnelGatewayBuffer::GetTunnelDataMsgs (uint32_t tunnelID) 
	{ 
		std::vector<I2NPMessage *> res;
		int cnt = m_I2NPMsgs.size ();
		m_NextOffset = 0;
		if (cnt > 0)
		{	
			for (auto m: m_I2NPMsgs)
			{
				if (m->totalLen <= 1003)
					res.push_back (CreateNextTunnelMessage (tunnelID, m, m->totalLen));
				else
				{
					res.push_back (CreateNextTunnelMessage (tunnelID, m, 1003));
					size_t remaining = m->data->GetLength () - m_NextOffset; // remaining payload
					remaining += 7; // follow-on header
					res.push_back (CreateNextTunnelMessage (tunnelID, m, remaining)); 
				}	
				delete m;
			}	
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

	I2NPMessage * TunnelGatewayBuffer::CreateNextTunnelMessage (uint32_t tunnelID, 
		TunnelMessageBlockExt * block, size_t size)
	{
		I2NPMessage * tunnelMsg = NewI2NPMessage ();
		uint8_t * buf = tunnelMsg->GetPayload ();
		*(uint32_t *)(buf) = htobe32 (tunnelID);
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (buf + 4, 16); // original IV	
		memcpy (buf + 1028, buf + 4, 16); // copy IV for checksum 	
		size_t zero  = 1028 - size -1;
		buf[zero] = 0; // zero
	
		if (m_NextOffset)
		{	
			size_t s = CreateFollowOnFragment (block, buf + zero + 1, 1003);
			if (s != size)
				LogPrint ("Follow-on fragment size mismatch ", s, "!=", size);
		}	
		else	
			CreateFirstFragment (block, buf + zero + 1, 1003);
			
		uint8_t hash[32];
		CryptoPP::SHA256().CalculateDigest(hash, buf+zero+1, size+16);
		memcpy (buf+20, hash, 4); // checksum
		if (zero > 24)
			memset (buf+24, 1, zero-24); // padding
		tunnelMsg->len += 1028;
		
		// we can't fill message header yet because encryption is required
		return tunnelMsg;
	}	


	void TunnelGateway::SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg)
	{
		m_Buffer.PutI2NPMsg (gwHash, gwTunnel, msg);
		auto tunnelMsgs = m_Buffer.GetTunnelDataMsgs (m_Tunnel->GetNextTunnelID ());
		for (auto tunnelMsg : tunnelMsgs)
		{	
			m_Tunnel->EncryptTunnelMsg (tunnelMsg);
			FillI2NPMessageHeader (tunnelMsg, eI2NPTunnelData);
			i2p::transports.SendMessage (m_Tunnel->GetNextIdentHash (), tunnelMsg);
		}	
	}	
}		
}	

