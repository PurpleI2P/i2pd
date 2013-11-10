#include <string.h>
#include <endian.h>
#include <cryptopp/gzip.h>
#include <cryptopp/sha.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "ElGamal.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "NetDb.h"
#include "Tunnel.h"
#include "base64.h"
#include "Transports.h"
#include "I2NPProtocol.h"

namespace i2p
{

	I2NPMessage * NewI2NPMessage ()
	{
		I2NPMessage * msg = new I2NPMessage;
		msg->offset = 2; // reserve 2 bytes for NTCP header, should reserve more for SSU in future
		msg->len = sizeof (I2NPHeader) + 2;
		return msg;
	}
	
	void DeleteI2NPMessage (I2NPMessage * msg)
	{
		delete msg;
	}	

	void FillI2NPMessageHeader (I2NPMessage * msg, I2NPMessageType msgType, uint32_t replyMsgID)
	{
		static uint32_t msgID = 0;
		I2NPHeader * header = msg->GetHeader ();
		header->typeID = msgType;
		if (replyMsgID) // for tunnel creation
			header->msgID = htobe32 (replyMsgID); 
		else
		{	
			header->msgID = htobe32 (msgID);
			msgID++;
		}	
		header->expiration = htobe64 (i2p::util::GetMillisecondsSinceEpoch () + 5000); // TODO: 5 secs is a magic number
		int len = msg->GetLength () - sizeof (I2NPHeader);
		header->size = htobe16 (len);
		uint8_t hash[32];
		CryptoPP::SHA256().CalculateDigest(hash, msg->GetPayload (), len);
		header->chks = hash[0];
	}	

	I2NPMessage * CreateI2NPMessage (I2NPMessageType msgType, const uint8_t * buf, int len, uint32_t replyMsgID)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		memcpy (msg->GetPayload (), buf, len);
		msg->len += len;
		FillI2NPMessageHeader (msg, msgType, replyMsgID);
		return msg;
	}	

	I2NPMessage * CreateI2NPMessage (const uint8_t * buf, int len)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		memcpy (msg->GetBuffer (), buf, len);
		msg->len += msg->offset + len;
		return msg;
	}	
	
	I2NPMessage * CreateDeliveryStatusMsg ()
	{
#pragma pack(1)		
		struct
		{
			uint32_t msgID;
			uint64_t timestamp;
		} msg;
#pragma pack ()
		
		msg.msgID = 0;
		msg.timestamp = htobe64 (i2p::util::GetMillisecondsSinceEpoch ());
		return CreateI2NPMessage (eI2NPDeliveryStatus, (uint8_t *)&msg, sizeof (msg));
	}

	I2NPMessage * CreateDatabaseLookupMsg (const uint8_t * key, const uint8_t * from, uint32_t replyTunnelID)
	{
#pragma pack(1)
		struct
		{
			uint8_t key[32];
			uint8_t from[32];
			uint8_t flags;
			uint32_t replyTunnelID;
			uint16_t size;		
		} msg;		
#pragma pack ()	

		memcpy (msg.key, key, 32);
		memcpy (msg.from, from, 32);
		msg.flags = replyTunnelID ? 0x01 : 0;
		msg.replyTunnelID = htobe32 (replyTunnelID);
		msg.size = 0;
		return CreateI2NPMessage (eI2NPDatabaseLookup, (uint8_t *)&msg, sizeof (msg));
	}	

	I2NPMessage * CreateDatabaseStoreMsg ()
	{
		I2NPMessage * m = NewI2NPMessage ();
		I2NPDatabaseStoreMsg * msg = (I2NPDatabaseStoreMsg *)m->GetPayload ();		

		memcpy (msg->key, context.GetRouterInfo ().GetIdentHash (), 32);
		msg->type = 0;
		msg->replyToken = 0;
		msg->size = 0;
		
		CryptoPP::Gzip compressor;
		compressor.Put ((uint8_t *)context.GetRouterInfo ().GetBuffer (), context.GetRouterInfo ().GetBufferLen ());
		compressor.MessageEnd();
		int size = compressor.MaxRetrievable ();
		msg->size = htobe16 (size);
		uint8_t * buf = m->GetPayload () + sizeof (I2NPDatabaseStoreMsg);
		compressor.Get (buf, size); 
		m->len += sizeof (I2NPDatabaseStoreMsg) + size; // payload size
		FillI2NPMessageHeader (m, eI2NPDatabaseStore);
		
		return m;
	}	

	void HandleDatabaseStoreMsg (uint8_t * buf, size_t len)
	{		
		I2NPDatabaseStoreMsg * msg = (I2NPDatabaseStoreMsg *)buf;	
		if (msg->type)
		{
			LogPrint ("LeaseSet");
			i2p::data::netdb.AddLeaseSet (buf + sizeof (I2NPDatabaseStoreMsg)-2, len - sizeof (I2NPDatabaseStoreMsg)+2);
		}	
		else
		{
			LogPrint ("RouterInfo");
			CryptoPP::Gunzip decompressor;
			decompressor.Put (buf + sizeof (I2NPDatabaseStoreMsg), be16toh (msg->size));
			decompressor.MessageEnd();
			uint8_t uncompressed[1024];
			int size = decompressor.MaxRetrievable ();
			decompressor.Get (uncompressed, size);
			i2p::data::netdb.AddRouterInfo (uncompressed, size);
		}	
	}	

	void HandleDatabaseSearchReplyMsg (uint8_t * buf, size_t len)
	{	
#pragma pack(1)
		struct
		{
			uint8_t key[32];
			uint8_t num;
		} * msg;	
#pragma pack()	
		msg = (decltype(msg))buf;
		char key[48];
		int l = i2p::data::ByteStreamToBase64 (msg->key, 32, key, 48);
		key[l] = 0;
		LogPrint ("DatabaseSearchReply for ", key, " num=", (int)msg->num);
		for (int i = 0; i < msg->num; i++)
		{
			char peerHash[48];
			int l1 = i2p::data::ByteStreamToBase64 (buf + sizeof (*msg) +i*32, 32, peerHash, 48);
			peerHash[l1] = 0;
			LogPrint (i,": ", peerHash);	

			i2p::data::netdb.RequestDestination (msg->key, buf + sizeof (*msg) +i*32);
		}	
	}	

	I2NPBuildRequestRecordClearText CreateBuildRequestRecord (
		const uint8_t * ourIdent, uint32_t receiveTunnelID, 
	    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    const uint8_t * layerKey,const uint8_t * ivKey,                                                                 
	    const uint8_t * replyKey, const uint8_t * replyIV, uint32_t nextMessageID,
	          bool isGateway, bool isEndpoint)
	{
		I2NPBuildRequestRecordClearText clearText;	
		clearText.receiveTunnel = htobe32 (receiveTunnelID); 		
		clearText.nextTunnel = htobe32(nextTunnelID);
		memcpy (clearText.layerKey, layerKey, 32);
		memcpy (clearText.ivKey, ivKey, 32);
		memcpy (clearText.replyKey, replyKey, 32);
		memcpy (clearText.replyIV, replyIV, 16);
		clearText.flag = 0;
		if (isGateway) clearText.flag |= 0x80;
		if (isEndpoint) clearText.flag |= 0x40;
		memcpy (clearText.ourIdent, ourIdent, 32);
		memcpy (clearText.nextIdent, nextIdent, 32);
		clearText.requestTime = i2p::util::GetHoursSinceEpoch (); 
		clearText.nextMessageID = htobe32(nextMessageID);
		return clearText;
	}	

	void EncryptBuildRequestRecord (const i2p::data::RouterInfo& router, 
		const I2NPBuildRequestRecordClearText& clearText,
	    I2NPBuildRequestRecordElGamalEncrypted& record)
	{
		i2p::crypto::ElGamalEncrypt (router.GetRouterIdentity ().publicKey, (uint8_t *)&clearText, sizeof(clearText), record.encrypted);
		memcpy (record.toPeer, router.GetIdentHash (), 16);
	}	
	
	void HandleVariableTunnelBuildMsg (uint32_t replyMsgID, uint8_t * buf, size_t len)
	{	
		int num = buf[0];
		LogPrint ("VariableTunnelBuild ", num, " records");

		i2p::tunnel::Tunnel * tunnel =  i2p::tunnel::tunnels.GetPendingTunnel (replyMsgID);
		if (tunnel)
		{
			LogPrint ("VariableTunnelBuild reply for tunnel ", tunnel->GetTunnelID ());
			tunnel->HandleVariableTunnelBuildReplyMsg (buf, len);
		}
		else
		{
			I2NPBuildRequestRecordElGamalEncrypted * records = (I2NPBuildRequestRecordElGamalEncrypted *)(buf+1); 
			for (int i = 0; i < num; i++)
			{	
				if (!memcmp (records[i].toPeer, i2p::context.GetRouterInfo ().GetIdentHash (), 16))
				{	
					LogPrint ("Record ",i," is ours");	
				
					I2NPBuildRequestRecordClearText clearText;	
					i2p::crypto::ElGamalDecrypt (i2p::context.GetPrivateKey (), records[i].encrypted, (uint8_t *)&clearText);

					i2p::tunnel::TransitTunnel * transitTunnel = 
						new i2p::tunnel::TransitTunnel (
						be32toh (clearText.receiveTunnel), 
						clearText.nextIdent, be32toh (clearText.nextTunnel),
					    clearText.layerKey, clearText.ivKey, 
					    clearText.flag & 0x80, clearText.flag & 0x40);
					i2p::tunnel::tunnels.AddTransitTunnel (transitTunnel);
					// replace record to reply
					I2NPBuildResponseRecord * reply = (I2NPBuildResponseRecord *)(records + i);
					reply->ret = 0;
					//TODO: fill filler
					CryptoPP::SHA256().CalculateDigest(reply->hash, reply->padding, sizeof (reply->padding) + 1); // + 1 byte of ret
					// encrypt reply
					CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
					for (int j = 0; j < num; j++)
					{
						encryption.SetKeyWithIV (clearText.replyKey, 32, clearText.replyIV);
						encryption.ProcessData((uint8_t *)(records + j), (uint8_t *)(records + j), sizeof (records[j])); 
					}

					if (clearText.flag & 0x40) // we are endpoint of outboud tunnel
					{
						// so we send it to reply tunnel 
						i2p::transports.SendMessage (clearText.nextIdent, 
							CreateTunnelGatewayMsg (be32toh (clearText.nextTunnel),
								eI2NPVariableTunnelBuildReply, buf, len, 
							    be32toh (clearText.nextMessageID)));                         
					}	
					else	
						i2p::transports.SendMessage (clearText.nextIdent, 
							CreateI2NPMessage (eI2NPVariableTunnelBuild, buf, len, be32toh (clearText.nextMessageID)));
					return;
				}	
			}	
		}	
	}

	void HandleVariableTunnelBuildReplyMsg (uint32_t replyMsgID, uint8_t * buf, size_t len)
	{	
		LogPrint ("VariableTunnelBuildReplyMsg replyMsgID=", replyMsgID);
		i2p::tunnel::Tunnel * tunnel = i2p::tunnel::tunnels.GetPendingTunnel (replyMsgID);
		if (tunnel)
		{	
			tunnel->HandleVariableTunnelBuildReplyMsg (buf, len);
			LogPrint ("Tunnel ", tunnel->GetTunnelID (), " has been created");
		}	
		else
			LogPrint ("Pending tunnel for message ", replyMsgID, " not found");
	}


	I2NPMessage * CreateTunnelDataMsg (const uint8_t * buf)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		memcpy (msg->GetPayload (), buf, 1028);
		msg->len += 1028; 
		FillI2NPMessageHeader (msg, eI2NPTunnelData);
		return msg;
	}	

	I2NPMessage * CreateTunnelDataMsg (uint32_t tunnelID, const uint8_t * payload)	
	{
		I2NPMessage * msg = NewI2NPMessage ();
		memcpy (msg->GetPayload () + 4, payload, 1024);
		*(uint32_t *)(msg->GetPayload ()) = htobe32 (tunnelID);
		msg->len += 1028; 
		FillI2NPMessageHeader (msg, eI2NPTunnelData);
		return msg;
	}	
	
	I2NPMessage * CreateTunnelGatewayMsg (uint32_t tunnelID, const uint8_t * buf, size_t len)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		TunnelGatewayHeader * header = (TunnelGatewayHeader *)msg->GetPayload ();
		header->tunnelID = htobe32 (tunnelID);
		header->length = htobe16 (len);
		memcpy (msg->GetPayload () + sizeof (TunnelGatewayHeader), buf, len);
		msg->len += sizeof (TunnelGatewayHeader) + len;
		FillI2NPMessageHeader (msg, eI2NPTunnelGateway);
		return msg;
	}	

	I2NPMessage * CreateTunnelGatewayMsg (uint32_t tunnelID, I2NPMessage * msg)
	{
		if (msg->offset >= sizeof (I2NPHeader) + sizeof (TunnelGatewayHeader))
		{
			// message is capable to be used without copying
			TunnelGatewayHeader * header = (TunnelGatewayHeader *)(msg->GetBuffer () - sizeof (TunnelGatewayHeader));
			header->tunnelID = htobe32 (tunnelID);
			int len = msg->GetLength ();
			header->length = htobe16 (len);
			msg->offset -= (sizeof (I2NPHeader) + sizeof (TunnelGatewayHeader));
			msg->len = msg->offset + sizeof (I2NPHeader) + sizeof (TunnelGatewayHeader) +len;
			FillI2NPMessageHeader (msg, eI2NPTunnelGateway);
			return msg;
		}
		else
		{	
			I2NPMessage * msg1 = CreateTunnelGatewayMsg (tunnelID, msg->GetBuffer (), msg->GetLength ());
			DeleteI2NPMessage (msg);
			return msg1;
		}	                               
	}

	I2NPMessage * CreateTunnelGatewayMsg (uint32_t tunnelID, I2NPMessageType msgType, 
		const uint8_t * buf, size_t len, uint32_t replyMsgID)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		size_t gatewayMsgOffset = sizeof (I2NPHeader) + sizeof (TunnelGatewayHeader);
		msg->offset += gatewayMsgOffset;
		msg->len += gatewayMsgOffset;
		memcpy (msg->GetPayload (), buf, len);
		msg->len += len;
		FillI2NPMessageHeader (msg, msgType, replyMsgID); // create content message
		len = msg->GetLength ();
		msg->offset -= gatewayMsgOffset;
		TunnelGatewayHeader * header = (TunnelGatewayHeader *)msg->GetPayload ();
		header->tunnelID = htobe32 (tunnelID);
		header->length = htobe16 (len);
		FillI2NPMessageHeader (msg, eI2NPTunnelGateway); // gateway message
		return msg;
	}	
	
	void HandleTunnelGatewayMsg (I2NPMessage * msg)
	{		
		TunnelGatewayHeader * header = (TunnelGatewayHeader *)msg->GetPayload ();
		uint32_t tunnelID = be32toh(header->tunnelID);
		uint16_t len = be16toh(header->length);
		LogPrint ("TunnelGateway of ", (int)len, " bytes for tunnel ", (unsigned int)tunnelID);
		i2p::tunnel::TransitTunnel * tunnel =  i2p::tunnel::tunnels.GetTransitTunnel (tunnelID);
		if (tunnel)
		{	
			// we make payload as new I2NP message to send
			msg->offset += sizeof (I2NPHeader) + sizeof (TunnelGatewayHeader);
			msg->len = msg->offset + len;
			tunnel->SendTunnelDataMsg (nullptr, 0, msg);
		}	
		else
		{	
			LogPrint ("Tunnel ", (unsigned int)tunnelID, " not found");
			i2p::DeleteI2NPMessage (msg);
		}	
	}	
	
	void HandleI2NPMessage (uint8_t * msg, size_t len)
	{
		I2NPHeader * header = (I2NPHeader *)msg;
		uint32_t msgID = be32toh (header->msgID);	
		LogPrint ("I2NP msg received len=", len,", type=", (int)header->typeID, ", msgID=", (unsigned int)msgID);

		uint8_t * buf = msg + sizeof (I2NPHeader);
		int size = be16toh (header->size);
		switch (header->typeID)
		{
			case eI2NPGarlic:
				LogPrint ("Garlic");
			break;	
			case eI2NPDatabaseStore:
				LogPrint ("DatabaseStore");
				HandleDatabaseStoreMsg (buf, size);
			break;	
			case eI2NPDatabaseSearchReply:
				LogPrint ("DatabaseSearchReply");
				HandleDatabaseSearchReplyMsg (buf, size);
			break;	
			case eI2NPDeliveryStatus:
				LogPrint ("DeliveryStatus");
			break;	
			case eI2NPVariableTunnelBuild:
				LogPrint ("VariableTunnelBuild");
				HandleVariableTunnelBuildMsg  (msgID, buf, size);
			break;	
			case eI2NPVariableTunnelBuildReply:
				LogPrint ("VariableTunnelBuildReply");
				HandleVariableTunnelBuildReplyMsg (msgID, buf, size);
			break;		
			default:
				LogPrint ("Unexpected message ", (int)header->typeID);
		}	
	}

	void HandleI2NPMessage (I2NPMessage * msg)
	{
		if (msg)
		{	
			if (msg->GetHeader ()->typeID == eI2NPTunnelData)
			{
				LogPrint ("TunnelData");
				i2p::tunnel::tunnels.PostTunnelData (msg);
			}
			else if (msg->GetHeader ()->typeID == eI2NPTunnelGateway)
			{
				LogPrint ("TunnelGateway");
				HandleTunnelGatewayMsg (msg);
			}	
			else
			{	
				HandleI2NPMessage (msg->GetBuffer (), msg->GetLength ());
				DeleteI2NPMessage (msg);
			}	
		}	
	}	
}
