#ifndef I2NP_PROTOCOL_H__
#define I2NP_PROTOCOL_H__

#include <inttypes.h>
#include <vector>
#include <string.h>
#include "RouterInfo.h"

namespace i2p
{
#pragma pack (1)

	struct I2NPHeader
	{
		uint8_t typeID;
		uint32_t msgID;
		uint64_t expiration;
		uint16_t size;
		uint8_t chks;
	};	

	struct I2NPDatabaseStoreMsg
	{
		uint8_t key[32];
		uint8_t type;
		uint32_t replyToken;	
	};

	
	struct I2NPBuildRequestRecordClearText
	{
		uint32_t receiveTunnel;
		uint8_t ourIdent[32];
		uint32_t nextTunnel;
		uint8_t nextIdent[32];
		uint8_t layerKey[32];
		uint8_t ivKey[32];
		uint8_t replyKey[32];
		uint8_t replyIV[16];
		uint8_t flag;
		uint32_t requestTime;
		uint32_t nextMessageID;	
		uint8_t filler[29];
	};

	struct I2NPBuildResponseRecord
	{
		uint8_t hash[32];
		uint8_t padding[495];
		uint8_t ret;
	};	
	
	struct I2NPBuildRequestRecordElGamalEncrypted
	{
		uint8_t toPeer[16];
		uint8_t encrypted[512];
	};

	struct TunnelGatewayHeader
	{
		uint32_t tunnelID;
		uint16_t length;
	};		

	
#pragma pack ()	

	enum I2NPMessageType
	{
		eI2NPDatabaseStore = 1,
		eI2NPDatabaseLookup = 2,
		eI2NPDatabaseSearchReply = 3,
		eI2NPDeliveryStatus = 10,
		eI2NPGarlic = 11,
		eI2NPTunnelData = 18,
		eI2NPTunnelGateway = 19,
		eI2NPData = 20,
		eI2NPVariableTunnelBuild = 23,
		eI2NPVariableTunnelBuildReply = 24	
	};	

	const int NTCP_MAX_MESSAGE_SIZE = 16384; 
	struct I2NPMessage
	{	
		uint8_t buf[NTCP_MAX_MESSAGE_SIZE];	
		size_t len, offset;
		
		I2NPHeader * GetHeader () { return (I2NPHeader *)(buf + offset); };
		uint8_t * GetPayload () { return buf + offset + sizeof(I2NPHeader); };
		uint8_t * GetBuffer () { return buf + offset; };
		size_t GetLength () const { return len - offset; };

		I2NPMessage& operator=(const I2NPMessage& other)
		{
			memcpy (buf + offset, other.buf + other.offset, other.GetLength ());
			len = offset + other.GetLength ();
			return *this;
		}	
	};	
	I2NPMessage * NewI2NPMessage ();
	void DeleteI2NPMessage (I2NPMessage * msg);
	void FillI2NPMessageHeader (I2NPMessage * msg, I2NPMessageType msgType, uint32_t replyMsgID = 0);
	I2NPMessage * CreateI2NPMessage (I2NPMessageType msgType, const uint8_t * buf, int len, uint32_t replyMsgID = 0);	
	I2NPMessage * CreateI2NPMessage (const uint8_t * buf, int len);
	
	I2NPMessage * CreateDeliveryStatusMsg ();
	I2NPMessage * CreateDatabaseLookupMsg (const uint8_t * key, const uint8_t * from, 
		uint32_t replyTunnelID, bool exploratory = false);

	I2NPMessage * CreateDatabaseStoreMsg ();
	
	I2NPBuildRequestRecordClearText CreateBuildRequestRecord (
		const uint8_t * ourIdent, uint32_t receiveTunnelID, 
	    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    const uint8_t * layerKey,const uint8_t * ivKey,                                                                 
	    const uint8_t * replyKey, const uint8_t * replyIV, uint32_t nextMessageID,
	          bool isGateway, bool isEndpoint);
	void EncryptBuildRequestRecord (const i2p::data::RouterInfo& router, 
		const I2NPBuildRequestRecordClearText& clearText,
	    I2NPBuildRequestRecordElGamalEncrypted& record);
		
	void HandleVariableTunnelBuildMsg (uint32_t replyMsgID, uint8_t * buf, size_t len);
	void HandleVariableTunnelBuildReplyMsg (uint32_t replyMsgID, uint8_t * buf, size_t len);
	
	I2NPMessage * CreateTunnelDataMsg (const uint8_t * buf);	
	I2NPMessage * CreateTunnelDataMsg (uint32_t tunnelID, const uint8_t * payload);		
	
	void HandleTunnelGatewayMsg (I2NPMessage * msg);
	I2NPMessage * CreateTunnelGatewayMsg (uint32_t tunnelID, const uint8_t * buf, size_t len);
	I2NPMessage * CreateTunnelGatewayMsg (uint32_t tunnelID, I2NPMessageType msgType, 
		const uint8_t * buf, size_t len, uint32_t replyMsgID = 0);
	I2NPMessage * CreateTunnelGatewayMsg (uint32_t tunnelID, I2NPMessage * msg);

	size_t GetI2NPMessageLength (uint8_t * msg);
	void HandleI2NPMessage (uint8_t * msg, size_t len);
	void HandleI2NPMessage (I2NPMessage * msg);
}	

#endif
