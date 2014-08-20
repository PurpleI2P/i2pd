#ifndef I2NP_PROTOCOL_H__
#define I2NP_PROTOCOL_H__

#include <inttypes.h>
#include <set>
#include <string.h>
#include "I2PEndian.h"
#include "RouterInfo.h"
#include "LeaseSet.h"

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

	struct I2NPHeaderShort
	{
		uint8_t typeID;
		uint32_t shortExpiration;
	};	

	struct I2NPDatabaseStoreMsg
	{
		uint8_t key[32];
		uint8_t type;
		uint32_t replyToken;	
	};

	struct I2NPDeliveryStatusMsg
	{
		uint32_t msgID;
		uint64_t timestamp;
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
		eI2NPTunnelBuild = 21,
		eI2NPTunnelBuildReply = 22,
		eI2NPVariableTunnelBuild = 23,
		eI2NPVariableTunnelBuildReply = 24	
	};	

	const int NUM_TUNNEL_BUILD_RECORDS = 8;	

namespace tunnel
{		
	class InboundTunnel;
}

	const size_t I2NP_MAX_MESSAGE_SIZE = 32768; 
	const size_t I2NP_MAX_SHORT_MESSAGE_SIZE = 2400; 
	struct I2NPMessage
	{	
		uint8_t * buf;	
		size_t len, offset, maxLen;
		i2p::tunnel::InboundTunnel * from;
		
		I2NPMessage (): buf (nullptr),len (sizeof (I2NPHeader) + 2), 
			offset(2), maxLen (0), from (nullptr) {}; 
		// reserve 2 bytes for NTCP header
		I2NPHeader * GetHeader () { return (I2NPHeader *)GetBuffer (); };
		uint8_t * GetPayload () { return GetBuffer () + sizeof(I2NPHeader); };
		uint8_t * GetBuffer () { return buf + offset; };
		const uint8_t * GetBuffer () const { return buf + offset; };
		size_t GetLength () const { return len - offset; };

		I2NPMessage& operator=(const I2NPMessage& other)
		{
			memcpy (buf + offset, other.buf + other.offset, other.GetLength ());
			len = offset + other.GetLength ();
			from = other.from;
			return *this;
		}	

		// for SSU only
		uint8_t * GetSSUHeader () { return buf + offset + sizeof(I2NPHeader) - sizeof(I2NPHeaderShort); };	
		void FromSSU (uint32_t msgID) // we have received SSU message and convert it to regular
		{
			I2NPHeaderShort ssu = *(I2NPHeaderShort *)GetSSUHeader ();
			I2NPHeader * header = GetHeader ();
			header->typeID = ssu.typeID;
			header->msgID = htobe32 (msgID);
			header->expiration = htobe64 (be32toh (ssu.shortExpiration)*1000LL);
			header->size = htobe16 (len - offset - sizeof (I2NPHeader));
			header->chks = 0;
		}
		uint32_t ToSSU () // return msgID
		{
			I2NPHeader header = *GetHeader ();
			I2NPHeaderShort * ssu = (I2NPHeaderShort *)GetSSUHeader ();
			ssu->typeID = header.typeID;
			ssu->shortExpiration = htobe32 (be64toh (header.expiration)/1000LL); 
			len = offset + sizeof (I2NPHeaderShort) + be16toh (header.size);
			return be32toh (header.msgID);
		}	
	};	

	template<int sz>
	struct I2NPMessageBuffer: public I2NPMessage
	{
		I2NPMessageBuffer () { buf = m_Buffer; maxLen = sz; };
		uint8_t m_Buffer[sz];
	};

	I2NPMessage * NewI2NPMessage ();
	I2NPMessage * NewI2NPShortMessage ();
	I2NPMessage * NewI2NPMessage (size_t len);
	void DeleteI2NPMessage (I2NPMessage * msg);
	void FillI2NPMessageHeader (I2NPMessage * msg, I2NPMessageType msgType, uint32_t replyMsgID = 0);
	void RenewI2NPMessageHeader (I2NPMessage * msg);
	I2NPMessage * CreateI2NPMessage (I2NPMessageType msgType, const uint8_t * buf, int len, uint32_t replyMsgID = 0);	
	I2NPMessage * CreateI2NPMessage (const uint8_t * buf, int len);
	
	I2NPMessage * CreateDeliveryStatusMsg (uint32_t msgID);
	I2NPMessage * CreateDatabaseLookupMsg (const uint8_t * key, const uint8_t * from, 
		uint32_t replyTunnelID, bool exploratory = false, 
	    std::set<i2p::data::IdentHash> * excludedPeers = nullptr, bool encryption = false);
	I2NPMessage * CreateDatabaseSearchReply (const i2p::data::IdentHash& ident, const i2p::data::RouterInfo * floodfill);
	
	I2NPMessage * CreateDatabaseStoreMsg (const i2p::data::RouterInfo * router = nullptr);
	I2NPMessage * CreateDatabaseStoreMsg (const i2p::data::LeaseSet * leaseSet, uint32_t replyToken = 0);		

	I2NPBuildRequestRecordClearText CreateBuildRequestRecord (
		const uint8_t * ourIdent, uint32_t receiveTunnelID, 
	    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    const uint8_t * layerKey,const uint8_t * ivKey,                                                                 
	    const uint8_t * replyKey, const uint8_t * replyIV, uint32_t nextMessageID,
	          bool isGateway, bool isEndpoint);
	void EncryptBuildRequestRecord (const i2p::data::RouterInfo& router, 
		const I2NPBuildRequestRecordClearText& clearText,
	    I2NPBuildRequestRecordElGamalEncrypted& record);
	
	bool HandleBuildRequestRecords (int num, I2NPBuildRequestRecordElGamalEncrypted * records, I2NPBuildRequestRecordClearText& clearText);
	void HandleVariableTunnelBuildMsg (uint32_t replyMsgID, uint8_t * buf, size_t len);
	void HandleVariableTunnelBuildReplyMsg (uint32_t replyMsgID, uint8_t * buf, size_t len);
	void HandleTunnelBuildMsg (uint8_t * buf, size_t len);	

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
