#ifndef DNNP_PROTOCOL_H__
#define DNNP_PROTOCOL_H__

#include <inttypes.h>
#include <string.h>
#include <set>
#include <memory>
#include "Crypto.h"
#include "DotNetEndian.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "LeaseSet.h"

namespace dotnet
{
	// DNNP header
	const size_t DNNP_HEADER_TYPEID_OFFSET = 0;
	const size_t DNNP_HEADER_MSGID_OFFSET = DNNP_HEADER_TYPEID_OFFSET + 1;
	const size_t DNNP_HEADER_EXPIRATION_OFFSET = DNNP_HEADER_MSGID_OFFSET + 4;
	const size_t DNNP_HEADER_SIZE_OFFSET = DNNP_HEADER_EXPIRATION_OFFSET + 8;
	const size_t DNNP_HEADER_CHKS_OFFSET = DNNP_HEADER_SIZE_OFFSET + 2;
	const size_t DNNP_HEADER_SIZE = DNNP_HEADER_CHKS_OFFSET + 1;

	// DNNP short header
	const size_t DNNP_SHORT_HEADER_TYPEID_OFFSET = 0;
	const size_t DNNP_SHORT_HEADER_EXPIRATION_OFFSET = DNNP_SHORT_HEADER_TYPEID_OFFSET + 1;
	const size_t DNNP_SHORT_HEADER_SIZE = DNNP_SHORT_HEADER_EXPIRATION_OFFSET + 4;

	// DNNP NTCP2 header
	const size_t DNNP_NTCP2_HEADER_SIZE = DNNP_HEADER_EXPIRATION_OFFSET + 4;		

	// Tunnel Gateway header
	const size_t TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET = 0;
	const size_t TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET = TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET + 4;
	const size_t TUNNEL_GATEWAY_HEADER_SIZE = TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET + 2;

	// DeliveryStatus
	const size_t DELIVERY_STATUS_MSGID_OFFSET = 0;
	const size_t DELIVERY_STATUS_TIMESTAMP_OFFSET = DELIVERY_STATUS_MSGID_OFFSET + 4;
	const size_t DELIVERY_STATUS_SIZE = DELIVERY_STATUS_TIMESTAMP_OFFSET + 8;

	// DatabaseStore
	const size_t DATABASE_STORE_KEY_OFFSET = 0;
	const size_t DATABASE_STORE_TYPE_OFFSET = DATABASE_STORE_KEY_OFFSET + 32;
	const size_t DATABASE_STORE_REPLY_TOKEN_OFFSET = DATABASE_STORE_TYPE_OFFSET + 1;
	const size_t DATABASE_STORE_HEADER_SIZE = DATABASE_STORE_REPLY_TOKEN_OFFSET + 4;

	// TunnelBuild
	const size_t TUNNEL_BUILD_RECORD_SIZE = 528;

	//BuildRequestRecordClearText
	const size_t BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET = 0;
	const size_t BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET = BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET + 4;
	const size_t BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET = BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET + 32;
	const size_t BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET = BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET + 4;
	const size_t BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET = BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET + 32;
	const size_t BUILD_REQUEST_RECORD_IV_KEY_OFFSET = BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET + 32;
	const size_t BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET = BUILD_REQUEST_RECORD_IV_KEY_OFFSET + 32;
	const size_t BUILD_REQUEST_RECORD_REPLY_IV_OFFSET = BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET + 32;
	const size_t BUILD_REQUEST_RECORD_FLAG_OFFSET = BUILD_REQUEST_RECORD_REPLY_IV_OFFSET + 16;
	const size_t BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET = BUILD_REQUEST_RECORD_FLAG_OFFSET + 1;
	const size_t BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET = BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET + 4;
	const size_t BUILD_REQUEST_RECORD_PADDING_OFFSET = BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET + 4;
	const size_t BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE = 222;

	// BuildRequestRecordEncrypted
	const size_t BUILD_REQUEST_RECORD_TO_PEER_OFFSET = 0;
	const size_t BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET = BUILD_REQUEST_RECORD_TO_PEER_OFFSET + 16;

	// BuildResponseRecord
	const size_t BUILD_RESPONSE_RECORD_HASH_OFFSET = 0;
	const size_t BUILD_RESPONSE_RECORD_PADDING_OFFSET = 32;
	const size_t BUILD_RESPONSE_RECORD_PADDING_SIZE = 495;
	const size_t BUILD_RESPONSE_RECORD_RET_OFFSET = BUILD_RESPONSE_RECORD_PADDING_OFFSET + BUILD_RESPONSE_RECORD_PADDING_SIZE;

	enum DNNPMessageType
	{
		eDNNPDummyMsg = 0,	
		eDNNPDatabaseStore = 1,
		eDNNPDatabaseLookup = 2,
		eDNNPDatabaseSearchReply = 3,
		eDNNPDeliveryStatus = 10,
		eDNNPGarlic = 11,
		eDNNPTunnelData = 18,
		eDNNPTunnelGateway = 19,
		eDNNPData = 20,
		eDNNPTunnelBuild = 21,
		eDNNPTunnelBuildReply = 22,
		eDNNPVariableTunnelBuild = 23,
		eDNNPVariableTunnelBuildReply = 24
	};

	const int NUM_TUNNEL_BUILD_RECORDS = 8;

	// DatabaseLookup flags
	const uint8_t DATABASE_LOOKUP_DELIVERY_FLAG = 0x01;
	const uint8_t DATABASE_LOOKUP_ENCRYPTION_FLAG = 0x02;
	const uint8_t DATABASE_LOOKUP_TYPE_FLAGS_MASK = 0x0C;
	const uint8_t DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP = 0;
	const uint8_t DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP = 0x04; // 0100
	const uint8_t DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP = 0x08; // 1000
	const uint8_t DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP = 0x0C; // 1100

namespace tunnel
{
	class InboundTunnel;
	class TunnelPool;
}

	const size_t DNNP_MAX_MESSAGE_SIZE = 62708;
	const size_t DNNP_MAX_SHORT_MESSAGE_SIZE = 4096;
	const unsigned int DNNP_MESSAGE_EXPIRATION_TIMEOUT = 8000; // in milliseconds (as initial RTT)
	const unsigned int DNNP_MESSAGE_CLOCK_SKEW = 60*1000; // 1 minute in milliseconds

	struct DNNPMessage
	{
		uint8_t * buf;
		size_t len, offset, maxLen;
		std::shared_ptr<dotnet::tunnel::InboundTunnel> from;

		DNNPMessage (): buf (nullptr),len (DNNP_HEADER_SIZE + 2),
			offset(2), maxLen (0), from (nullptr) {};  // reserve 2 bytes for NTCP header

		// header accessors
		uint8_t * GetHeader () { return GetBuffer (); };
		const uint8_t * GetHeader () const { return GetBuffer (); };
		void SetTypeID (uint8_t typeID) { GetHeader ()[DNNP_HEADER_TYPEID_OFFSET] = typeID; };
		uint8_t GetTypeID () const { return GetHeader ()[DNNP_HEADER_TYPEID_OFFSET]; };
		void SetMsgID (uint32_t msgID) { htobe32buf (GetHeader () + DNNP_HEADER_MSGID_OFFSET, msgID); };
		uint32_t GetMsgID () const { return bufbe32toh (GetHeader () + DNNP_HEADER_MSGID_OFFSET); };
		void SetExpiration (uint64_t expiration) { htobe64buf (GetHeader () + DNNP_HEADER_EXPIRATION_OFFSET, expiration); };
		uint64_t GetExpiration () const { return bufbe64toh (GetHeader () + DNNP_HEADER_EXPIRATION_OFFSET); };
		void SetSize (uint16_t size) { htobe16buf (GetHeader () + DNNP_HEADER_SIZE_OFFSET, size); };
		uint16_t GetSize () const { return bufbe16toh (GetHeader () + DNNP_HEADER_SIZE_OFFSET); };
		void UpdateSize () { SetSize (GetPayloadLength ()); };
		void SetChks (uint8_t chks) { GetHeader ()[DNNP_HEADER_CHKS_OFFSET] = chks; };
		void UpdateChks ()
		{
			uint8_t hash[32];
			SHA256(GetPayload (), GetPayloadLength (), hash);
			GetHeader ()[DNNP_HEADER_CHKS_OFFSET] = hash[0];
		}

		// payload
		uint8_t * GetPayload () { return GetBuffer () + DNNP_HEADER_SIZE; };
		const uint8_t * GetPayload () const { return GetBuffer () + DNNP_HEADER_SIZE; };
		uint8_t * GetBuffer () { return buf + offset; };
		const uint8_t * GetBuffer () const { return buf + offset; };
		size_t GetLength () const { return len - offset; };
		size_t GetPayloadLength () const { return GetLength () - DNNP_HEADER_SIZE; };

		void Align (size_t alignment)
		{
			if (len + alignment > maxLen) return;
			size_t rem = ((size_t)GetBuffer ()) % alignment;
			if (rem)
			{
				offset += (alignment - rem);
				len += (alignment - rem);
			}
		}

		size_t Concat (const uint8_t * buf1, size_t len1)
		{
			// make sure with don't write beyond maxLen
			if (len + len1 > maxLen) len1 = maxLen - len;
			memcpy (buf + len, buf1, len1);
			len += len1;
			return len1;
		}

		DNNPMessage& operator=(const DNNPMessage& other)
		{
			memcpy (buf + offset, other.buf + other.offset, other.GetLength ());
			len = offset + other.GetLength ();
			from = other.from;
			return *this;
		}

		// for SSU only
		uint8_t * GetSSUHeader () { return buf + offset + DNNP_HEADER_SIZE - DNNP_SHORT_HEADER_SIZE; };
		void FromSSU (uint32_t msgID) // we have received SSU message and convert it to regular
		{
			const uint8_t * ssu = GetSSUHeader ();
			GetHeader ()[DNNP_HEADER_TYPEID_OFFSET] = ssu[DNNP_SHORT_HEADER_TYPEID_OFFSET]; // typeid
			SetMsgID (msgID);
			SetExpiration (bufbe32toh (ssu + DNNP_SHORT_HEADER_EXPIRATION_OFFSET)*1000LL);
			SetSize (len - offset - DNNP_HEADER_SIZE);
			SetChks (0);
		}
		uint32_t ToSSU () // return msgID
		{
			uint8_t header[DNNP_HEADER_SIZE];
			memcpy (header, GetHeader (), DNNP_HEADER_SIZE);
			uint8_t * ssu = GetSSUHeader ();
			ssu[DNNP_SHORT_HEADER_TYPEID_OFFSET] = header[DNNP_HEADER_TYPEID_OFFSET]; // typeid
			htobe32buf (ssu + DNNP_SHORT_HEADER_EXPIRATION_OFFSET, bufbe64toh (header + DNNP_HEADER_EXPIRATION_OFFSET)/1000LL);
			len = offset + DNNP_SHORT_HEADER_SIZE + bufbe16toh (header + DNNP_HEADER_SIZE_OFFSET);
			return bufbe32toh (header + DNNP_HEADER_MSGID_OFFSET);
		}
		// for NTCP2 only
		uint8_t * GetNTCP2Header () { return GetPayload () - DNNP_NTCP2_HEADER_SIZE; };
		size_t GetNTCP2Length () const { return GetPayloadLength () + DNNP_NTCP2_HEADER_SIZE; };
		void FromNTCP2 ()
		{
			const uint8_t * ntcp2 = GetNTCP2Header ();
			memcpy (GetHeader () + DNNP_HEADER_TYPEID_OFFSET, ntcp2 + DNNP_HEADER_TYPEID_OFFSET, 5); // typeid + msgid
			SetExpiration (bufbe32toh (ntcp2 + DNNP_HEADER_EXPIRATION_OFFSET)*1000LL);
			SetSize (len - offset - DNNP_HEADER_SIZE);
			SetChks (0);
		}	

		void ToNTCP2 ()
		{
			uint8_t * ntcp2 = GetNTCP2Header ();
			htobe32buf (ntcp2 + DNNP_HEADER_EXPIRATION_OFFSET, bufbe64toh (GetHeader () + DNNP_HEADER_EXPIRATION_OFFSET)/1000LL);
			memcpy (ntcp2 + DNNP_HEADER_TYPEID_OFFSET, GetHeader () + DNNP_HEADER_TYPEID_OFFSET, 5); // typeid + msgid
		}

		void FillDNNPMessageHeader (DNNPMessageType msgType, uint32_t replyMsgID = 0);
		void RenewDNNPMessageHeader ();
		bool IsExpired () const;
	};

	template<int sz>
	struct DNNPMessageBuffer: public DNNPMessage
	{
		DNNPMessageBuffer () { buf = m_Buffer; maxLen = sz; };
		uint8_t m_Buffer[sz + 32]; // 16 alignment + 16 padding
	};

	std::shared_ptr<DNNPMessage> NewDNNPMessage ();
	std::shared_ptr<DNNPMessage> NewDNNPShortMessage ();
	std::shared_ptr<DNNPMessage> NewDNNPTunnelMessage ();
	std::shared_ptr<DNNPMessage> NewDNNPMessage (size_t len);

	std::shared_ptr<DNNPMessage> CreateDNNPMessage (DNNPMessageType msgType, const uint8_t * buf, size_t len, uint32_t replyMsgID = 0);
	std::shared_ptr<DNNPMessage> CreateDNNPMessage (const uint8_t * buf, size_t len, std::shared_ptr<dotnet::tunnel::InboundTunnel> from = nullptr);
	std::shared_ptr<DNNPMessage> CopyDNNPMessage (std::shared_ptr<DNNPMessage> msg);

	std::shared_ptr<DNNPMessage> CreateDeliveryStatusMsg (uint32_t msgID);
	std::shared_ptr<DNNPMessage> CreateRouterInfoDatabaseLookupMsg (const uint8_t * key, const uint8_t * from,
		uint32_t replyTunnelID, bool exploratory = false, std::set<dotnet::data::IdentHash> * excludedPeers = nullptr);
	std::shared_ptr<DNNPMessage> CreateLeaseSetDatabaseLookupMsg (const dotnet::data::IdentHash& dest,
		const std::set<dotnet::data::IdentHash>& excludedFloodfills,
		std::shared_ptr<const dotnet::tunnel::InboundTunnel> replyTunnel, const uint8_t * replyKey, const uint8_t * replyTag);
	std::shared_ptr<DNNPMessage> CreateDatabaseSearchReply (const dotnet::data::IdentHash& ident, std::vector<dotnet::data::IdentHash> routers);

	std::shared_ptr<DNNPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const dotnet::data::RouterInfo> router = nullptr, uint32_t replyToken = 0);
	std::shared_ptr<DNNPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const dotnet::data::LeaseSet> leaseSet); // for floodfill only
	std::shared_ptr<DNNPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const dotnet::data::LocalLeaseSet> leaseSet, uint32_t replyToken = 0, std::shared_ptr<const dotnet::tunnel::InboundTunnel> replyTunnel = nullptr);
	bool IsRouterInfoMsg (std::shared_ptr<DNNPMessage> msg);

	bool HandleBuildRequestRecords (int num, uint8_t * records, uint8_t * clearText);
	void HandleVariableTunnelBuildMsg (uint32_t replyMsgID, uint8_t * buf, size_t len);
	void HandleVariableTunnelBuildReplyMsg (uint32_t replyMsgID, uint8_t * buf, size_t len);
	void HandleTunnelBuildMsg (uint8_t * buf, size_t len);

	std::shared_ptr<DNNPMessage> CreateTunnelDataMsg (const uint8_t * buf);
	std::shared_ptr<DNNPMessage> CreateTunnelDataMsg (uint32_t tunnelID, const uint8_t * payload);
	std::shared_ptr<DNNPMessage> CreateEmptyTunnelDataMsg ();

	std::shared_ptr<DNNPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, const uint8_t * buf, size_t len);
	std::shared_ptr<DNNPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, DNNPMessageType msgType,
		const uint8_t * buf, size_t len, uint32_t replyMsgID = 0);
	std::shared_ptr<DNNPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, std::shared_ptr<DNNPMessage> msg);

	size_t GetDNNPMessageLength (const uint8_t * msg, size_t len);
	void HandleDNNPMessage (uint8_t * msg, size_t len);
	void HandleDNNPMessage (std::shared_ptr<DNNPMessage> msg);

	class DNNPMessagesHandler
	{
		public:

			~DNNPMessagesHandler ();
			void PutNextMessage (std::shared_ptr<DNNPMessage> msg);
			void Flush ();

		private:

			std::vector<std::shared_ptr<DNNPMessage> > m_TunnelMsgs, m_TunnelGatewayMsgs;
	};

	const uint16_t DEFAULT_MAX_NUM_TRANSIT_TUNNELS = 2500;
	void SetMaxNumTransitTunnels (uint16_t maxNumTransitTunnels);
}

#endif
