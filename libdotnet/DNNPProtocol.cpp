#include <string.h>
#include <atomic>
#include "Base.h"
#include "Log.h"
#include "Crypto.h"
#include "DotNetEndian.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "NetDb.hpp"
#include "Tunnel.h"
#include "Transports.h"
#include "Garlic.h"
#include "DNNPProtocol.h"
#include "version.h"

using namespace dotnet::transport;

namespace dotnet
{
	std::shared_ptr<DNNPMessage> NewDNNPMessage ()
	{
		return std::make_shared<DNNPMessageBuffer<DNNP_MAX_MESSAGE_SIZE> >();
	}

	std::shared_ptr<DNNPMessage> NewDNNPShortMessage ()
	{
		return std::make_shared<DNNPMessageBuffer<DNNP_MAX_SHORT_MESSAGE_SIZE> >();
	}

	std::shared_ptr<DNNPMessage> NewDNNPTunnelMessage ()
	{
		auto msg = new DNNPMessageBuffer<dotnet::tunnel::TUNNEL_DATA_MSG_SIZE + DNNP_HEADER_SIZE + 34>(); // reserved for alignment and NTCP 16 + 6 + 12
		msg->Align (12);
		return std::shared_ptr<DNNPMessage>(msg);
	}

	std::shared_ptr<DNNPMessage> NewDNNPMessage (size_t len)
	{
		return (len < DNNP_MAX_SHORT_MESSAGE_SIZE - DNNP_HEADER_SIZE - 2) ? NewDNNPShortMessage () : NewDNNPMessage ();
	}

	void DNNPMessage::FillDNNPMessageHeader (DNNPMessageType msgType, uint32_t replyMsgID)
	{
		SetTypeID (msgType);
		if (!replyMsgID) RAND_bytes ((uint8_t *)&replyMsgID, 4);
		SetMsgID (replyMsgID);
		SetExpiration (dotnet::util::GetMillisecondsSinceEpoch () + DNNP_MESSAGE_EXPIRATION_TIMEOUT);
		UpdateSize ();
		UpdateChks ();
	}

	void DNNPMessage::RenewDNNPMessageHeader ()
	{
		uint32_t msgID;
		RAND_bytes ((uint8_t *)&msgID, 4);
		SetMsgID (msgID);
		SetExpiration (dotnet::util::GetMillisecondsSinceEpoch () + DNNP_MESSAGE_EXPIRATION_TIMEOUT);
	}

	bool DNNPMessage::IsExpired () const
	{
		auto ts = dotnet::util::GetMillisecondsSinceEpoch ();
		auto exp = GetExpiration ();
		return (ts > exp + DNNP_MESSAGE_CLOCK_SKEW) || (ts < exp - 3*DNNP_MESSAGE_CLOCK_SKEW); // check if expired or too far in future
	}

	std::shared_ptr<DNNPMessage> CreateDNNPMessage (DNNPMessageType msgType, const uint8_t * buf, size_t len, uint32_t replyMsgID)
	{
		auto msg = NewDNNPMessage (len);
		if (msg->Concat (buf, len) < len)
			LogPrint (eLogError, "DNNP: message length ", len, " exceeds max length ", msg->maxLen);
		msg->FillDNNPMessageHeader (msgType, replyMsgID);
		return msg;
	}

	std::shared_ptr<DNNPMessage> CreateDNNPMessage (const uint8_t * buf, size_t len, std::shared_ptr<dotnet::tunnel::InboundTunnel> from)
	{
		auto msg = NewDNNPMessage ();
		if (msg->offset + len < msg->maxLen)
		{
			memcpy (msg->GetBuffer (), buf, len);
			msg->len = msg->offset + len;
			msg->from = from;
		}
		else
			LogPrint (eLogError, "DNNP: message length ", len, " exceeds max length");
		return msg;
	}

	std::shared_ptr<DNNPMessage> CopyDNNPMessage (std::shared_ptr<DNNPMessage> msg)
	{
		if (!msg) return nullptr;
		auto newMsg = NewDNNPMessage (msg->len);
		newMsg->offset = msg->offset;
		*newMsg = *msg;
		return newMsg;
	}

	std::shared_ptr<DNNPMessage> CreateDeliveryStatusMsg (uint32_t msgID)
	{
		auto m = NewDNNPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		if (msgID)
		{
			htobe32buf (buf + DELIVERY_STATUS_MSGID_OFFSET, msgID);
			htobe64buf (buf + DELIVERY_STATUS_TIMESTAMP_OFFSET, dotnet::util::GetMillisecondsSinceEpoch ());
		}
		else // for SSU establishment
		{
			RAND_bytes ((uint8_t *)&msgID, 4);
			htobe32buf (buf + DELIVERY_STATUS_MSGID_OFFSET, msgID);
			htobe64buf (buf + DELIVERY_STATUS_TIMESTAMP_OFFSET, dotnet::context.GetNetID ());
		}
		m->len += DELIVERY_STATUS_SIZE;
		m->FillDNNPMessageHeader (eDNNPDeliveryStatus);
		return m;
	}

	std::shared_ptr<DNNPMessage> CreateRouterInfoDatabaseLookupMsg (const uint8_t * key, const uint8_t * from,
		uint32_t replyTunnelID, bool exploratory, std::set<dotnet::data::IdentHash> * excludedPeers)
	{
		auto m = excludedPeers ? NewDNNPMessage () : NewDNNPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		memcpy (buf, key, 32); // key
		buf += 32;
		memcpy (buf, from, 32); // from
		buf += 32;
		uint8_t flag = exploratory ? DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP : DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP;
		if (replyTunnelID)
		{
			*buf = flag | DATABASE_LOOKUP_DELIVERY_FLAG; // set delivery flag
			htobe32buf (buf+1, replyTunnelID);
			buf += 5;
		}
		else
		{
			*buf = flag; // flag
			buf++;
		}

		if (excludedPeers)
		{
			int cnt = excludedPeers->size ();
			htobe16buf (buf, cnt);
			buf += 2;
			for (auto& it: *excludedPeers)
			{
				memcpy (buf, it, 32);
				buf += 32;
			}
		}
		else
		{
			// nothing to exclude
			htobuf16 (buf, 0);
			buf += 2;
		}

		m->len += (buf - m->GetPayload ());
		m->FillDNNPMessageHeader (eDNNPDatabaseLookup);
		return m;
	}

	std::shared_ptr<DNNPMessage> CreateLeaseSetDatabaseLookupMsg (const dotnet::data::IdentHash& dest,
		const std::set<dotnet::data::IdentHash>& excludedFloodfills,
		std::shared_ptr<const dotnet::tunnel::InboundTunnel> replyTunnel, const uint8_t * replyKey, const uint8_t * replyTag)
	{
		int cnt = excludedFloodfills.size ();
		auto m = cnt > 0 ? NewDNNPMessage () : NewDNNPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		memcpy (buf, dest, 32); // key
		buf += 32;
		memcpy (buf, replyTunnel->GetNextIdentHash (), 32); // reply tunnel GW
		buf += 32;
		*buf = DATABASE_LOOKUP_DELIVERY_FLAG | DATABASE_LOOKUP_ENCRYPTION_FLAG | DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP; // flags
		buf ++;
		htobe32buf (buf, replyTunnel->GetNextTunnelID ()); // reply tunnel ID
		buf += 4;

		// excluded
		htobe16buf (buf, cnt);
		buf += 2;
		if (cnt > 0)
		{
			for (auto& it: excludedFloodfills)
			{
				memcpy (buf, it, 32);
				buf += 32;
			}
		}
		// encryption
		memcpy (buf, replyKey, 32);
		buf[32] = uint8_t( 1 ); // 1 tag
		memcpy (buf + 33, replyTag, 32);
		buf += 65;

		m->len += (buf - m->GetPayload ());
		m->FillDNNPMessageHeader (eDNNPDatabaseLookup);
		return m;
	}

	std::shared_ptr<DNNPMessage> CreateDatabaseSearchReply (const dotnet::data::IdentHash& ident,
		 std::vector<dotnet::data::IdentHash> routers)
	{
		auto m = NewDNNPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		size_t len = 0;
		memcpy (buf, ident, 32);
		len += 32;
		buf[len] = routers.size ();
		len++;
		for (const auto& it: routers)
		{
			memcpy (buf + len, it, 32);
			len += 32;
		}
		memcpy (buf + len, dotnet::context.GetRouterInfo ().GetIdentHash (), 32);
		len += 32;
		m->len += len;
		m->FillDNNPMessageHeader (eDNNPDatabaseSearchReply);
		return m;
	}

	std::shared_ptr<DNNPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const dotnet::data::RouterInfo> router, uint32_t replyToken)
	{
		if (!router) // we send own RouterInfo
			router = context.GetSharedRouterInfo ();

		auto m = NewDNNPShortMessage ();
		uint8_t * payload = m->GetPayload ();

		memcpy (payload + DATABASE_STORE_KEY_OFFSET, router->GetIdentHash (), 32);
		payload[DATABASE_STORE_TYPE_OFFSET] = 0; // RouterInfo
		htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, replyToken);
		uint8_t * buf = payload + DATABASE_STORE_HEADER_SIZE;
		if (replyToken)
		{
			memset (buf, 0, 4); // zero tunnelID means direct reply
			buf += 4;
			memcpy (buf, router->GetIdentHash (), 32);
			buf += 32;
		}

		uint8_t * sizePtr = buf;
		buf += 2;
		m->len += (buf - payload); // payload size
		dotnet::data::GzipDeflator deflator;
		size_t size = deflator.Deflate (router->GetBuffer (), router->GetBufferLen (), buf, m->maxLen -m->len);
		if (size)
		{
			htobe16buf (sizePtr, size); // size
			m->len += size;
		}
		else
			m = nullptr;
		if (m)
			m->FillDNNPMessageHeader (eDNNPDatabaseStore);
		return m;
	}

	std::shared_ptr<DNNPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const dotnet::data::LeaseSet> leaseSet)
	{
		if (!leaseSet) return nullptr;
		auto m = NewDNNPShortMessage ();
		uint8_t * payload = m->GetPayload ();
		memcpy (payload + DATABASE_STORE_KEY_OFFSET, leaseSet->GetIdentHash (), 32);
		payload[DATABASE_STORE_TYPE_OFFSET] = leaseSet->GetStoreType (); //  1 for LeaseSet
		htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
		size_t size = DATABASE_STORE_HEADER_SIZE;
		memcpy (payload + size, leaseSet->GetBuffer (), leaseSet->GetBufferLen ());
		size += leaseSet->GetBufferLen ();
		m->len += size;
		m->FillDNNPMessageHeader (eDNNPDatabaseStore);
		return m;
	}

	std::shared_ptr<DNNPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const dotnet::data::LocalLeaseSet> leaseSet,  uint32_t replyToken, std::shared_ptr<const dotnet::tunnel::InboundTunnel> replyTunnel)
	{
		if (!leaseSet) return nullptr;
		auto m = NewDNNPShortMessage ();
		uint8_t * payload = m->GetPayload ();
		memcpy (payload + DATABASE_STORE_KEY_OFFSET, leaseSet->GetStoreHash (), 32);
		payload[DATABASE_STORE_TYPE_OFFSET] = leaseSet->GetStoreType (); // LeaseSet or LeaseSet2
		htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, replyToken);
		size_t size = DATABASE_STORE_HEADER_SIZE;
		if (replyToken && replyTunnel)
		{
			if (replyTunnel)
			{
				htobe32buf (payload + size, replyTunnel->GetNextTunnelID ());
				size += 4; // reply tunnelID
				memcpy (payload + size, replyTunnel->GetNextIdentHash (), 32);
				size += 32; // reply tunnel gateway
			}
			else
				htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
		}
		memcpy (payload + size, leaseSet->GetBuffer (), leaseSet->GetBufferLen ());
		size += leaseSet->GetBufferLen ();
		m->len += size;
		m->FillDNNPMessageHeader (eDNNPDatabaseStore);
		return m;
	}

	bool IsRouterInfoMsg (std::shared_ptr<DNNPMessage> msg)
	{
		if (!msg || msg->GetTypeID () != eDNNPDatabaseStore) return false;
		return !msg->GetPayload ()[DATABASE_STORE_TYPE_OFFSET]; // 0- RouterInfo
	}

	static uint16_t g_MaxNumTransitTunnels = DEFAULT_MAX_NUM_TRANSIT_TUNNELS; // TODO:
	void SetMaxNumTransitTunnels (uint16_t maxNumTransitTunnels)
	{
		if (maxNumTransitTunnels > 0 && maxNumTransitTunnels <= 10000 && g_MaxNumTransitTunnels != maxNumTransitTunnels)
		{
			LogPrint (eLogDebug, "DNNP: Max number of  transit tunnels set to ", maxNumTransitTunnels);
			g_MaxNumTransitTunnels = maxNumTransitTunnels;
		}
	}

	bool HandleBuildRequestRecords (int num, uint8_t * records, uint8_t * clearText)
	{
		for (int i = 0; i < num; i++)
		{
			uint8_t * record = records + i*TUNNEL_BUILD_RECORD_SIZE;
			if (!memcmp (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)dotnet::context.GetRouterInfo ().GetIdentHash (), 16))
			{
				LogPrint (eLogDebug, "DNNP: Build request record ", i, " is ours");
				BN_CTX * ctx = BN_CTX_new ();
				dotnet::context.DecryptTunnelBuildRecord (record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, clearText, ctx);
				BN_CTX_free (ctx);
				// replace record to reply
				if (dotnet::context.AcceptsTunnels () &&
					dotnet::tunnel::tunnels.GetTransitTunnels ().size () <= g_MaxNumTransitTunnels &&
					!dotnet::transport::transports.IsBandwidthExceeded () &&
					!dotnet::transport::transports.IsTransitBandwidthExceeded ())
				{
					auto transitTunnel = dotnet::tunnel::CreateTransitTunnel (
							bufbe32toh (clearText + BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET),
							clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						    bufbe32toh (clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							clearText + BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET,
						    clearText + BUILD_REQUEST_RECORD_IV_KEY_OFFSET,
							clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] & 0x80,
						    clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET ] & 0x40);
					dotnet::tunnel::tunnels.AddTransitTunnel (transitTunnel);
					record[BUILD_RESPONSE_RECORD_RET_OFFSET] = 0;
				}
				else
					record[BUILD_RESPONSE_RECORD_RET_OFFSET] = 30; // always reject with bandwidth reason (30)

				//TODO: fill filler
				SHA256 (record + BUILD_RESPONSE_RECORD_PADDING_OFFSET, BUILD_RESPONSE_RECORD_PADDING_SIZE + 1, // + 1 byte of ret
					record + BUILD_RESPONSE_RECORD_HASH_OFFSET);
				// encrypt reply
				dotnet::crypto::CBCEncryption encryption;
				for (int j = 0; j < num; j++)
				{
					encryption.SetKey (clearText + BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET);
					encryption.SetIV (clearText + BUILD_REQUEST_RECORD_REPLY_IV_OFFSET);
					uint8_t * reply = records + j*TUNNEL_BUILD_RECORD_SIZE;
					encryption.Encrypt(reply, TUNNEL_BUILD_RECORD_SIZE, reply);
				}
				return true;
			}
		}
		return false;
	}

	void HandleVariableTunnelBuildMsg (uint32_t replyMsgID, uint8_t * buf, size_t len)
	{
		int num = buf[0];
		LogPrint (eLogDebug, "DNNP: VariableTunnelBuild ", num, " records");
		if (len < num*BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE + 1)
		{
			LogPrint (eLogError, "VaribleTunnelBuild message of ", num, " records is too short ", len);
			return;
		}

		auto tunnel =  dotnet::tunnel::tunnels.GetPendingInboundTunnel (replyMsgID);
		if (tunnel)
		{
			// endpoint of inbound tunnel
			LogPrint (eLogDebug, "DNNP: VariableTunnelBuild reply for tunnel ", tunnel->GetTunnelID ());
			if (tunnel->HandleTunnelBuildResponse (buf, len))
			{
				LogPrint (eLogInfo, "DNNP: Inbound tunnel ", tunnel->GetTunnelID (), " has been created");
				tunnel->SetState (dotnet::tunnel::eTunnelStateEstablished);
				dotnet::tunnel::tunnels.AddInboundTunnel (tunnel);
			}
			else
			{
				LogPrint (eLogInfo, "DNNP: Inbound tunnel ", tunnel->GetTunnelID (), " has been declined");
				tunnel->SetState (dotnet::tunnel::eTunnelStateBuildFailed);
			}
		}
		else
		{
			uint8_t clearText[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
			if (HandleBuildRequestRecords (num, buf + 1, clearText))
			{
				if (clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] & 0x40) // we are endpoint of outboud tunnel
				{
					// so we send it to reply tunnel
					transports.SendMessage (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						CreateTunnelGatewayMsg (bufbe32toh (clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							eDNNPVariableTunnelBuildReply, buf, len,
						    bufbe32toh (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
				}
				else
					transports.SendMessage (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						CreateDNNPMessage (eDNNPVariableTunnelBuild, buf, len,
							bufbe32toh (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
			}
		}
	}

	void HandleTunnelBuildMsg (uint8_t * buf, size_t len)
	{
		if (len < NUM_TUNNEL_BUILD_RECORDS*BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE)
		{
			LogPrint (eLogError, "TunnelBuild message is too short ", len);
			return;
		}
		uint8_t clearText[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
		if (HandleBuildRequestRecords (NUM_TUNNEL_BUILD_RECORDS, buf, clearText))
		{
			if (clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] & 0x40) // we are endpoint of outbound tunnel
			{
				// so we send it to reply tunnel
				transports.SendMessage (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
					CreateTunnelGatewayMsg (bufbe32toh (clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
						eDNNPTunnelBuildReply, buf, len,
					    bufbe32toh (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
			}
			else
				transports.SendMessage (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
					CreateDNNPMessage (eDNNPTunnelBuild, buf, len,
						bufbe32toh (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
		}
	}

	void HandleVariableTunnelBuildReplyMsg (uint32_t replyMsgID, uint8_t * buf, size_t len)
	{
		int num = buf[0];
		LogPrint (eLogDebug, "DNNP: VariableTunnelBuildReplyMsg of ", num, " records replyMsgID=", replyMsgID);
		if (len < num*BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE + 1)
		{
			LogPrint (eLogError, "VaribleTunnelBuildReply message of ", num, " records is too short ", len);
			return;
		}

		auto tunnel = dotnet::tunnel::tunnels.GetPendingOutboundTunnel (replyMsgID);
		if (tunnel)
		{
			// reply for outbound tunnel
			if (tunnel->HandleTunnelBuildResponse (buf, len))
			{
				LogPrint (eLogInfo, "DNNP: Outbound tunnel ", tunnel->GetTunnelID (), " has been created");
				tunnel->SetState (dotnet::tunnel::eTunnelStateEstablished);
				dotnet::tunnel::tunnels.AddOutboundTunnel (tunnel);
			}
			else
			{
				LogPrint (eLogInfo, "DNNP: Outbound tunnel ", tunnel->GetTunnelID (), " has been declined");
				tunnel->SetState (dotnet::tunnel::eTunnelStateBuildFailed);
			}
		}
		else
			LogPrint (eLogWarning, "DNNP: Pending tunnel for message ", replyMsgID, " not found");
	}


	std::shared_ptr<DNNPMessage> CreateTunnelDataMsg (const uint8_t * buf)
	{
		auto msg = NewDNNPTunnelMessage ();
		msg->Concat (buf, dotnet::tunnel::TUNNEL_DATA_MSG_SIZE);
		msg->FillDNNPMessageHeader (eDNNPTunnelData);
		return msg;
	}

	std::shared_ptr<DNNPMessage> CreateTunnelDataMsg (uint32_t tunnelID, const uint8_t * payload)
	{
		auto msg = NewDNNPTunnelMessage ();
		htobe32buf (msg->GetPayload (), tunnelID);
		msg->len += 4; // tunnelID
		msg->Concat (payload, dotnet::tunnel::TUNNEL_DATA_MSG_SIZE - 4);
		msg->FillDNNPMessageHeader (eDNNPTunnelData);
		return msg;
	}

	std::shared_ptr<DNNPMessage> CreateEmptyTunnelDataMsg ()
	{
		auto msg = NewDNNPTunnelMessage ();
		msg->len += dotnet::tunnel::TUNNEL_DATA_MSG_SIZE;
		return msg;
	}

	std::shared_ptr<DNNPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, const uint8_t * buf, size_t len)
	{
		auto msg = NewDNNPMessage (len);
		uint8_t * payload = msg->GetPayload ();
		htobe32buf (payload + TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET, tunnelID);
		htobe16buf (payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET, len);
		msg->len += TUNNEL_GATEWAY_HEADER_SIZE;
		if (msg->Concat (buf, len) < len)
			LogPrint (eLogError, "DNNP: tunnel gateway buffer overflow ", msg->maxLen);
		msg->FillDNNPMessageHeader (eDNNPTunnelGateway);
		return msg;
	}

	std::shared_ptr<DNNPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, std::shared_ptr<DNNPMessage> msg)
	{
		if (msg->offset >= DNNP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE)
		{
			// message is capable to be used without copying
			uint8_t * payload = msg->GetBuffer () - TUNNEL_GATEWAY_HEADER_SIZE;
			htobe32buf (payload + TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET, tunnelID);
			int len = msg->GetLength ();
			htobe16buf (payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET, len);
			msg->offset -= (DNNP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE);
			msg->len = msg->offset + DNNP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE +len;
			msg->FillDNNPMessageHeader (eDNNPTunnelGateway);
			return msg;
		}
		else
			return CreateTunnelGatewayMsg (tunnelID, msg->GetBuffer (), msg->GetLength ());
	}

	std::shared_ptr<DNNPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, DNNPMessageType msgType,
		const uint8_t * buf, size_t len, uint32_t replyMsgID)
	{
		auto msg = NewDNNPMessage (len);
		size_t gatewayMsgOffset = DNNP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE;
		msg->offset += gatewayMsgOffset;
		msg->len += gatewayMsgOffset;
		if (msg->Concat (buf, len) < len)
			LogPrint (eLogError, "DNNP: tunnel gateway buffer overflow ", msg->maxLen);
		msg->FillDNNPMessageHeader (msgType, replyMsgID); // create content message
		len = msg->GetLength ();
		msg->offset -= gatewayMsgOffset;
		uint8_t * payload = msg->GetPayload ();
		htobe32buf (payload + TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET, tunnelID);
		htobe16buf (payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET, len);
		msg->FillDNNPMessageHeader (eDNNPTunnelGateway); // gateway message
		return msg;
	}

	size_t GetDNNPMessageLength (const uint8_t * msg, size_t len)
	{
		if (len < DNNP_HEADER_SIZE_OFFSET + 2)
		{
			LogPrint (eLogError, "DNNP: message length ", len, " is smaller than header");
			return len;
		}
		auto l = bufbe16toh (msg + DNNP_HEADER_SIZE_OFFSET) + DNNP_HEADER_SIZE;
		if (l > len)
		{
			LogPrint (eLogError, "DNNP: message length ", l, " exceeds buffer length ", len);
			l = len;
		}
		return l;
	}

	void HandleDNNPMessage (uint8_t * msg, size_t len)
	{
		if (len < DNNP_HEADER_SIZE)
		{
			LogPrint (eLogError, "DNNP: message length ", len, " is smaller than header");
			return;
		}
		uint8_t typeID = msg[DNNP_HEADER_TYPEID_OFFSET];
		uint32_t msgID = bufbe32toh (msg + DNNP_HEADER_MSGID_OFFSET);
		LogPrint (eLogDebug, "DNNP: msg received len=", len,", type=", (int)typeID, ", msgID=", (unsigned int)msgID);
		uint8_t * buf = msg + DNNP_HEADER_SIZE;
		auto size = bufbe16toh (msg + DNNP_HEADER_SIZE_OFFSET);
		len -= DNNP_HEADER_SIZE;
		if (size > len)
		{
			LogPrint (eLogError, "DNNP: payload size ", size, " exceeds buffer length ", len);
			size = len;
		}
		switch (typeID)
		{
			case eDNNPVariableTunnelBuild:
				HandleVariableTunnelBuildMsg  (msgID, buf, size);
			break;
			case eDNNPVariableTunnelBuildReply:
				HandleVariableTunnelBuildReplyMsg (msgID, buf, size);
			break;
			case eDNNPTunnelBuild:
				HandleTunnelBuildMsg  (buf, size);
			break;
			case eDNNPTunnelBuildReply:
				// TODO:
			break;
			default:
				LogPrint (eLogWarning, "DNNP: Unexpected message ", (int)typeID);
		}
	}

	void HandleDNNPMessage (std::shared_ptr<DNNPMessage> msg)
	{
		if (msg)
		{
			uint8_t typeID = msg->GetTypeID ();
			LogPrint (eLogDebug, "DNNP: Handling message with type ", (int)typeID);
			switch (typeID)
			{
				case eDNNPTunnelData:
					dotnet::tunnel::tunnels.PostTunnelData (msg);
				break;
				case eDNNPTunnelGateway:
					dotnet::tunnel::tunnels.PostTunnelData (msg);
				break;
				case eDNNPGarlic:
				{
					if (msg->from)
					{
						if (msg->from->GetTunnelPool ())
							msg->from->GetTunnelPool ()->ProcessGarlicMessage (msg);
						else
							LogPrint (eLogInfo, "DNNP: Local destination for garlic doesn't exist anymore");
					}
					else
						dotnet::context.ProcessGarlicMessage (msg);
					break;
				}
				case eDNNPDatabaseStore:
				case eDNNPDatabaseSearchReply:
				case eDNNPDatabaseLookup:
					// forward to netDb
					dotnet::data::netdb.PostDNNPMsg (msg);
				break;
				case eDNNPDeliveryStatus:
				{
					if (msg->from && msg->from->GetTunnelPool ())
						msg->from->GetTunnelPool ()->ProcessDeliveryStatus (msg);
					else
						dotnet::context.ProcessDeliveryStatusMessage (msg);
					break;
				}
				case eDNNPVariableTunnelBuild:
				case eDNNPVariableTunnelBuildReply:
				case eDNNPTunnelBuild:
				case eDNNPTunnelBuildReply:
					// forward to tunnel thread
					dotnet::tunnel::tunnels.PostTunnelData (msg);
				break;
				default:
					HandleDNNPMessage (msg->GetBuffer (), msg->GetLength ());
			}
		}
	}

	DNNPMessagesHandler::~DNNPMessagesHandler ()
	{
		Flush ();
	}

	void DNNPMessagesHandler::PutNextMessage (std::shared_ptr<DNNPMessage>  msg)
	{
		if (msg)
		{
			switch (msg->GetTypeID ())
			{
				case eDNNPTunnelData:
					m_TunnelMsgs.push_back (msg);
				break;
				case eDNNPTunnelGateway:
					m_TunnelGatewayMsgs.push_back (msg);
				break;
				default:
					HandleDNNPMessage (msg);
			}
		}
	}

	void DNNPMessagesHandler::Flush ()
	{
		if (!m_TunnelMsgs.empty ())
		{
			dotnet::tunnel::tunnels.PostTunnelData (m_TunnelMsgs);
			m_TunnelMsgs.clear ();
		}
		if (!m_TunnelGatewayMsgs.empty ())
		{
			dotnet::tunnel::tunnels.PostTunnelData (m_TunnelGatewayMsgs);
			m_TunnelGatewayMsgs.clear ();
		}
	}
}
