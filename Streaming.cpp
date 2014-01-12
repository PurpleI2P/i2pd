#include "I2PEndian.h"
#include <string>
#include <algorithm>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "CryptoConst.h"
#include "Garlic.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	Stream::Stream (StreamingDestination * local, const i2p::data::LeaseSet * remote):
		m_SendStreamID (0), m_SequenceNumber (0), m_LastReceivedSequenceNumber (0), m_IsOpen (false),
		m_LocalDestination (local), m_RemoteLeaseSet (remote), m_OutboundTunnel (nullptr)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
	}	

	Stream::~Stream ()
	{
		while (auto packet = m_ReceiveQueue.Get ())
			delete packet;
	}	
		
	void Stream::HandleNextPacket (Packet * packet)
	{
		const uint8_t * end = packet->buf + packet->len, * buf = packet->buf;
		buf += 4; // sendStreamID
		if (!m_SendStreamID)
			m_SendStreamID = be32toh (*(uint32_t *)buf);
		buf += 4; // receiveStreamID	
		m_LastReceivedSequenceNumber = be32toh (*(uint32_t *)buf);
		buf += 4; // sequenceNum
		buf += 4; // ackThrough
		int nackCount = buf[0];
		buf++; // NACK count
		buf += 4*nackCount; // NACKs
		buf++; // resendDelay 
		uint16_t flags = be16toh (*(uint16_t *)buf);
		buf += 2; // flags
		uint16_t optionalSize = be16toh (*(uint16_t *)buf);	
		buf += 2; // optional size
		const uint8_t * optionalData = buf;
		buf += optionalSize;

		// process flags
		if (flags & PACKET_FLAG_SYNCHRONIZE)
		{
			LogPrint ("Synchronize");
		}	
		
		if (flags & PACKET_FLAG_SIGNATURE_INCLUDED)
		{
			LogPrint ("Signature");
			optionalData += 40;
		}	

		if (flags & PACKET_FLAG_FROM_INCLUDED)
		{
			LogPrint ("From identity");
			optionalData += sizeof (i2p::data::Identity);
		}	
		
		// we have reached payload section
		LogPrint ("seqn=",m_LastReceivedSequenceNumber,", flags=", flags); 
		std::string str((const char *)buf, end-buf);
		LogPrint ("Payload: ", str);

		packet->offset = buf - packet->buf;
		m_ReceiveQueue.Put (packet);

		if (flags & PACKET_FLAG_CLOSE)
		{
			LogPrint ("Closed");
			m_IsOpen = false;
		}	
		else
			SendQuickAck ();
	}	

	size_t Stream::Send (uint8_t * buf, size_t len, int timeout)
	{
		if (!m_IsOpen)
			ConnectAndSend (buf, len);
		else
		{
			// TODO: implement
		}	
		return len;
	}	

	void Stream::ConnectAndSend (uint8_t * buf, size_t len)
	{
		m_IsOpen = true;
		uint8_t packet[STREAMING_MTU];
		size_t size = 0;
		*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
		size += 4; // sendStreamID
		*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
		size += 4; // receiveStreamID
		*(uint32_t *)(packet + size) = htobe32 (m_SequenceNumber);
		size += 4; // sequenceNum
		*(uint32_t *)(packet + size) = 0; // TODO
		size += 4; // ack Through
		packet[size] = 0; 
		size++; // NACK count
		size++; // resend delay
		// TODO: for initial packet only, following packets have different falgs
		*(uint16_t *)(packet + size) = htobe16 (PACKET_FLAG_SYNCHRONIZE | 
			PACKET_FLAG_FROM_INCLUDED | PACKET_FLAG_SIGNATURE_INCLUDED | 
		    PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED | PACKET_FLAG_NO_ACK);
		size += 2; // flags
		*(uint16_t *)(packet + size) = htobe16 (sizeof (i2p::data::Identity) + 40 + 2); // identity + signature + packet size
		size += 2; // options size
		memcpy (packet + size, &m_LocalDestination->GetIdentity (), sizeof (i2p::data::Identity)); 
		size += sizeof (i2p::data::Identity); // from
		*(uint16_t *)(packet + size) = htobe16 (STREAMING_MTU);
		size += 2; // max packet size
		uint8_t * signature = packet + size; // set it later
		memset (signature, 0, 40); // zeroes for now
		size += 40; // signature
		
		memcpy (packet + size, buf, len); 
		size += len; // payload
		m_LocalDestination->Sign (packet, size, signature);
		I2NPMessage * msg = i2p::garlic::routing.WrapSingleMessage (m_RemoteLeaseSet, 
			CreateDataMessage (this, packet, size), m_LocalDestination->GetLeaseSet ()); 

		if (!m_OutboundTunnel)
			m_OutboundTunnel = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		if (m_OutboundTunnel)
		{
			auto& lease = m_RemoteLeaseSet->GetLeases ()[0]; // TODO:
			m_OutboundTunnel->SendTunnelDataMsg (lease.tunnelGateway, lease.tunnelID, msg);
		}	
		else
			DeleteI2NPMessage (msg);
	}	
		
	void Stream::SendQuickAck ()
	{
		uint8_t packet[STREAMING_MTU];
		size_t size = 0;
		*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
		size += 4; // sendStreamID
		*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
		size += 4; // receiveStreamID
		*(uint32_t *)(packet + size) = 0; // this is plain Ack message
		size += 4; // sequenceNum
		*(uint32_t *)(packet + size) = htobe32 (m_LastReceivedSequenceNumber);
		size += 4; // ack Through
		packet[size] = 0; 
		size++; // NACK count
		size++; // resend delay
		*(uint16_t *)(packet + size) = 0; // nof flags set
		size += 2; // flags
		*(uint16_t *)(packet + size) = 0; // nof flags set
		size += 2; // options size

		I2NPMessage * msg = i2p::garlic::routing.WrapSingleMessage (m_RemoteLeaseSet, 
			CreateDataMessage (this, packet, size));
		if (m_OutboundTunnel)
		{
			auto& lease = m_RemoteLeaseSet->GetLeases ()[0]; // TODO:
			m_OutboundTunnel->SendTunnelDataMsg (lease.tunnelGateway, lease.tunnelID, msg);
			LogPrint ("Quick Ack sent");
		}	
		else
			DeleteI2NPMessage (msg);
	}	

	void Stream::Close ()
	{
		if (m_IsOpen)
		{	
			m_IsOpen = false;
			uint8_t packet[STREAMING_MTU];
			size_t size = 0;
			*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
			size += 4; // sendStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
			size += 4; // receiveStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_SequenceNumber);
			size += 4; // sequenceNum
			*(uint32_t *)(packet + size) = htobe32 (m_LastReceivedSequenceNumber);
			size += 4; // ack Through
			packet[size] = 0; 
			size++; // NACK count
			size++; // resend delay
			*(uint16_t *)(packet + size) = PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED;
			size += 2; // flags
			*(uint16_t *)(packet + size) = 40; // 40 bytes signature
			size += 2; // options size
			uint8_t * signature = packet + size;
			memset (packet + size, 0, 40);
			size += 40; // signature
			m_LocalDestination->Sign (packet, size, signature);

			I2NPMessage * msg = i2p::garlic::routing.WrapSingleMessage (m_RemoteLeaseSet, 
				CreateDataMessage (this, packet, size));
			if (m_OutboundTunnel)
			{
				auto& lease = m_RemoteLeaseSet->GetLeases ()[0]; // TODO:
				m_OutboundTunnel->SendTunnelDataMsg (lease.tunnelGateway, lease.tunnelID, msg);
				LogPrint ("FIN sent");
			}	
			else
				DeleteI2NPMessage (msg);
		}	
	}
		
	size_t Stream::Receive (uint8_t * buf, size_t len, int timeout)
	{
		if (m_ReceiveQueue.IsEmpty ())
		{
			if (!m_ReceiveQueue.Wait (timeout, 0))
				return 0;
		}

		// either non-empty or we have received empty
		size_t pos = 0;
		while (pos < len)
		{
			Packet * packet = m_ReceiveQueue.Peek ();
			if (packet)
			{
				size_t l = std::min (packet->GetLength (), len - pos);
				memcpy (buf + pos, packet->GetBuffer (), l);
				pos += l;
				packet->offset += l;
				if (!packet->GetLength ())
				{
					m_ReceiveQueue.Get ();
					delete packet;
				}	
			}
			else // no more data available
				break;
		}	
		return pos; 
	}	
		
	StreamingDestination * sharedLocalDestination = nullptr;	

	StreamingDestination::StreamingDestination (): m_LeaseSet (nullptr)
	{		
		// TODO: read from file later
		m_Keys = i2p::data::CreateRandomKeys ();
		m_Identity = m_Keys;
		m_IdentHash = i2p::data::CalculateIdentHash (m_Identity);
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));
	}

	StreamingDestination::~StreamingDestination ()
	{
		if (m_LeaseSet)
			DeleteI2NPMessage (m_LeaseSet);
	}	
		
	void StreamingDestination::HandleNextPacket (Packet * packet)
	{
		uint32_t sendStreamID = be32toh (*(uint32_t *)(packet->buf));
		auto it = m_Streams.find (sendStreamID);
		if (it != m_Streams.end ())
			it->second->HandleNextPacket (packet);
		else
		{	
			LogPrint ("Unknown stream ", sendStreamID);
			delete packet;
		}	
	}	

	Stream * StreamingDestination::CreateNewStream (const i2p::data::LeaseSet * remote)
	{
		Stream * s = new Stream (this, remote);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}	

	void StreamingDestination::DeleteStream (Stream * stream)
	{
		if (stream)
		{
			m_Streams.erase (stream->GetRecvStreamID ());
			delete stream;
		}	
	}	

	I2NPMessage * StreamingDestination::GetLeaseSet ()
	{
		if (m_LeaseSet) // temporary always create new LeaseSet
			DeleteI2NPMessage (m_LeaseSet);
		m_LeaseSet = CreateLeaseSet ();
		
		return m_LeaseSet;
	}	
		
	I2NPMessage * StreamingDestination::CreateLeaseSet () const
	{
		I2NPMessage * m = NewI2NPMessage ();
		I2NPDatabaseStoreMsg * msg = (I2NPDatabaseStoreMsg *)m->GetPayload ();
		memcpy (msg->key, (const uint8_t *)m_IdentHash, 32);
		msg->type = 1; // LeaseSet
		msg->replyToken = 0;
		
		uint8_t * buf = m->GetPayload () + sizeof (I2NPDatabaseStoreMsg);
		size_t size = 0;
		memcpy (buf + size, &m_Identity, sizeof (m_Identity));
		size += sizeof (m_Identity); // destination
		memcpy (buf + size, i2p::context.GetLeaseSetPublicKey (), 256);
		size += 256; // encryption key
		memset (buf + size, 0, 128);
		size += 128; // signing key
		auto tunnel = i2p::tunnel::tunnels.GetNextInboundTunnel ();
		if (tunnel)
		{	
			buf[size] = 1; // 1 lease
			size++; // num
			memcpy (buf + size, (const uint8_t *)tunnel->GetNextIdentHash (), 32);
			size += 32; // tunnel_gw
			*(uint32_t *)(buf + size) = htobe32 (tunnel->GetNextTunnelID ());
			size += 4; // tunnel_id
			uint64_t ts = tunnel->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT;
			ts *= 1000; // in milliseconds
			*(uint64_t *)(buf + size) = htobe64 (ts);
			size += 8; // end_date
		}	
		else
		{
			buf[size] = 0; // zero leases
			size++; // num
		}	
		Sign (buf, size, buf+ size);
		size += 40; // signature

		m->len += size + sizeof (I2NPDatabaseStoreMsg);
		FillI2NPMessageHeader (m, eI2NPDatabaseStore);
		return m;
	}	

	void StreamingDestination::Sign (uint8_t * buf, int len, uint8_t * signature) const
	{
		CryptoPP::DSA::Signer signer (m_SigningPrivateKey);
		signer.SignMessage (i2p::context.GetRandomNumberGenerator (), buf, len, signature);
	}
		
	Stream * CreateStream (const i2p::data::LeaseSet * remote)
	{
		if (!sharedLocalDestination)
			sharedLocalDestination = new StreamingDestination ();
		return sharedLocalDestination->CreateNewStream (remote);
	}
		
	void CloseStream (Stream * stream)
	{
		if (sharedLocalDestination)
			sharedLocalDestination->DeleteStream (stream);
	}	
		
	void HandleDataMessage (i2p::data::IdentHash * destination, const uint8_t * buf, size_t len)
	{
		uint32_t length = be32toh (*(uint32_t *)buf);
		buf += 4;
		// we assume I2CP payload
		if (buf[9] == 6) // streaming protocol
		{	
			// unzip it
			CryptoPP::Gunzip decompressor;
			decompressor.Put (buf, length);
			decompressor.MessageEnd();
			Packet * uncompressed = new Packet;
			uncompressed->offset = 0;
			uncompressed->len = decompressor.MaxRetrievable ();
			if (uncompressed->len > MAX_PACKET_SIZE)
			{
				LogPrint ("Recieved packet size exceeds mac packer size");
				uncompressed->len = MAX_PACKET_SIZE;
			}	
			decompressor.Get (uncompressed->buf, uncompressed->len);
			// then forward to streaming engine
			// TODO: we have onle one destination, might be more
			if (sharedLocalDestination)
				sharedLocalDestination->HandleNextPacket (uncompressed);
		}	
		else
			LogPrint ("Data: protocol ", buf[9], " is not supported");
	}	

	I2NPMessage * CreateDataMessage (Stream * s, uint8_t * payload, size_t len)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		CryptoPP::Gzip compressor;
		compressor.Put (payload, len);
		compressor.MessageEnd();
		int size = compressor.MaxRetrievable ();
		uint8_t * buf = msg->GetPayload ();
		*(uint32_t *)buf = htobe32 (size); // length
		buf += 4;
		compressor.Get (buf, size);
		buf[9] = 6; // streaming protocol
		msg->len += size + 4; 
		FillI2NPMessageHeader (msg, eI2NPData);
		
		return msg;
	}	
}		
}	
