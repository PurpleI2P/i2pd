#include <endian.h>
#include <string>
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
		m_SendStreamID (0), m_SequenceNumber (0), m_LocalDestination (local), m_RemoteLeaseSet (remote)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
	}	

	void Stream::HandleNextPacket (const uint8_t * buf, size_t len)
	{
		const uint8_t * end = buf + len;
		buf += 4; // sendStreamID
		buf += 4; // receiveStreamID
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
		std::string str((const char *)buf, end-buf);
		LogPrint ("Payload: ", str);
	}	

	size_t Stream::Send (uint8_t * buf, size_t len, int timeout)
	{
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
			PACKET_FLAG_FROM_INCLUDED | PACKET_FLAG_SIGNATURE_INCLUDED | PACKET_FLAG_NO_ACK);
		size += 2; // flags
		*(uint16_t *)(packet + size) = htobe16 (sizeof (i2p::data::Identity) + 40); // identity + signature
		size += 2; // options size
		memcpy (packet + size, &m_LocalDestination->GetIdentity (), sizeof (i2p::data::Identity)); 
		size += sizeof (i2p::data::Identity); // from
		uint8_t * signature = packet + size; // set it later
		memset (signature, 0, 40); // zeroes for now
		size += 40; // signature
		memcpy (packet + size, buf, len); 
		size += len; // payload
		m_LocalDestination->Sign (packet, size, signature);
		I2NPMessage * msg = i2p::garlic::routing.WrapSingleMessage (m_RemoteLeaseSet, 
			CreateDataMessage (this, packet, size), m_LocalDestination->CreateLeaseSet ()); 

		auto outbound = i2p::tunnel::tunnels.GetNextOutboundTunnel ();
		if (outbound)
		{
			auto& lease = m_RemoteLeaseSet->GetLeases ()[0]; // TODO:
			outbound->SendTunnelDataMsg (lease.tunnelGateway, lease.tunnelID, msg);
		}	
		else
			DeleteI2NPMessage (msg);
		return len;
	}	
		
	StreamingDestination * sharedLocalDestination = nullptr;	

	StreamingDestination::StreamingDestination ()
	{		
		// TODO: read from file later
		m_Keys = i2p::data::CreateRandomKeys ();
		m_Identity = m_Keys;
		m_IdentHash = i2p::data::CalculateIdentHash (m_Identity);
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));
	}
		
	void StreamingDestination::HandleNextPacket (const uint8_t * buf, size_t len)
	{
		uint32_t sendStreamID = *(uint32_t *)(buf);
		auto it = m_Streams.find (sendStreamID);
		if (it != m_Streams.end ())
			it->second->HandleNextPacket (buf, len);
		else
			LogPrint ("Unknown stream ", sendStreamID);
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
			uint8_t uncompressed[2048];
			int uncompressedSize = decompressor.MaxRetrievable ();
			decompressor.Get (uncompressed, uncompressedSize);
			// then forward to streaming engine
			// TODO: we have onle one destination, might be more
			if (sharedLocalDestination)
				sharedLocalDestination->HandleNextPacket (uncompressed, uncompressedSize);
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
