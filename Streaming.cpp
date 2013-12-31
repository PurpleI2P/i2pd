#include <endian.h>
#include <string>
#include <cryptopp/gzip.h>
#include <cryptopp/dsa.h>
#include "Log.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "CryptoConst.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	Stream::Stream (StreamingDestination * local, const i2p::data::IdentHash& remote):
		m_SendStreamID (0), m_LocalDestination (local)
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
		
	StreamingDestination * sharedLocalDestination = nullptr;	

	StreamingDestination::StreamingDestination ()
	{		
		// TODO: read from file later
		m_Keys = i2p::data::CreateRandomKeys ();
		m_Identity = m_Keys;
		m_IdentHash = i2p::data::CalculateIdentHash (m_Identity);
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

	Stream * StreamingDestination::CreateNewStream (const i2p::data::IdentHash& destination)
	{
		/*i2p::data::LeaseSet * leaseSet = i2p::data::netdb.FindLeaseSet (destination);
		if (!leaseSet)
		{
			i2p::data::netdb.RequestDestination (destination);
			sleep (5); // wait for 5 seconds
			leaseSet = i2p::data::netdb.FindLeaseSet (destination);
			if (!leaseSet)
			{
				LogPrint ("Couldn't find LeaseSet");
				return nullptr;
			}	
		}	*/
		Stream * s = new Stream (this, destination);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
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

		CryptoPP::DSA::PrivateKey signingPrivateKey;
		signingPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));
		CryptoPP::DSA::Signer signer (signingPrivateKey);
		signer.SignMessage (i2p::context.GetRandomNumberGenerator (), buf, size, buf+ size);
		size += 40; // signature

		m->len += size + sizeof (I2NPDatabaseStoreMsg);
		FillI2NPMessageHeader (m, eI2NPDatabaseStore);
		return m;
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
		*(uint16_t *)buf = htobe32 (size); // length
		buf += 4;
		compressor.Get (buf, size);
		buf[9] = 6; // streaming protocol
		msg->len += size + 4; 
		FillI2NPMessageHeader (msg, eI2NPData);
		
		return msg;
	}	
}		
}	
