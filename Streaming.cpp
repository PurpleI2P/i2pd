#include <endian.h>
#include <string>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	Stream::Stream (const i2p::data::IdentHash& destination):
		m_SendStreamID (0)
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
		
	StreamingDestination m_SharedLocalDestination;	
	
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
		Stream * s = new Stream (destination);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
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
			m_SharedLocalDestination.HandleNextPacket (uncompressed, uncompressedSize);
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
