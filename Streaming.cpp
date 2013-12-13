#include <endian.h>
#include <string>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "RouterInfo.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	void StreamingDestination::HandleNextPacket (const uint8_t * buf, size_t len)
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
			optionalData += sizeof (i2p::data::RouterIdentity);
		}	

		// we have reached payload section
		std::string str((const char *)buf, end-buf);
		LogPrint ("Payload: ", str);
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
			int uncomressedSize = decompressor.MaxRetrievable ();
			decompressor.Get (uncompressed, uncomressedSize);
			// then forward to streaming engine
		}	
		else
			LogPrint ("Data: protocol ", buf[9], " is not supported");
	}	
}		
}	
