#include <cryptopp/gzip.h>
#include "Log.h"
#include "Datagram.h"

namespace i2p
{
namespace datagram
{
	void DatagramDestination::HandleDataMessagePayload (const uint8_t * buf, size_t len)
	{
		// unzip it
		CryptoPP::Gunzip decompressor;
		decompressor.Put (buf, len);
		decompressor.MessageEnd();
		uint8_t uncompressed[MAX_DATAGRAM_SIZE];
		auto uncompressedLen = decompressor.MaxRetrievable ();
		if (uncompressedLen <= MAX_DATAGRAM_SIZE)
		{
			decompressor.Get (uncompressed, uncompressedLen);
			//HandleNextPacket (uncompressed); 
		}
		else
			LogPrint ("Received datagram size ", uncompressedLen,  " exceeds max size");

	}

}
}

