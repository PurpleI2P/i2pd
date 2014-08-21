#ifndef BASE64_H
#define BASE64_H

#include <inttypes.h>
#include <string.h>

namespace i2p
{
namespace data
{

	size_t ByteStreamToBase64 (const uint8_t * InBuffer, size_t InCount, char * OutBuffer, size_t len);
	size_t Base64ToByteStream (const char * InBuffer, size_t InCount, uint8_t * OutBuffer, size_t len );
	const char * GetBase64SubstitutionTable ();	
	
	size_t Base32ToByteStream (const char * inBuf, size_t len, uint8_t * outBuf, size_t outLen);
	size_t ByteStreamToBase32 (const uint8_t * InBuf, size_t len, char * outBuf, size_t outLen);
}
}

#endif

