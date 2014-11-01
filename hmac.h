#ifndef HMAC_H__
#define HMAC_H__

#include <inttypes.h>
#include <string.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include "Identity.h"

namespace i2p
{
namespace crypto
{
	const uint64_t IPAD = 0x3636363636363636;
	const uint64_t OPAD = 0x5C5C5C5C5C5C5C5C; 			

	typedef i2p::data::Tag<32> MACKey;
		
	inline void HMACMD5Digest (uint8_t * msg, size_t len, const MACKey& key, uint8_t * digest)
	// key is 32 bytes
	// digest is 16 bytes
	// block size is 64 bytes	
	{
		uint64_t buf[256];
		// ikeypad
		buf[0] = key.GetLL ()[0] ^ IPAD; 
		buf[1] = key.GetLL ()[1] ^ IPAD; 
		buf[2] = key.GetLL ()[2] ^ IPAD; 
		buf[3] = key.GetLL ()[3] ^ IPAD; 
		buf[4] = IPAD; 
		buf[5] = IPAD; 
		buf[6] = IPAD; 
		buf[7] = IPAD; 		
		// concatenate with msg
		memcpy (buf + 8, msg, len);
		// calculate first hash
		uint8_t hash[16]; // MD5
		CryptoPP::Weak1::MD5().CalculateDigest (hash, (uint8_t *)buf, len + 64);
		
		// okeypad			
		buf[0] = key.GetLL ()[0] ^ OPAD; 
		buf[1] = key.GetLL ()[1] ^ OPAD; 
		buf[2] = key.GetLL ()[2] ^ OPAD; 
		buf[3] = key.GetLL ()[3] ^ OPAD; 
		buf[4] = OPAD; 
		buf[5] = OPAD; 
		buf[6] = OPAD; 
		buf[7] = OPAD; 
		// copy first hash after okeypad		
		memcpy (buf + 8, hash, 16);
		// fill next 16 bytes with zeros (first hash size assumed 32 bytes in I2P)
		memset (buf + 10, 0, 16);			
		
		// calculate digest
		CryptoPP::Weak1::MD5().CalculateDigest (digest, (uint8_t *)buf, 96);
	}
}
}

#endif

