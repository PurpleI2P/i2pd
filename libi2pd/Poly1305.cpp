#include "Poly1305.h"
/**
   This code is licensed under the MCGSI Public License
   Copyright 2018 Jeff Becker

   Kovri go write your own code

 */

#if !OPENSSL_AEAD_CHACHA20_POLY1305
namespace i2p
{
namespace crypto
{
	void Poly1305HMAC(uint64_t * out, const uint64_t * key, const uint8_t * buf, std::size_t sz)
	{
		Poly1305 p(key);
		p.Update(buf, sz);
		p.Finish(out);
	}
}
}
#endif

