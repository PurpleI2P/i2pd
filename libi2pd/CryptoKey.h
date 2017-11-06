#ifndef CRYPTO_KEY_H__
#define CRYPTO_KEY_H__

#include <inttypes.h>
#include "Crypto.h"

namespace i2p
{
namespace crypto
{
	void CreateECIESP256RandomKeys (uint8_t * priv, uint8_t * pub);
}
}

#endif

