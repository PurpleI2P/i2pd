#ifndef GARLIC_H__
#define GARLIC_H__

#include <inttypes.h>
#include "I2NPProtocol.h"

namespace i2p
{
	enum GarlicDeliveryType 
	{ 
		eGarlicDeliveryTypeLocal = 0, 
		eGarlicDeliveryTypeDestination = 1,
		eGarlicDeliveryTypeRouter = 2,	
		eGarlicDeliveryTypeTunnel = 3
	};	

#pragma pack(1)
	struct ElGamalBlock
	{
		uint8_t sessionKey[32];
		uint8_t preIV[32];
		uint8_t padding[158];
	};		
#pragma pack()	
	
	I2NPMessage * WrapI2NPMessage (const uint8_t * encryptionKey, I2NPMessage * msg);
	size_t CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg);
}	

#endif
