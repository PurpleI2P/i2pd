#ifndef TUNNEL_BASE_H__
#define TUNNEL_BASE_H__

#include <inttypes.h>

namespace i2p
{
namespace tunnel
{
	enum TunnelDeliveryType 
	{ 
		eDeliveryTypeLocal = 0, 
		eDeliveryTypeTunnel = 1,
		eDeliveryTypeRouter = 2
	};		
	struct TunnelMessageBlock
	{
		TunnelDeliveryType deliveryType;
		uint32_t tunnelID;
		uint8_t hash[32];	
		I2NPMessage * data;
	};
}
}

#endif
