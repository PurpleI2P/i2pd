#ifndef TUNNEL_BASE_H__
#define TUNNEL_BASE_H__

#include <inttypes.h>
#include "I2NPProtocol.h"

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

	class TunnelBase
	{
		public:

			virtual void EncryptTunnelMsg (I2NPMessage * tunnelMsg) = 0;
			virtual uint32_t GetNextTunnelID () const = 0;
			virtual const uint8_t * GetNextIdentHash () const = 0;
	};	
}
}

#endif
