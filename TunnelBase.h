#ifndef TUNNEL_BASE_H__
#define TUNNEL_BASE_H__

#include <inttypes.h>
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "Identity.h"

namespace i2p
{
namespace tunnel
{
	const size_t TUNNEL_DATA_MSG_SIZE = 1028;
	const size_t TUNNEL_DATA_ENCRYPTED_SIZE = 1008;
	const size_t TUNNEL_DATA_MAX_PAYLOAD_SIZE = 1003;
	
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
		i2p::data::IdentHash hash;	
		I2NPMessage * data;
	};

	class TunnelBase
	{
		public:

			//WARNING!!! GetSecondsSinceEpoch() return uint64_t
			TunnelBase (): m_CreationTime (i2p::util::GetSecondsSinceEpoch ()) {};
			virtual ~TunnelBase () {};
			
			virtual void EncryptTunnelMsg (I2NPMessage * tunnelMsg) = 0;
			virtual uint32_t GetNextTunnelID () const = 0;
			virtual const i2p::data::IdentHash& GetNextIdentHash () const = 0;
			virtual uint32_t GetTunnelID () const = 0; // as known at our side

			uint32_t GetCreationTime () const { return m_CreationTime; };
			void SetCreationTime (uint32_t t) { m_CreationTime = t; };

		private:
			
			uint32_t m_CreationTime; // seconds since epoch
	};	
}
}

#endif
