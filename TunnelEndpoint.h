#ifndef TUNNEL_ENDPOINT_H__
#define TUNNEL_ENDPOINT_H__

#include <inttypes.h>
#include <map>
#include <string>
#include "I2NPProtocol.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class TunnelEndpoint
	{	
		public:

			void HandleDecryptedTunnelDataMsg (I2NPMessage * msg);

		private:

			void HandleNextMessage (const TunnelMessageBlock& msg);
			
		private:
		
			std::map<uint32_t, TunnelMessageBlock> m_IncompleteMessages;
	};	
}		
}

#endif
