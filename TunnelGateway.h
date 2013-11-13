#ifndef TUNNEL_GATEWAY_H__
#define TUNNEL_GATEWAY_H__

#include <inttypes.h>
#include <vector>
#include "I2NPProtocol.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class TunnelGatewayBuffer
	{
		struct TunnelMessageBlockExt: public TunnelMessageBlock
		{
			size_t deliveryInstructionsLen, totalLen;
		};	
		
		public:

			void PutI2NPMsg (const uint8_t * gwHash, uint32_t gwTunnel, I2NPMessage * msg);	
			std::vector<I2NPMessage *> GetTunnelDataMsgs (uint32_t tunnelID);

		private:

			size_t CreateFirstFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len);
			size_t CreateFollowOnFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len);
			I2NPMessage * CreateNextTunnelMessage (uint32_t tunnelID, TunnelMessageBlockExt * block, size_t size);
			
		private:

			std::vector<TunnelMessageBlockExt *> m_I2NPMsgs;
			// for fragmented  messages
			size_t m_NextOffset, m_NextSeqn;
			uint32_t m_NextMsgID;
	};	

	class TunnelGateway
	{
		public:

			TunnelGateway (TunnelBase * tunnel): m_Tunnel (tunnel) {};
			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			
		private:

			TunnelBase * m_Tunnel;
			TunnelGatewayBuffer m_Buffer;
	};	
}		
}	

#endif
