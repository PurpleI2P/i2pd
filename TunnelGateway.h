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
			bool isFragmented;
		};	
		
		public:

			TunnelGatewayBuffer (uint32_t tunnelID): m_TunnelID (tunnelID), m_Remaining (0) {}; 
			
			void PutI2NPMsg (const uint8_t * gwHash, uint32_t gwTunnel, I2NPMessage * msg);	
			std::vector<I2NPMessage *> GetTunnelDataMsgs ();

		private:

			size_t CreateFirstFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len);
			size_t CreateFollowOnFragment (TunnelMessageBlockExt * block, uint8_t * buf, size_t len);
			I2NPMessage * CreateNextTunnelMessage (int& ind);
			
		private:

			uint32_t m_TunnelID;
			std::vector<TunnelMessageBlockExt *> m_I2NPMsgs;
			// for fragmented  messages
			size_t m_NextOffset, m_NextSeqn, m_Remaining;
			uint32_t m_NextMsgID;
	};	

	class TunnelGateway
	{
		public:

			TunnelGateway (TunnelBase * tunnel): 
				m_Tunnel (tunnel), m_Buffer (tunnel->GetNextTunnelID ()), m_NumSentBytes (0) {};
			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			void PutTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);	
			void SendBuffer ();
			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			
		private:

			TunnelBase * m_Tunnel;
			TunnelGatewayBuffer m_Buffer;
			size_t m_NumSentBytes;
	};	
}		
}	

#endif
