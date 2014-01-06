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
		public:
			TunnelGatewayBuffer (uint32_t tunnelID): m_TunnelID (tunnelID), 
				m_CurrentTunnelDataMsg (nullptr), m_RemainingSize (0) {};
			void PutI2NPMsg (const uint8_t * gwHash, uint32_t gwTunnel, I2NPMessage * msg);	
			std::vector<I2NPMessage *> GetTunnelDataMsgs ();

		private:

			void CreateCurrentTunnelDataMessage ();
			void CompleteCurrentTunnelDataMessage ();
			
		private:

			uint32_t m_TunnelID;
			std::vector<I2NPMessage *> m_TunnelDataMsgs;
			I2NPMessage * m_CurrentTunnelDataMsg;
			size_t m_RemainingSize;
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
