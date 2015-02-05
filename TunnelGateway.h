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
			~TunnelGatewayBuffer ();
			void PutI2NPMsg (const TunnelMessageBlock& block);	
			const std::vector<I2NPMessage *>& GetTunnelDataMsgs () const { return m_TunnelDataMsgs; };
			void ClearTunnelDataMsgs ();
			void CompleteCurrentTunnelDataMessage ();

		private:

			void CreateCurrentTunnelDataMessage ();
			
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
			void SendTunnelDataMsg (const TunnelMessageBlock& block);	
			void PutTunnelDataMsg (const TunnelMessageBlock& block);
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
