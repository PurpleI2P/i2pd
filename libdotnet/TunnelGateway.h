#ifndef TUNNEL_GATEWAY_H__
#define TUNNEL_GATEWAY_H__

#include <inttypes.h>
#include <vector>
#include <memory>
#include "DNNPProtocol.h"
#include "TunnelBase.h"

namespace dotnet
{
namespace tunnel
{
	class TunnelGatewayBuffer
	{
		public:
			TunnelGatewayBuffer ();
			~TunnelGatewayBuffer ();
			void PutDNNPMsg (const TunnelMessageBlock& block);
			const std::vector<std::shared_ptr<const DNNPMessage> >& GetTunnelDataMsgs () const { return m_TunnelDataMsgs; };
			void ClearTunnelDataMsgs ();
			void CompleteCurrentTunnelDataMessage ();

		private:

			void CreateCurrentTunnelDataMessage ();

		private:

			std::vector<std::shared_ptr<const DNNPMessage> > m_TunnelDataMsgs;
			std::shared_ptr<DNNPMessage> m_CurrentTunnelDataMsg;
			size_t m_RemainingSize;
			uint8_t m_NonZeroRandomBuffer[TUNNEL_DATA_MAX_PAYLOAD_SIZE];
	};

	class TunnelGateway
	{
		public:

			TunnelGateway (TunnelBase * tunnel):
				m_Tunnel (tunnel), m_NumSentBytes (0) {};
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
