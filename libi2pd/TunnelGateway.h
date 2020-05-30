/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TUNNEL_GATEWAY_H__
#define TUNNEL_GATEWAY_H__

#include <inttypes.h>
#include <vector>
#include <memory>
#include "I2NPProtocol.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class TunnelGatewayBuffer
	{
		public:
			TunnelGatewayBuffer ();
			~TunnelGatewayBuffer ();
			void PutI2NPMsg (const TunnelMessageBlock& block);
			const std::vector<std::shared_ptr<const I2NPMessage> >& GetTunnelDataMsgs () const { return m_TunnelDataMsgs; };
			void ClearTunnelDataMsgs ();
			void CompleteCurrentTunnelDataMessage ();

		private:

			void CreateCurrentTunnelDataMessage ();

		private:

			std::vector<std::shared_ptr<const I2NPMessage> > m_TunnelDataMsgs;
			std::shared_ptr<I2NPMessage> m_CurrentTunnelDataMsg;
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
