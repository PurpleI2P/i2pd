/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TRANSIT_TUNNEL_H__
#define TRANSIT_TUNNEL_H__

#include <inttypes.h>
#include <vector>
#include <mutex>
#include <memory>
#include "Crypto.h"
#include "I2NPProtocol.h"
#include "TunnelEndpoint.h"
#include "TunnelGateway.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class TransitTunnel: public TunnelBase
	{
		public:

			TransitTunnel (uint32_t receiveTunnelID,
				const uint8_t * nextIdent, uint32_t nextTunnelID,
				const uint8_t * layerKey,const uint8_t * ivKey);

			virtual size_t GetNumTransmittedBytes () const { return 0; };

			// implements TunnelBase
			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg);
			void HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);
			void EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out);
		private:

			i2p::crypto::TunnelEncryption m_Encryption;
	};

	class TransitTunnelParticipant: public TransitTunnel
	{
		public:

			TransitTunnelParticipant (uint32_t receiveTunnelID,
				const uint8_t * nextIdent, uint32_t nextTunnelID,
				const uint8_t * layerKey,const uint8_t * ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID,
				layerKey, ivKey), m_NumTransmittedBytes (0) {};
			~TransitTunnelParticipant ();

			size_t GetNumTransmittedBytes () const { return m_NumTransmittedBytes; };
			void HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);
			void FlushTunnelDataMsgs ();

		private:

			size_t m_NumTransmittedBytes;
			std::vector<std::shared_ptr<i2p::I2NPMessage> > m_TunnelDataMsgs;
	};

	class TransitTunnelGateway: public TransitTunnel
	{
		public:

			TransitTunnelGateway (uint32_t receiveTunnelID,
				const uint8_t * nextIdent, uint32_t nextTunnelID,
				const uint8_t * layerKey,const uint8_t * ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID,
				layerKey, ivKey), m_Gateway(this) {};

			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg);
			void FlushTunnelDataMsgs ();
			size_t GetNumTransmittedBytes () const { return m_Gateway.GetNumSentBytes (); };

		private:

			std::mutex m_SendMutex;
			TunnelGateway m_Gateway;
	};

	class TransitTunnelEndpoint: public TransitTunnel
	{
		public:

			TransitTunnelEndpoint (uint32_t receiveTunnelID,
				const uint8_t * nextIdent, uint32_t nextTunnelID,
				const uint8_t * layerKey,const uint8_t * ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey),
				m_Endpoint (false) {}; // transit endpoint is always outbound

			void Cleanup () { m_Endpoint.Cleanup (); }

			void HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);
			size_t GetNumTransmittedBytes () const { return m_Endpoint.GetNumReceivedBytes (); }

		private:

			TunnelEndpoint m_Endpoint;
	};

	std::shared_ptr<TransitTunnel> CreateTransitTunnel (uint32_t receiveTunnelID,
		const uint8_t * nextIdent, uint32_t nextTunnelID,
		const uint8_t * layerKey,const uint8_t * ivKey,
		bool isGateway, bool isEndpoint);
}
}

#endif
