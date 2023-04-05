/*
* Copyright (c) 2013-2023, The PurpleI2P Project
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
				const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
				const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey);

			virtual size_t GetNumTransmittedBytes () const { return 0; };

			// implements TunnelBase
			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg) override;
			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg) override;
			void EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out) override;
		private:

			i2p::crypto::AESKey m_LayerKey, m_IVKey;
			std::unique_ptr<i2p::crypto::TunnelEncryption> m_Encryption;
	};

	class TransitTunnelParticipant: public TransitTunnel
	{
		public:

			TransitTunnelParticipant (uint32_t receiveTunnelID,
				const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
				const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID,
				layerKey, ivKey), m_NumTransmittedBytes (0) {};
			~TransitTunnelParticipant ();

			size_t GetNumTransmittedBytes () const override { return m_NumTransmittedBytes; };
			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg) override;
			void FlushTunnelDataMsgs () override;

		private:

			size_t m_NumTransmittedBytes;
			std::vector<std::shared_ptr<i2p::I2NPMessage> > m_TunnelDataMsgs;
	};

	class TransitTunnelGateway: public TransitTunnel
	{
		public:

			TransitTunnelGateway (uint32_t receiveTunnelID,
				const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
				const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID,
				layerKey, ivKey), m_Gateway(this) {};

			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg) override;
			void FlushTunnelDataMsgs () override;
			size_t GetNumTransmittedBytes () const override { return m_Gateway.GetNumSentBytes (); };

		private:

			std::mutex m_SendMutex;
			TunnelGateway m_Gateway;
	};

	class TransitTunnelEndpoint: public TransitTunnel
	{
		public:

			TransitTunnelEndpoint (uint32_t receiveTunnelID,
				const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
				const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey),
				m_Endpoint (false) {}; // transit endpoint is always outbound

			void Cleanup () override { m_Endpoint.Cleanup (); }

			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg) override;
			size_t GetNumTransmittedBytes () const override { return m_Endpoint.GetNumReceivedBytes (); }

		private:

			TunnelEndpoint m_Endpoint;
	};

	std::shared_ptr<TransitTunnel> CreateTransitTunnel (uint32_t receiveTunnelID,
		const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
		const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey,
		bool isGateway, bool isEndpoint);
}
}

#endif
