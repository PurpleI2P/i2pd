/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TRANSIT_TUNNEL_H__
#define TRANSIT_TUNNEL_H__

#include <inttypes.h>
#include <list>
#include <mutex>
#include <memory>
#include "Crypto.h"
#include "Queue.h"
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
			virtual std::string GetNextPeerName () const;

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
			std::string GetNextPeerName () const override;
			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg) override;
			void FlushTunnelDataMsgs () override;

		private:

			size_t m_NumTransmittedBytes;
			std::list<std::shared_ptr<i2p::I2NPMessage> > m_TunnelDataMsgs;
			std::unique_ptr<TunnelTransportSender> m_Sender;
	};

	class TransitTunnelGateway: public TransitTunnel
	{
		public:

			TransitTunnelGateway (uint32_t receiveTunnelID,
				const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
				const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID,
				layerKey, ivKey), m_Gateway(*this) {};

			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg) override;
			void FlushTunnelDataMsgs () override;
			size_t GetNumTransmittedBytes () const override { return m_Gateway.GetNumSentBytes (); };
			std::string GetNextPeerName () const override;
			
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

			void Cleanup () override;
		
			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg) override;
			void FlushTunnelDataMsgs () override;
			size_t GetNumTransmittedBytes () const override { return m_Endpoint.GetNumReceivedBytes (); }
			std::string GetNextPeerName () const override;
			
		private:

			std::mutex m_HandleMutex;
			TunnelEndpoint m_Endpoint;
	};

	std::shared_ptr<TransitTunnel> CreateTransitTunnel (uint32_t receiveTunnelID,
		const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
		const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey,
		bool isGateway, bool isEndpoint);

	
	const int TRANSIT_TUNNELS_QUEUE_WAIT_INTERVAL = 10; // in seconds
		
	class TransitTunnels
	{	
		public:

			TransitTunnels ();
			~TransitTunnels ();
			
			void Start ();
			void Stop ();
			void PostTransitTunnelBuildMsg  (std::shared_ptr<I2NPMessage>&& msg);
			
			size_t GetNumTransitTunnels () const { return m_TransitTunnels.size (); }
			int GetTransitTunnelsExpirationTimeout ();

		private:

			bool AddTransitTunnel (std::shared_ptr<TransitTunnel> tunnel);
			void ManageTransitTunnels (uint64_t ts);

			void HandleShortTransitTunnelBuildMsg (std::shared_ptr<I2NPMessage>&& msg);
			void HandleVariableTransitTunnelBuildMsg (std::shared_ptr<I2NPMessage>&& msg);
			bool HandleBuildRequestRecords (int num, uint8_t * records, uint8_t * clearText);

			void Run ();
			
		private:

			volatile bool m_IsRunning;
			std::unique_ptr<std::thread> m_Thread;
			std::list<std::shared_ptr<TransitTunnel> > m_TransitTunnels;
			i2p::util::Queue<std::shared_ptr<I2NPMessage> > m_TunnelBuildMsgQueue;
			std::mt19937 m_Rng;
			
		public:

			// for HTTP only
			const auto& GetTransitTunnels () const { return m_TransitTunnels; };
			size_t GetTunnelBuildMsgQueueSize () const { return m_TunnelBuildMsgQueue.GetSize (); };
	};
}
}

#endif
