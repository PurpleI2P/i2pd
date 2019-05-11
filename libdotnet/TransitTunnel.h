#ifndef TRANSIT_TUNNEL_H__
#define TRANSIT_TUNNEL_H__

#include <inttypes.h>
#include <vector>
#include <mutex>
#include <memory>
#include "Crypto.h"
#include "DNNPProtocol.h"
#include "TunnelEndpoint.h"
#include "TunnelGateway.h"
#include "TunnelBase.h"

namespace dotnet
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
			void SendTunnelDataMsg (std::shared_ptr<dotnet::DNNPMessage> msg);
			void HandleTunnelDataMsg (std::shared_ptr<const dotnet::DNNPMessage> tunnelMsg);
			void EncryptTunnelMsg (std::shared_ptr<const DNNPMessage> in, std::shared_ptr<DNNPMessage> out);
		private:

			dotnet::crypto::TunnelEncryption m_Encryption;
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
			void HandleTunnelDataMsg (std::shared_ptr<const dotnet::DNNPMessage> tunnelMsg);
			void FlushTunnelDataMsgs ();

		private:

			size_t m_NumTransmittedBytes;
			std::vector<std::shared_ptr<dotnet::DNNPMessage> > m_TunnelDataMsgs;
	};

	class TransitTunnelGateway: public TransitTunnel
	{
		public:

			TransitTunnelGateway (uint32_t receiveTunnelID,
				const uint8_t * nextIdent, uint32_t nextTunnelID,
				const uint8_t * layerKey,const uint8_t * ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID,
				layerKey, ivKey), m_Gateway(this) {};

			void SendTunnelDataMsg (std::shared_ptr<dotnet::DNNPMessage> msg);
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

			void HandleTunnelDataMsg (std::shared_ptr<const dotnet::DNNPMessage> tunnelMsg);
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
