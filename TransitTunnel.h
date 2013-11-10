#ifndef TRANSIT_TUNNEL_H__
#define TRANSIT_TUNNEL_H__

#include <inttypes.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "I2NPProtocol.h"
#include "TunnelEndpoint.h"
#include "TunnelGateway.h"

namespace i2p
{
namespace tunnel
{	
	class TransitTunnel
	{
		public:

			TransitTunnel (uint32_t receiveTunnelID,
			    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    		const uint8_t * layerKey,const uint8_t * ivKey, 
			    bool isGateway, bool isEndpoint); 
			
			void HandleTunnelDataMsg (i2p::I2NPMessage * tunnelMsg);
			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			
			uint32_t GetTunnelID () const { return m_TunnelID; };
			bool IsGateway () const { return m_IsGateway; };
			bool IsEndpoint () const { return m_IsEndpoint; };
			bool IsParticipant () const { return !IsGateway () && !IsEndpoint (); };

		private:

			void Encrypt (uint8_t * payload);
			
		private:

			uint32_t m_TunnelID, m_NextTunnelID;
			uint8_t m_NextIdent[32];
			uint8_t m_LayerKey[32];
			uint8_t m_IVKey[32];
			bool m_IsGateway, m_IsEndpoint;

			TunnelEndpoint m_Endpoint;
			TunnelGatewayBuffer m_Gateway;
			
			CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_ECBEncryption;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_CBCEncryption;
	};	
}
}

#endif
