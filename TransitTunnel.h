#ifndef TRANSIT_TUNNEL_H__
#define TRANSIT_TUNNEL_H__

#include <inttypes.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "I2NPProtocol.h"
#include "TunnelEndpoint.h"
#include "TunnelGateway.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{	
	class TransitTunnel: public TunnelBase // tunnel patricipant
	{
		public:

			TransitTunnel (uint32_t receiveTunnelID,
			    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    		const uint8_t * layerKey,const uint8_t * ivKey); 
			
			virtual void HandleTunnelDataMsg (i2p::I2NPMessage * tunnelMsg);
			virtual void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			
			uint32_t GetTunnelID () const { return m_TunnelID; };

			// implements TunnelBase
			void EncryptTunnelMsg (I2NPMessage * tunnelMsg); 
			uint32_t GetNextTunnelID () const { return m_NextTunnelID; };
			const i2p::data::IdentHash& GetNextIdentHash () const { return m_NextIdent; };
			
		private:

			uint32_t m_TunnelID, m_NextTunnelID;
			i2p::data::IdentHash m_NextIdent;
			uint8_t m_LayerKey[32];
			uint8_t m_IVKey[32];
			
			CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_ECBEncryption;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_CBCEncryption;
	};	

	class TransitTunnelGateway: public TransitTunnel
	{
		public:

			TransitTunnelGateway (uint32_t receiveTunnelID,
			    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    		const uint8_t * layerKey,const uint8_t * ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID, 
				layerKey, ivKey), m_Gateway(this) {};

			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			
		private:

			TunnelGateway m_Gateway;
	};	

	class TransitTunnelEndpoint: public TransitTunnel
	{
		public:

			TransitTunnelEndpoint (uint32_t receiveTunnelID,
			    const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    		const uint8_t * layerKey,const uint8_t * ivKey):
				TransitTunnel (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey) {};

			void HandleTunnelDataMsg (i2p::I2NPMessage * tunnelMsg);
			
		private:

			TunnelEndpoint m_Endpoint;
	};
	
	TransitTunnel * CreateTransitTunnel (uint32_t receiveTunnelID,
		const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    const uint8_t * layerKey,const uint8_t * ivKey, 
		bool isGateway, bool isEndpoint);
}
}

#endif
