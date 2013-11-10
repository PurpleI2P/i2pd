#include <string.h>
#include "Log.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "Transports.h"
#include "TransitTunnel.h"

namespace i2p
{
namespace tunnel
{	
	TransitTunnel::TransitTunnel (uint32_t receiveTunnelID, 
	    const uint8_t * nextIdent, uint32_t nextTunnelID, 
		const uint8_t * layerKey,const uint8_t * ivKey, 
	    bool isGateway, bool isEndpoint)
	{	
		memcpy (m_LayerKey, layerKey, 32);
		memcpy (m_IVKey, ivKey, 32);
		memcpy (m_NextIdent, nextIdent, 32);
		m_IsGateway = isGateway;
		m_IsEndpoint = isEndpoint;
		m_TunnelID = receiveTunnelID;
		m_NextTunnelID = nextTunnelID;
		if (m_IsEndpoint)
			LogPrint ("TransitTunnel endpoint: ", m_TunnelID, " created");
		else if (m_IsGateway)
			LogPrint ("TransitTunnel gateway: ", m_TunnelID, " created");
		else	
			LogPrint ("TransitTunnel: ",m_TunnelID,"->", m_NextTunnelID, " created");
	}	

	void TransitTunnel::Encrypt (uint8_t * payload)
	{
		m_ECBEncryption.SetKey (m_IVKey, 32); 
		m_ECBEncryption.ProcessData(payload, payload, 16); // iv

		m_CBCEncryption.SetKeyWithIV (m_LayerKey, 32, payload); 
		m_CBCEncryption.ProcessData(payload + 16, payload + 16, 1008); // payload

		m_ECBEncryption.SetKey (m_IVKey, 32); 
		m_ECBEncryption.ProcessData(payload, payload, 16); // double iv encryption

	}	
	
	void TransitTunnel::HandleTunnelDataMsg (i2p::I2NPMessage * tunnelMsg)
	{
		Encrypt (tunnelMsg->GetPayload () + 4);
		
		if (m_IsEndpoint)
		{
			LogPrint ("TransitTunnel endpoint for ", m_TunnelID);
			m_Endpoint.HandleDecryptedTunnelDataMsg (tunnelMsg); 
		}	
		else	
		{	
			LogPrint ("TransitTunnel: ",m_TunnelID,"->", m_NextTunnelID);
			*(uint32_t *)(tunnelMsg->GetPayload ()) = htobe32 (m_NextTunnelID);
			FillI2NPMessageHeader (tunnelMsg, eI2NPTunnelData);
		
			i2p::transports.SendMessage (m_NextIdent, tunnelMsg);
		}	
	}

	void TransitTunnel::SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg)
	{
		if (m_IsGateway)
		{
			m_Gateway.PutI2NPMsg (gwHash, gwTunnel, msg);
			auto tunnelMsgs = m_Gateway.GetTunnelDataMsgs (m_NextTunnelID);
			for (auto tunnelMsg : tunnelMsgs)
			{	
				Encrypt (tunnelMsg->GetPayload () + 4);
				FillI2NPMessageHeader (tunnelMsg, eI2NPTunnelData);
				i2p::transports.SendMessage (m_NextIdent, tunnelMsg);
			}	
		}
		else
		{	
			LogPrint ("We are not a gateway for transit tunnel ", m_TunnelID);
			i2p::DeleteI2NPMessage (msg);
		}	
	}		
}
}