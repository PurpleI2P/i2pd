#include <string.h>
#include "I2PEndian.h"
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
		const uint8_t * layerKey,const uint8_t * ivKey): 
			TunnelBase (receiveTunnelID, nextTunnelID, nextIdent)
	{	
		m_Encryption.SetKeys (layerKey, ivKey);
	}	

	void TransitTunnel::EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out)
	{		
		m_Encryption.Encrypt (in->GetPayload () + 4, out->GetPayload () + 4); 
		i2p::transport::transports.UpdateTotalTransitTransmittedBytes (TUNNEL_DATA_MSG_SIZE);
	}	

	TransitTunnelParticipant::~TransitTunnelParticipant ()
	{
	}	
		
	void TransitTunnelParticipant::HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg)
	{
		auto newMsg = CreateEmptyTunnelDataMsg ();
		EncryptTunnelMsg (tunnelMsg, newMsg);
		
		m_NumTransmittedBytes += tunnelMsg->GetLength ();
		htobe32buf (newMsg->GetPayload (), GetNextTunnelID ());
		newMsg->FillI2NPMessageHeader (eI2NPTunnelData); 
		m_TunnelDataMsgs.push_back (newMsg);
	}

	void TransitTunnelParticipant::FlushTunnelDataMsgs ()
	{
		if (!m_TunnelDataMsgs.empty ())
		{	
			auto num = m_TunnelDataMsgs.size ();
			if (num > 1)
				LogPrint (eLogDebug, "TransitTunnel: ", GetTunnelID (), "->", GetNextTunnelID (), " ", num);
			i2p::transport::transports.SendMessages (GetNextIdentHash (), m_TunnelDataMsgs);
			m_TunnelDataMsgs.clear ();
		}	
	}	
		
	void TransitTunnel::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{	
		LogPrint (eLogError, "TransitTunnel: We are not a gateway for ", GetTunnelID ());
	}		

	void TransitTunnel::HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg)
	{
		LogPrint (eLogError, "TransitTunnel: Incoming tunnel message is not supported ", GetTunnelID ());
	}	
		
	void TransitTunnelGateway::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		TunnelMessageBlock block;
		block.deliveryType = eDeliveryTypeLocal;
		block.data = msg;
		std::unique_lock<std::mutex> l(m_SendMutex);
		m_Gateway.PutTunnelDataMsg (block);
	}		

	void TransitTunnelGateway::FlushTunnelDataMsgs ()
	{
		std::unique_lock<std::mutex> l(m_SendMutex);
		m_Gateway.SendBuffer ();
	}	
		
	void TransitTunnelEndpoint::HandleTunnelDataMsg (std::shared_ptr<const i2p::I2NPMessage> tunnelMsg)
	{
		auto newMsg = CreateEmptyTunnelDataMsg ();
		EncryptTunnelMsg (tunnelMsg, newMsg);
		
		LogPrint (eLogDebug, "TransitTunnel: handle msg for endpoint ", GetTunnelID ());
		m_Endpoint.HandleDecryptedTunnelDataMsg (newMsg); 
	}
		
	std::shared_ptr<TransitTunnel> CreateTransitTunnel (uint32_t receiveTunnelID,
		const uint8_t * nextIdent, uint32_t nextTunnelID, 
	    const uint8_t * layerKey,const uint8_t * ivKey, 
		bool isGateway, bool isEndpoint)
	{
		if (isEndpoint)
		{	
			LogPrint (eLogDebug, "TransitTunnel: endpoint ", receiveTunnelID, " created");
			return std::make_shared<TransitTunnelEndpoint> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}	
		else if (isGateway)
		{	
			LogPrint (eLogInfo, "TransitTunnel: gateway ", receiveTunnelID, " created");
			return std::make_shared<TransitTunnelGateway> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}	
		else	
		{	
			LogPrint (eLogDebug, "TransitTunnel: ", receiveTunnelID, "->", nextTunnelID, " created");
			return std::make_shared<TransitTunnelParticipant> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}	
	}		
}
}
