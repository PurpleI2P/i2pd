#include <string.h>
#include <vector>
#include "Crypto.h"
#include "Log.h"
#include "TunnelBase.h"
#include "RouterContext.h"
#include "Destination.h"
#include "Datagram.h"

namespace i2p
{
namespace datagram
{
	DatagramDestination::DatagramDestination (std::shared_ptr<i2p::client::LeaseSetDestination> owner): 
		m_Owner (owner), m_Receiver (nullptr)
	{
	}
	
	DatagramDestination::~DatagramDestination ()
	{
	}
	
	void DatagramDestination::SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint16_t fromPort, uint16_t toPort)
	{
		uint8_t buf[MAX_DATAGRAM_SIZE];
		auto identityLen = m_Owner->GetIdentity ()->ToBuffer (buf, MAX_DATAGRAM_SIZE);
		uint8_t * signature = buf + identityLen;
		auto signatureLen = m_Owner->GetIdentity ()->GetSignatureLen ();
		uint8_t * buf1 = signature + signatureLen;
		size_t headerLen = identityLen + signatureLen;
		
		memcpy (buf1, payload, len);	
		if (m_Owner->GetIdentity ()->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
		{
			uint8_t hash[32];	
			SHA256(buf1, len, hash);
			m_Owner->Sign (hash, 32, signature);
		}
		else
			m_Owner->Sign (buf1, len, signature);

		auto msg = CreateDataMessage (buf, len + headerLen, fromPort, toPort); 
		auto remote = m_Owner->FindLeaseSet (ident);
		if (remote)
			m_Owner->GetService ().post (std::bind (&DatagramDestination::SendMsg, this, msg, remote));
		else
			m_Owner->RequestDestination (ident, std::bind (&DatagramDestination::HandleLeaseSetRequestComplete, this, std::placeholders::_1, msg));
	}

	void DatagramDestination::HandleLeaseSetRequestComplete (std::shared_ptr<i2p::data::LeaseSet> remote, std::shared_ptr<I2NPMessage> msg)
	{
		if (remote)
			SendMsg (msg, remote);
	}	
		
	void DatagramDestination::SendMsg (std::shared_ptr<I2NPMessage> msg, std::shared_ptr<const i2p::data::LeaseSet> remote)
	{
		auto outboundTunnel = m_Owner->GetTunnelPool ()->GetNextOutboundTunnel ();
		auto leases = remote->GetNonExpiredLeases ();
		if (!leases.empty () && outboundTunnel)
		{
			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;			
			uint32_t i = rand () % leases.size ();
			auto garlic = m_Owner->WrapMessage (remote, msg, true);
			msgs.push_back (i2p::tunnel::TunnelMessageBlock 
				{ 
					i2p::tunnel::eDeliveryTypeTunnel,
					leases[i]->tunnelGateway, leases[i]->tunnelID,
					garlic
				});
			outboundTunnel->SendTunnelDataMsg (msgs);
		}
		else
		{
			if (outboundTunnel)
				LogPrint (eLogWarning, "Failed to send datagram. All leases expired");
			else
				LogPrint (eLogWarning, "Failed to send datagram. No outbound tunnels");
		}	
	}

	void DatagramDestination::HandleDatagram (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		i2p::data::IdentityEx identity;
		size_t identityLen = identity.FromBuffer (buf, len);
		const uint8_t * signature = buf + identityLen;
		size_t headerLen = identityLen + identity.GetSignatureLen ();

		bool verified = false;
		if (identity.GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
		{
			uint8_t hash[32];
			SHA256(buf + headerLen, len - headerLen, hash);
			verified = identity.Verify (hash, 32, signature);
		}	
		else	
			verified = identity.Verify (buf + headerLen, len - headerLen, signature);
				
		if (verified)
		{
			auto it = m_ReceiversByPorts.find (toPort);
			if (it != m_ReceiversByPorts.end ())
				it->second (identity, fromPort, toPort, buf + headerLen, len -headerLen);
			else if (m_Receiver != nullptr)
				m_Receiver (identity, fromPort, toPort, buf + headerLen, len -headerLen);
			else
				LogPrint (eLogWarning, "Receiver for datagram is not set");	
		}
		else
			LogPrint (eLogWarning, "Datagram signature verification failed");	
	}

	void DatagramDestination::HandleDataMessagePayload (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		// unzip it
		uint8_t uncompressed[MAX_DATAGRAM_SIZE];
		size_t uncompressedLen = m_Inflator.Inflate (buf, len, uncompressed, MAX_DATAGRAM_SIZE);
		if (uncompressedLen)
			HandleDatagram (fromPort, toPort, uncompressed, uncompressedLen); 
	}

	std::shared_ptr<I2NPMessage> DatagramDestination::CreateDataMessage (const uint8_t * payload, size_t len, uint16_t fromPort, uint16_t toPort)
	{
		auto msg = NewI2NPMessage ();
		uint8_t * buf = msg->GetPayload ();
		buf += 4; // reserve for length
		size_t size = m_Deflator.Deflate (payload, len, buf, msg->maxLen - msg->len);
		if (size)
		{
			htobe32buf (msg->GetPayload (), size); // length
			htobe16buf (buf + 4, fromPort); // source port
			htobe16buf (buf + 6, toPort); // destination port 
			buf[9] = i2p::client::PROTOCOL_TYPE_DATAGRAM; // datagram protocol
			msg->len += size + 4; 
			msg->FillI2NPMessageHeader (eI2NPData);
		}	
		else
			msg = nullptr;
		return msg;
	}	
}
}

