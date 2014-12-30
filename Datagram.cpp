#include <string.h>
#include <vector>
#include <cryptopp/sha.h>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "TunnelBase.h"
#include "RouterContext.h"
#include "Destination.h"
#include "Datagram.h"

namespace i2p
{
namespace datagram
{
	DatagramDestination::DatagramDestination (i2p::client::ClientDestination& owner): 
		m_Owner (owner), m_Receiver (nullptr)
	{
	}

	void DatagramDestination::SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::LeaseSet& remote)
	{
		uint8_t buf[MAX_DATAGRAM_SIZE];
		auto identityLen = m_Owner.GetIdentity ().ToBuffer (buf, MAX_DATAGRAM_SIZE);
		uint8_t * signature = buf + identityLen;
		auto signatureLen = m_Owner.GetIdentity ().GetSignatureLen ();
		uint8_t * buf1 = signature + signatureLen;
		size_t headerLen = identityLen + signatureLen;
		
		memcpy (buf1, payload, len);	
		if (m_Owner.GetIdentity ().GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
		{
			uint8_t hash[32];	
			CryptoPP::SHA256().CalculateDigest (hash, buf1, len);
			m_Owner.Sign (hash, 32, signature);
		}
		else
			m_Owner.Sign (buf1, len, signature);
		
		m_Owner.GetService ().post (std::bind (&DatagramDestination::SendMsg, this, 
			CreateDataMessage (buf, len + headerLen), remote));
	}

	void DatagramDestination::SendMsg (I2NPMessage * msg, const i2p::data::LeaseSet& remote)
	{
		auto outboundTunnel = m_Owner.GetTunnelPool ()->GetNextOutboundTunnel ();
		auto leases = remote.GetNonExpiredLeases ();
		if (!leases.empty () && outboundTunnel)
		{
			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;			
			uint32_t i = i2p::context.GetRandomNumberGenerator ().GenerateWord32 (0, leases.size () - 1);
			auto garlic = m_Owner.WrapMessage (remote, msg, true);
			msgs.push_back (i2p::tunnel::TunnelMessageBlock 
				{ 
					i2p::tunnel::eDeliveryTypeTunnel,
					leases[i].tunnelGateway, leases[i].tunnelID,
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
			DeleteI2NPMessage (msg);	
		}	
	}

	void DatagramDestination::HandleDatagram (const uint8_t * buf, size_t len)
	{
		i2p::data::IdentityEx identity;
		size_t identityLen = identity.FromBuffer (buf, len);
		const uint8_t * signature = buf + identityLen;
		size_t headerLen = identityLen + identity.GetSignatureLen ();

		bool verified = false;
		if (identity.GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
			verified = CryptoPP::SHA256().VerifyDigest (signature, buf + headerLen, len - headerLen);
		else	
			verified = identity.Verify (buf + headerLen, len - headerLen, signature);
				
		if (verified)
		{
			if (m_Receiver != nullptr)
				m_Receiver (identity, buf + headerLen, len -headerLen);
			else
				LogPrint (eLogWarning, "Receiver for datagram is not set");	
		}
		else
			LogPrint (eLogWarning, "Datagram signature verification failed");	
	}

	void DatagramDestination::HandleDataMessagePayload (const uint8_t * buf, size_t len)
	{
		// unzip it
		CryptoPP::Gunzip decompressor;
		decompressor.Put (buf, len);
		decompressor.MessageEnd();
		uint8_t uncompressed[MAX_DATAGRAM_SIZE];
		auto uncompressedLen = decompressor.MaxRetrievable ();
		if (uncompressedLen <= MAX_DATAGRAM_SIZE)
		{
			decompressor.Get (uncompressed, uncompressedLen);
			HandleDatagram (uncompressed, uncompressedLen); 
		}
		else
			LogPrint ("Received datagram size ", uncompressedLen,  " exceeds max size");

	}

	I2NPMessage * DatagramDestination::CreateDataMessage (const uint8_t * payload, size_t len)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		CryptoPP::Gzip compressor; // default level
		compressor.Put (payload, len);
		compressor.MessageEnd();
		int size = compressor.MaxRetrievable ();
		uint8_t * buf = msg->GetPayload ();
		htobe32buf (buf, size); // length
		buf += 4;
		compressor.Get (buf, size);
		memset (buf + 4, 0, 4); // source and destination are zeroes
		buf[9] = i2p::client::PROTOCOL_TYPE_DATAGRAM; // datagram protocol
		msg->len += size + 4; 
		FillI2NPMessageHeader (msg, eI2NPData);
		return msg;
	}	
}
}

