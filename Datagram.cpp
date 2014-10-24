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
		m_Owner (owner) 
	{
		auto identityLen = m_Owner.GetIdentity ().ToBuffer (m_OutgoingBuffer, MAX_DATAGRAM_SIZE);
		m_Signature = m_OutgoingBuffer + identityLen;
		auto signatureLen = m_Owner.GetIdentity ().GetSignatureLen ();
		m_Payload = m_Signature + signatureLen;
		m_HeaderLen = identityLen + signatureLen;
	}

	void DatagramDestination::SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::LeaseSet& remote)
	{
		auto leases = remote.GetNonExpiredLeases ();
		if (!leases.empty ())
		{
			memcpy (m_Payload, payload, len);
			if (m_Owner.GetIdentity ().GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
			{
				uint8_t hash[32];	
				CryptoPP::SHA256().CalculateDigest (hash, m_Payload, len);
				m_Owner.Sign (hash, 32, m_Signature);
			}
			else
				m_Owner.Sign (m_Payload, len, m_Signature);

			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;			
			uint32_t i = i2p::context.GetRandomNumberGenerator ().GenerateWord32 (0, leases.size () - 1);
			auto msg = m_Owner.WrapMessage (remote, CreateDataMessage (m_OutgoingBuffer, len + m_HeaderLen), true);
			msgs.push_back (i2p::tunnel::TunnelMessageBlock 
				{ 
					i2p::tunnel::eDeliveryTypeTunnel,
					leases[i].tunnelGateway, leases[i].tunnelID,
					msg
				});
			m_Owner.SendTunnelDataMsgs (msgs);
		}
		else
			LogPrint ("Failed to send datagram. All leases expired");	
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
			//HandleNextPacket (uncompressed); 
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
		*(uint32_t *)buf = htobe32 (size); // length
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

