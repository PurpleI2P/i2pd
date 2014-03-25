#include <fstream>
#include <algorithm>
#include <cryptopp/gzip.h>
#include "Log.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "CryptoConst.h"
#include "Garlic.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	Stream::Stream (boost::asio::io_service& service, StreamingDestination * local, 
		const i2p::data::LeaseSet& remote): m_Service (service), m_SendStreamID (0), 
		m_SequenceNumber (0), m_LastReceivedSequenceNumber (0), m_IsOpen (false), 
		m_LeaseSetUpdated (true), m_LocalDestination (local), m_RemoteLeaseSet (remote), 
		m_OutboundTunnel (nullptr), m_ReceiveTimer (m_Service)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
		UpdateCurrentRemoteLease ();
	}	

	Stream::~Stream ()
	{
		m_ReceiveTimer.cancel ();
		while (auto packet = m_ReceiveQueue.Get ())
			delete packet;
		for (auto it: m_SavedPackets)
			delete it;
	}	
		
	void Stream::HandleNextPacket (Packet * packet)
	{
		if (!m_SendStreamID)
			m_SendStreamID = packet->GetReceiveStreamID ();
		
		uint32_t receivedSeqn = packet->GetSeqn ();
		LogPrint ("Received seqn=", receivedSeqn); 
		if (!receivedSeqn || receivedSeqn == m_LastReceivedSequenceNumber + 1)
		{			
			// we have received next in sequence message
			ProcessPacket (packet);

			// we should also try stored messages if any
			for (auto it = m_SavedPackets.begin (); it != m_SavedPackets.end ();)
			{			
				if ((*it)->GetSeqn () == m_LastReceivedSequenceNumber + 1)
				{
					Packet * savedPacket = *it;
					m_SavedPackets.erase (it++);

					ProcessPacket (savedPacket);
				}
				else
					break;
			}

			// send ack for last message
			SendQuickAck ();
		}	
		else 
		{	
			if (receivedSeqn <= m_LastReceivedSequenceNumber)
			{
				// we have received duplicate. Most likely our outbound tunnel is dead
				LogPrint ("Duplicate message ", receivedSeqn, " received");
				UpdateCurrentRemoteLease (); // pick another lease
				m_OutboundTunnel = i2p::tunnel::tunnels.GetNextOutboundTunnel (); // pick another tunnel
				if (m_OutboundTunnel)
					SendQuickAck (); // resend ack for previous message again
				delete packet; // packet dropped
			}	
			else
			{
				LogPrint ("Missing messages from ", m_LastReceivedSequenceNumber + 1, " to ", receivedSeqn - 1);
				// save message and wait for missing message again
				SavePacket (packet);
			}	
		}	
	}	

	void Stream::SavePacket (Packet * packet)
	{
		m_SavedPackets.insert (packet);
	}	

	void Stream::ProcessPacket (Packet * packet)
	{
		// process flags
		uint32_t receivedSeqn = packet->GetSeqn ();
		uint16_t flags = packet->GetFlags ();
		LogPrint ("Process seqn=", receivedSeqn, ", flags=", flags);
		
		const uint8_t * optionData = packet->GetOptionData ();
		if (flags & PACKET_FLAG_SYNCHRONIZE)
		{
			LogPrint ("Synchronize");
		}	
		
		if (flags & PACKET_FLAG_SIGNATURE_INCLUDED)
		{
			LogPrint ("Signature");
			optionData += 40;
		}	

		if (flags & PACKET_FLAG_FROM_INCLUDED)
		{
			LogPrint ("From identity");
			optionData += sizeof (i2p::data::Identity);
		}	

		packet->offset = packet->GetPayload () - packet->buf;
		if (packet->GetLength () > 0)
			m_ReceiveQueue.Put (packet);
		else
			delete packet;
		
		m_LastReceivedSequenceNumber = receivedSeqn;

		if (flags & PACKET_FLAG_CLOSE)
		{
			LogPrint ("Closed");
			m_IsOpen = false;
			m_ReceiveQueue.WakeUp ();
			m_ReceiveTimer.cancel ();
		}
	}	
		
	size_t Stream::Send (uint8_t * buf, size_t len, int timeout)
	{
		if (!m_IsOpen)
			ConnectAndSend (buf, len);
		else
		{
			// TODO: implement
		}	
		return len;
	}	

	void Stream::ConnectAndSend (uint8_t * buf, size_t len)
	{
		m_IsOpen = true;
		Packet * p = new Packet ();
		uint8_t * packet = p->GetBuffer ();
		// TODO: implement setters
		size_t size = 0;
		*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
		size += 4; // sendStreamID
		*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
		size += 4; // receiveStreamID
		*(uint32_t *)(packet + size) = htobe32 (m_SequenceNumber);
		size += 4; // sequenceNum
		*(uint32_t *)(packet + size) = 0; // TODO
		size += 4; // ack Through
		packet[size] = 0; 
		size++; // NACK count
		size++; // resend delay
		// TODO: for initial packet only, following packets have different falgs
		*(uint16_t *)(packet + size) = htobe16 (PACKET_FLAG_SYNCHRONIZE | 
			PACKET_FLAG_FROM_INCLUDED | PACKET_FLAG_SIGNATURE_INCLUDED | 
		    PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED | PACKET_FLAG_NO_ACK);
		size += 2; // flags
		*(uint16_t *)(packet + size) = htobe16 (sizeof (i2p::data::Identity) + 40 + 2); // identity + signature + packet size
		size += 2; // options size
		memcpy (packet + size, &m_LocalDestination->GetIdentity (), sizeof (i2p::data::Identity)); 
		size += sizeof (i2p::data::Identity); // from
		*(uint16_t *)(packet + size) = htobe16 (STREAMING_MTU);
		size += 2; // max packet size
		uint8_t * signature = packet + size; // set it later
		memset (signature, 0, 40); // zeroes for now
		size += 40; // signature		
		memcpy (packet + size, buf, len); 
		size += len; // payload
		m_LocalDestination->Sign (packet, size, signature);
		p->len = size;
		
		m_Service.post (boost::bind (&Stream::SendPacket, this, p));
	}	
		
	void Stream::SendQuickAck ()
	{
		uint8_t packet[MAX_PACKET_SIZE];
		size_t size = 0;
		*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
		size += 4; // sendStreamID
		*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
		size += 4; // receiveStreamID
		*(uint32_t *)(packet + size) = 0; // this is plain Ack message
		size += 4; // sequenceNum
		*(uint32_t *)(packet + size) = htobe32 (m_LastReceivedSequenceNumber);
		size += 4; // ack Through
		packet[size] = 0; 
		size++; // NACK count
		size++; // resend delay
		*(uint16_t *)(packet + size) = 0; // nof flags set
		size += 2; // flags
		*(uint16_t *)(packet + size) = 0; // no options
		size += 2; // options size
		
		if (SendPacket (packet, size))
			LogPrint ("Quick Ack sent");
	}	

	void Stream::Close ()
	{
		if (m_IsOpen)
		{	
			m_IsOpen = false;
			uint8_t packet[MAX_PACKET_SIZE];
			size_t size = 0;
			*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
			size += 4; // sendStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
			size += 4; // receiveStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_SequenceNumber);
			size += 4; // sequenceNum
			*(uint32_t *)(packet + size) = htobe32 (m_LastReceivedSequenceNumber);
			size += 4; // ack Through
			packet[size] = 0; 
			size++; // NACK count
			size++; // resend delay
			*(uint16_t *)(packet + size) = PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED;
			size += 2; // flags
			*(uint16_t *)(packet + size) = htobe16 (40); // 40 bytes signature
			size += 2; // options size
			uint8_t * signature = packet + size;
			memset (packet + size, 0, 40);
			size += 40; // signature
			m_LocalDestination->Sign (packet, size, signature);
			
			if (SendPacket (packet, size))
				LogPrint ("FIN sent");
			m_ReceiveQueue.WakeUp ();
		}	
	}
		
	size_t Stream::Receive (uint8_t * buf, size_t len, int timeout)
	{
		if (!m_IsOpen) return 0;
		if (m_ReceiveQueue.IsEmpty ())
		{
			if (!timeout) return 0;
			if (!m_ReceiveQueue.Wait (timeout, 0))
				return 0;
		}

		// either non-empty or we have received empty
		size_t pos = 0;
		while (pos < len)
		{
			Packet * packet = m_ReceiveQueue.Peek ();
			if (packet)
			{
				size_t l = std::min (packet->GetLength (), len - pos);
				memcpy (buf + pos, packet->GetBuffer (), l);
				pos += l;
				packet->offset += l;
				if (!packet->GetLength ())
				{
					m_ReceiveQueue.Get ();
					delete packet;
				}	
			}
			else // no more data available
				break;
		}	
		return pos; 
	}	

	bool Stream::SendPacket (Packet * packet)
	{
		if (packet)
		{	
			bool ret = SendPacket (packet->GetBuffer (), packet->GetLength ());
			delete packet;
			return ret;
		}	
		else
			return false;
	}	
	
	bool Stream::SendPacket (const uint8_t * buf, size_t len)
	{		
		const I2NPMessage * leaseSet = nullptr;
		if (m_LeaseSetUpdated)
		{	
			leaseSet = m_LocalDestination->GetLeaseSet ();
			m_LeaseSetUpdated = false;
		}	
		I2NPMessage * msg = i2p::garlic::routing.WrapMessage (m_RemoteLeaseSet, 
			CreateDataMessage (this, buf, len), leaseSet);
		if (!m_OutboundTunnel)
			m_OutboundTunnel = m_LocalDestination->GetTunnelPool ()->GetNextOutboundTunnel ();
		if (m_OutboundTunnel)
		{
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			if (ts >= m_CurrentRemoteLease.endDate)
				UpdateCurrentRemoteLease ();
			if (ts < m_CurrentRemoteLease.endDate)
			{	
				m_OutboundTunnel->SendTunnelDataMsg (m_CurrentRemoteLease.tunnelGateway, m_CurrentRemoteLease.tunnelID, msg);
				return true;
			}	
			else
			{
				LogPrint ("All leases are expired");
				DeleteI2NPMessage (msg);
			}	
		}	
		else
		{	
			LogPrint ("No outbound tunnels in the pool");
			DeleteI2NPMessage (msg);
		}	
		return false;
	}

	void Stream::UpdateCurrentRemoteLease ()
	{
		auto leases = m_RemoteLeaseSet.GetNonExpiredLeases ();
		if (!leases.empty ())
		{	
			uint32_t i = i2p::context.GetRandomNumberGenerator ().GenerateWord32 (0, leases.size () - 1);
			m_CurrentRemoteLease = leases[i];
		}	
		else
			m_CurrentRemoteLease.endDate = 0;
	}	
		

	StreamingDestination::StreamingDestination (): m_LeaseSet (nullptr)
	{		
		m_Keys = i2p::data::CreateRandomKeys ();
		m_IdentHash = i2p::data::CalculateIdentHash (m_Keys.pub);
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (this);
	}

	StreamingDestination::StreamingDestination (const std::string& fullPath): m_LeaseSet (nullptr) 
	{
		std::ifstream s(fullPath.c_str (), std::ifstream::binary);
		if (s.is_open ())	
			s.read ((char *)&m_Keys, sizeof (m_Keys));
		else
			LogPrint ("Can't open file ", fullPath);
		m_Pool = i2p::tunnel::tunnels.CreateTunnelPool (this);
	}

	StreamingDestination::~StreamingDestination ()
	{
		if (m_LeaseSet)
			DeleteI2NPMessage (m_LeaseSet);
		if (m_Pool)
			i2p::tunnel::tunnels.DeleteTunnelPool (m_Pool);		
	}	
	
	void StreamingDestination::HandleNextPacket (Packet * packet)
	{
		uint32_t sendStreamID = packet->GetSendStreamID ();
		auto it = m_Streams.find (sendStreamID);
		if (it != m_Streams.end ())
			it->second->HandleNextPacket (packet);
		else
		{	
			LogPrint ("Unknown stream ", sendStreamID);
			delete packet;
		}	
	}	

	Stream * StreamingDestination::CreateNewStream (boost::asio::io_service& service,
		const i2p::data::LeaseSet& remote)
	{
		Stream * s = new Stream (service, this, remote);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}	

	void StreamingDestination::DeleteStream (Stream * stream)
	{
		if (stream)
		{
			m_Streams.erase (stream->GetRecvStreamID ());
			delete stream;
		}	
	}	

	void StreamingDestination::UpdateLeaseSet ()
	{
		auto newLeaseSet = CreateLeaseSet ();
		// TODO: make it atomic
		auto oldLeaseSet = m_LeaseSet;
		m_LeaseSet = newLeaseSet;
		if (oldLeaseSet)
			DeleteI2NPMessage (oldLeaseSet);
		for (auto it: m_Streams)
			it.second->SetLeaseSetUpdated ();
	}	
		
	const I2NPMessage * StreamingDestination::GetLeaseSet ()
	{
		if (!m_LeaseSet)
			m_LeaseSet = CreateLeaseSet ();
		else
			RenewI2NPMessageHeader (m_LeaseSet); 
		return m_LeaseSet;
	}	
		
	I2NPMessage * StreamingDestination::CreateLeaseSet () const
	{
		I2NPMessage * m = NewI2NPMessage ();
		I2NPDatabaseStoreMsg * msg = (I2NPDatabaseStoreMsg *)m->GetPayload ();
		memcpy (msg->key, (const uint8_t *)m_IdentHash, 32);
		msg->type = 1; // LeaseSet
		msg->replyToken = 0;
		
		uint8_t * buf = m->GetPayload () + sizeof (I2NPDatabaseStoreMsg);
		size_t size = 0;
		memcpy (buf + size, &m_Keys.pub, sizeof (m_Keys.pub));
		size += sizeof (m_Keys.pub); // destination
		memcpy (buf + size, m_Pool->GetEncryptionPublicKey (), 256);
		size += 256; // encryption key
		memset (buf + size, 0, 128);
		size += 128; // signing key
		auto tunnels = m_Pool->GetInboundTunnels (5); // 5 tunnels maximum
		buf[size] = tunnels.size (); // num leases
		size++; // num	
		for (auto it: tunnels)
		{	
			auto tunnel = it;	
			memcpy (buf + size, (const uint8_t *)tunnel->GetNextIdentHash (), 32);
			size += 32; // tunnel_gw
			*(uint32_t *)(buf + size) = htobe32 (tunnel->GetNextTunnelID ());
			size += 4; // tunnel_id
			uint64_t ts = tunnel->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - 60; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			*(uint64_t *)(buf + size) = htobe64 (ts);
			size += 8; // end_date
		}	
		Sign (buf, size, buf+ size);
		size += 40; // signature
		LogPrint ("Local LeaseSet of ", tunnels.size (), " leases created");
		m->len += size + sizeof (I2NPDatabaseStoreMsg);
		FillI2NPMessageHeader (m, eI2NPDatabaseStore);
		return m;
	}	

	void StreamingDestination::Sign (uint8_t * buf, int len, uint8_t * signature) const
	{
		CryptoPP::DSA::Signer signer (m_SigningPrivateKey);
		signer.SignMessage (i2p::context.GetRandomNumberGenerator (), buf, len, signature);
	}

	StreamingDestinations destinations;	
	void StreamingDestinations::Start ()
	{
		if (!m_SharedLocalDestination)
			m_SharedLocalDestination = new StreamingDestination ();
		
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&StreamingDestinations::Run, this));
	}
		
	void StreamingDestinations::Stop ()
	{
		delete m_SharedLocalDestination;
		
		m_IsRunning = false;
		m_Service.stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
	}	
		
	void StreamingDestinations::Run ()
	{
		m_Service.run ();
	}	

	Stream * StreamingDestinations::CreateClientStream (const i2p::data::LeaseSet& remote)
	{
		if (!m_SharedLocalDestination) return nullptr;
		return m_SharedLocalDestination->CreateNewStream (m_Service, remote);
	}
		
	void StreamingDestinations::DeleteClientStream (Stream * stream)
	{
		if (m_SharedLocalDestination)
			m_SharedLocalDestination->DeleteStream (stream);
		else
			delete stream;
	}	

	void StreamingDestinations::HandleNextPacket (i2p::data::IdentHash destination, Packet * packet)
	{
		m_Service.post (boost::bind (&StreamingDestinations::PostNextPacket, this, destination, packet)); 
	}	
	
	void StreamingDestinations::PostNextPacket (i2p::data::IdentHash destination, Packet * packet)
	{
		// TODO: we have onle one destination, might be more
		if (m_SharedLocalDestination)
			m_SharedLocalDestination->HandleNextPacket (packet);
	}	
		
	Stream * CreateStream (const i2p::data::LeaseSet& remote)
	{
		return destinations.CreateClientStream (remote);
	}
		
	void DeleteStream (Stream * stream)
	{
		destinations.DeleteClientStream (stream);
	}	

	void StartStreaming ()
	{
		destinations.Start ();
	}
		
	void StopStreaming ()
	{
		destinations.Stop ();
	}	
		
	void HandleDataMessage (i2p::data::IdentHash destination, const uint8_t * buf, size_t len)
	{
		uint32_t length = be32toh (*(uint32_t *)buf);
		buf += 4;
		// we assume I2CP payload
		if (buf[9] == 6) // streaming protocol
		{	
			// unzip it
			CryptoPP::Gunzip decompressor;
			decompressor.Put (buf, length);
			decompressor.MessageEnd();
			Packet * uncompressed = new Packet;
			uncompressed->offset = 0;
			uncompressed->len = decompressor.MaxRetrievable ();
			if (uncompressed->len > MAX_PACKET_SIZE)
			{
				LogPrint ("Recieved packet size exceeds mac packet size");
				uncompressed->len = MAX_PACKET_SIZE;
			}	
			decompressor.Get (uncompressed->buf, uncompressed->len);
			// then forward to streaming engine thread
			destinations.HandleNextPacket (destination, uncompressed);
		}	
		else
			LogPrint ("Data: protocol ", buf[9], " is not supported");
	}	

	I2NPMessage * CreateDataMessage (Stream * s, const uint8_t * payload, size_t len)
	{
		I2NPMessage * msg = NewI2NPMessage ();
		CryptoPP::Gzip compressor;
		compressor.SetDeflateLevel (CryptoPP::Gzip::MIN_DEFLATE_LEVEL);
		compressor.Put (payload, len);
		compressor.MessageEnd();
		int size = compressor.MaxRetrievable ();
		uint8_t * buf = msg->GetPayload ();
		*(uint32_t *)buf = htobe32 (size); // length
		buf += 4;
		compressor.Get (buf, size);
		memset (buf + 4, 0, 4); // source and destination ports. TODO: fill with proper values later
		buf[9] = 6; // streaming protocol
		msg->len += size + 4; 
		FillI2NPMessageHeader (msg, eI2NPData);
		
		return msg;
	}	
}		
}	
