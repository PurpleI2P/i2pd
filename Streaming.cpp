#include <cryptopp/gzip.h>
#include "Log.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "Destination.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	Stream::Stream (boost::asio::io_service& service, StreamingDestination& local, 
		const i2p::data::LeaseSet& remote, int port): m_Service (service), m_SendStreamID (0), 
		m_SequenceNumber (0), m_LastReceivedSequenceNumber (-1), m_IsOpen (false), 
		m_IsReset (false), m_IsAckSendScheduled (false), m_LocalDestination (local), 
		m_RemoteLeaseSet (&remote), m_RoutingSession (nullptr), m_ReceiveTimer (m_Service),
		m_ResendTimer (m_Service), m_AckSendTimer (m_Service), m_NumSentBytes (0), 
		m_NumReceivedBytes (0), m_Port (port)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
		UpdateCurrentRemoteLease ();
	}	

	Stream::Stream (boost::asio::io_service& service, StreamingDestination& local):
		m_Service (service), m_SendStreamID (0), m_SequenceNumber (0), m_LastReceivedSequenceNumber (-1), 
		m_IsOpen (false), m_IsReset (false), m_IsAckSendScheduled (false), m_LocalDestination (local),
		m_RemoteLeaseSet (nullptr), m_RoutingSession (nullptr), m_ReceiveTimer (m_Service), 
		m_ResendTimer (m_Service), m_AckSendTimer (m_Service), m_NumSentBytes (0), 
		m_NumReceivedBytes (0), m_Port (0)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
	}

	Stream::~Stream ()
	{	
		m_AckSendTimer.cancel ();
		while (!m_ReceiveQueue.empty ())
		{
			auto packet = m_ReceiveQueue.front ();
			m_ReceiveQueue.pop ();
			delete packet;
		}	
		m_ReceiveTimer.cancel ();
					
		for (auto it: m_SentPackets)
			delete it;
		m_SentPackets.clear ();
		m_ResendTimer.cancel ();

		for (auto it: m_SavedPackets)
			delete it;
		m_SavedPackets.clear ();
		
		Close ();
	}	
		
	void Stream::HandleNextPacket (Packet * packet)
	{
		m_NumReceivedBytes += packet->GetLength ();
		if (!m_SendStreamID) 
			m_SendStreamID = packet->GetReceiveStreamID (); 	

		if (!packet->IsNoAck ()) // ack received
			ProcessAck (packet);
		
		int32_t receivedSeqn = packet->GetSeqn ();
		bool isSyn = packet->IsSYN ();
		if (!receivedSeqn && !isSyn)
		{
			// plain ack
			LogPrint ("Plain ACK received");
			delete packet;
			return;
		}

		LogPrint ("Received seqn=", receivedSeqn); 
		if (isSyn || receivedSeqn == m_LastReceivedSequenceNumber + 1)
		{			
			// we have received next in sequence message
			ProcessPacket (packet);
			
			// we should also try stored messages if any
			for (auto it = m_SavedPackets.begin (); it != m_SavedPackets.end ();)
			{			
				if ((*it)->GetSeqn () == (uint32_t)(m_LastReceivedSequenceNumber + 1))
				{
					Packet * savedPacket = *it;
					m_SavedPackets.erase (it++);

					ProcessPacket (savedPacket);
				}
				else
					break;
			}

			// schedule ack for last message
			if (m_IsOpen)
			{
				if (!m_IsAckSendScheduled)
				{
					m_IsAckSendScheduled = true;
					m_AckSendTimer.expires_from_now (boost::posix_time::milliseconds(ACK_SEND_TIMEOUT));
					m_AckSendTimer.async_wait (boost::bind (&Stream::HandleAckSendTimer,
						this, boost::asio::placeholders::error));
				}
			}	
			else if (isSyn)
				// we have to send SYN back to incoming connection
				Send (nullptr, 0); // also sets m_IsOpen				
		}	
		else 
		{	
			if (receivedSeqn <= m_LastReceivedSequenceNumber)
			{
				// we have received duplicate. Most likely our outbound tunnel is dead
				LogPrint ("Duplicate message ", receivedSeqn, " received");
				m_LocalDestination.GetOwner ().ResetCurrentOutboundTunnel (); // pick another outbound tunnel 
				UpdateCurrentRemoteLease (); // pick another lease
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
			LogPrint ("Synchronize");

		if (flags & PACKET_FLAG_DELAY_REQUESTED)
		{
			optionData += 2;
		}	
		
		if (flags & PACKET_FLAG_FROM_INCLUDED)
		{
			optionData += m_RemoteIdentity.FromBuffer (optionData, packet->GetOptionSize ());
			LogPrint ("From identity ", m_RemoteIdentity.GetIdentHash ().ToBase64 ());		
			if (!m_RemoteLeaseSet)
				LogPrint ("Incoming stream from ", m_RemoteIdentity.GetIdentHash ().ToBase64 ());
		}	

		if (flags & PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED)
		{
			uint16_t maxPacketSize = be16toh (*(uint16_t *)optionData);
			LogPrint ("Max packet size ", maxPacketSize);
			optionData += 2;
		}	
		
		if (flags & PACKET_FLAG_SIGNATURE_INCLUDED)
		{
			LogPrint ("Signature");
			uint8_t signature[256]; 
			auto signatureLen = m_RemoteIdentity.GetSignatureLen ();
			memcpy (signature, optionData, signatureLen);
			memset (const_cast<uint8_t *>(optionData), 0, signatureLen);
			if (!m_RemoteIdentity.Verify (packet->GetBuffer (), packet->GetLength (), signature))
			{  
				LogPrint ("Signature verification failed");
			    Close ();
				flags |= PACKET_FLAG_CLOSE;
			}	
			memcpy (const_cast<uint8_t *>(optionData), signature, signatureLen);
			optionData += signatureLen;
		}	

		packet->offset = packet->GetPayload () - packet->buf;
		if (packet->GetLength () > 0)
		{	
			m_ReceiveQueue.push (packet);
			m_ReceiveTimer.cancel ();
		}	
		else
			delete packet;
		
		m_LastReceivedSequenceNumber = receivedSeqn;

		if (flags & PACKET_FLAG_CLOSE)
		{
			LogPrint ("Closed");
			SendQuickAck (); // send ack for close explicitly?
			m_IsOpen = false;
			m_IsReset = true;
			m_ReceiveTimer.cancel ();
			m_ResendTimer.cancel ();
			m_AckSendTimer.cancel ();
		}
	}	

	void Stream::ProcessAck (Packet * packet)
	{
		uint32_t ackThrough = packet->GetAckThrough ();
		int nackCount = packet->GetNACKCount ();
		for (auto it = m_SentPackets.begin (); it != m_SentPackets.end ();)
		{			
			auto seqn = (*it)->GetSeqn ();
			if (seqn <= ackThrough)
			{
				if (nackCount > 0)
				{
					bool nacked = false;
					for (int i = 0; i < nackCount; i++)
						if (seqn == packet->GetNACK (i))
						{
							nacked = true;
							break;
						}
					if (nacked)
					{
						LogPrint ("Packet ", seqn, " NACK");
						it++;
						continue;
					}	
				}
				auto sentPacket = *it;
				LogPrint ("Packet ", seqn, " acknowledged");
				m_SentPackets.erase (it++);
				delete sentPacket;	
			}
			else
				break;
		}
		if (m_SentPackets.empty ())
			m_ResendTimer.cancel ();
	}		
		
	size_t Stream::Send (const uint8_t * buf, size_t len)
	{
		bool isNoAck = m_LastReceivedSequenceNumber < 0; // first packet
		while (!m_IsOpen || len > 0)
		{
			Packet * p = new Packet ();
			uint8_t * packet = p->GetBuffer ();
			// TODO: implement setters
			size_t size = 0;
			*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
			size += 4; // sendStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
			size += 4; // receiveStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_SequenceNumber++);
			size += 4; // sequenceNum
			if (isNoAck)			
				*(uint32_t *)(packet + size) = htobe32 (m_LastReceivedSequenceNumber);
			else
				*(uint32_t *)(packet + size) = 0;
			size += 4; // ack Through
			packet[size] = 0; 
			size++; // NACK count
			size++; // resend delay
			if (!m_IsOpen)
			{	
				//  initial packet
				m_IsOpen = true; m_IsReset = false;
				uint16_t flags = PACKET_FLAG_SYNCHRONIZE | PACKET_FLAG_FROM_INCLUDED | 
					PACKET_FLAG_SIGNATURE_INCLUDED | PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED;
				if (isNoAck) flags |= PACKET_FLAG_NO_ACK;
				*(uint16_t *)(packet + size) = htobe16 (flags);
				size += 2; // flags
				size_t identityLen = m_LocalDestination.GetOwner ().GetIdentity ().GetFullLen ();
				size_t signatureLen = m_LocalDestination.GetOwner ().GetIdentity ().GetSignatureLen ();
				*(uint16_t *)(packet + size) = htobe16 (identityLen + signatureLen + 2); // identity + signature + packet size
				size += 2; // options size
				m_LocalDestination.GetOwner ().GetIdentity ().ToBuffer (packet + size, identityLen); 
				size += identityLen; // from
				*(uint16_t *)(packet + size) = htobe16 (STREAMING_MTU);
				size += 2; // max packet size
				uint8_t * signature = packet + size; // set it later
				memset (signature, 0, signatureLen); // zeroes for now
				size += signatureLen; // signature
				size_t sentLen = STREAMING_MTU - size;
				if (len < sentLen) sentLen = len;		
				memcpy (packet + size, buf, sentLen); 
				buf += sentLen;
				len -= sentLen;
				size += sentLen; // payload
				m_LocalDestination.GetOwner ().Sign (packet, size, signature);
			}	
			else
			{
				// follow on packet
				*(uint16_t *)(packet + size) = 0;
				size += 2; // flags
				*(uint16_t *)(packet + size) = 0; // no options
				size += 2; // options size
				size_t sentLen = STREAMING_MTU - size;
				if (len < sentLen) sentLen = len;		
				memcpy (packet + size, buf, sentLen); 
				buf += sentLen;
				len -= sentLen;
				size += sentLen; // payload
			}	
			p->len = size;
			m_Service.post (boost::bind (&Stream::SendPacket, this, p));
		}

		return len;
	}	

		
	void Stream::SendQuickAck ()
	{
		Packet p;
		uint8_t * packet = p.GetBuffer ();	
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
		p.len = size;		

		SendPackets (std::vector<Packet *> { &p });
		LogPrint ("Quick Ack sent");
	}	

	void Stream::Close ()
	{
		if (m_IsOpen)
		{	
			m_IsOpen = false;
			Packet * p = new Packet ();
			uint8_t * packet = p->GetBuffer ();
			size_t size = 0;
			*(uint32_t *)(packet + size) = htobe32 (m_SendStreamID);
			size += 4; // sendStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_RecvStreamID);
			size += 4; // receiveStreamID
			*(uint32_t *)(packet + size) = htobe32 (m_SequenceNumber++);
			size += 4; // sequenceNum
			*(uint32_t *)(packet + size) = htobe32 (m_LastReceivedSequenceNumber);
			size += 4; // ack Through
			packet[size] = 0; 
			size++; // NACK count
			size++; // resend delay
			*(uint16_t *)(packet + size) = htobe16 (PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED);
			size += 2; // flags
			size_t signatureLen = m_LocalDestination.GetOwner ().GetIdentity ().GetSignatureLen ();
			*(uint16_t *)(packet + size) = htobe16 (signatureLen); // signature only
			size += 2; // options size
			uint8_t * signature = packet + size;
			memset (packet + size, 0, signatureLen);
			size += signatureLen; // signature
			m_LocalDestination.GetOwner ().Sign (packet, size, signature);
			
			p->len = size;
			SendPacket (p);
			LogPrint ("FIN sent");
		}	
	}

	size_t Stream::ConcatenatePackets (uint8_t * buf, size_t len)
	{
		size_t pos = 0;
		while (pos < len && !m_ReceiveQueue.empty ())
		{
			Packet * packet = m_ReceiveQueue.front ();
			size_t l = std::min (packet->GetLength (), len - pos);
			memcpy (buf + pos, packet->GetBuffer (), l);
			pos += l;
			packet->offset += l;
			if (!packet->GetLength ())
			{
				m_ReceiveQueue.pop ();
				delete packet;
			}	
		}	
		return pos; 
	}

	bool Stream::SendPacket (Packet * packet)
	{
		if (packet)
		{	
			if (m_IsAckSendScheduled)
			{
				m_IsAckSendScheduled = false;	
				m_AckSendTimer.cancel ();
			}
			SendPackets (std::vector<Packet *> { packet });
			if (m_IsOpen)
			{	
				bool isEmpty = m_SentPackets.empty ();
				m_SentPackets.insert (packet);
				if (isEmpty)
					ScheduleResend ();
			}	
			else
				delete packet;
			return true;	
		}	
		else
			return false;
	}	
	
	void Stream::SendPackets (const std::vector<Packet *>& packets)
	{
		if (!m_RemoteLeaseSet)
		{
			UpdateCurrentRemoteLease ();	
			if (!m_RemoteLeaseSet)
			{
				LogPrint ("Can't send packets. Missing remote LeaseSet");
				return;
			}
		}

		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (ts >= m_CurrentRemoteLease.endDate)
			UpdateCurrentRemoteLease ();
		if (ts < m_CurrentRemoteLease.endDate)
		{	
			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
			for (auto it: packets)
			{ 
				auto msg = m_RoutingSession->WrapSingleMessage (CreateDataMessage (it->GetBuffer (), it->GetLength ()));
				msgs.push_back (i2p::tunnel::TunnelMessageBlock 
							{ 
								i2p::tunnel::eDeliveryTypeTunnel,
								m_CurrentRemoteLease.tunnelGateway, m_CurrentRemoteLease.tunnelID,
								msg
							});	
				m_NumSentBytes += it->GetLength ();
			}
			m_LocalDestination.GetOwner ().SendTunnelDataMsgs (msgs);
		}	
		else
			LogPrint ("All leases are expired");
	}

	void Stream::ScheduleResend ()
	{
		m_ResendTimer.cancel ();
		m_ResendTimer.expires_from_now (boost::posix_time::seconds(RESEND_TIMEOUT));
		m_ResendTimer.async_wait (boost::bind (&Stream::HandleResendTimer,
			this, boost::asio::placeholders::error));
	}
		
	void Stream::HandleResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			std::vector<Packet *> packets;
			for (auto it : m_SentPackets)
			{
				it->numResendAttempts++;
				if (it->numResendAttempts <= MAX_NUM_RESEND_ATTEMPTS)
					packets.push_back (it);
				else
				{
					Close ();
					m_IsReset = true;
					m_ReceiveTimer.cancel ();
					return;
				}	
			}	
			if (packets.size () > 0)
			{
				m_LocalDestination.GetOwner ().ResetCurrentOutboundTunnel (); // pick another outbound tunnel 
				UpdateCurrentRemoteLease (); // pick another lease
				SendPackets (packets);
			}	
			ScheduleResend ();
		}	
	}	
		
	void Stream::HandleAckSendTimer (const boost::system::error_code& ecode)
	{
		if (m_IsAckSendScheduled)
		{
			if (m_IsOpen)
				SendQuickAck ();
			m_IsAckSendScheduled = false;
		}	
	}

	void Stream::UpdateCurrentRemoteLease ()
	{
		if (!m_RemoteLeaseSet)
		{
			m_RemoteLeaseSet = m_LocalDestination.GetOwner ().FindLeaseSet (m_RemoteIdentity.GetIdentHash ());
			if (!m_RemoteLeaseSet)		
				LogPrint ("LeaseSet ", m_RemoteIdentity.GetIdentHash ().ToBase64 (), " not found");
		}
		if (m_RemoteLeaseSet)
		{
			if (!m_RoutingSession)
				m_RoutingSession = m_LocalDestination.GetOwner ().GetRoutingSession (*m_RemoteLeaseSet, 32);
			auto leases = m_RemoteLeaseSet->GetNonExpiredLeases ();
			if (!leases.empty ())
			{	
				uint32_t i = i2p::context.GetRandomNumberGenerator ().GenerateWord32 (0, leases.size () - 1);
				m_CurrentRemoteLease = leases[i];
			}	
			else
			{	
				m_RemoteLeaseSet = m_LocalDestination.GetOwner ().FindLeaseSet (m_RemoteIdentity.GetIdentHash ()); // re-request expired
				m_CurrentRemoteLease.endDate = 0;
			}	
		}
		else
			m_CurrentRemoteLease.endDate = 0;
	}	

	I2NPMessage * Stream::CreateDataMessage (const uint8_t * payload, size_t len)
	{
		I2NPMessage * msg = NewI2NPShortMessage ();
		CryptoPP::Gzip compressor;
		if (len <= i2p::stream::COMPRESSION_THRESHOLD_SIZE)
			compressor.SetDeflateLevel (CryptoPP::Gzip::MIN_DEFLATE_LEVEL);
		else
			compressor.SetDeflateLevel (CryptoPP::Gzip::DEFAULT_DEFLATE_LEVEL);
		compressor.Put (payload, len);
		compressor.MessageEnd();
		int size = compressor.MaxRetrievable ();
		uint8_t * buf = msg->GetPayload ();
		*(uint32_t *)buf = htobe32 (size); // length
		buf += 4;
		compressor.Get (buf, size);
		*(uint16_t *)(buf + 4) = 0; // source port
		*(uint16_t *)(buf + 6) = htobe16 (m_Port); // destination port 
		buf[9] = i2p::client::PROTOCOL_TYPE_STREAMING; // streaming protocol
		msg->len += size + 4; 
		FillI2NPMessageHeader (msg, eI2NPData);
		
		return msg;
	}	
		
	void StreamingDestination::Start ()
	{	
	}
		
	void StreamingDestination::Stop ()
	{	
		ResetAcceptor ();
		{
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			for (auto it: m_Streams)
				delete it.second;	
			m_Streams.clear ();
		}	
	}	

	void StreamingDestination::HandleNextPacket (Packet * packet)
	{
		uint32_t sendStreamID = packet->GetSendStreamID ();
		if (sendStreamID)
		{	
			auto it = m_Streams.find (sendStreamID);
			if (it != m_Streams.end ())
				it->second->HandleNextPacket (packet);
			else
			{	
				LogPrint ("Unknown stream ", sendStreamID);
				delete packet;
			}
		}	
		else // new incoming stream
		{
			auto incomingStream = CreateNewIncomingStream ();
			incomingStream->HandleNextPacket (packet);
			if (m_Acceptor != nullptr)
				m_Acceptor (incomingStream);
			else
			{
				LogPrint ("Acceptor for incoming stream is not set");
				DeleteStream (incomingStream);
			}
		}	
	}	

	Stream * StreamingDestination::CreateNewOutgoingStream (const i2p::data::LeaseSet& remote, int port)
	{
		Stream * s = new Stream (*m_Owner.GetService (), *this, remote, port);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}	

	Stream * StreamingDestination::CreateNewIncomingStream ()
	{
		Stream * s = new Stream (*m_Owner.GetService (), *this);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}

	void StreamingDestination::DeleteStream (Stream * stream)
	{
		if (stream)
		{	
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			auto it = m_Streams.find (stream->GetRecvStreamID ());
			if (it != m_Streams.end ())
			{	
				m_Streams.erase (it);
				if (m_Owner.GetService ())
					m_Owner.GetService ()->post ([stream](void) { delete stream; }); 
				else
					delete stream;
			}	
		}	
	}		

	void StreamingDestination::HandleDataMessagePayload (const uint8_t * buf, size_t len)
	{
		// unzip it
		CryptoPP::Gunzip decompressor;
		decompressor.Put (buf, len);
		decompressor.MessageEnd();
		Packet * uncompressed = new Packet;
		uncompressed->offset = 0;
		uncompressed->len = decompressor.MaxRetrievable ();
		if (uncompressed->len <= MAX_PACKET_SIZE)
		{
			decompressor.Get (uncompressed->buf, uncompressed->len);
			HandleNextPacket (uncompressed); 
		}
		else
		{
			LogPrint ("Received packet size ", uncompressed->len,  " exceeds max packet size. Skipped");
			delete uncompressed;
		}	
	}

	void DeleteStream (Stream * stream)
	{
		if (stream)
			stream->GetLocalDestination ().DeleteStream (stream);
	}
}		
}	
