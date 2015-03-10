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
		std::shared_ptr<const i2p::data::LeaseSet> remote, int port): m_Service (service),
		m_SendStreamID (0), m_SequenceNumber (0), m_LastReceivedSequenceNumber (-1), 
		m_Status (eStreamStatusNew), m_IsAckSendScheduled (false), m_LocalDestination (local), 
		m_RemoteLeaseSet (remote), m_ReceiveTimer (m_Service), m_ResendTimer (m_Service), 
		m_AckSendTimer (m_Service),  m_NumSentBytes (0), m_NumReceivedBytes (0), m_Port (port), 
		m_WindowSize (MIN_WINDOW_SIZE), m_RTT (INITIAL_RTT), m_RTO (INITIAL_RTO),
		m_LastWindowSizeIncreaseTime (0)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
		UpdateCurrentRemoteLease ();
	}	

	Stream::Stream (boost::asio::io_service& service, StreamingDestination& local):
		m_Service (service), m_SendStreamID (0), m_SequenceNumber (0), m_LastReceivedSequenceNumber (-1), 
		m_Status (eStreamStatusNew), m_IsAckSendScheduled (false), m_LocalDestination (local),
		m_ReceiveTimer (m_Service), m_ResendTimer (m_Service), m_AckSendTimer (m_Service), 
		m_NumSentBytes (0), m_NumReceivedBytes (0), m_Port (0),  m_WindowSize (MIN_WINDOW_SIZE), 
		m_RTT (INITIAL_RTT), m_RTO (INITIAL_RTO), m_LastWindowSizeIncreaseTime (0)
	{
		m_RecvStreamID = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
	}

	Stream::~Stream ()
	{	
		Terminate ();
		while (!m_ReceiveQueue.empty ())
		{
			auto packet = m_ReceiveQueue.front ();
			m_ReceiveQueue.pop ();
			delete packet;
		}
		
		for (auto it: m_SentPackets)
			delete it;
		m_SentPackets.clear ();
		
		for (auto it: m_SavedPackets)
			delete it;
		m_SavedPackets.clear ();
			
		LogPrint (eLogDebug, "Stream deleted");
	}	

	void Stream::Terminate ()
	{
		m_AckSendTimer.cancel ();
		m_ReceiveTimer.cancel ();
		m_ResendTimer.cancel ();
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
			LogPrint (eLogDebug, "Plain ACK received");
			delete packet;
			return;
		}

		LogPrint (eLogDebug, "Received seqn=", receivedSeqn); 
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
			if (m_Status == eStreamStatusOpen)
			{
				if (!m_IsAckSendScheduled)
				{
					m_IsAckSendScheduled = true;
					m_AckSendTimer.expires_from_now (boost::posix_time::milliseconds(ACK_SEND_TIMEOUT));
					m_AckSendTimer.async_wait (std::bind (&Stream::HandleAckSendTimer,
						shared_from_this (), std::placeholders::_1));
				}
			}	
			else if (isSyn)
				// we have to send SYN back to incoming connection
				SendBuffer (); // also sets m_IsOpen				
		}	
		else 
		{	
			if (receivedSeqn <= m_LastReceivedSequenceNumber)
			{
				// we have received duplicate
				LogPrint (eLogWarning, "Duplicate message ", receivedSeqn, " received");
				SendQuickAck (); // resend ack for previous message again
				delete packet; // packet dropped
			}	
			else
			{
				LogPrint (eLogWarning, "Missing messages from ", m_LastReceivedSequenceNumber + 1, " to ", receivedSeqn - 1);
				// save message and wait for missing message again
				SavePacket (packet);
				// send NACKs for missing messages ASAP
				if (m_IsAckSendScheduled)
				{
					m_IsAckSendScheduled = false;	
					m_AckSendTimer.cancel ();
				}
				SendQuickAck ();
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
		LogPrint (eLogDebug, "Process seqn=", receivedSeqn, ", flags=", flags);
		
		const uint8_t * optionData = packet->GetOptionData ();
		if (flags & PACKET_FLAG_SYNCHRONIZE)
			LogPrint (eLogDebug, "Synchronize");

		if (flags & PACKET_FLAG_DELAY_REQUESTED)
		{
			optionData += 2;
		}	
		
		if (flags & PACKET_FLAG_FROM_INCLUDED)
		{
			optionData += m_RemoteIdentity.FromBuffer (optionData, packet->GetOptionSize ());
			LogPrint (eLogInfo, "From identity ", m_RemoteIdentity.GetIdentHash ().ToBase64 ());		
			if (!m_RemoteLeaseSet)
				LogPrint (eLogDebug, "Incoming stream from ", m_RemoteIdentity.GetIdentHash ().ToBase64 ());
		}	

		if (flags & PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED)
		{
			uint16_t maxPacketSize = bufbe16toh (optionData);
			LogPrint (eLogDebug, "Max packet size ", maxPacketSize);
			optionData += 2;
		}	
		
		if (flags & PACKET_FLAG_SIGNATURE_INCLUDED)
		{
			LogPrint (eLogDebug, "Signature");
			uint8_t signature[256]; 
			auto signatureLen = m_RemoteIdentity.GetSignatureLen ();
			memcpy (signature, optionData, signatureLen);
			memset (const_cast<uint8_t *>(optionData), 0, signatureLen);
			if (!m_RemoteIdentity.Verify (packet->GetBuffer (), packet->GetLength (), signature))
			{  
				LogPrint (eLogError, "Signature verification failed");
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
			LogPrint (eLogInfo, "Closed");
			m_Status = eStreamStatusReset;
			Close ();
		}
	}	

	void Stream::ProcessAck (Packet * packet)
	{
		bool acknowledged = false;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
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
						LogPrint (eLogDebug, "Packet ", seqn, " NACK");
						it++;
						continue;
					}	
				}
				auto sentPacket = *it;
				uint64_t rtt = ts - sentPacket->sendTime;
				m_RTT = (m_RTT*seqn + rtt)/(seqn + 1);
				m_RTO = m_RTT*1.5; // TODO: implement it better
				LogPrint (eLogDebug, "Packet ", seqn, " acknowledged rtt=", rtt);
				m_SentPackets.erase (it++);
				delete sentPacket;	
				acknowledged = true;
				if (m_WindowSize < WINDOW_SIZE)
					m_WindowSize++; // slow start
				else
				{
					// linear growth
					if (ts > m_LastWindowSizeIncreaseTime + m_RTT)
					{
						m_WindowSize++;
						if (m_WindowSize > MAX_WINDOW_SIZE) m_WindowSize = MAX_WINDOW_SIZE;
						m_LastWindowSizeIncreaseTime = ts;
					}
				}
			}
			else
				break;
		}
		if (m_SentPackets.empty ())
			m_ResendTimer.cancel ();
		if (acknowledged)
			SendBuffer ();
		if (m_Status == eStreamStatusClosing)
			Close (); // all outgoing messages have been sent
	}		
		
	size_t Stream::Send (const uint8_t * buf, size_t len)
	{
		if (len > 0 && buf)
		{
			std::unique_lock<std::mutex> l(m_SendBufferMutex);
			m_SendBuffer.clear ();
			m_SendBuffer.write ((const char *)buf, len);
		}	
		m_Service.post (std::bind (&Stream::SendBuffer, shared_from_this ()));
		return len;
	}	

	void Stream::SendBuffer ()
	{	
		int numMsgs = m_WindowSize - m_SentPackets.size ();
		if (numMsgs <= 0) return; // window is full 
		
		bool isNoAck = m_LastReceivedSequenceNumber < 0; // first packet
		std::vector<Packet *> packets;
		{
			std::unique_lock<std::mutex> l(m_SendBufferMutex);
			while ((m_Status == eStreamStatusNew) || (IsEstablished () && !m_SendBuffer.eof () && numMsgs > 0))
			{
				Packet * p = new Packet ();
				uint8_t * packet = p->GetBuffer ();
				// TODO: implement setters
				size_t size = 0;
				htobe32buf (packet + size, m_SendStreamID);
				size += 4; // sendStreamID
				htobe32buf (packet + size, m_RecvStreamID);
				size += 4; // receiveStreamID
				htobe32buf (packet + size, m_SequenceNumber++);
				size += 4; // sequenceNum
				if (isNoAck)			
					htobe32buf (packet + size, m_LastReceivedSequenceNumber);
				else
					htobuf32 (packet + size, 0);
				size += 4; // ack Through
				packet[size] = 0; 
				size++; // NACK count
				packet[size] = m_RTO/1000;
				size++; // resend delay
				if (m_Status == eStreamStatusNew)
				{	
					//  initial packet
					m_Status = eStreamStatusOpen;
					uint16_t flags = PACKET_FLAG_SYNCHRONIZE | PACKET_FLAG_FROM_INCLUDED | 
						PACKET_FLAG_SIGNATURE_INCLUDED | PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED;
					if (isNoAck) flags |= PACKET_FLAG_NO_ACK;
					htobe16buf (packet + size, flags);
					size += 2; // flags
					size_t identityLen = m_LocalDestination.GetOwner ().GetIdentity ().GetFullLen ();
					size_t signatureLen = m_LocalDestination.GetOwner ().GetIdentity ().GetSignatureLen ();
					htobe16buf (packet + size, identityLen + signatureLen + 2); // identity + signature + packet size
					size += 2; // options size
					m_LocalDestination.GetOwner ().GetIdentity ().ToBuffer (packet + size, identityLen); 
					size += identityLen; // from
					htobe16buf (packet + size, STREAMING_MTU);
					size += 2; // max packet size
					uint8_t * signature = packet + size; // set it later
					memset (signature, 0, signatureLen); // zeroes for now
					size += signatureLen; // signature
					m_SendBuffer.read ((char *)(packet + size), STREAMING_MTU - size);
					size += m_SendBuffer.gcount (); // payload
					m_LocalDestination.GetOwner ().Sign (packet, size, signature);
				}	
				else
				{
					// follow on packet
					htobuf16 (packet + size, 0);
					size += 2; // flags
					htobuf16 (packet + size, 0); // no options
					size += 2; // options size
					m_SendBuffer.read((char *)(packet + size), STREAMING_MTU - size);  
					size += m_SendBuffer.gcount (); // payload
				}	
				p->len = size;
				packets.push_back (p);
				numMsgs--;
			}
		}	
		if (packets.size () > 0)
		{
			m_IsAckSendScheduled = false;	
			m_AckSendTimer.cancel ();
			bool isEmpty = m_SentPackets.empty ();
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			for (auto it: packets)
			{
				it->sendTime = ts;
				m_SentPackets.insert (it);
			}
			SendPackets (packets);
			if (m_Status == eStreamStatusClosing && m_SendBuffer.eof ())
				SendClose ();
			if (isEmpty)
				ScheduleResend ();
		}	
	}
		
	void Stream::SendQuickAck ()
	{
		int32_t lastReceivedSeqn = m_LastReceivedSequenceNumber;
		if (!m_SavedPackets.empty ())
		{
			int32_t seqn = (*m_SavedPackets.rbegin ())->GetSeqn ();
			if (seqn > lastReceivedSeqn) lastReceivedSeqn = seqn;
		}	
		if (lastReceivedSeqn < 0) 
		{	
			LogPrint (eLogError, "No packets have been received yet");
			return;
		}
		
		Packet p;
		uint8_t * packet = p.GetBuffer ();	
		size_t size = 0;
		htobe32buf (packet + size, m_SendStreamID);
		size += 4; // sendStreamID
		htobe32buf (packet + size, m_RecvStreamID);
		size += 4; // receiveStreamID
		htobuf32 (packet + size, 0); // this is plain Ack message
		size += 4; // sequenceNum
		htobe32buf (packet + size, lastReceivedSeqn);
		size += 4; // ack Through
		uint8_t numNacks = 0;
		if (lastReceivedSeqn > m_LastReceivedSequenceNumber) 
		{	
			// fill NACKs
			uint8_t * nacks = packet + size + 1;
			auto nextSeqn = m_LastReceivedSequenceNumber + 1;
			for (auto it: m_SavedPackets)
			{
				auto seqn = it->GetSeqn ();
				if (numNacks + (seqn - nextSeqn) >= 256)
				{
					LogPrint (eLogError, "Number of NACKs exceeds 256. seqn=", seqn, " nextSeqn=", nextSeqn);
					htobe32buf (packet + 12, nextSeqn); // change ack Through
					break;
				}	
				for (uint32_t i = nextSeqn; i < seqn; i++)
				{
					htobe32buf (nacks, i);
					nacks += 4;
					numNacks++;
				}	
				nextSeqn = seqn + 1;
			}
			packet[size] = numNacks; 
			size++; // NACK count	
			size += numNacks*4; // NACKs
		}	
		else
		{
			// No NACKs
			packet[size] = 0; 
			size++; // NACK count		
		}	
		size++; // resend delay
		htobuf16 (packet + size, 0); // nof flags set
		size += 2; // flags
		htobuf16 (packet + size, 0); // no options
		size += 2; // options size
		p.len = size;		

		SendPackets (std::vector<Packet *> { &p });
		LogPrint ("Quick Ack sent. ", (int)numNacks, " NACKs");
	}	

	void Stream::Close ()
	{
		switch (m_Status)
		{
			case eStreamStatusOpen:
				m_Status = eStreamStatusClosing;
				Close (); // recursion
				if (m_Status == eStreamStatusClosing) //still closing
					LogPrint (eLogInfo, "Trying to send stream data before closing");
			break;
			case eStreamStatusReset:
				SendClose ();
				Terminate ();
				m_LocalDestination.DeleteStream (shared_from_this ());	
			break;
			case eStreamStatusClosing:
				if (m_SentPackets.empty () && m_SendBuffer.eof ()) // nothing to send
				{
					m_Status = eStreamStatusClosed;
					SendClose ();
					Terminate ();
					m_LocalDestination.DeleteStream (shared_from_this ());	
				}
			break;
			case eStreamStatusClosed:
				// already closed
				Terminate ();
				m_LocalDestination.DeleteStream (shared_from_this ());		
			break;				
			default:
				LogPrint (eLogWarning, "Unexpected stream status ", (int)m_Status);
		};			
	}

	void Stream::SendClose ()
	{
		Packet * p = new Packet ();
		uint8_t * packet = p->GetBuffer ();
		size_t size = 0;
		htobe32buf (packet + size, m_SendStreamID);
		size += 4; // sendStreamID
		htobe32buf (packet + size, m_RecvStreamID);
		size += 4; // receiveStreamID
		htobe32buf (packet + size, m_SequenceNumber++);
		size += 4; // sequenceNum
		htobe32buf (packet + size, m_LastReceivedSequenceNumber);
		size += 4; // ack Through
		packet[size] = 0; 
		size++; // NACK count
		size++; // resend delay
		htobe16buf (packet + size, PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED);
		size += 2; // flags
		size_t signatureLen = m_LocalDestination.GetOwner ().GetIdentity ().GetSignatureLen ();
		htobe16buf (packet + size, signatureLen); // signature only
		size += 2; // options size
		uint8_t * signature = packet + size;
		memset (packet + size, 0, signatureLen);
		size += signatureLen; // signature
		m_LocalDestination.GetOwner ().Sign (packet, size, signature);
		
		p->len = size;
		m_Service.post (std::bind (&Stream::SendPacket, shared_from_this (), p));
		LogPrint ("FIN sent");
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
			if (m_Status == eStreamStatusOpen)
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
		if (!m_CurrentOutboundTunnel || !m_CurrentOutboundTunnel->IsEstablished ())
			m_CurrentOutboundTunnel = m_LocalDestination.GetOwner ().GetTunnelPool ()->GetNextOutboundTunnel ();
		if (!m_CurrentOutboundTunnel)
		{
			LogPrint ("No outbound tunnels in the pool");
			return;
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
			m_CurrentOutboundTunnel->SendTunnelDataMsg (msgs);
		}	
		else
			LogPrint ("All leases are expired");
	}

	void Stream::ScheduleResend ()
	{
		m_ResendTimer.cancel ();
		m_ResendTimer.expires_from_now (boost::posix_time::milliseconds(m_RTO));
		m_ResendTimer.async_wait (std::bind (&Stream::HandleResendTimer,
			shared_from_this (), std::placeholders::_1));
	}
		
	void Stream::HandleResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			bool congesion = false, first = true;
			std::vector<Packet *> packets;
			for (auto it : m_SentPackets)
			{
				if (ts < it->sendTime + m_RTO) continue; // don't resend too early
				it->numResendAttempts++;
				if (first && it->numResendAttempts == 1) // detect congesion at first attempt of first packet only
					congesion = true;
				first = false;
				if (it->numResendAttempts <= MAX_NUM_RESEND_ATTEMPTS)
				{
					it->sendTime = ts;
					packets.push_back (it);
				}
				else
				{
					LogPrint (eLogWarning, "Packet ", it->GetSeqn (), " was not ACKed after ", MAX_NUM_RESEND_ATTEMPTS,  " attempts. Terminate");
					m_Status = eStreamStatusReset;
					Close ();
					return;
				}	
			}	
			if (packets.size () > 0)
			{
				if (congesion)
				{
					// congesion avoidance
					m_WindowSize /= 2;
					if (m_WindowSize < MIN_WINDOW_SIZE) m_WindowSize = MIN_WINDOW_SIZE; 
				}	
				else
				{	
					// congesion avoidance didn't help
					m_CurrentOutboundTunnel = nullptr; // pick another outbound tunnel 
					UpdateCurrentRemoteLease (); // pick another lease
					m_RTO = INITIAL_RTO; // drop RTO to initial upon tunnels pair change
				}	
				SendPackets (packets);
			}	
			ScheduleResend ();
		}	
	}	
		
	void Stream::HandleAckSendTimer (const boost::system::error_code& ecode)
	{
		if (m_IsAckSendScheduled)
		{
			if (m_Status == eStreamStatusOpen)
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
				m_RoutingSession = m_LocalDestination.GetOwner ().GetRoutingSession (m_RemoteLeaseSet, 32);
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
		htobe32buf (buf, size); // length
		buf += 4;
		compressor.Get (buf, size);
		htobe16buf (buf + 4, m_LocalDestination.GetLocalPort ()); // source port
		htobe16buf (buf + 6, m_Port); // destination port 
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
				LogPrint ("Unknown stream sendStreamID=", sendStreamID);
				delete packet;
			}
		}	
		else 
		{
			if (packet->IsSYN () && !packet->GetSeqn ()) // new incoming stream
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
			else // follow on packet without SYN
			{
				uint32_t receiveStreamID = packet->GetReceiveStreamID ();
				for (auto it: m_Streams)
					if (it.second->GetSendStreamID () == receiveStreamID)
					{
						// found
						it.second->HandleNextPacket (packet);
						return;
					}
				// TODO: should queue it up
				LogPrint ("Unknown stream receiveStreamID=", receiveStreamID);
				delete packet;
			}	
		}	
	}	

	std::shared_ptr<Stream> StreamingDestination::CreateNewOutgoingStream (std::shared_ptr<const i2p::data::LeaseSet> remote, int port)
	{
		auto s = std::make_shared<Stream> (m_Owner.GetService (), *this, remote, port);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}	

	std::shared_ptr<Stream> StreamingDestination::CreateNewIncomingStream ()
	{
		auto s = std::make_shared<Stream> (m_Owner.GetService (), *this);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}

	void StreamingDestination::DeleteStream (std::shared_ptr<Stream> stream)
	{
		if (stream)
		{	
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			auto it = m_Streams.find (stream->GetRecvStreamID ());
			if (it != m_Streams.end ())
				m_Streams.erase (it);
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
}		
}	
