/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Crypto.h"
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
	void SendBufferQueue::Add (const uint8_t * buf, size_t len, SendHandler handler)
	{
		m_Buffers.push_back (std::make_shared<SendBuffer>(buf, len, handler));
		m_Size += len;
	}

	size_t SendBufferQueue::Get (uint8_t * buf, size_t len)
	{
		size_t offset = 0;
		while (!m_Buffers.empty () && offset < len)
		{
			auto nextBuffer = m_Buffers.front ();
			auto rem = nextBuffer->GetRemainingSize ();
			if (offset + rem <= len)
			{
				// whole buffer
				memcpy (buf + offset, nextBuffer->GetRemaningBuffer (), rem);
				offset += rem;
				m_Buffers.pop_front (); // delete it
			}
			else
			{
				// partially
				rem = len - offset;
				memcpy (buf + offset, nextBuffer->GetRemaningBuffer (), len - offset);
				nextBuffer->offset += (len - offset);
				offset = len; // break
			}
		}
		m_Size -= offset;
		return offset;
	}

	void SendBufferQueue::CleanUp ()
	{
		if (!m_Buffers.empty ())
		{
			for (auto it: m_Buffers)
				it->Cancel ();
			m_Buffers.clear ();
			m_Size = 0;
		}
	}

	Stream::Stream (boost::asio::io_service& service, StreamingDestination& local,
		std::shared_ptr<const i2p::data::LeaseSet> remote, int port): m_Service (service),
		m_SendStreamID (0), m_SequenceNumber (0), m_LastReceivedSequenceNumber (-1),
		m_Status (eStreamStatusNew), m_IsAckSendScheduled (false), m_LocalDestination (local),
		m_RemoteLeaseSet (remote), m_ReceiveTimer (m_Service), m_ResendTimer (m_Service),
		m_AckSendTimer (m_Service), m_NumSentBytes (0), m_NumReceivedBytes (0), m_Port (port),
		m_WindowSize (MIN_WINDOW_SIZE), m_RTT (INITIAL_RTT), m_RTO (INITIAL_RTO),
		m_AckDelay (local.GetOwner ()->GetStreamingAckDelay ()),
		m_LastWindowSizeIncreaseTime (0), m_NumResendAttempts (0), m_MTU (STREAMING_MTU)
	{
		RAND_bytes ((uint8_t *)&m_RecvStreamID, 4);
		m_RemoteIdentity = remote->GetIdentity ();
	}

	Stream::Stream (boost::asio::io_service& service, StreamingDestination& local):
		m_Service (service), m_SendStreamID (0), m_SequenceNumber (0), m_LastReceivedSequenceNumber (-1),
		m_Status (eStreamStatusNew), m_IsAckSendScheduled (false), m_LocalDestination (local),
		m_ReceiveTimer (m_Service), m_ResendTimer (m_Service), m_AckSendTimer (m_Service),
		m_NumSentBytes (0), m_NumReceivedBytes (0), m_Port (0), m_WindowSize (MIN_WINDOW_SIZE),
		m_RTT (INITIAL_RTT), m_RTO (INITIAL_RTO), m_AckDelay (local.GetOwner ()->GetStreamingAckDelay ()),
		m_LastWindowSizeIncreaseTime (0), m_NumResendAttempts (0), m_MTU (STREAMING_MTU)
	{
		RAND_bytes ((uint8_t *)&m_RecvStreamID, 4);
	}

	Stream::~Stream ()
	{
		CleanUp ();
		LogPrint (eLogDebug, "Streaming: Stream deleted");
	}

	void Stream::Terminate (bool deleteFromDestination) // shoudl be called from StreamingDestination::Stop only
	{
		m_AckSendTimer.cancel ();
		m_ReceiveTimer.cancel ();
		m_ResendTimer.cancel ();
		//CleanUp (); /* Need to recheck - broke working on windows */
		if (deleteFromDestination)
			m_LocalDestination.DeleteStream (shared_from_this ());
	}

	void Stream::CleanUp ()
	{
		{
			std::unique_lock<std::mutex> l(m_SendBufferMutex);
			m_SendBuffer.CleanUp ();
		}
		while (!m_ReceiveQueue.empty ())
		{
			auto packet = m_ReceiveQueue.front ();
			m_ReceiveQueue.pop ();
			m_LocalDestination.DeletePacket (packet);
		}

		for (auto it: m_SentPackets)
			m_LocalDestination.DeletePacket (it);
		m_SentPackets.clear ();

		for (auto it: m_SavedPackets)
			m_LocalDestination.DeletePacket (it);
		m_SavedPackets.clear ();
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
			LogPrint (eLogDebug, "Streaming: Plain ACK received");
			m_LocalDestination.DeletePacket (packet);
			return;
		}

		LogPrint (eLogDebug, "Streaming: Received seqn=", receivedSeqn, " on sSID=", m_SendStreamID);
		if (receivedSeqn == m_LastReceivedSequenceNumber + 1)
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
					auto ackTimeout = m_RTT/10;
					if (ackTimeout > m_AckDelay) ackTimeout = m_AckDelay;
					m_AckSendTimer.expires_from_now (boost::posix_time::milliseconds(ackTimeout));
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
				LogPrint (eLogWarning, "Streaming: Duplicate message ", receivedSeqn, " on sSID=", m_SendStreamID);
				SendQuickAck (); // resend ack for previous message again
				m_LocalDestination.DeletePacket (packet); // packet dropped
			}
			else
			{
				LogPrint (eLogWarning, "Streaming: Missing messages on sSID=", m_SendStreamID, ": from ", m_LastReceivedSequenceNumber + 1, " to ", receivedSeqn - 1);
				// save message and wait for missing message again
				SavePacket (packet);
				if (m_LastReceivedSequenceNumber >= 0)
				{
					// send NACKs for missing messages ASAP
					if (m_IsAckSendScheduled)
					{
						m_IsAckSendScheduled = false;
						m_AckSendTimer.cancel ();
					}
					SendQuickAck ();
				}
				else
				{
					// wait for SYN
					m_IsAckSendScheduled = true;
					m_AckSendTimer.expires_from_now (boost::posix_time::milliseconds(SYN_TIMEOUT));
					m_AckSendTimer.async_wait (std::bind (&Stream::HandleAckSendTimer,
						shared_from_this (), std::placeholders::_1));
				}
			}
		}
	}

	void Stream::SavePacket (Packet * packet)
	{
		if (!m_SavedPackets.insert (packet).second)
			m_LocalDestination.DeletePacket (packet);
	}

	void Stream::ProcessPacket (Packet * packet)
	{
		uint32_t receivedSeqn = packet->GetSeqn ();
		uint16_t flags = packet->GetFlags ();
		LogPrint (eLogDebug, "Streaming: Process seqn=", receivedSeqn, ", flags=", flags);

		if (!ProcessOptions (flags, packet))
		{
			m_LocalDestination.DeletePacket (packet);
			Terminate ();
			return;
		}

		packet->offset = packet->GetPayload () - packet->buf;
		if (packet->GetLength () > 0)
		{
			m_ReceiveQueue.push (packet);
			m_ReceiveTimer.cancel ();
		}
		else
			m_LocalDestination.DeletePacket (packet);

		m_LastReceivedSequenceNumber = receivedSeqn;

		if (flags & PACKET_FLAG_RESET)
		{
			LogPrint (eLogDebug, "Streaming: closing stream sSID=", m_SendStreamID, ", rSID=", m_RecvStreamID, ": reset flag received in packet #", receivedSeqn);
			m_Status = eStreamStatusReset;
			Close ();
		}
		else if (flags & PACKET_FLAG_CLOSE)
		{
			if (m_Status != eStreamStatusClosed)
				SendClose ();
			m_Status = eStreamStatusClosed;
			Terminate ();
		}
	}

	bool Stream::ProcessOptions (uint16_t flags, Packet * packet)
	{
		const uint8_t * optionData = packet->GetOptionData ();
		size_t optionSize = packet->GetOptionSize ();
		if (flags & PACKET_FLAG_DELAY_REQUESTED)
			optionData += 2;

		if (flags & PACKET_FLAG_FROM_INCLUDED)
		{
			if (m_RemoteLeaseSet) m_RemoteIdentity = m_RemoteLeaseSet->GetIdentity ();
			if (!m_RemoteIdentity)
				m_RemoteIdentity = std::make_shared<i2p::data::IdentityEx>(optionData, optionSize);
			if (m_RemoteIdentity->IsRSA ())
			{
				LogPrint (eLogInfo, "Streaming: Incoming stream from RSA destination ", m_RemoteIdentity->GetIdentHash ().ToBase64 (), " Discarded");
				return false;
			}
			optionData += m_RemoteIdentity->GetFullLen ();
			if (!m_RemoteLeaseSet)
				LogPrint (eLogDebug, "Streaming: Incoming stream from ", m_RemoteIdentity->GetIdentHash ().ToBase64 (), ", sSID=", m_SendStreamID, ", rSID=", m_RecvStreamID);
		}

		if (flags & PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED)
		{
			uint16_t maxPacketSize = bufbe16toh (optionData);
			LogPrint (eLogDebug, "Streaming: Max packet size ", maxPacketSize);
			optionData += 2;
		}

		if (flags & PACKET_FLAG_OFFLINE_SIGNATURE)
		{
			if (!m_RemoteIdentity)
			{
				LogPrint (eLogInfo, "Streaming: offline signature without identity");
				return false;
			}
			// if we have it in LeaseSet already we don't need to parse it again
			if (m_RemoteLeaseSet) m_TransientVerifier = m_RemoteLeaseSet->GetTransientVerifier ();
			if (m_TransientVerifier)
			{
				// skip option data
				optionData += 6; // timestamp and key type
				optionData += m_TransientVerifier->GetPublicKeyLen (); // public key
				optionData += m_RemoteIdentity->GetSignatureLen (); // signature
			}
			else
			{
				// transient key
				size_t offset = 0;
				m_TransientVerifier = i2p::data::ProcessOfflineSignature (m_RemoteIdentity, optionData, optionSize - (optionData - packet->GetOptionData ()), offset);
				optionData += offset;
				if (!m_TransientVerifier)
				{
					LogPrint (eLogError, "Streaming: offline signature failed");
					return false;
				}
			}
		}

		if (flags & PACKET_FLAG_SIGNATURE_INCLUDED)
		{
			uint8_t signature[256];
			auto signatureLen = m_RemoteIdentity->GetSignatureLen ();
			if(signatureLen <= sizeof(signature))
			{
				memcpy (signature, optionData, signatureLen);
				memset (const_cast<uint8_t *>(optionData), 0, signatureLen);
				bool verified = m_TransientVerifier ?
					m_TransientVerifier->Verify (packet->GetBuffer (), packet->GetLength (), signature) :
					m_RemoteIdentity->Verify (packet->GetBuffer (), packet->GetLength (), signature);
				if (!verified)
				{
					LogPrint (eLogError, "Streaming: Signature verification failed, sSID=", m_SendStreamID, ", rSID=", m_RecvStreamID);
					Close ();
					flags |= PACKET_FLAG_CLOSE;
				}
				memcpy (const_cast<uint8_t *>(optionData), signature, signatureLen);
				optionData += signatureLen;
			}
			else
			{
				LogPrint (eLogError, "Streaming: Signature too big, ", signatureLen, " bytes");
				return false;
			}
		}
		return true;
	}

	void Stream::HandlePing (Packet * packet)
	{
		uint16_t flags = packet->GetFlags ();
		if (ProcessOptions (flags, packet) && m_RemoteIdentity)
		{
			// send pong
			Packet p;
			memset (p.buf, 0, 22); // minimal header all zeroes
			memcpy (p.buf + 4, packet->buf, 4); // but receiveStreamID is the sendStreamID from the ping
			htobe16buf (p.buf + 18, PACKET_FLAG_ECHO); // and echo flag
			ssize_t payloadLen = packet->len - (packet->GetPayload () - packet->buf);
			if (payloadLen > 0)
				memcpy (p.buf + 22, packet->GetPayload (), payloadLen);
			else
				payloadLen = 0;
			p.len = payloadLen + 22;
			SendPackets (std::vector<Packet *> { &p });
			LogPrint (eLogDebug, "Streaming: Pong of ", p.len, " bytes sent");
		}	
		m_LocalDestination.DeletePacket (packet);
	}	
		
	void Stream::ProcessAck (Packet * packet)
	{
		bool acknowledged = false;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		uint32_t ackThrough = packet->GetAckThrough ();
		if (ackThrough > m_SequenceNumber)
		{
			LogPrint (eLogError, "Streaming: Unexpected ackThrough=", ackThrough, " > seqn=", m_SequenceNumber);
			return;
		}
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
						LogPrint (eLogDebug, "Streaming: Packet ", seqn, " NACK");
						++it;
						continue;
					}
				}
				auto sentPacket = *it;
				uint64_t rtt = ts - sentPacket->sendTime;
				if(ts < sentPacket->sendTime)
				{
					LogPrint(eLogError, "Streaming: Packet ", seqn, "sent from the future, sendTime=", sentPacket->sendTime);
					rtt = 1;
				}
				m_RTT = (m_RTT*seqn + rtt)/(seqn + 1);
				m_RTO = m_RTT*1.5; // TODO: implement it better
				LogPrint (eLogDebug, "Streaming: Packet ", seqn, " acknowledged rtt=", rtt, " sentTime=", sentPacket->sendTime);
				m_SentPackets.erase (it++);
				m_LocalDestination.DeletePacket (sentPacket);
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
				if (!seqn && m_RoutingSession) // first message confirmed
					m_RoutingSession->SetSharedRoutingPath (
						std::make_shared<i2p::garlic::GarlicRoutingPath> (
							i2p::garlic::GarlicRoutingPath{m_CurrentOutboundTunnel, m_CurrentRemoteLease, m_RTT, 0, 0}));
			}
			else
				break;
		}
		if (m_SentPackets.empty ())
			m_ResendTimer.cancel ();
		if (acknowledged)
		{
			m_NumResendAttempts = 0;
			SendBuffer ();
		}
		if (m_Status == eStreamStatusClosed)
			Terminate ();
		else if (m_Status == eStreamStatusClosing)
			Close (); // check is all outgoing messages have been sent and we can send close
	}

	size_t Stream::Send (const uint8_t * buf, size_t len)
	{
		AsyncSend (buf, len, nullptr);
		return len;
	}

	void Stream::AsyncSend (const uint8_t * buf, size_t len, SendHandler handler)
	{
		if (len > 0 && buf)
		{
			std::unique_lock<std::mutex> l(m_SendBufferMutex);
			m_SendBuffer.Add (buf, len, handler);
		}
		else if (handler)
			handler(boost::system::error_code ());
		m_Service.post (std::bind (&Stream::SendBuffer, shared_from_this ()));
	}

	void Stream::SendBuffer ()
	{
		int numMsgs = m_WindowSize - m_SentPackets.size ();
		if (numMsgs <= 0) return; // window is full

		bool isNoAck = m_LastReceivedSequenceNumber < 0; // first packet
		std::vector<Packet *> packets;
		{
			std::unique_lock<std::mutex> l(m_SendBufferMutex);
			while ((m_Status == eStreamStatusNew) || (IsEstablished () && !m_SendBuffer.IsEmpty () && numMsgs > 0))
			{
				Packet * p = m_LocalDestination.NewPacket ();
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
					htobuf32 (packet + size, 0);
				else
					htobe32buf (packet + size, m_LastReceivedSequenceNumber);
				size += 4; // ack Through
				packet[size] = 0;
				size++; // NACK count
				packet[size] = m_RTO/1000;
				size++; // resend delay
				if (m_Status == eStreamStatusNew)
				{
					// initial packet
					m_Status = eStreamStatusOpen;
					if (!m_RemoteLeaseSet) m_RemoteLeaseSet = m_LocalDestination.GetOwner ()->FindLeaseSet (m_RemoteIdentity->GetIdentHash ());;
					if (m_RemoteLeaseSet)
					{
						m_RoutingSession = m_LocalDestination.GetOwner ()->GetRoutingSession (m_RemoteLeaseSet, true);
						m_MTU = m_RoutingSession->IsRatchets () ? STREAMING_MTU_RATCHETS : STREAMING_MTU;
					}
					uint16_t flags = PACKET_FLAG_SYNCHRONIZE | PACKET_FLAG_FROM_INCLUDED |
						PACKET_FLAG_SIGNATURE_INCLUDED | PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED;
					if (isNoAck) flags |= PACKET_FLAG_NO_ACK;
					bool isOfflineSignature = m_LocalDestination.GetOwner ()->GetPrivateKeys ().IsOfflineSignature ();
					if (isOfflineSignature) flags |= PACKET_FLAG_OFFLINE_SIGNATURE;
					htobe16buf (packet + size, flags);
					size += 2; // flags
					size_t identityLen = m_LocalDestination.GetOwner ()->GetIdentity ()->GetFullLen ();
					size_t signatureLen = m_LocalDestination.GetOwner ()->GetPrivateKeys ().GetSignatureLen ();
					uint8_t * optionsSize = packet + size; // set options size later
					size += 2; // options size
					m_LocalDestination.GetOwner ()->GetIdentity ()->ToBuffer (packet + size, identityLen);
					size += identityLen; // from
					htobe16buf (packet + size, m_MTU);
					size += 2; // max packet size
					if (isOfflineSignature)
					{
						const auto& offlineSignature = m_LocalDestination.GetOwner ()->GetPrivateKeys ().GetOfflineSignature ();
						memcpy (packet + size, offlineSignature.data (), offlineSignature.size ());
						size += offlineSignature.size (); // offline signature
					}
					uint8_t * signature = packet + size; // set it later
					memset (signature, 0, signatureLen); // zeroes for now
					size += signatureLen; // signature
					htobe16buf (optionsSize, packet + size - 2 - optionsSize); // actual options size
					size += m_SendBuffer.Get (packet + size, m_MTU); // payload
					m_LocalDestination.GetOwner ()->Sign (packet, size, signature);
				}
				else
				{
					// follow on packet
					htobuf16 (packet + size, 0);
					size += 2; // flags
					htobuf16 (packet + size, 0); // no options
					size += 2; // options size
					size += m_SendBuffer.Get(packet + size, m_MTU); // payload
				}
				p->len = size;
				packets.push_back (p);
				numMsgs--;
			}
		}
		if (packets.size () > 0)
		{
			if (m_SavedPackets.empty ()) // no NACKS
			{
				m_IsAckSendScheduled = false;
				m_AckSendTimer.cancel ();
			}
			bool isEmpty = m_SentPackets.empty ();
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			for (auto& it: packets)
			{
				it->sendTime = ts;
				m_SentPackets.insert (it);
			}
			SendPackets (packets);
			if (m_Status == eStreamStatusClosing && m_SendBuffer.IsEmpty ())
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
			LogPrint (eLogError, "Streaming: No packets have been received yet");
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
					LogPrint (eLogError, "Streaming: Number of NACKs exceeds 256. seqn=", seqn, " nextSeqn=", nextSeqn);
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
		packet[size] = 0;
		size++; // resend delay
		htobuf16 (packet + size, 0); // no flags set
		size += 2; // flags
		htobuf16 (packet + size, 0); // no options
		size += 2; // options size
		p.len = size;

		SendPackets (std::vector<Packet *> { &p });
		LogPrint (eLogDebug, "Streaming: Quick Ack sent. ", (int)numNacks, " NACKs");
	}

	void Stream::Close ()
	{
		LogPrint(eLogDebug, "Streaming: closing stream with sSID=", m_SendStreamID, ", rSID=", m_RecvStreamID, ", status=", m_Status);
		switch (m_Status)
		{
			case eStreamStatusOpen:
				m_Status = eStreamStatusClosing;
				Close (); // recursion
				if (m_Status == eStreamStatusClosing) //still closing
					LogPrint (eLogDebug, "Streaming: Trying to send stream data before closing, sSID=", m_SendStreamID);
			break;
			case eStreamStatusReset:
				// TODO: send reset
				Terminate ();
			break;
			case eStreamStatusClosing:
				if (m_SentPackets.empty () && m_SendBuffer.IsEmpty ()) // nothing to send
				{
					m_Status = eStreamStatusClosed;
					SendClose();
				}
			break;
			case eStreamStatusClosed:
				// already closed
				Terminate ();
			break;
			default:
				LogPrint (eLogWarning, "Streaming: Unexpected stream status ", (int)m_Status, "sSID=", m_SendStreamID);
		};
	}

	void Stream::SendClose ()
	{
		Packet * p = m_LocalDestination.NewPacket ();
		uint8_t * packet = p->GetBuffer ();
		size_t size = 0;
		htobe32buf (packet + size, m_SendStreamID);
		size += 4; // sendStreamID
		htobe32buf (packet + size, m_RecvStreamID);
		size += 4; // receiveStreamID
		htobe32buf (packet + size, m_SequenceNumber++);
		size += 4; // sequenceNum
		htobe32buf (packet + size, m_LastReceivedSequenceNumber >= 0 ? m_LastReceivedSequenceNumber : 0);
		size += 4; // ack Through
		packet[size] = 0;
		size++; // NACK count
		packet[size] = 0;
		size++; // resend delay
		htobe16buf (packet + size, PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED);
		size += 2; // flags
		size_t signatureLen = m_LocalDestination.GetOwner ()->GetIdentity ()->GetSignatureLen ();
		htobe16buf (packet + size, signatureLen); // signature only
		size += 2; // options size
		uint8_t * signature = packet + size;
		memset (packet + size, 0, signatureLen);
		size += signatureLen; // signature
		m_LocalDestination.GetOwner ()->Sign (packet, size, signature);

		p->len = size;
		m_Service.post (std::bind (&Stream::SendPacket, shared_from_this (), p));
		LogPrint (eLogDebug, "Streaming: FIN sent, sSID=", m_SendStreamID);
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
				m_LocalDestination.DeletePacket (packet);
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
			bool isEmpty = m_SentPackets.empty ();
			m_SentPackets.insert (packet);
			if (isEmpty)
				ScheduleResend ();
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
				LogPrint (eLogError, "Streaming: Can't send packets, missing remote LeaseSet, sSID=", m_SendStreamID);
				return;
			}
		}
		if (!m_RoutingSession || !m_RoutingSession->GetOwner ()) // expired and detached
			m_RoutingSession = m_LocalDestination.GetOwner ()->GetRoutingSession (m_RemoteLeaseSet, true);
		if (!m_CurrentOutboundTunnel && m_RoutingSession) // first message to send
		{
			// try to get shared path first
			auto routingPath = m_RoutingSession->GetSharedRoutingPath ();
			if (routingPath)
			{
				m_CurrentOutboundTunnel = routingPath->outboundTunnel;
				m_CurrentRemoteLease = routingPath->remoteLease;
				m_RTT = routingPath->rtt;
				m_RTO = m_RTT*1.5; // TODO: implement it better
			}
		}
		if (!m_CurrentOutboundTunnel || !m_CurrentOutboundTunnel->IsEstablished ())
			m_CurrentOutboundTunnel = m_LocalDestination.GetOwner ()->GetTunnelPool ()->GetNewOutboundTunnel (m_CurrentOutboundTunnel);
		if (!m_CurrentOutboundTunnel)
		{
			LogPrint (eLogError, "Streaming: No outbound tunnels in the pool, sSID=", m_SendStreamID);
			return;
		}

		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (!m_CurrentRemoteLease || !m_CurrentRemoteLease->endDate || // excluded from LeaseSet
			ts >= m_CurrentRemoteLease->endDate - i2p::data::LEASE_ENDDATE_THRESHOLD)
			UpdateCurrentRemoteLease (true);
		if (m_CurrentRemoteLease && ts < m_CurrentRemoteLease->endDate + i2p::data::LEASE_ENDDATE_THRESHOLD)
		{
			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
			for (auto it: packets)
			{
				auto msg = m_RoutingSession->WrapSingleMessage (m_LocalDestination.CreateDataMessage (
					it->GetBuffer (), it->GetLength (), m_Port, !m_RoutingSession->IsRatchets ()));
				msgs.push_back (i2p::tunnel::TunnelMessageBlock
					{
						i2p::tunnel::eDeliveryTypeTunnel,
						m_CurrentRemoteLease->tunnelGateway, m_CurrentRemoteLease->tunnelID,
						msg
					});
				m_NumSentBytes += it->GetLength ();
			}
			m_CurrentOutboundTunnel->SendTunnelDataMsg (msgs);
		}
		else
		{
			LogPrint (eLogWarning, "Streaming: Remote lease is not available, sSID=", m_SendStreamID);
			if (m_RoutingSession)
				m_RoutingSession->SetSharedRoutingPath (nullptr); // invalidate routing path
		}
	}

	void Stream::SendUpdatedLeaseSet ()
	{
		if (m_RoutingSession)
		{
			if (m_RoutingSession->IsLeaseSetNonConfirmed ())
			{
				auto ts = i2p::util::GetMillisecondsSinceEpoch ();
				if (ts > m_RoutingSession->GetLeaseSetSubmissionTime () + i2p::garlic::LEASET_CONFIRMATION_TIMEOUT)
				{
					// LeaseSet was not confirmed, should try other tunnels
					LogPrint (eLogWarning, "Streaming: LeaseSet was not confirmed in ", i2p::garlic::LEASET_CONFIRMATION_TIMEOUT, " milliseconds. Trying to resubmit");
					m_RoutingSession->SetSharedRoutingPath (nullptr);
					m_CurrentOutboundTunnel = nullptr;
					m_CurrentRemoteLease = nullptr;
					SendQuickAck ();
				}
			}
			else if (m_RoutingSession->IsLeaseSetUpdated ())
			{
				LogPrint (eLogDebug, "Streaming: sending updated LeaseSet");
				SendQuickAck ();
			}
		}
	}

	void Stream::ScheduleResend ()
	{
		m_ResendTimer.cancel ();
		// check for invalid value
		if (m_RTO <= 0) m_RTO = INITIAL_RTO;
		m_ResendTimer.expires_from_now (boost::posix_time::milliseconds(m_RTO));
		m_ResendTimer.async_wait (std::bind (&Stream::HandleResendTimer,
			shared_from_this (), std::placeholders::_1));
	}

	void Stream::HandleResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			// check for resend attempts
			if (m_NumResendAttempts >= MAX_NUM_RESEND_ATTEMPTS)
			{
				LogPrint (eLogWarning, "Streaming: packet was not ACKed after ", MAX_NUM_RESEND_ATTEMPTS, " attempts, terminate, rSID=", m_RecvStreamID, ", sSID=", m_SendStreamID);
				m_Status = eStreamStatusReset;
				Close ();
				return;
			}

			// collect packets to resend
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			std::vector<Packet *> packets;
			for (auto it : m_SentPackets)
			{
				if (ts >= it->sendTime + m_RTO)
				{
					it->sendTime = ts;
					packets.push_back (it);
				}
			}

			// select tunnels if necessary and send
			if (packets.size () > 0)
			{
				m_NumResendAttempts++;
				m_RTO *= 2;
				switch (m_NumResendAttempts)
				{
					case 1: // congesion avoidance
						m_WindowSize >>= 1; // /2
						if (m_WindowSize < MIN_WINDOW_SIZE) m_WindowSize = MIN_WINDOW_SIZE;
					break;
					case 2:
						m_RTO = INITIAL_RTO; // drop RTO to initial upon tunnels pair change first time
#if (__cplusplus >= 201703L) // C++ 17 or higher
						[[fallthrough]];
#endif
						// no break here
					case 4:
						if (m_RoutingSession) m_RoutingSession->SetSharedRoutingPath (nullptr);
						UpdateCurrentRemoteLease (); // pick another lease
						LogPrint (eLogWarning, "Streaming: Another remote lease has been selected for stream with rSID=", m_RecvStreamID, ", sSID=", m_SendStreamID);
					break;
					case 3:
						// pick another outbound tunnel
						if (m_RoutingSession) m_RoutingSession->SetSharedRoutingPath (nullptr);
						m_CurrentOutboundTunnel = m_LocalDestination.GetOwner ()->GetTunnelPool ()->GetNextOutboundTunnel (m_CurrentOutboundTunnel);
						LogPrint (eLogWarning, "Streaming: Another outbound tunnel has been selected for stream with sSID=", m_SendStreamID);
					break;
					default: ;
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
			if (m_LastReceivedSequenceNumber < 0)
			{
				LogPrint (eLogWarning, "Streaming: SYN has not been received after ", SYN_TIMEOUT, " milliseconds after follow on, terminate rSID=", m_RecvStreamID, ", sSID=", m_SendStreamID);
				m_Status = eStreamStatusReset;
				Close ();
				return;
			}
			if (m_Status == eStreamStatusOpen)
			{
				if (m_RoutingSession && m_RoutingSession->IsLeaseSetNonConfirmed ())
				{
					// seems something went wrong and we should re-select tunnels
					m_CurrentOutboundTunnel = nullptr;
					m_CurrentRemoteLease = nullptr;
				}
				SendQuickAck ();
			}
			m_IsAckSendScheduled = false;
		}
	}

	void Stream::UpdateCurrentRemoteLease (bool expired)
	{
		if (!m_RemoteLeaseSet || m_RemoteLeaseSet->IsExpired ())
		{
			m_RemoteLeaseSet = m_LocalDestination.GetOwner ()->FindLeaseSet (m_RemoteIdentity->GetIdentHash ());
			if (!m_RemoteLeaseSet)
			{
				LogPrint (eLogWarning, "Streaming: LeaseSet ", m_RemoteIdentity->GetIdentHash ().ToBase64 (), " not found");
				m_LocalDestination.GetOwner ()->RequestDestination (m_RemoteIdentity->GetIdentHash ()); // try to request for a next attempt
			}
			else
			{
				// LeaseSet updated
				m_RemoteIdentity = m_RemoteLeaseSet->GetIdentity ();
				m_TransientVerifier = m_RemoteLeaseSet->GetTransientVerifier ();
			}
		}
		if (m_RemoteLeaseSet)
		{
			if (!m_RoutingSession)
				m_RoutingSession = m_LocalDestination.GetOwner ()->GetRoutingSession (m_RemoteLeaseSet, true);
			auto leases = m_RemoteLeaseSet->GetNonExpiredLeases (false); // try without threshold first
			if (leases.empty ())
			{
				expired = false;
				// time to request
				if (m_RemoteLeaseSet->IsPublishedEncrypted ())
					m_LocalDestination.GetOwner ()->RequestDestinationWithEncryptedLeaseSet (
						std::make_shared<i2p::data::BlindedPublicKey>(m_RemoteIdentity));
				else
					m_LocalDestination.GetOwner ()->RequestDestination (m_RemoteIdentity->GetIdentHash ());
				leases = m_RemoteLeaseSet->GetNonExpiredLeases (true); // then with threshold
			}
			if (!leases.empty ())
			{
				bool updated = false;
				if (expired && m_CurrentRemoteLease)
				{
					for (const auto& it: leases)
						if ((it->tunnelGateway == m_CurrentRemoteLease->tunnelGateway) && (it->tunnelID != m_CurrentRemoteLease->tunnelID))
						{
							m_CurrentRemoteLease = it;
							updated = true;
							break;
						}
				}
				if (!updated)
				{
					uint32_t i = rand () % leases.size ();
					if (m_CurrentRemoteLease && leases[i]->tunnelID == m_CurrentRemoteLease->tunnelID)
						// make sure we don't select previous
						i = (i + 1) % leases.size (); // if so, pick next
					m_CurrentRemoteLease = leases[i];
				}
			}
			else
			{
				LogPrint (eLogWarning, "Streaming: All remote leases are expired");
				m_RemoteLeaseSet = nullptr;
				m_CurrentRemoteLease = nullptr;
				// we have requested expired before, no need to do it twice
			}
		}
		else
		{
			LogPrint (eLogWarning, "Streaming: Remote LeaseSet not found");
			m_CurrentRemoteLease = nullptr;
		}
	}

	StreamingDestination::StreamingDestination (std::shared_ptr<i2p::client::ClientDestination> owner, uint16_t localPort, bool gzip):
		m_Owner (owner), m_LocalPort (localPort), m_Gzip (gzip),
		m_PendingIncomingTimer (m_Owner->GetService ())
	{
	}

	StreamingDestination::~StreamingDestination ()
	{
		for (auto& it: m_SavedPackets)
		{
			for (auto it1: it.second) DeletePacket (it1);
			it.second.clear ();
		}
		m_SavedPackets.clear ();
	}

	void StreamingDestination::Start ()
	{
	}

	void StreamingDestination::Stop ()
	{
		ResetAcceptor ();
		m_PendingIncomingTimer.cancel ();
		m_PendingIncomingStreams.clear ();
		{
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			for (auto it: m_Streams)
				it.second->Terminate (false); // we delete here
			m_Streams.clear ();
			m_IncomingStreams.clear ();
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
			else if (packet->IsEcho () && m_Owner->IsStreamingAnswerPings ())
			{
				// ping
				LogPrint (eLogInfo, "Streaming: Ping received sSID=", sendStreamID);
				auto s = std::make_shared<Stream> (m_Owner->GetService (), *this);
				s->HandlePing (packet);
			}		
			else
			{
				LogPrint (eLogInfo, "Streaming: Unknown stream sSID=", sendStreamID);
				DeletePacket (packet);
			}
		}
		else
		{
			if (packet->IsSYN () && !packet->GetSeqn ()) // new incoming stream
			{
				uint32_t receiveStreamID = packet->GetReceiveStreamID ();
				auto it1 = m_IncomingStreams.find (receiveStreamID);
				if (it1 != m_IncomingStreams.end ())
				{
					// already pending
					LogPrint(eLogWarning, "Streaming: Incoming streaming with rSID=", receiveStreamID, " already exists");
					DeletePacket (packet); // drop it, because previous should be connected
					return;
				}
				auto incomingStream = CreateNewIncomingStream (receiveStreamID);
				incomingStream->HandleNextPacket (packet); // SYN
				auto ident = incomingStream->GetRemoteIdentity();

				// handle saved packets if any
				{
					auto it = m_SavedPackets.find (receiveStreamID);
					if (it != m_SavedPackets.end ())
					{
						LogPrint (eLogDebug, "Streaming: Processing ", it->second.size (), " saved packets for rSID=", receiveStreamID);
						for (auto it1: it->second)
							incomingStream->HandleNextPacket (it1);
						m_SavedPackets.erase (it);
					}
				}
				// accept
				if (m_Acceptor != nullptr)
					m_Acceptor (incomingStream);
				else
				{
					LogPrint (eLogWarning, "Streaming: Acceptor for incoming stream is not set");
					if (m_PendingIncomingStreams.size () < MAX_PENDING_INCOMING_BACKLOG)
					{
						m_PendingIncomingStreams.push_back (incomingStream);
						m_PendingIncomingTimer.cancel ();
						m_PendingIncomingTimer.expires_from_now (boost::posix_time::seconds(PENDING_INCOMING_TIMEOUT));
						m_PendingIncomingTimer.async_wait (std::bind (&StreamingDestination::HandlePendingIncomingTimer,
							shared_from_this (), std::placeholders::_1));
						LogPrint (eLogDebug, "Streaming: Pending incoming stream added, rSID=", receiveStreamID);
					}
					else
					{
						LogPrint (eLogWarning, "Streaming: Pending incoming streams backlog exceeds ", MAX_PENDING_INCOMING_BACKLOG);
						incomingStream->Close ();
					}
				}
			}
			else // follow on packet without SYN
			{
				uint32_t receiveStreamID = packet->GetReceiveStreamID ();
				auto it1 = m_IncomingStreams.find (receiveStreamID);
				if (it1 != m_IncomingStreams.end ())
				{
					// found
					it1->second->HandleNextPacket (packet);
					return;
				}
				// save follow on packet
				auto it = m_SavedPackets.find (receiveStreamID);
				if (it != m_SavedPackets.end ())
					it->second.push_back (packet);
				else
				{
					m_SavedPackets[receiveStreamID] = std::list<Packet *>{ packet };
					auto timer = std::make_shared<boost::asio::deadline_timer> (m_Owner->GetService ());
					timer->expires_from_now (boost::posix_time::seconds(PENDING_INCOMING_TIMEOUT));
					auto s = shared_from_this ();
					timer->async_wait ([s,timer,receiveStreamID](const boost::system::error_code& ecode)
					{
						if (ecode != boost::asio::error::operation_aborted)
						{
							auto it = s->m_SavedPackets.find (receiveStreamID);
							if (it != s->m_SavedPackets.end ())
							{
								for (auto it1: it->second) s->DeletePacket (it1);
								it->second.clear ();
								s->m_SavedPackets.erase (it);
							}
						}
					});
				}
			}
		}
	}

	std::shared_ptr<Stream> StreamingDestination::CreateNewOutgoingStream (std::shared_ptr<const i2p::data::LeaseSet> remote, int port)
	{
		auto s = std::make_shared<Stream> (m_Owner->GetService (), *this, remote, port);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		return s;
	}

	std::shared_ptr<Stream> StreamingDestination::CreateNewIncomingStream (uint32_t receiveStreamID)
	{
		auto s = std::make_shared<Stream> (m_Owner->GetService (), *this);
		std::unique_lock<std::mutex> l(m_StreamsMutex);
		m_Streams[s->GetRecvStreamID ()] = s;
		m_IncomingStreams[receiveStreamID] = s;
		return s;
	}

	void StreamingDestination::DeleteStream (std::shared_ptr<Stream> stream)
	{
		if (stream)
		{
			std::unique_lock<std::mutex> l(m_StreamsMutex);
			m_Streams.erase (stream->GetRecvStreamID ());
			m_IncomingStreams.erase (stream->GetSendStreamID ());
		}
	}

	bool StreamingDestination::DeleteStream (uint32_t recvStreamID)
	{
		auto it = m_Streams.find (recvStreamID);
		if (it == m_Streams.end ())
			return false;
		DeleteStream (it->second);
		return true;
	}

	void StreamingDestination::SetAcceptor (const Acceptor& acceptor)
	{
		m_Acceptor = acceptor; // we must set it immediately for IsAcceptorSet
		auto s = shared_from_this ();
		m_Owner->GetService ().post([s](void)
			{
				// take care about incoming queue
				for (auto& it: s->m_PendingIncomingStreams)
					if (it->GetStatus () == eStreamStatusOpen) // still open?
						s->m_Acceptor (it);
				s->m_PendingIncomingStreams.clear ();
				s->m_PendingIncomingTimer.cancel ();
			});
	}

	void StreamingDestination::ResetAcceptor ()
	{
		if (m_Acceptor) m_Acceptor (nullptr);
		m_Acceptor = nullptr;
	}

	void StreamingDestination::AcceptOnce (const Acceptor& acceptor)
	{
		m_Owner->GetService ().post([acceptor, this](void)
			{
				if (!m_PendingIncomingStreams.empty ())
				{
					acceptor (m_PendingIncomingStreams.front ());
					m_PendingIncomingStreams.pop_front ();
					if (m_PendingIncomingStreams.empty ())
						m_PendingIncomingTimer.cancel ();
				}
				else // we must save old acceptor and set it back
				{
					m_Acceptor = std::bind (&StreamingDestination::AcceptOnceAcceptor, this,
						std::placeholders::_1, acceptor, m_Acceptor);
				}
			});
	}

	void StreamingDestination::AcceptOnceAcceptor (std::shared_ptr<Stream> stream, Acceptor acceptor, Acceptor prev)
	{
		m_Acceptor = prev;
		acceptor (stream);
	}

	void StreamingDestination::HandlePendingIncomingTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			LogPrint (eLogWarning, "Streaming: Pending incoming timeout expired");
			for (auto& it: m_PendingIncomingStreams)
				it->Close ();
			m_PendingIncomingStreams.clear ();
		}
	}

	void StreamingDestination::HandleDataMessagePayload (const uint8_t * buf, size_t len)
	{
		// unzip it
		Packet * uncompressed = NewPacket ();
		uncompressed->offset = 0;
		uncompressed->len = m_Inflator.Inflate (buf, len, uncompressed->buf, MAX_PACKET_SIZE);
		if (uncompressed->len)
			HandleNextPacket (uncompressed);
		else
			DeletePacket (uncompressed);
	}

	std::shared_ptr<I2NPMessage> StreamingDestination::CreateDataMessage (
		const uint8_t * payload, size_t len, uint16_t toPort, bool checksum)
	{
		auto msg = m_I2NPMsgsPool.AcquireShared ();
		uint8_t * buf = msg->GetPayload ();
		buf += 4; // reserve for lengthlength
		msg->len += 4;
		size_t size = (!m_Gzip || len <= i2p::stream::COMPRESSION_THRESHOLD_SIZE)?
			i2p::data::GzipNoCompression (payload, len, buf, msg->maxLen - msg->len):
			m_Deflator.Deflate (payload, len, buf, msg->maxLen - msg->len);
		if (size)
		{
			htobe32buf (msg->GetPayload (), size); // length
			htobe16buf (buf + 4, m_LocalPort); // source port
			htobe16buf (buf + 6, toPort); // destination port
			buf[9] = i2p::client::PROTOCOL_TYPE_STREAMING; // streaming protocol
			msg->len += size;
			msg->FillI2NPMessageHeader (eI2NPData, 0, checksum);
		}
		else
			msg = nullptr;
		return msg;
	}

}
}
