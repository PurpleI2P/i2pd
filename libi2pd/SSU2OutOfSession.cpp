/*
* Copyright (c) 2024-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "SSU2.h"
#include "SSU2OutOfSession.h"

namespace i2p
{
namespace transport
{
	SSU2PeerTestSession::SSU2PeerTestSession (SSU2Server& server, uint64_t sourceConnID, uint64_t destConnID): 
		SSU2Session (server, nullptr, nullptr, false), 
		m_MsgNumReceived (0), m_NumResends (0),m_IsConnectedRecently (false), m_IsStatusChanged (false),
		m_PeerTestResendTimer (server.GetService ())
	{
		if (!sourceConnID) sourceConnID = ~destConnID;
		if (!destConnID) destConnID = ~sourceConnID;
		SetSourceConnID (sourceConnID);
		SetDestConnID (destConnID);	
		SetState (eSSU2SessionStatePeerTest);	
		SetTerminationTimeout (SSU2_PEER_TEST_EXPIRATION_TIMEOUT);
	}	

	bool SSU2PeerTestSession::ProcessPeerTest (uint8_t * buf, size_t len)
	{
		// we are Alice or Charlie, msgs 5,6,7
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 12));
		if (header.h.type != eSSU2PeerTest)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " instead ", (int)eSSU2PeerTest);
			return false;
		}
		if (len < 48)
		{
			LogPrint (eLogWarning, "SSU2: PeerTest message too short ", len);
			return false;
		}
		uint8_t nonce[12] = {0};
		uint64_t headerX[2]; // sourceConnID, token
		GetServer ().ChaCha20 (buf + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, (uint8_t *)headerX);
		SetDestConnID (headerX[0]);
		// decrypt and handle payload
		uint8_t * payload = buf + 32;
		CreateNonce (be32toh (header.h.packetNum), nonce);
		uint8_t h[32];
		memcpy (h, header.buf, 16);
		memcpy (h + 16, &headerX, 16);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 48, h, 32,
			i2p::context.GetSSU2IntroKey (), nonce, payload, len - 48, false))
		{
			LogPrint (eLogWarning, "SSU2: PeerTest AEAD verification failed ");
			return false;
		}
		HandlePayload (payload, len - 48);
		SetIsDataReceived (false);
		return true;
	}	

	void SSU2PeerTestSession::HandleAddress (const uint8_t * buf, size_t len)
	{
		if (!ExtractEndpoint (buf, len, m_OurEndpoint))
			LogPrint (eLogWarning, "SSU2: Can't handle address block from peer test message");
	}	
		
	void SSU2PeerTestSession::HandlePeerTest (const uint8_t * buf, size_t len)
	{
		// msgs 5-7
		if (len < 8) return;
		uint8_t msg = buf[0];
		if (msg <= m_MsgNumReceived)
		{
			LogPrint (eLogDebug, "SSU2: PeerTest msg num ", msg, " received after ", m_MsgNumReceived, ". Ignored");
			return;
		}	
		size_t offset = 3; // points to signed data after msg + code + flag
		uint32_t nonce = bufbe32toh (buf + offset + 1); // 1 - ver
		switch (msg) // msg
		{
			case 5: // Alice from Charlie 1
			{	
				if (htobe64 (((uint64_t)nonce << 32) | nonce) == GetSourceConnID ())
				{
					m_PeerTestResendTimer.cancel (); // cancel delayed msg 6 if any
					m_IsConnectedRecently = GetServer ().IsConnectedRecently (GetRemoteEndpoint ());
					if (GetAddress ())
					{
						if (!m_IsConnectedRecently)
							SetRouterStatus (eRouterStatusOK);
						else if (m_IsStatusChanged && GetRouterStatus () == eRouterStatusFirewalled)
							SetRouterStatus (eRouterStatusUnknown);
						SendPeerTest (6, buf + offset, len - offset);
					}
				}
				else
					LogPrint (eLogWarning, "SSU2: Peer test 5 nonce mismatch ", nonce, " connID=", GetSourceConnID ());
				break;
			}
			case 6: // Charlie from Alice
			{	
				m_PeerTestResendTimer.cancel (); // no more msg 5 resends
				if (GetAddress ())
					SendPeerTest (7, buf + offset, len - offset);
				else
					LogPrint (eLogWarning, "SSU2: Unknown address for peer test 6");
				GetServer ().RequestRemoveSession (GetConnID ());
				break;
			}			
			case 7: // Alice from Charlie 2
			{	
				m_PeerTestResendTimer.cancel (); // no more msg 6 resends
				if (m_MsgNumReceived < 5 && m_OurEndpoint.port ()) // msg 5 was not received
				{
					if (m_OurEndpoint.address ().is_v4 ()) // ipv4
					{
						if (i2p::context.GetStatus () == eRouterStatusFirewalled)
						{	
						    if (m_OurEndpoint.port () != GetServer ().GetPort (true))
								i2p::context.SetError (eRouterErrorSymmetricNAT);
							else if (i2p::context.GetError () == eRouterErrorSymmetricNAT)
								i2p::context.SetError (eRouterErrorNone);
						}
					}	
					else
					{
						if (i2p::context.GetStatusV6 () == eRouterStatusFirewalled)
						{	
						    if (m_OurEndpoint.port () != GetServer ().GetPort (false))
								i2p::context.SetErrorV6 (eRouterErrorSymmetricNAT);
							else if (i2p::context.GetErrorV6 () == eRouterErrorSymmetricNAT)
								i2p::context.SetErrorV6 (eRouterErrorNone);
						}
					}	
				}	
				GetServer ().RequestRemoveSession (GetConnID ());	
				break;
			}	
			default:	
				LogPrint (eLogWarning, "SSU2: PeerTest unexpected msg num ", msg);
				return;
		}	
		m_MsgNumReceived = msg;	
	}

	void SSU2PeerTestSession::SendPeerTest (uint8_t msg)
	{
		auto addr = GetAddress ();
		if (!addr) return;
		Header header;
		uint8_t h[32], payload[SSU2_MAX_PACKET_SIZE];
		// fill packet
		header.h.connID = GetDestConnID (); // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2PeerTest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		htobuf64 (h + 16, GetSourceConnID ()); // source id
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, (i2p::util::GetMillisecondsSinceEpoch () + 500)/1000);
		size_t payloadSize = 7;
		if (msg == 6 || msg == 7)
			payloadSize += CreateAddressBlock (payload + payloadSize, GetMaxPayloadSize () - payloadSize, GetRemoteEndpoint ());
		payloadSize += CreatePeerTestBlock (payload + payloadSize, GetMaxPayloadSize () - payloadSize,
			msg, eSSU2PeerTestCodeAccept, nullptr, m_SignedData.data (), m_SignedData.size ());
		payloadSize += CreatePaddingBlock (payload + payloadSize, GetMaxPayloadSize () - payloadSize);
		// encrypt
		uint8_t n[12];
		CreateNonce (be32toh (header.h.packetNum), n);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, addr->i, n, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (addr->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (addr->i, payload + (payloadSize - 12));
		memset (n, 0, 12);
		GetServer ().ChaCha20 (h + 16, 16, addr->i, n, h + 16);
		// send
		GetServer ().Send (header.buf, 16, h + 16, 16, payload, payloadSize, GetRemoteEndpoint ());
		UpdateNumSentBytes (payloadSize + 32);
	}	

	void SSU2PeerTestSession::SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, bool delayed)
	{
#if __cplusplus >= 202002L // C++20
		m_SignedData.assign (signedData, signedData + signedDataLen);
#else		
		m_SignedData.resize (signedDataLen);
		memcpy (m_SignedData.data (), signedData, signedDataLen);
#endif		
		if (!delayed)
			SendPeerTest (msg);
		// schedule resend for msgs 5 or 6
		if (msg == 5 || msg == 6)
			ScheduleResend (msg);
	}	
		
	void SSU2PeerTestSession::SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, 
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr, bool delayed)
	{
		if (!addr) return;
		SetAddress (addr);
		SendPeerTest (msg, signedData, signedDataLen, delayed);	
	}	

	void SSU2PeerTestSession::Connect ()
	{
		LogPrint (eLogError, "SSU2: Can't connect peer test session");
	}	

	bool SSU2PeerTestSession::ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len)
	{
		LogPrint (eLogError, "SSU2: Can't handle incoming message in peer test session");
		return false;
	}	

	void SSU2PeerTestSession::ScheduleResend (uint8_t msg)
	{
		if (m_NumResends < SSU2_PEER_TEST_MAX_NUM_RESENDS)
		{
			m_PeerTestResendTimer.expires_from_now (boost::posix_time::milliseconds(
				SSU2_PEER_TEST_RESEND_INTERVAL + GetServer ().GetRng ()() % SSU2_PEER_TEST_RESEND_INTERVAL_VARIANCE));
			std::weak_ptr<SSU2PeerTestSession> s(std::static_pointer_cast<SSU2PeerTestSession>(shared_from_this ()));
			m_PeerTestResendTimer.async_wait ([s, msg](const boost::system::error_code& ecode)
				{
					if (ecode != boost::asio::error::operation_aborted)
					{
						auto s1 = s.lock ();
						if (s1) 
						{
							if (msg > s1->m_MsgNumReceived) 
							{	
								s1->SendPeerTest (msg);
								s1->m_NumResends++;
								s1->ScheduleResend (msg);
							}	
						}	
					}	
				});
		}	
	}	

	SSU2HolePunchSession::SSU2HolePunchSession (SSU2Server& server, uint32_t nonce,
		const boost::asio::ip::udp::endpoint& remoteEndpoint,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr):
		SSU2Session (server), // we create full incoming session
		m_NumResends (0), m_HolePunchResendTimer (server.GetService ())
	{
		// we are Charlie
		uint64_t destConnID = htobe64 (((uint64_t)nonce << 32) | nonce); // dest id
		uint32_t sourceConnID = ~destConnID;
		SetSourceConnID (sourceConnID);
		SetDestConnID (destConnID);	
		SetState (eSSU2SessionStateHolePunch);
		SetRemoteEndpoint (remoteEndpoint);
		SetAddress (addr);
		SetTerminationTimeout (SSU2_RELAY_NONCE_EXPIRATION_TIMEOUT);	
	}	

	void SSU2HolePunchSession::SendHolePunch ()
	{
		auto addr = GetAddress ();
		if (!addr) return;
		auto& ep = GetRemoteEndpoint ();
		LogPrint (eLogDebug, "SSU2: Sending HolePunch to ", ep);
		Header header;
		uint8_t h[32], payload[SSU2_MAX_PACKET_SIZE];
		// fill packet
		header.h.connID = GetDestConnID (); // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2HolePunch;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		htobuf64 (h + 16, GetSourceConnID ()); // source id
		RAND_bytes (h + 24, 8); // header token, to be ignored by Alice
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, (i2p::util::GetMillisecondsSinceEpoch () + 500)/1000);
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (payload + payloadSize, GetMaxPayloadSize () - payloadSize, ep);
		// relay response block	
		if (payloadSize + m_RelayResponseBlock.size () < GetMaxPayloadSize ())
		{	
			memcpy (payload + payloadSize, m_RelayResponseBlock.data (), m_RelayResponseBlock.size ());
			payloadSize += m_RelayResponseBlock.size ();
		}	
		payloadSize += CreatePaddingBlock (payload + payloadSize, GetMaxPayloadSize () - payloadSize);
		// encrypt
		uint8_t n[12];
		CreateNonce (be32toh (header.h.packetNum), n);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, addr->i, n, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (addr->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (addr->i, payload + (payloadSize - 12));
		memset (n, 0, 12);
		GetServer ().ChaCha20 (h + 16, 16, addr->i, n, h + 16);
		// send
		GetServer ().Send (header.buf, 16, h + 16, 16, payload, payloadSize, ep);
		UpdateNumSentBytes (payloadSize + 32);
	}	

	void SSU2HolePunchSession::SendHolePunch (const uint8_t * relayResponseBlock, size_t relayResponseBlockLen)
	{
#if __cplusplus >= 202002L // C++20
		m_RelayResponseBlock.assign (relayResponseBlock, relayResponseBlock + relayResponseBlockLen);
#else		
		m_RelayResponseBlock.resize (relayResponseBlockLen);
		memcpy (m_RelayResponseBlock.data (), relayResponseBlock, relayResponseBlockLen);
#endif		
		SendHolePunch ();
		ScheduleResend ();
	}	

	void SSU2HolePunchSession::ScheduleResend ()
	{
		if (m_NumResends < SSU2_HOLE_PUNCH_MAX_NUM_RESENDS)
		{
			m_HolePunchResendTimer.expires_from_now (boost::posix_time::milliseconds(
				SSU2_HOLE_PUNCH_RESEND_INTERVAL + GetServer ().GetRng ()() % SSU2_HOLE_PUNCH_RESEND_INTERVAL_VARIANCE));
			std::weak_ptr<SSU2HolePunchSession> s(std::static_pointer_cast<SSU2HolePunchSession>(shared_from_this ()));
			m_HolePunchResendTimer.async_wait ([s](const boost::system::error_code& ecode)
				{
					if (ecode != boost::asio::error::operation_aborted)
					{
						auto s1 = s.lock ();
						if (s1 && s1->GetState () == eSSU2SessionStateHolePunch) 
						{
							s1->SendHolePunch ();
							s1->m_NumResends++;
							s1->ScheduleResend ();	
						}	
					}	
				});
		}	
	}

	bool SSU2HolePunchSession::ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len)
	{
		m_HolePunchResendTimer.cancel ();
		return SSU2Session::ProcessFirstIncomingMessage (connID, buf, len);
	}	
}
}
