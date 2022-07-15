/*
* Copyright (c) 2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <openssl/rand.h>
#include "Log.h"
#include "Transports.h"
#include "Gzip.h"
#include "NetDb.hpp"
#include "SSU2.h"

namespace i2p
{
namespace transport
{
	SSU2Session::SSU2Session (SSU2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr):
		TransportSession (in_RemoteRouter, SSU2_CONNECT_TIMEOUT),
		m_Server (server), m_Address (addr), m_RemoteTransports (0),
		m_DestConnID (0), m_SourceConnID (0), m_State (eSSU2SessionStateUnknown),
		m_SendPacketNum (0), m_ReceivePacketNum (0), m_IsDataReceived (false), 
		m_WindowSize (SSU2_MAX_WINDOW_SIZE), m_RelayTag (0), 
		m_ConnectTimer (server.GetService ()), m_TerminationReason (eSSU2TerminationReasonNormalClose),
		m_MaxPayloadSize (SSU2_MIN_PACKET_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE - 32) // min size
	{
		m_NoiseState.reset (new i2p::crypto::NoiseSymmetricState);
		if (in_RemoteRouter && m_Address)
		{
			// outgoing
			InitNoiseXKState1 (*m_NoiseState, m_Address->s);
			m_RemoteEndpoint = boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port);
			m_RemoteTransports = in_RemoteRouter->GetCompatibleTransports (false);
			RAND_bytes ((uint8_t *)&m_DestConnID, 8);
			RAND_bytes ((uint8_t *)&m_SourceConnID, 8);
		}
		else
		{
			// incoming
			InitNoiseXKState1 (*m_NoiseState, i2p::context.GetSSU2StaticPublicKey ());
		}
	}

	SSU2Session::~SSU2Session ()
	{
	}

	void SSU2Session::Connect ()
	{
		if (m_State == eSSU2SessionStateUnknown || m_State == eSSU2SessionStateTokenReceived)
		{	
			ScheduleConnectTimer ();
			auto token = m_Server.FindOutgoingToken (m_RemoteEndpoint);
			if (token)
				SendSessionRequest (token);
			else
			{	
				m_State = eSSU2SessionStateUnknown;	
				SendTokenRequest ();
			}		
		}	
	}

	void SSU2Session::ScheduleConnectTimer ()
	{
		m_ConnectTimer.cancel ();
		m_ConnectTimer.expires_from_now (boost::posix_time::seconds(SSU2_CONNECT_TIMEOUT));
		m_ConnectTimer.async_wait (std::bind (&SSU2Session::HandleConnectTimer,
			shared_from_this (), std::placeholders::_1));
	}

	void SSU2Session::HandleConnectTimer (const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			// timeout expired
			LogPrint (eLogWarning, "SSU2: Session with ", m_RemoteEndpoint, " was not established after ", SSU2_CONNECT_TIMEOUT, " seconds");
			Terminate ();
		}
	}
		
	bool SSU2Session::Introduce (std::shared_ptr<SSU2Session> session, uint32_t relayTag)
	{
		// we are Alice
		if (!session || !relayTag) return false;
		// find local adddress to introduce
		auto localAddress = session->FindLocalAddress ();
		if (!localAddress) return false;
		// create nonce
		uint32_t nonce;
		RAND_bytes ((uint8_t *)&nonce, 4);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		// payload
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = 0;
		payload[0] = eSSU2BlkRelayRequest;
		payload[3] = 0; // flag
		htobe32buf (payload + 4, nonce);
		htobe32buf (payload + 8, relayTag);
		htobe32buf (payload + 12, ts);
		payload[16] = 2; // ver
		size_t asz = CreateEndpoint (payload + 18, m_MaxPayloadSize - 18, boost::asio::ip::udp::endpoint (localAddress->host, localAddress->port));
		if (!asz) return false;
		payload[17] = asz;
		payloadSize += asz + 18;
		SignedData s;
		s.Insert ((const uint8_t *)"RelayRequestData", 16); // prologue
		s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
		s.Insert (session->GetRemoteIdentity ()->GetIdentHash (), 32); // chash
		s.Insert (payload + 4, 14 + asz); // nonce, relay tag, timestamp, ver, asz and Alice's endpoint
		s.Sign (i2p::context.GetPrivateKeys (), payload + payloadSize);
		payloadSize += i2p::context.GetIdentity ()->GetSignatureLen ();
		htobe16buf (payload + 1, payloadSize - 3); // size
		payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		// send
		m_RelaySessions.emplace (nonce, std::make_pair (session, ts));
		session->m_SourceConnID = htobe64 (((uint64_t)nonce << 32) | nonce);
		session->m_DestConnID = ~session->m_SourceConnID;
		m_Server.AddSession (session);
		SendData (payload, payloadSize);

		return true;
	}

	void SSU2Session::WaitForIntroduction ()
	{
		m_State = eSSU2SessionStateIntroduced;
		ScheduleConnectTimer ();
	}
		
	void SSU2Session::SendPeerTest ()
	{
		// we are Alice
		uint32_t nonce;
		RAND_bytes ((uint8_t *)&nonce, 4);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		// session for message 5
		auto session = std::make_shared<SSU2Session> (m_Server);
		session->SetState (eSSU2SessionStatePeerTest);
		m_PeerTests.emplace (nonce, std::make_pair (session, ts));
		session->m_SourceConnID = htobe64 (((uint64_t)nonce << 32) | nonce);
		session->m_DestConnID = ~session->m_SourceConnID;
		m_Server.AddSession (session);
		// peer test block
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = CreatePeerTestBlock (payload, m_MaxPayloadSize, nonce);
		payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		SendData (payload, payloadSize);
	}	

	void SSU2Session::SendKeepAlive ()
	{
		if (IsEstablished ())
		{	
			uint8_t payload[20];
			size_t payloadSize = CreatePaddingBlock (payload, 20, 5);
			SendData (payload, payloadSize);
		}	
	}	
		
	void SSU2Session::Terminate ()
	{
		if (m_State != eSSU2SessionStateTerminated)
		{
			m_State = eSSU2SessionStateTerminated;
			m_ConnectTimer.cancel ();
			m_OnEstablished = nullptr;
			if (m_RelayTag)
				m_Server.RemoveRelay (m_RelayTag);
			m_SentHandshakePacket.reset (nullptr);
			m_SendQueue.clear ();
			m_SentPackets.clear ();
			m_IncompleteMessages.clear ();
			m_RelaySessions.clear ();
			m_PeerTests.clear ();
			m_Server.RemoveSession (m_SourceConnID);
			transports.PeerDisconnected (shared_from_this ());
			LogPrint (eLogDebug, "SSU2: Session terminated");
		}
	}

	void SSU2Session::RequestTermination (SSU2TerminationReason reason)
	{
		if (m_State == eSSU2SessionStateEstablished || m_State == eSSU2SessionStateClosing)
		{
			m_State = eSSU2SessionStateClosing;
			m_TerminationReason = reason;
			SendTermination ();
		}	
	}	
		
	void SSU2Session::Established ()
	{
		m_State = eSSU2SessionStateEstablished;
		m_EphemeralKeys = nullptr;
		m_NoiseState.reset (nullptr);
		m_SessionConfirmedFragment.reset (nullptr);
		m_SentHandshakePacket.reset (nullptr);
		m_ConnectTimer.cancel ();
		SetTerminationTimeout (SSU2_TERMINATION_TIMEOUT);
		transports.PeerConnected (shared_from_this ());
		if (m_OnEstablished) 
		{	
			m_OnEstablished ();
			m_OnEstablished = nullptr;
		}	
	}

	void SSU2Session::Done ()
	{
		m_Server.GetService ().post (std::bind (&SSU2Session::Terminate, shared_from_this ()));
	}

	void SSU2Session::SendLocalRouterInfo (bool update)
	{
		if (update || !IsOutgoing ())
		{	
			auto s = shared_from_this ();
			m_Server.GetService ().post ([s]()
				{
					if (!s->IsEstablished ()) return;
					uint8_t payload[SSU2_MAX_PACKET_SIZE];
					size_t payloadSize = s->CreateRouterInfoBlock (payload, s->m_MaxPayloadSize - 32, i2p::context.GetSharedRouterInfo ());
					if (payloadSize)
					{
						if (payloadSize < s->m_MaxPayloadSize)
							payloadSize += s->CreatePaddingBlock (payload + payloadSize, s->m_MaxPayloadSize - payloadSize);
						s->SendData (payload, payloadSize);
					}	
					else
						s->SendFragmentedMessage (CreateDatabaseStoreMsg ());
				});
		}	

	}	
		
	void SSU2Session::SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		m_Server.GetService ().post (std::bind (&SSU2Session::PostI2NPMessages, shared_from_this (), msgs));
	}

	void SSU2Session::PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		if (m_State == eSSU2SessionStateTerminated) return;
		for (auto it: msgs)
			m_SendQueue.push_back (it);
		SendQueue ();
		
		if (m_SendQueue.size () > SSU2_MAX_OUTGOING_QUEUE_SIZE)	
		{
			LogPrint (eLogWarning, "SSU2: Outgoing messages queue size to ",
				GetIdentHashBase64(), " exceeds ", SSU2_MAX_OUTGOING_QUEUE_SIZE);
			RequestTermination (eSSU2TerminationReasonTimeout);
		}
	}

	bool SSU2Session::SendQueue ()
	{
		if (!m_SendQueue.empty () && m_SentPackets.size () <= m_WindowSize)
		{
			auto nextResend = i2p::util::GetSecondsSinceEpoch () + SSU2_RESEND_INTERVAL;
			auto packet = std::make_shared<SentPacket>();
			packet->payloadSize += CreateAckBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - packet->payloadSize);
			while (!m_SendQueue.empty () && m_SentPackets.size () <= m_WindowSize)
			{
				auto msg = m_SendQueue.front ();
				size_t len = msg->GetNTCP2Length ();
				if (len + 3 < m_MaxPayloadSize - packet->payloadSize)
				{
					m_SendQueue.pop_front ();
					packet->payloadSize += CreateI2NPBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - packet->payloadSize, std::move (msg));
				}
				else if (len > m_MaxPayloadSize) // message too long
				{
					m_SendQueue.pop_front ();
					SendFragmentedMessage (msg);
				}
				else
				{
					// send right a way
					if (packet->payloadSize + 16 < m_MaxPayloadSize)
						packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - packet->payloadSize);
					uint32_t packetNum = SendData (packet->payload, packet->payloadSize);
					packet->nextResendTime = nextResend;
					m_SentPackets.emplace (packetNum, packet);
					packet = std::make_shared<SentPacket>();
					packet->payloadSize += CreateAckBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - packet->payloadSize);
				}
			};
			if (packet->payloadSize)
			{
				if (packet->payloadSize + 16 < m_MaxPayloadSize)
					packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - packet->payloadSize);
				uint32_t packetNum = SendData (packet->payload, packet->payloadSize);
				packet->nextResendTime = nextResend;
				m_SentPackets.emplace (packetNum, packet);
			}
			return true;
		}
		return false;
	}

	void SSU2Session::SendFragmentedMessage (std::shared_ptr<I2NPMessage> msg)
	{
		uint32_t msgID;
		memcpy (&msgID, msg->GetHeader () + I2NP_HEADER_MSGID_OFFSET, 4);
		auto nextResend = i2p::util::GetSecondsSinceEpoch () + SSU2_RESEND_INTERVAL;
		auto packet = std::make_shared<SentPacket>();
		packet->payloadSize = CreateAckBlock (packet->payload, m_MaxPayloadSize);
		auto size = CreateFirstFragmentBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - 16 - packet->payloadSize, msg);
		if (!size) return;
		packet->payloadSize += size;
		packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - 16 - packet->payloadSize);
		uint32_t firstPacketNum = SendData (packet->payload, packet->payloadSize);
		packet->nextResendTime = nextResend;
		m_SentPackets.emplace (firstPacketNum, packet);
		uint8_t fragmentNum = 0;
		while (msg->offset < msg->len)
		{
			packet = std::make_shared<SentPacket>();
			packet->payloadSize = CreateFollowOnFragmentBlock (packet->payload, m_MaxPayloadSize - 16, msg, fragmentNum, msgID);
			packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, m_MaxPayloadSize - 16 - packet->payloadSize);
			uint32_t followonPacketNum = SendData (packet->payload, packet->payloadSize);
			packet->nextResendTime = nextResend;
			m_SentPackets.emplace (followonPacketNum, packet);
		}
	}

	void SSU2Session::Resend (uint64_t ts)
	{
		// resend handshake packet
		if (m_SentHandshakePacket && ts >= m_SentHandshakePacket->nextResendTime)
		{
			LogPrint (eLogDebug, "SSU2: Resending ", (int)m_State);
			m_Server.Send (m_SentHandshakePacket->header.buf, 16, m_SentHandshakePacket->headerX, 48, 
				m_SentHandshakePacket->payload, m_SentHandshakePacket->payloadSize, m_RemoteEndpoint);
			m_SentHandshakePacket->nextResendTime = ts + SSU2_HANDSHAKE_RESEND_INTERVAL;
			if (m_SessionConfirmedFragment && m_State == eSSU2SessionStateSessionConfirmedSent)
				// resend second fragment of SessionConfirmed
				m_Server.Send (m_SessionConfirmedFragment->header.buf, 16, 
					m_SessionConfirmedFragment->payload, m_SessionConfirmedFragment->payloadSize, m_RemoteEndpoint);
			return;
		}	
		// resend data packets
		if (m_SentPackets.empty ()) return;
		std::map<uint32_t, std::shared_ptr<SentPacket> > resentPackets;
		for (auto it = m_SentPackets.begin (); it != m_SentPackets.end (); )
			if (ts >= it->second->nextResendTime)
			{
				if (it->second->numResends > SSU2_MAX_NUM_RESENDS)
				{
					LogPrint (eLogInfo, "SSU2: Packet was not Acked after ", it->second->numResends, " attempts. Terminate session");
					m_SentPackets.clear ();
					m_SendQueue.clear ();
					RequestTermination (eSSU2TerminationReasonTimeout);
					return;
				}	
				else
				{
					uint32_t packetNum = SendData (it->second->payload, it->second->payloadSize);
					it->second->numResends++;
					it->second->nextResendTime = ts + it->second->numResends*SSU2_RESEND_INTERVAL;
					m_LastActivityTimestamp = ts;
					resentPackets.emplace (packetNum, it->second);
					it = m_SentPackets.erase (it);
				}
			}
			else
				it++;
		if (!resentPackets.empty ())
		{
#if (__cplusplus >= 201703L) // C++ 17 or higher
			m_SentPackets.merge (resentPackets);
#else
			m_SentPackets.insert (resentPackets.begin (), resentPackets.end ());
#endif
		}
		SendQueue ();
	}

	bool SSU2Session::ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len)
	{
		// we are Bob
		m_SourceConnID = connID;
		Header header;
		header.h.connID = connID;
		memcpy (header.buf + 8, buf + 8, 8);
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 12));
		switch (header.h.type)
		{
			case eSSU2SessionRequest:
				ProcessSessionRequest (header, buf, len);
			break;
			case eSSU2TokenRequest:
				ProcessTokenRequest (header, buf, len);
			break;
			case eSSU2PeerTest:
			{
				// TODO: remove later	
				const uint8_t nonce[12] = {0};	
				uint64_t headerX[2]; 
				i2p::crypto::ChaCha20 (buf + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, (uint8_t *)headerX);	
				LogPrint (eLogWarning, "SSU2: Unexpected PeerTest message SourceConnID=", connID, " DestConnID=", headerX[0]);
				break;
			}		
			default:
			{
				LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " from ", m_RemoteEndpoint);
				return false;
			}
		}
		return true;
	}

	void SSU2Session::SendSessionRequest (uint64_t token)
	{
		// we are Alice
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		m_SentHandshakePacket.reset (new HandshakePacket);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		m_SentHandshakePacket->nextResendTime = ts + SSU2_HANDSHAKE_RESEND_INTERVAL;
		
		Header& header = m_SentHandshakePacket->header;
		uint8_t * headerX = m_SentHandshakePacket->headerX, 
				* payload = m_SentHandshakePacket->payload;
		// fill packet
		header.h.connID = m_DestConnID; // dest id
		header.h.packetNum = 0;
		header.h.type = eSSU2SessionRequest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (headerX, &m_SourceConnID, 8); // source id
		memcpy (headerX + 8, &token, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // X
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, ts);
		size_t payloadSize = 7;
		if (GetRouterStatus () == eRouterStatusFirewalled && m_Address->IsIntroducer ())
		{
			// relay tag request
			payload[payloadSize] = eSSU2BlkRelayTagRequest;
			memset (payload + payloadSize + 1, 0, 2); // size = 0
			payloadSize += 3;
		}	
		payloadSize += CreatePaddingBlock (payload + payloadSize, 40 - payloadSize, 1);
		// KDF for session request
		m_NoiseState->MixHash ({ {header.buf, 16}, {headerX, 16} }); // h = SHA256(h || header)
		m_NoiseState->MixHash (m_EphemeralKeys->GetPublicKey (), 32); // h = SHA256(h || aepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (m_Address->s, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// encrypt
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 12));
		i2p::crypto::ChaCha20 (headerX, 48, m_Address->i, nonce, headerX);
		m_NoiseState->MixHash (payload, payloadSize); // h = SHA256(h || encrypted payload from Session Request) for SessionCreated
		m_SentHandshakePacket->payloadSize = payloadSize;
		// send
		if (m_State == eSSU2SessionStateTokenReceived || m_Server.AddPendingOutgoingSession (shared_from_this ()))
		{	
			m_State = eSSU2SessionStateSessionRequestSent;
			m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
		}	
		else
		{
			LogPrint (eLogWarning, "SSU2: SessionRequest request to ", m_RemoteEndpoint, " already pending");  	
			Terminate ();
		}		
	}

	void SSU2Session::ProcessSessionRequest (Header& header, uint8_t * buf, size_t len)
	{
		// we are Bob
		const uint8_t nonce[12] = {0};
		uint8_t headerX[48];
		i2p::crypto::ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
		memcpy (&m_DestConnID, headerX, 8);
		uint64_t token;
		memcpy (&token, headerX + 8, 8);
		if (!token || token != m_Server.GetIncomingToken (m_RemoteEndpoint))
		{
			LogPrint (eLogDebug, "SSU2: SessionRequest token mismatch. Retry");
			SendRetry ();
			return;
		}
		// KDF for session request
		m_NoiseState->MixHash ( { {header.buf, 16}, {headerX, 16} } ); // h = SHA256(h || header)
		m_NoiseState->MixHash (headerX + 16, 32); // h = SHA256(h || aepk);
		uint8_t sharedSecret[32];
		i2p::context.GetSSU2StaticKeys ().Agree (headerX + 16, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// decrypt
		uint8_t * payload = buf + 64;
		std::vector<uint8_t> decryptedPayload(len - 80);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 80, m_NoiseState->m_H, 32,
			m_NoiseState->m_CK + 32, nonce, decryptedPayload.data (), decryptedPayload.size (), false))
		{
			LogPrint (eLogWarning, "SSU2: SessionRequest AEAD verification failed ");
			return;
		}
		m_NoiseState->MixHash (payload, len - 64); // h = SHA256(h || encrypted payload from Session Request) for SessionCreated
		// payload
		m_State = eSSU2SessionStateSessionRequestReceived;
		HandlePayload (decryptedPayload.data (), decryptedPayload.size ());

		m_Server.AddSession (shared_from_this ());
		SendSessionCreated (headerX + 16);
	}

	void SSU2Session::SendSessionCreated (const uint8_t * X)
	{
		// we are Bob
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		m_SentHandshakePacket.reset (new HandshakePacket);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		m_SentHandshakePacket->nextResendTime = ts + SSU2_HANDSHAKE_RESEND_INTERVAL;
		
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessCreateHeader", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
		// fill packet
		Header& header = m_SentHandshakePacket->header;
		uint8_t * headerX = m_SentHandshakePacket->headerX, 
				* payload = m_SentHandshakePacket->payload;
		header.h.connID = m_DestConnID; // dest id
		header.h.packetNum = 0;
		header.h.type = eSSU2SessionCreated;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (headerX, &m_SourceConnID, 8); // source id
		memset (headerX + 8, 0, 8); // token = 0
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // Y
		// payload
		size_t maxPayloadSize = m_MaxPayloadSize - 48;
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, ts);
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (payload + payloadSize, maxPayloadSize - payloadSize, m_RemoteEndpoint);
		if (m_RelayTag)
		{
			payload[payloadSize] = eSSU2BlkRelayTag;
			htobe16buf (payload + payloadSize + 1, 4);
			htobe32buf (payload + payloadSize + 3, m_RelayTag);
			payloadSize += 7;
		}
		auto token = m_Server.NewIncomingToken (m_RemoteEndpoint);
		if (ts + SSU2_TOKEN_EXPIRATION_THRESHOLD > token.second) // not expired?
		{	
			payload[payloadSize] = eSSU2BlkNewToken;
			htobe16buf (payload + payloadSize + 1, 12);
			htobe32buf (payload + payloadSize + 3, token.second - SSU2_TOKEN_EXPIRATION_THRESHOLD); // expires
			memcpy (payload + payloadSize + 7, &token.first, 8); // token
			payloadSize += 15;
		}	
		if (m_TerminationReason != eSSU2TerminationReasonNormalClose)
			payloadSize += CreateTerminationBlock (payload + payloadSize, maxPayloadSize - payloadSize);
		payloadSize += CreatePaddingBlock (payload + payloadSize, maxPayloadSize - payloadSize);
		// KDF for SessionCreated
		m_NoiseState->MixHash ( { {header.buf, 16}, {headerX, 16} } ); // h = SHA256(h || header)
		m_NoiseState->MixHash (headerX + 16, 32); // h = SHA256(h || bepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (X, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// encrypt
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		m_NoiseState->MixHash (payload, payloadSize); // h = SHA256(h || encrypted Noise payload from Session Created)
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (kh2, payload + (payloadSize - 12));
		i2p::crypto::ChaCha20 (headerX, 48, kh2, nonce, headerX);
		m_State = eSSU2SessionStateSessionCreatedSent;
		m_SentHandshakePacket->payloadSize = payloadSize;
		// send
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
		// terminate if errors
		if (m_TerminationReason != eSSU2TerminationReasonNormalClose)
			Terminate ();
	}

	bool SSU2Session::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		// we are Alice
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (m_Address->i, buf + (len - 24));
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessCreateHeader", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)
		header.ll[1] ^= CreateHeaderMask (kh2, buf + (len - 12));
		if (header.h.type != eSSU2SessionCreated)
		// this situation is valid, because it might be Retry with different encryption
			return false;
		const uint8_t nonce[12] = {0};
		uint8_t headerX[48];
		i2p::crypto::ChaCha20 (buf + 16, 48, kh2, nonce, headerX);
		// KDF for SessionCreated
		m_NoiseState->MixHash ( { {header.buf, 16}, {headerX, 16} } ); // h = SHA256(h || header)
		m_NoiseState->MixHash (headerX + 16, 32); // h = SHA256(h || bepk);
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (headerX + 16, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// decrypt
		uint8_t * payload = buf + 64;
		std::vector<uint8_t> decryptedPayload(len - 80);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 80, m_NoiseState->m_H, 32,
			m_NoiseState->m_CK + 32, nonce, decryptedPayload.data (), decryptedPayload.size (), false))
		{
			LogPrint (eLogWarning, "SSU2: SessionCreated AEAD verification failed ");
			return false;
		}
		m_NoiseState->MixHash (payload, len - 64); // h = SHA256(h || encrypted payload from SessionCreated) for SessionConfirmed
		// payload
		HandlePayload (decryptedPayload.data (), decryptedPayload.size ());

		m_Server.AddSession (shared_from_this ());
		AdjustMaxPayloadSize ();
		SendSessionConfirmed (headerX + 16);
		KDFDataPhase (m_KeyDataSend, m_KeyDataReceive);

		return true;
	}

	void SSU2Session::SendSessionConfirmed (const uint8_t * Y)
	{
		// we are Alice
		m_SentHandshakePacket.reset (new HandshakePacket);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		m_SentHandshakePacket->nextResendTime = ts + SSU2_HANDSHAKE_RESEND_INTERVAL;
		
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessionConfirmed", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
		// fill packet
		Header& header = m_SentHandshakePacket->header;
		header.h.connID = m_DestConnID; // dest id
		header.h.packetNum = 0;
		header.h.type = eSSU2SessionConfirmed;
		memset (header.h.flags, 0, 3);
		header.h.flags[0] = 1; // frag, total fragments always 1
		// payload
		size_t maxPayloadSize = m_MaxPayloadSize - 48; // for part 2, 48 is part1
		uint8_t * payload = m_SentHandshakePacket->payload;
		size_t payloadSize = CreateRouterInfoBlock (payload, maxPayloadSize, i2p::context.GetSharedRouterInfo ());
		if (!payloadSize)
		{
			// split by two fragments
			maxPayloadSize += m_MaxPayloadSize;
			payloadSize = CreateRouterInfoBlock (payload, maxPayloadSize, i2p::context.GetSharedRouterInfo ());
			header.h.flags[0] = 0x02; // frag 0, total fragments 2
			// TODO: check if we need more fragments
		}	
		if (payloadSize < maxPayloadSize)
			payloadSize += CreatePaddingBlock (payload + payloadSize, maxPayloadSize - payloadSize);
		// KDF for Session Confirmed part 1
		m_NoiseState->MixHash (header.buf, 16); // h = SHA256(h || header)
		// Encrypt part 1
		uint8_t * part1 = m_SentHandshakePacket->headerX;
		uint8_t nonce[12];
		CreateNonce (1, nonce);
		i2p::crypto::AEADChaCha20Poly1305 (i2p::context.GetSSU2StaticPublicKey (), 32, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, part1, 48, true);
		m_NoiseState->MixHash (part1, 48); // h = SHA256(h || ciphertext);
		// KDF for Session Confirmed part 2
		uint8_t sharedSecret[32];
		i2p::context.GetSSU2StaticKeys ().Agree (Y, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// Encrypt part2
		memset (nonce, 0, 12);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, m_NoiseState->m_H, 32, m_NoiseState->m_CK + 32, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		m_NoiseState->MixHash (payload, payloadSize); // h = SHA256(h || ciphertext);
		m_SentHandshakePacket->payloadSize = payloadSize;
		if (header.h.flags[0] > 1)
		{
			if (payloadSize > m_MaxPayloadSize - 48)
			{
				payloadSize = m_MaxPayloadSize - 48 - (rand () % 16);
				if (m_SentHandshakePacket->payloadSize - payloadSize < 24)
					payloadSize -= 24;
			}	
			else
				header.h.flags[0] = 1;
		}	
		// Encrypt header
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (kh2, payload + (payloadSize - 12));
		m_State = eSSU2SessionStateSessionConfirmedSent;
		// send
		m_Server.Send (header.buf, 16, part1, 48, payload, payloadSize, m_RemoteEndpoint);
		m_SendPacketNum++;
		if (m_SentHandshakePacket->payloadSize > payloadSize)
		{
			// send second fragment
			m_SessionConfirmedFragment.reset (new HandshakePacket);
			Header& header = m_SessionConfirmedFragment->header;
			header.h.connID = m_DestConnID; // dest id
			header.h.packetNum = 0;
			header.h.type = eSSU2SessionConfirmed;
			memset (header.h.flags, 0, 3);
			header.h.flags[0] = 0x12; // frag 1, total fragments 2
			m_SessionConfirmedFragment->payloadSize = m_SentHandshakePacket->payloadSize - payloadSize;
			memcpy (m_SessionConfirmedFragment->payload, m_SentHandshakePacket->payload + payloadSize, m_SessionConfirmedFragment->payloadSize); 
			m_SentHandshakePacket->payloadSize = payloadSize;
			header.ll[0] ^= CreateHeaderMask (m_Address->i, m_SessionConfirmedFragment->payload + (m_SessionConfirmedFragment->payloadSize - 24));
			header.ll[1] ^= CreateHeaderMask (kh2, m_SessionConfirmedFragment->payload + (m_SessionConfirmedFragment->payloadSize - 12));
			m_Server.Send (header.buf, 16, m_SessionConfirmedFragment->payload, m_SessionConfirmedFragment->payloadSize, m_RemoteEndpoint);
		}	
	}

	bool SSU2Session::ProcessSessionConfirmed (uint8_t * buf, size_t len)
	{
		// we are Bob
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessionConfirmed", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
		header.ll[1] ^= CreateHeaderMask (kh2, buf + (len - 12));
		if (header.h.type != eSSU2SessionConfirmed)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " instead ", (int)eSSU2SessionConfirmed);
			return false;
		}
		// check if fragmented
		if ((header.h.flags[0] & 0x0F) > 1)
		{
			// fragmented
			if (!(header.h.flags[0] & 0xF0))
			{
				// first fragment
				if (!m_SessionConfirmedFragment)
				{	
					m_SessionConfirmedFragment.reset (new HandshakePacket);
					m_SessionConfirmedFragment->header = header;
					memcpy (m_SessionConfirmedFragment->payload, buf + 16, len - 16);
					m_SessionConfirmedFragment->payloadSize = len - 16;
				}	
				return true; // wait for second fragment
			}
			else
			{
				// second fragment
				if (!m_SessionConfirmedFragment) return false; // out of sequence
				header = m_SessionConfirmedFragment->header;
				memcpy (m_SessionConfirmedFragment->payload + m_SessionConfirmedFragment->payloadSize, buf + 16, len - 16);
				m_SessionConfirmedFragment->payloadSize += (len - 16);
				buf = m_SessionConfirmedFragment->payload - 16;
				len = m_SessionConfirmedFragment->payloadSize + 16;
			}
		}
		// KDF for Session Confirmed part 1
		m_NoiseState->MixHash (header.buf, 16); // h = SHA256(h || header)
		// decrypt part1
		uint8_t nonce[12];
		CreateNonce (1, nonce);
		uint8_t S[32];
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf + 16, 32, m_NoiseState->m_H, 32,
			m_NoiseState->m_CK + 32, nonce, S, 32, false))
		{
			LogPrint (eLogWarning, "SSU2: SessionConfirmed part 1 AEAD verification failed ");
			return false;
		}
		m_NoiseState->MixHash (buf + 16, 48); // h = SHA256(h || ciphertext);
		// KDF for Session Confirmed part 2 and data phase
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (S, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		KDFDataPhase (m_KeyDataReceive, m_KeyDataSend);
		// decrypt part2
		memset (nonce, 0, 12);
		uint8_t * payload = buf + 64;
		std::vector<uint8_t> decryptedPayload(len - 80);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 80, m_NoiseState->m_H, 32,
			m_NoiseState->m_CK + 32, nonce, decryptedPayload.data (), decryptedPayload.size (), false))
		{
			LogPrint (eLogWarning, "SSU2: SessionConfirmed part 2 AEAD verification failed ");
			m_TerminationReason = eSSU2TerminationReasonSessionConfirmedError;
			SendTermination ();
			return false;
		}
		m_NoiseState->MixHash (payload, len - 64); // h = SHA256(h || ciphertext);
		// payload
		// handle RouterInfo block that must be first
		if (decryptedPayload[0] != eSSU2BlkRouterInfo)
		{
			LogPrint (eLogError, "SSU2: SessionConfirmed unexpected first block type ", (int)decryptedPayload[0]);
			m_TerminationReason = eSSU2TerminationReasonPayloadFormatError;
			SendTermination ();
			return false;
		}
		size_t riSize = bufbe16toh (decryptedPayload.data () + 1);
		if (riSize + 3 > decryptedPayload.size ())
		{
			LogPrint (eLogError, "SSU2: SessionConfirmed RouterInfo block is too long ", riSize);
			m_TerminationReason = eSSU2TerminationReasonPayloadFormatError;
			SendTermination ();
			return false;
		}
		LogPrint (eLogDebug, "SSU2: RouterInfo in SessionConfirmed");
		auto ri = ExtractRouterInfo (decryptedPayload.data () + 3, riSize);
		if (!ri)
		{
			LogPrint (eLogError, "SSU2: SessionConfirmed malformed RouterInfo block");
			m_TerminationReason = eSSU2TerminationReasonRouterInfoSignatureVerificationFail;
			SendTermination ();
			return false;
		}
		SetRemoteIdentity (ri->GetRouterIdentity ());
		m_Address = ri->GetSSU2AddressWithStaticKey (S, m_RemoteEndpoint.address ().is_v6 ());
		if (!m_Address)
		{
			LogPrint (eLogError, "SSU2: No SSU2 address with static key found in SessionConfirmed");
			m_TerminationReason = eSSU2TerminationReasonInvalidS;
			SendTermination ();
			return false;
		}
		AdjustMaxPayloadSize ();
		m_Server.AddSessionByRouterHash (shared_from_this ()); // we know remote router now
		m_RemoteTransports = ri->GetCompatibleTransports (false);
		i2p::data::netdb.PostI2NPMsg (CreateDatabaseStoreMsg (ri)); // TODO: should insert ri
		// handle other blocks
		HandlePayload (decryptedPayload.data () + riSize + 3, decryptedPayload.size () - riSize - 3);
		Established ();

		SendQuickAck ();

		return true;
	}

	void SSU2Session::KDFDataPhase (uint8_t * keydata_ab, uint8_t * keydata_ba)
	{
		uint8_t keydata[64];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "", keydata); // keydata = HKDF(chainKey, ZEROLEN, "", 64)
		// ab
		i2p::crypto::HKDF (keydata, nullptr, 0, "HKDFSSU2DataKeys", keydata_ab); // keydata_ab = HKDF(keydata, ZEROLEN, "HKDFSSU2DataKeys", 64)
		// ba
		i2p::crypto::HKDF (keydata + 32, nullptr, 0, "HKDFSSU2DataKeys", keydata_ba); // keydata_ba = HKDF(keydata + 32, ZEROLEN, "HKDFSSU2DataKeys", 64)
	}

	void SSU2Session::SendTokenRequest ()
	{
		// we are Alice
		Header header;
		uint8_t h[32], payload[41];
		// fill packet
		header.h.connID = m_DestConnID; // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2TokenRequest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		memcpy (h + 16, &m_SourceConnID, 8); // source id
		memset (h + 24, 0, 8); // zero token
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		payloadSize += CreatePaddingBlock (payload + payloadSize, 25 - payloadSize, 1);
		// encrypt
		uint8_t nonce[12];
		CreateNonce (be32toh (header.h.packetNum), nonce);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, m_Address->i, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 12));
		memset (nonce, 0, 12);
		i2p::crypto::ChaCha20 (h + 16, 16, m_Address->i, nonce, h + 16);
		// send
		if (m_Server.AddPendingOutgoingSession (shared_from_this ()))	
			m_Server.Send (header.buf, 16, h + 16, 16, payload, payloadSize, m_RemoteEndpoint);
		else
		{
			LogPrint (eLogWarning, "SSU2: TokenRequest request to ", m_RemoteEndpoint, " already pending");  	
			Terminate ();
		}		
	}

	void SSU2Session::ProcessTokenRequest (Header& header, uint8_t * buf, size_t len)
	{
		// we are Bob
		if (len < 48)
		{
			LogPrint (eLogWarning, "SSU2: Incorrect TokenRequest len ", len);
			return;
		}	
		uint8_t nonce[12] = {0};
		uint8_t h[32];
		memcpy (h, header.buf, 16);
		i2p::crypto::ChaCha20 (buf + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, h + 16);
		memcpy (&m_DestConnID, h + 16, 8);
		// decrypt
		CreateNonce (be32toh (header.h.packetNum), nonce);
		uint8_t * payload = buf + 32;
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 48, h, 32,
			i2p::context.GetSSU2IntroKey (), nonce, payload, len - 48, false))
		{
			LogPrint (eLogWarning, "SSU2: TokenRequest AEAD verification failed ");
			return;
		}
		// payload
		HandlePayload (payload, len - 48);
		SendRetry ();
	}

	void SSU2Session::SendRetry ()
	{
		// we are Bob
		Header header;
		uint8_t h[32], payload[64];
		// fill packet
		header.h.connID = m_DestConnID; // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2Retry;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		memcpy (h + 16, &m_SourceConnID, 8); // source id
		uint64_t token = m_Server.GetIncomingToken (m_RemoteEndpoint);
		memcpy (h + 24, &token, 8); // token
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (payload + payloadSize, 64 - payloadSize, m_RemoteEndpoint);
		payloadSize += CreatePaddingBlock (payload + payloadSize, 64 - payloadSize);
		// encrypt
		uint8_t nonce[12];
		CreateNonce (be32toh (header.h.packetNum), nonce);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, i2p::context.GetSSU2IntroKey (), nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), payload + (payloadSize - 12));
		memset (nonce, 0, 12);
		i2p::crypto::ChaCha20 (h + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, h + 16);
		// send
		m_Server.Send (header.buf, 16, h + 16, 16, payload, payloadSize, m_RemoteEndpoint);
	}

	bool SSU2Session::ProcessRetry (uint8_t * buf, size_t len)
	{
		// we are Alice
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (m_Address->i, buf + (len - 24));
		header.ll[1] ^= CreateHeaderMask (m_Address->i, buf + (len - 12));
		if (header.h.type != eSSU2Retry)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " instead ", (int)eSSU2Retry);
			return false;
		}
		uint8_t nonce[12] = {0};
		uint64_t headerX[2]; // sourceConnID, token
		i2p::crypto::ChaCha20 (buf + 16, 16, m_Address->i, nonce, (uint8_t *)headerX);
		m_Server.UpdateOutgoingToken (m_RemoteEndpoint, headerX[1], i2p::util::GetSecondsSinceEpoch () + SSU2_TOKEN_EXPIRATION_TIMEOUT);
		// decrypt and handle payload
		uint8_t * payload = buf + 32;
		CreateNonce (be32toh (header.h.packetNum), nonce);
		uint8_t h[32];
		memcpy (h, header.buf, 16);
		memcpy (h + 16, &headerX, 16);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 48, h, 32,
			m_Address->i, nonce, payload, len - 48, false))
		{
			LogPrint (eLogWarning, "SSU2: Retry AEAD verification failed ");
			return false;
		}
		HandlePayload (payload, len - 48);

		m_State = eSSU2SessionStateTokenReceived;
		InitNoiseXKState1 (*m_NoiseState, m_Address->s); // reset Noise TODO: check state
		SendSessionRequest (headerX[1]);
		return true;
	}

	void SSU2Session::SendHolePunch (uint32_t nonce, const boost::asio::ip::udp::endpoint& ep, 
		const uint8_t * introKey, uint64_t token)
	{
		// we are Charlie
		Header header;
		uint8_t h[32], payload[SSU2_MAX_PACKET_SIZE];
		// fill packet
		header.h.connID = htobe64 (((uint64_t)nonce << 32) | nonce); // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2HolePunch;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		uint64_t c = ~header.h.connID;
		memcpy (h + 16, &c, 8); // source id
		RAND_bytes (h + 24, 8); // token
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize, ep);
		payloadSize += CreateRelayResponseBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize, 
			eSSU2RelayResponseCodeAccept, nonce, true, token);
		payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		// encrypt
		uint8_t n[12];
		CreateNonce (be32toh (header.h.packetNum), n);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, introKey, n, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (introKey, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (introKey, payload + (payloadSize - 12));
		memset (n, 0, 12);
		i2p::crypto::ChaCha20 (h + 16, 16, introKey, n, h + 16);
		// send
		m_Server.Send (header.buf, 16, h + 16, 16, payload, payloadSize, ep);
	}

	bool SSU2Session::ProcessHolePunch (uint8_t * buf, size_t len)
	{
		// we are Alice
		LogPrint (eLogDebug, "SSU2: HolePunch");
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 12));
		if (header.h.type != eSSU2HolePunch)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " instead ", (int)eSSU2HolePunch);
			return false;
		}
		uint8_t nonce[12] = {0};
		uint64_t headerX[2]; // sourceConnID, token
		i2p::crypto::ChaCha20 (buf + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, (uint8_t *)headerX);
		m_DestConnID = headerX[0];
		// decrypt and handle payload
		uint8_t * payload = buf + 32;
		CreateNonce (be32toh (header.h.packetNum), nonce);
		uint8_t h[32];
		memcpy (h, header.buf, 16);
		memcpy (h + 16, &headerX, 16);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 48, h, 32,
			i2p::context.GetSSU2IntroKey (), nonce, payload, len - 48, false))
		{
			LogPrint (eLogWarning, "SSU2: HolePunch AEAD verification failed ");
			return false;
		}
		HandlePayload (payload, len - 48);
		// connect to Charlie
		if (m_State == eSSU2SessionStateIntroduced)
		{
			// create new connID
			uint64_t oldConnID = GetConnID ();
			RAND_bytes ((uint8_t *)&m_DestConnID, 8);
			RAND_bytes ((uint8_t *)&m_SourceConnID, 8);	
			// connect
			m_State = eSSU2SessionStateTokenReceived;
			m_Server.AddPendingOutgoingSession (shared_from_this ());
			m_Server.RemoveSession (oldConnID);
			Connect ();
		}

		return true;
	}

	void SSU2Session::SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, const uint8_t * introKey)
	{
		Header header;
		uint8_t h[32], payload[SSU2_MAX_PACKET_SIZE];
		// fill packet
		header.h.connID = m_DestConnID; // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2PeerTest;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		memcpy (h + 16, &m_SourceConnID, 8); // source id
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		if (msg == 6 || msg == 7)
			payloadSize += CreateAddressBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize, m_RemoteEndpoint);
		payloadSize += CreatePeerTestBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize, 
			msg, eSSU2PeerTestCodeAccept, nullptr, signedData, signedDataLen);
		payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		// encrypt
		uint8_t n[12];
		CreateNonce (be32toh (header.h.packetNum), n);
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, introKey, n, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (introKey, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (introKey, payload + (payloadSize - 12));
		memset (n, 0, 12);
		i2p::crypto::ChaCha20 (h + 16, 16, introKey, n, h + 16);
		// send
		m_Server.Send (header.buf, 16, h + 16, 16, payload, payloadSize, m_RemoteEndpoint);
	}	
		
	bool SSU2Session::ProcessPeerTest (uint8_t * buf, size_t len)
	{
		// we are Alice or Charlie
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 12));
		if (header.h.type != eSSU2PeerTest)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " instead ", (int)eSSU2PeerTest);
			return false;
		}
		uint8_t nonce[12] = {0};
		uint64_t headerX[2]; // sourceConnID, token
		i2p::crypto::ChaCha20 (buf + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, (uint8_t *)headerX);
		m_DestConnID = headerX[0];
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
		return true;
	}

	uint32_t SSU2Session::SendData (const uint8_t * buf, size_t len)
	{
		if (len < 8)
		{
			LogPrint (eLogWarning, "SSU2: Data message payload is too short ", (int)len);
			return 0;
		}
		Header header;
		header.h.connID = m_DestConnID;
		header.h.packetNum = htobe32 (m_SendPacketNum);
		header.h.type = eSSU2Data;
		memset (header.h.flags, 0, 3);
		uint8_t nonce[12];
		CreateNonce (m_SendPacketNum, nonce);
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		i2p::crypto::AEADChaCha20Poly1305 (buf, len, header.buf, 16, m_KeyDataSend, nonce, payload, SSU2_MAX_PACKET_SIZE, true);
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (len - 8));
		header.ll[1] ^= CreateHeaderMask (m_KeyDataSend + 32, payload + (len + 4));
		m_Server.Send (header.buf, 16, payload, len + 16, m_RemoteEndpoint);
		m_SendPacketNum++;
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		m_NumSentBytes += len + 32;
		return m_SendPacketNum - 1;
	}

	void SSU2Session::ProcessData (uint8_t * buf, size_t len)
	{
		Header header;
		header.ll[0] = m_SourceConnID;
		memcpy (header.buf + 8, buf + 8, 8);
		header.ll[1] ^= CreateHeaderMask (m_KeyDataReceive + 32, buf + (len - 12));
		if (header.h.type != eSSU2Data)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type, " instead ", (int)eSSU2Data);
			SendQuickAck (); // in case it was SessionConfirmed
			return;
		}
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = len - 32;
		uint32_t packetNum = be32toh (header.h.packetNum);
		uint8_t nonce[12];
		CreateNonce (packetNum, nonce);
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf + 16, payloadSize, header.buf, 16,
			m_KeyDataReceive, nonce, payload, payloadSize, false))
		{
			LogPrint (eLogWarning, "SSU2: Data AEAD verification failed ");
			return;
		}
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		m_NumReceivedBytes += len;
		if (!packetNum || UpdateReceivePacketNum (packetNum))
			HandlePayload (payload, payloadSize);
	}

	void SSU2Session::HandlePayload (const uint8_t * buf, size_t len)
	{
		size_t offset = 0;
		while (offset < len)
		{
			uint8_t blk = buf[offset];
			offset++;
			auto size = bufbe16toh (buf + offset);
			offset += 2;
			LogPrint (eLogDebug, "SSU2: Block type ", (int)blk, " of size ", size);
			if (size > len)
			{
				LogPrint (eLogError, "SSU2: Unexpected block length ", size);
				break;
			}
			switch (blk)
			{
				case eSSU2BlkDateTime:
					LogPrint (eLogDebug, "SSU2: Datetime");
					if (m_State == eSSU2SessionStateSessionRequestReceived)
					{
						auto ts = i2p::util::GetSecondsSinceEpoch ();
						uint32_t signedOnTime = bufbe32toh (buf + offset);
						if (signedOnTime < ts - SSU2_CLOCK_SKEW || signedOnTime > ts + SSU2_CLOCK_SKEW)
							m_TerminationReason = eSSU2TerminationReasonClockSkew;
					};	
				break;
				case eSSU2BlkOptions:
					LogPrint (eLogDebug, "SSU2: Options");
				break;
				case eSSU2BlkRouterInfo:
				{
					// not from SessionConfirmed, we must add it instantly to use in next block
					LogPrint (eLogDebug, "SSU2: RouterInfo");
					auto ri = ExtractRouterInfo (buf + offset, size);
					if (ri)
						i2p::data::netdb.AddRouterInfo (ri->GetBuffer (), ri->GetBufferLen ());	// TODO: add ri 
					break;
				}
				case eSSU2BlkI2NPMessage:
				{
					LogPrint (eLogDebug, "SSU2: I2NP message");
					auto nextMsg = NewI2NPShortMessage ();
					nextMsg->len = nextMsg->offset + size + 7; // 7 more bytes for full I2NP header
					memcpy (nextMsg->GetNTCP2Header (), buf + offset, size);
					nextMsg->FromNTCP2 (); // SSU2 has the same format as NTCP2
					m_Handler.PutNextMessage (std::move (nextMsg));
					m_IsDataReceived = true;
					break;
				}
				case eSSU2BlkFirstFragment:
					LogPrint (eLogDebug, "SSU2: First fragment");
					HandleFirstFragment (buf + offset, size);
					m_IsDataReceived = true;
				break;
				case eSSU2BlkFollowOnFragment:
					LogPrint (eLogDebug, "SSU2: Follow-on fragment");
					HandleFollowOnFragment (buf + offset, size);
					m_IsDataReceived = true;
				break;
				case eSSU2BlkTermination:
					LogPrint (eLogDebug, "SSU2: Termination reason=", (int)buf[11]);
					Terminate ();
				break;
				case eSSU2BlkRelayRequest:
					LogPrint (eLogDebug, "SSU2: RelayRequest");
					HandleRelayRequest (buf + offset, size);
				break;
				case eSSU2BlkRelayResponse:
					LogPrint (eLogDebug, "SSU2: RelayResponse");
					HandleRelayResponse (buf + offset, size);
				break;
				case eSSU2BlkRelayIntro:
					LogPrint (eLogDebug, "SSU2: RelayIntro");
					HandleRelayIntro (buf + offset, size);
				break;
				case eSSU2BlkPeerTest:
					LogPrint (eLogDebug, "SSU2: PeerTest msg=", (int)buf[offset], " code=", (int)buf[offset+1]);
					HandlePeerTest (buf + offset, size);
				break;
				case eSSU2BlkNextNonce:
				break;
				case eSSU2BlkAck:
					LogPrint (eLogDebug, "SSU2: Ack");
					HandleAck (buf + offset, size);
				break;
				case eSSU2BlkAddress:
				{
					boost::asio::ip::udp::endpoint ep;
					if (ExtractEndpoint (buf + offset, size, ep))
					{		
						LogPrint (eLogInfo, "SSU2: Our external address is ", ep);
						if (!i2p::util::net::IsInReservedRange (ep.address ()))
							i2p::context.UpdateAddress (ep.address ());
					}	
					break;
				}
				case eSSU2BlkIntroKey:
				break;
				case eSSU2BlkRelayTagRequest:
					LogPrint (eLogDebug, "SSU2: RelayTagRequest");
					if (!m_RelayTag)
					{
						RAND_bytes ((uint8_t *)&m_RelayTag, 4);
						m_Server.AddRelay (m_RelayTag, shared_from_this ());
					}
				break;
				case eSSU2BlkRelayTag:
					LogPrint (eLogDebug, "SSU2: RelayTag");
					m_RelayTag = bufbe32toh (buf + offset);
				break;
				case eSSU2BlkNewToken:
				{
					LogPrint (eLogDebug, "SSU2: New token");
					uint64_t token;
					memcpy (&token, buf + offset + 4, 8);
					m_Server.UpdateOutgoingToken (m_RemoteEndpoint, token, bufbe32toh (buf + offset));
					break;
				}
				case eSSU2BlkPathChallenge:
				break;
				case eSSU2BlkPathResponse:
				break;
				case eSSU2BlkFirstPacketNumber:
				break;
				case eSSU2BlkPadding:
					LogPrint (eLogDebug, "SSU2: Padding");
				break;
				default:
					LogPrint (eLogWarning, "SSU2: Unknown block type ", (int)blk);
			}
			offset += size;
		}
	}

	void SSU2Session::HandleAck (const uint8_t * buf, size_t len)
	{
		if (m_State == eSSU2SessionStateSessionConfirmedSent)
		{
			Established ();
			return;
		}	
		if (m_SentPackets.empty ()) return;
		if (len < 5) return;
		// acnt
		uint32_t ackThrough = bufbe32toh (buf);
		uint32_t firstPacketNum = ackThrough > buf[4] ? ackThrough - buf[4] : 0;
		HandleAckRange (firstPacketNum, ackThrough); // acnt
		// ranges
		len -= 5;
		const uint8_t * ranges = buf + 5;
		while (len > 0 && firstPacketNum)
		{
			uint32_t lastPacketNum = firstPacketNum - 1;
			if (*ranges > lastPacketNum) break;
			lastPacketNum -= *ranges; ranges++; // nacks
			if (*ranges > lastPacketNum + 1) break;
			firstPacketNum = lastPacketNum - *ranges + 1; ranges++; // acks
			len -= 2;
			HandleAckRange (firstPacketNum, lastPacketNum);
		}
	}

	void SSU2Session::HandleAckRange (uint32_t firstPacketNum, uint32_t lastPacketNum)
	{
		if (firstPacketNum > lastPacketNum) return;
		auto it = m_SentPackets.begin ();
		while (it != m_SentPackets.end () && it->first < firstPacketNum) it++; // find first acked packet
		if (it == m_SentPackets.end () || it->first > lastPacketNum) return; // not found
		auto it1 = it;
		while (it1 != m_SentPackets.end () && it1->first <= lastPacketNum) it1++;
		m_SentPackets.erase (it, it1);
	}

	void SSU2Session::HandleFirstFragment (const uint8_t * buf, size_t len)
	{
		uint32_t msgID; memcpy (&msgID, buf + 1, 4);
		auto msg = NewI2NPMessage ();
		// same format as I2NP message block
		msg->len = msg->offset + len + 7;
		memcpy (msg->GetNTCP2Header (), buf, len);
		std::shared_ptr<SSU2IncompleteMessage> m;
		bool found = false;
		auto it = m_IncompleteMessages.find (msgID);
		if (it != m_IncompleteMessages.end ())
		{
			found = true;
			m = it->second;
		}
		else
		{
			m = std::make_shared<SSU2IncompleteMessage>();
			m_IncompleteMessages.emplace (msgID, m);
		}
		m->msg = msg;
		m->nextFragmentNum = 1;
		m->lastFragmentInsertTime = i2p::util::GetSecondsSinceEpoch ();
		if (found && ConcatOutOfSequenceFragments (m))
		{
			// we have all follow-on fragments already
			m->msg->FromNTCP2 ();
			m_Handler.PutNextMessage (std::move (m->msg));
			m_IncompleteMessages.erase (it);
		}
	}

	void SSU2Session::HandleFollowOnFragment (const uint8_t * buf, size_t len)
	{
		if (len < 5) return;
		uint8_t fragmentNum = buf[0] >> 1;
		bool isLast = buf[0] & 0x01;
		uint32_t msgID; memcpy (&msgID, buf + 1, 4);
		auto it = m_IncompleteMessages.find (msgID);
		if (it != m_IncompleteMessages.end ())
		{
			if (it->second->nextFragmentNum == fragmentNum && it->second->msg)
			{
				// in sequence
				it->second->msg->Concat (buf + 5, len - 5);
				if (isLast)
				{
					it->second->msg->FromNTCP2 ();
					m_Handler.PutNextMessage (std::move (it->second->msg));
					m_IncompleteMessages.erase (it);
				}
				else
				{
					it->second->nextFragmentNum++;
					if (ConcatOutOfSequenceFragments (it->second))
					{
						m_Handler.PutNextMessage (std::move (it->second->msg));
						m_IncompleteMessages.erase (it);
					}
					else
						it->second->lastFragmentInsertTime = i2p::util::GetSecondsSinceEpoch ();
				}
				return;
			}
		}
		else
		{
			// follow-on fragment before first fragment
			auto msg = std::make_shared<SSU2IncompleteMessage> ();
			msg->nextFragmentNum = 0;
			it = m_IncompleteMessages.emplace (msgID, msg).first;
		}
		// insert out of sequence fragment
		auto fragment = std::make_shared<SSU2IncompleteMessage::Fragment> ();
		memcpy (fragment->buf, buf + 5, len -5);
		fragment->len = len - 5;
		fragment->isLast = isLast;
		it->second->outOfSequenceFragments.emplace (fragmentNum, fragment);
		it->second->lastFragmentInsertTime = i2p::util::GetSecondsSinceEpoch ();
	}

	bool SSU2Session::ConcatOutOfSequenceFragments (std::shared_ptr<SSU2IncompleteMessage> m)
	{
		if (!m) return false;
		bool isLast = false;
		for (auto it = m->outOfSequenceFragments.begin (); it != m->outOfSequenceFragments.end ();)
			if (it->first == m->nextFragmentNum)
			{
				m->msg->Concat (it->second->buf, it->second->len);
				isLast = it->second->isLast;
				it = m->outOfSequenceFragments.erase (it);
				m->nextFragmentNum++;
			}
			else
				break;
		return isLast;
	}

	void SSU2Session::HandleRelayRequest (const uint8_t * buf, size_t len)
	{
		// we are Bob
		uint32_t relayTag = bufbe32toh (buf + 5); // relay tag
		auto session = m_Server.FindRelaySession (relayTag);
		if (!session)
		{
			LogPrint (eLogWarning, "SSU2: RelayRequest session with relay tag ", relayTag, " not found");
			// send relay response back to Alice
			uint8_t payload[SSU2_MAX_PACKET_SIZE];
			size_t payloadSize = CreateRelayResponseBlock (payload, m_MaxPayloadSize, 
				eSSU2RelayResponseCodeBobRelayTagNotFound, bufbe32toh (buf + 1), false, 0);
			payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
			SendData (payload, payloadSize);
			return; 
		}
		session->m_RelaySessions.emplace (bufbe32toh (buf + 1), // nonce
			std::make_pair (shared_from_this (), i2p::util::GetSecondsSinceEpoch ()) );

		// send relay intro to Charlie
		auto r = i2p::data::netdb.FindRouter (GetRemoteIdentity ()->GetIdentHash ()); // Alice's RI
		if (r) 
			i2p::data::netdb.PopulateRouterInfoBuffer (r);
		else
			LogPrint (eLogWarning, "SSU2: RelayRequest Alice's router info not found");
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = r ? CreateRouterInfoBlock (payload, m_MaxPayloadSize - len - 32, r) : 0;
		if (!payloadSize && r)
			session->SendFragmentedMessage (CreateDatabaseStoreMsg (r));
		payloadSize += CreateRelayIntroBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize, buf + 1, len -1);
		if (payloadSize < m_MaxPayloadSize)
			payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		session->SendData (payload, payloadSize);
	}

	void SSU2Session::HandleRelayIntro (const uint8_t * buf, size_t len)
	{
		// we are Charlie
		SSU2RelayResponseCode code = eSSU2RelayResponseCodeAccept;
		uint64_t token = 0;
		auto r = i2p::data::netdb.FindRouter (buf + 1); // Alice
		if (r)
		{	
			SignedData s;
			s.Insert ((const uint8_t *)"RelayRequestData", 16); // prologue
			s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
			s.Insert (i2p::context.GetIdentHash (), 32); // chash
			s.Insert (buf + 33, 14); // nonce, relay tag, timestamp, ver, asz
			uint8_t asz = buf[46];
			s.Insert (buf + 47, asz); // Alice Port, Alice IP
			if (s.Verify (r->GetIdentity (), buf + 47 + asz))
			{
				// send HolePunch
				boost::asio::ip::udp::endpoint ep;
				if (ExtractEndpoint (buf + 47, asz, ep))
				{
					auto addr = ep.address ().is_v6 () ? r->GetSSU2V6Address () : r->GetSSU2V4Address ();
					if (addr)
					{
						if (m_Server.IsSupported (ep.address ()))
						{
							token = m_Server.GetIncomingToken (ep);
							SendHolePunch (bufbe32toh (buf + 33), ep, addr->i, token);
						}	
						else
							code = eSSU2RelayResponseCodeCharlieUnsupportedAddress;
					}	
					else
					{
						LogPrint (eLogWarning, "SSU2: RelayInfo unknown address");
						code = eSSU2RelayResponseCodeCharlieAliceIsUnknown;	
					}		
				}
			}
			else
			{
				LogPrint (eLogWarning, "SSU2: RelayIntro signature verification failed");
				code = eSSU2RelayResponseCodeCharlieSignatureFailure;
			}
		}	
		else
		{
			LogPrint (eLogError, "SSU2: RelayIntro unknown router to introduce");
			code = eSSU2RelayResponseCodeCharlieAliceIsUnknown;
		}	
		// send relay response to Bob
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = CreateRelayResponseBlock (payload, m_MaxPayloadSize, 
			code, bufbe32toh (buf + 33), true, token);
		payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		SendData (payload, payloadSize);
	}

	void SSU2Session::HandleRelayResponse (const uint8_t * buf, size_t len)
	{		
		uint32_t nonce = bufbe32toh (buf + 2);
		if (m_State == eSSU2SessionStateIntroduced) 
		{	
			// HolePunch from Charlie
			// TODO: verify address and signature
			// verify nonce
			if (~htobe64 (((uint64_t)nonce << 32) | nonce) != m_DestConnID)
				LogPrint (eLogWarning, "SSU2: Relay response nonce mismatch ", nonce, " connID=", m_DestConnID);
			if (len >= 8)
			{
				// new token
				uint64_t token;	
				memcpy (&token, buf + len - 8, 8);
				m_Server.UpdateOutgoingToken (m_RemoteEndpoint, token, i2p::util::GetSecondsSinceEpoch () + SSU2_TOKEN_EXPIRATION_TIMEOUT);
			}	
			return; 
		}	
		auto it = m_RelaySessions.find (nonce); 
		if (it != m_RelaySessions.end ())
		{
			if (it->second.first && it->second.first->IsEstablished ())
			{	
				// we are Bob, message from Charlie
				uint8_t payload[SSU2_MAX_PACKET_SIZE];
				payload[0] = eSSU2BlkRelayResponse;
				htobe16buf (payload + 1, len);
				memcpy (payload + 3, buf, len); // forward to Alice as is
				size_t payloadSize = len + 3;
				payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
				it->second.first->SendData (payload, payloadSize); 
			}	
			else
			{
				// we are Alice, message from Bob
				if (!buf[1]) // status code accepted?
				{
					// verify signature
					uint8_t csz = buf[11];
					SignedData s;
					s.Insert ((const uint8_t *)"RelayAgreementOK", 16); // prologue
					s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
					s.Insert (buf + 2, 10 + csz); // nonce, timestamp, ver, csz and Charlie's endpoint
					if (s.Verify (it->second.first->GetRemoteIdentity (), buf + 12 + csz))
					{
						if (it->second.first->m_State == eSSU2SessionStateIntroduced) // HolePunch not received yet
							// update Charlie's endpoint
							ExtractEndpoint (buf + 12, csz, it->second.first->m_RemoteEndpoint);
					}
					else
					{	
						LogPrint (eLogWarning, "SSU2: RelayResponse signature verification failed");
						m_Server.GetService ().post (std::bind (&SSU2Session::Terminate, it->second.first));
					}	
				}
				else
				{		
					LogPrint (eLogInfo, "SSU2: RelayResponse status code=", (int)buf[1]);
					m_Server.GetService ().post (std::bind (&SSU2Session::Terminate, it->second.first));
				}	
			}
			m_RelaySessions.erase (it);
		}
		else
			LogPrint (eLogWarning, "SSU2: RelayResponse unknown nonce ", bufbe32toh (buf + 2));
	}

	void SSU2Session::HandlePeerTest (const uint8_t * buf, size_t len)
	{
		if (len < 3) return;
		uint8_t msg = buf[0];
		size_t offset = 3; // points to signed data
		if (msg == 2 || msg == 4) offset += 32;  // hash is presented for msg 2 and 4 only
		if (len < offset + 5) return;    
		uint32_t nonce = bufbe32toh (buf + offset + 1); 
		switch (msg) // msg
		{
			case 1: // Bob from Alice
			{	
				auto session = m_Server.GetRandomSession ((buf[12] == 6) ? i2p::data::RouterInfo::eSSU2V4 : i2p::data::RouterInfo::eSSU2V6,
					GetRemoteIdentity ()->GetIdentHash ());
				if (session) // session with Charlie
				{
					session->m_PeerTests.emplace (nonce, std::make_pair (shared_from_this (), i2p::util::GetSecondsSinceEpoch ()));
					uint8_t payload[SSU2_MAX_PACKET_SIZE];
					// Alice's RouterInfo
					auto r = i2p::data::netdb.FindRouter (GetRemoteIdentity ()->GetIdentHash ());
					if (r) i2p::data::netdb.PopulateRouterInfoBuffer (r);
					size_t payloadSize = r ? CreateRouterInfoBlock (payload, m_MaxPayloadSize - len - 32, r) : 0;
					if (!payloadSize && r)
						session->SendFragmentedMessage (CreateDatabaseStoreMsg (r));
					if (payloadSize + len + 48 > m_MaxPayloadSize)
					{
						// doesn't fit one message, send RouterInfo in separate message
						session->SendData (payload, payloadSize);
						payloadSize = 0;
					}	
					// PeerTest to Charlie
					payloadSize += CreatePeerTestBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize, 2, 
						eSSU2PeerTestCodeAccept, GetRemoteIdentity ()->GetIdentHash (), buf + offset, len - offset);
					payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
					session->SendData (payload, payloadSize);
				}
				else
				{
					// Charlie not found, send error back to Alice
					uint8_t payload[SSU2_MAX_PACKET_SIZE], zeroHash[32] = {0};
					size_t payloadSize = CreatePeerTestBlock (payload, m_MaxPayloadSize, 4, 
						eSSU2PeerTestCodeBobNoCharlieAvailable, zeroHash, buf + offset, len - offset);
					payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
					SendData (payload, payloadSize);
				}	
				break;
			}
			case 2: // Charlie from Bob
			{
				// sign with Charlie's key
				uint8_t asz = buf[offset + 9];
				std::vector<uint8_t> newSignedData (asz + 10 + i2p::context.GetIdentity ()->GetSignatureLen ());
				memcpy (newSignedData.data (), buf + offset, asz + 10);
				SignedData s;
				s.Insert ((const uint8_t *)"PeerTestValidate", 16); // prologue
				s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
				s.Insert (buf + 3, 32); // ahash
				s.Insert (newSignedData.data (), asz + 10); // ver, nonce, ts, asz, Alice's endpoint 
				s.Sign (i2p::context.GetPrivateKeys (), newSignedData.data () + 10 + asz);
				// send response (msg 3) back and msg 5 if accepted
				SSU2PeerTestCode code = eSSU2PeerTestCodeAccept;
				auto r = i2p::data::netdb.FindRouter (buf + 3); // find Alice
				if (r)
				{
					size_t signatureLen = r->GetIdentity ()->GetSignatureLen ();
					if (len >= offset + asz + 10 + signatureLen)
					{	
						s.Reset ();
						s.Insert ((const uint8_t *)"PeerTestValidate", 16); // prologue
						s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
						s.Insert (buf + offset, asz + 10); // signed data
						if (s.Verify (r->GetIdentity (), buf + offset + asz + 10))
						{	
							if (!m_Server.FindSession (r->GetIdentity ()->GetIdentHash ()))
							{	
								boost::asio::ip::udp::endpoint ep;
								std::shared_ptr<const i2p::data::RouterInfo::Address> addr;
								if (ExtractEndpoint (buf + offset + 10, asz, ep))
									addr = r->GetSSU2Address (ep.address ().is_v4 ());
								if (addr && m_Server.IsSupported (ep.address ()))
								{	
									// send msg 5 to Alice
									auto session = std::make_shared<SSU2Session> (m_Server, r, addr);
									session->SetState (eSSU2SessionStatePeerTest);	
									session->m_RemoteEndpoint = ep; // might be different
									session->m_DestConnID = htobe64 (((uint64_t)nonce << 32) | nonce);
									session->m_SourceConnID = ~session->m_DestConnID;
									m_Server.AddSession (session);
									session->SendPeerTest (5, newSignedData.data (), newSignedData.size (), addr->i);
								}	
								else
									code = eSSU2PeerTestCodeCharlieUnsupportedAddress;
							}
							else
								code = eSSU2PeerTestCodeCharlieAliceIsAlreadyConnected;
						}
						else 
							code = eSSU2PeerTestCodeCharlieSignatureFailure; 
					}	
					else // maformed message
						code = eSSU2PeerTestCodeCharlieReasonUnspecified;
				}
				else
					code = eSSU2PeerTestCodeCharlieAliceIsUnknown;
				// send msg 3 back to Bob
				uint8_t payload[SSU2_MAX_PACKET_SIZE];
				size_t payloadSize = CreatePeerTestBlock (payload, m_MaxPayloadSize, 3, 
					code, nullptr, newSignedData.data (), newSignedData.size ());
				payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
				SendData (payload, payloadSize);
				break;
			}	
			case 3: // Bob from Charlie
			{
				auto it = m_PeerTests.find (nonce);
				if (it != m_PeerTests.end () && it->second.first)
				{
					uint8_t payload[SSU2_MAX_PACKET_SIZE];
					// Charlie's RouterInfo
					auto r = i2p::data::netdb.FindRouter (GetRemoteIdentity ()->GetIdentHash ());
					if (r) i2p::data::netdb.PopulateRouterInfoBuffer (r);
					size_t payloadSize = r ? CreateRouterInfoBlock (payload, m_MaxPayloadSize - len - 32, r) : 0;
					if (!payloadSize && r)
						it->second.first->SendFragmentedMessage (CreateDatabaseStoreMsg (r));
					if (payloadSize + len + 16 > m_MaxPayloadSize)
					{
						// doesn't fit one message, send RouterInfo in separate message
						it->second.first->SendData (payload, payloadSize);
						payloadSize = 0;
					}
					// PeerTest to Alice
					payloadSize += CreatePeerTestBlock (payload + payloadSize, m_MaxPayloadSize, 4, 
						(SSU2PeerTestCode)buf[1], GetRemoteIdentity ()->GetIdentHash (), buf + offset, len - offset);
					if (payloadSize < m_MaxPayloadSize)
						payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
					it->second.first->SendData (payload, payloadSize);
					m_PeerTests.erase (it);
				}
				else
					LogPrint (eLogWarning, "SSU2: Unknown peer test 3 nonce ", nonce);
				break;
			}
			case 4: // Alice from Bob
			{	
				auto it = m_PeerTests.find (nonce);
				if (it != m_PeerTests.end ())
				{
					if (buf[1] == eSSU2PeerTestCodeAccept)
					{	
						auto r = i2p::data::netdb.FindRouter (buf + 3); // find Charlie
						if (r && it->second.first)
						{	
							uint8_t asz = buf[offset + 9];
							SignedData s;
							s.Insert ((const uint8_t *)"PeerTestValidate", 16); // prologue
							s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
							s.Insert (i2p::context.GetIdentity ()->GetIdentHash (), 32); // ahash
							s.Insert (buf + offset, asz + 10); // ver, nonce, ts, asz, Alice's endpoint 
							if (s.Verify (r->GetIdentity (), buf + offset + asz + 10))
							{
								it->second.first->SetRemoteIdentity (r->GetIdentity ());
								auto addr = r->GetSSU2Address (m_Address->IsV4 ());
								if (addr)
								{	
									it->second.first->m_Address = addr;
									if (it->second.first->m_State == eSSU2SessionStatePeerTestReceived)
									{
										// msg 5 already received. send msg 6 
										SetRouterStatus (eRouterStatusOK);
										it->second.first->m_State = eSSU2SessionStatePeerTest;
										it->second.first->SendPeerTest (6, buf + offset, len - offset, addr->i);
									}
									else
									{
										if (GetRouterStatus () == eRouterStatusTesting)
											SetRouterStatus (eRouterStatusFirewalled);
									}	
								}
								else
								{
									LogPrint (eLogWarning, "SSU2: Peer test 4 address not found");
									it->second.first->Terminate ();
								}	
							}
							else
							{	
								LogPrint (eLogWarning, "SSU2: Peer test 4 signature verification failed");
								it->second.first->Terminate ();
							}	
						}	
					}
					else
					{
						LogPrint (eLogInfo, "SSU2: Peer test 4 error code ", (int)buf[1], " from ",
							i2p::data::GetIdentHashAbbreviation (buf[1] < 64 ? GetRemoteIdentity ()->GetIdentHash () : i2p::data::IdentHash (buf + 3)));
						if (GetRouterStatus () == eRouterStatusTesting)
							SetRouterStatus (eRouterStatusUnknown);
						it->second.first->Terminate ();
					}	
					m_PeerTests.erase (it);
				}	
				else
					LogPrint (eLogWarning, "SSU2: Unknown peer test 4 nonce ", nonce);
				break;
			}	
			case 5: // Alice from Charlie 1
				if (htobe64 (((uint64_t)nonce << 32) | nonce) == m_SourceConnID)
				{
					if (m_Address)
					{	
						SetRouterStatus (eRouterStatusOK);
						SendPeerTest (6, buf + offset, len - offset, m_Address->i);
					}	
					else
						// we received msg 5 before msg 4
						m_State = eSSU2SessionStatePeerTestReceived;
				}	
				else
					LogPrint (eLogWarning, "SSU2: Peer test 5 nonce mismatch ", nonce, " connID=", m_SourceConnID);
			break;
			case 6: // Charlie from Alice
				if (m_Address)
					SendPeerTest (7, buf + offset, len - offset, m_Address->i);
				else
					LogPrint (eLogWarning, "SSU2: Unknown address for peer test 6");
				m_Server.RemoveSession (~htobe64 (((uint64_t)nonce << 32) | nonce));
			break;
			case 7: // Alice from Charlie 2
				m_Server.RemoveSession (htobe64 (((uint64_t)nonce << 32) | nonce));
				if (m_Address->IsV6 ())
					i2p::context.SetStatusV6 (eRouterStatusOK); // set status OK for ipv6 even if from SSU2
			break;
			default:
				LogPrint (eLogWarning, "SSU2: PeerTest unexpected msg num ", buf[0]);
		}
	}

	bool SSU2Session::ExtractEndpoint (const uint8_t * buf, size_t size, boost::asio::ip::udp::endpoint& ep)
	{
		if (size < 2) return false;
		int port = bufbe16toh (buf);
		if (size == 6)
		{
			boost::asio::ip::address_v4::bytes_type bytes;
			memcpy (bytes.data (), buf + 2, 4);
			ep = boost::asio::ip::udp::endpoint (boost::asio::ip::address_v4 (bytes), port);
		}
		else if (size == 18)
		{
			boost::asio::ip::address_v6::bytes_type bytes;
			memcpy (bytes.data (), buf + 2, 16);
			ep = boost::asio::ip::udp::endpoint (boost::asio::ip::address_v6 (bytes), port);
		}
		else
		{
			LogPrint (eLogWarning, "SSU2: Address size ", int(size), " is not supported");
			return false;
		}
		return true;
	}

	size_t SSU2Session::CreateEndpoint (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& ep)
	{
		if (len < 6) return 0;
		htobe16buf (buf, ep.port ());
		size_t size = 0;
		if (ep.address ().is_v4 ())
		{
			memcpy (buf + 2, ep.address ().to_v4 ().to_bytes ().data (), 4);
			size = 6;
		}
		else if (ep.address ().is_v6 ())
		{
			if (len < 18) return 0;
			memcpy (buf + 2, ep.address ().to_v6 ().to_bytes ().data (), 16);
			size = 18;
		}
		else
		{
			LogPrint (eLogWarning, "SSU2: Wrong address type ", ep.address ().to_string ());
			return 0;
		}
		return size;
	}

	std::shared_ptr<const i2p::data::RouterInfo::Address> SSU2Session::FindLocalAddress () const
	{
		if (m_Address)
			return i2p::context.GetRouterInfo ().GetSSU2Address (m_Address->IsV4 ());
		return nullptr;
	}	

	void SSU2Session::AdjustMaxPayloadSize ()
	{
		auto addr = FindLocalAddress ();
		if (addr && addr->ssu) 
		{	
			int mtu = addr->ssu->mtu;
			if (!mtu && addr->IsV4 ()) mtu = SSU2_MAX_PACKET_SIZE;
			if (m_Address && m_Address->ssu && (!mtu || m_Address->ssu->mtu < mtu)) 
				mtu = m_Address->ssu->mtu;
			if (mtu)
			{	
				m_MaxPayloadSize = mtu - (addr->IsV6 () ? IPV6_HEADER_SIZE: IPV4_HEADER_SIZE) - UDP_HEADER_SIZE - 32;
				LogPrint (eLogDebug, "SSU2: Session MTU=", mtu, ", max payload size=", m_MaxPayloadSize);
			}	
		}	
	}	
		
	RouterStatus SSU2Session::GetRouterStatus () const
	{
		if (m_Address)
		{
			if (m_Address->IsV4 ()) 
				return i2p::context.GetStatus ();
			if (m_Address->IsV6 ()) 
				return i2p::context.GetStatusV6 ();
		}	
		return eRouterStatusUnknown;
	}	
		
	void SSU2Session::SetRouterStatus (RouterStatus status) const
	{
		if (m_Address)
		{	
			if (m_Address->IsV4 ())
				i2p::context.SetStatusSSU2 (status);
			else if (m_Address->IsV6 ())
				i2p::context.SetStatusV6SSU2 (status);
		}	
	}	
		
	size_t SSU2Session::CreateAddressBlock (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& ep)
	{
		if (len < 9) return 0;
		buf[0] = eSSU2BlkAddress;
		size_t size = CreateEndpoint (buf + 3, len - 3, ep);
		if (!size) return 0;
		htobe16buf (buf + 1, size);
		return size + 3;
	}

	size_t SSU2Session::CreateRouterInfoBlock (uint8_t * buf, size_t len, std::shared_ptr<const i2p::data::RouterInfo> r)
	{
		if (!r || !r->GetBuffer () || len < 5) return 0;
		buf[0] = eSSU2BlkRouterInfo;
		size_t size = r->GetBufferLen ();
		if (size + 5 < len)
		{
			memcpy (buf + 5, r->GetBuffer (), size);
			buf[3] = 0; // flag
		}
		else
		{
			i2p::data::GzipDeflator deflator;
			deflator.SetCompressionLevel (9);
			size = deflator.Deflate (r->GetBuffer (), r->GetBufferLen (), buf + 5, len - 5);
			if (!size) return 0; // doesn't fit
			buf[3] = SSU2_ROUTER_INFO_FLAG_GZIP; // flag
		}
		htobe16buf (buf + 1, size + 2); // size
		buf[4] = 1; // frag
		return size + 5;
	}

	size_t SSU2Session::CreateAckBlock (uint8_t * buf, size_t len)
	{
		if (len < 8) return 0;
		buf[0] = eSSU2BlkAck;
		uint32_t ackThrough = m_OutOfSequencePackets.empty () ? m_ReceivePacketNum : *m_OutOfSequencePackets.rbegin ();
		htobe32buf (buf + 3, ackThrough); // Ack Through
		uint8_t acnt = 0;
		int numRanges = 0;
		if (ackThrough)
		{
			if (m_OutOfSequencePackets.empty ())
				acnt = std::min ((int)ackThrough, 255); // no gaps
			else
			{
				auto it = m_OutOfSequencePackets.rbegin (); it++; // prev packet num
				while (it != m_OutOfSequencePackets.rend () && *it == ackThrough - acnt	- 1)
				{
					acnt++;
					it++;
				}
				// ranges
				uint32_t lastNum = ackThrough - acnt;
				while (it != m_OutOfSequencePackets.rend () && numRanges < SSU2_MAX_NUM_ACK_RANGES)
				{
					if (lastNum - (*it) > 255)
					{	
						// NACKs only ranges
						if (lastNum > (*it) + 255*(SSU2_MAX_NUM_ACK_RANGES - numRanges)) break; // too many NACKs 
						while (lastNum - (*it) > 255)
						{
							buf[8 + numRanges*2] = 255; buf[8 + numRanges*2 + 1] = 0; // NACKs 255, Acks 0
							lastNum -= 255;
							numRanges++;
						}
					}	
					// NACKs and Acks ranges
					buf[8 + numRanges*2] = lastNum - (*it) - 1; // NACKs
					lastNum = *it; it++;
					int numAcks = 1;
					while (it != m_OutOfSequencePackets.rend () && lastNum > 0 && *it == lastNum - 1)
					{
						numAcks++; lastNum--;
						it++;
					}
					while (numAcks > 255)
					{
						// Acks only ranges
						buf[8 + numRanges*2 + 1] = 255; // Acks 255
						numAcks -= 255;
						numRanges++;
						buf[8 + numRanges*2] = 0;  // NACKs 0
						if (numRanges >= SSU2_MAX_NUM_ACK_RANGES) break;
					}	
					if (numAcks > 255) numAcks = 255;
					buf[8 + numRanges*2 + 1] = (uint8_t)numAcks; // Acks
					numRanges++;		
				}
				if (numRanges < SSU2_MAX_NUM_ACK_RANGES && it == m_OutOfSequencePackets.rend ())
				{
					// add range between out-of-seqence and received
					int nacks = *m_OutOfSequencePackets.begin () - m_ReceivePacketNum - 1;
					if (nacks > 0)
					{
						if (nacks > 255) nacks = 255;
						buf[8 + numRanges*2] = nacks;
						buf[8 + numRanges*2 + 1] = std::min ((int)m_ReceivePacketNum + 1, 255);
						numRanges++;
					}	
				}	
			}
		}
		buf[7] = acnt; // acnt
		htobe16buf (buf + 1, 5 + numRanges*2);
		return 8 + numRanges*2;
	}

	size_t SSU2Session::CreatePaddingBlock (uint8_t * buf, size_t len, size_t minSize)
	{
		if (len < minSize) return 0;
		uint8_t paddingSize = rand () & 0x0F; // 0 - 15
		if (paddingSize > len) paddingSize = len;
		else if (paddingSize < minSize) paddingSize = minSize;
		if (paddingSize)
		{
			buf[0] = eSSU2BlkPadding;
			htobe16buf (buf + 1, paddingSize);
			memset (buf + 3, 0, paddingSize);
		}
		else
			return 0;
		return paddingSize + 3;
	}

	size_t SSU2Session::CreateI2NPBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage>&& msg)
	{
		msg->ToNTCP2 ();
		auto msgBuf = msg->GetNTCP2Header ();
		auto msgLen = msg->GetNTCP2Length ();
		if (msgLen + 3 > len) msgLen = len - 3;
		buf[0] = eSSU2BlkI2NPMessage;
		htobe16buf (buf + 1, msgLen); // size
		memcpy (buf + 3, msgBuf, msgLen);
		return msgLen + 3;
	}

	size_t SSU2Session::CreateFirstFragmentBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage> msg)
	{
		if (len < 12) return 0;
		msg->ToNTCP2 ();
		auto msgBuf = msg->GetNTCP2Header ();
		auto msgLen = msg->GetNTCP2Length ();
		if (msgLen + 3 <= len) return 0;
		msgLen = len - 3;
		buf[0] = eSSU2BlkFirstFragment;
		htobe16buf (buf + 1, msgLen); // size
		memcpy (buf + 3, msgBuf, msgLen);
		msg->offset = (msgBuf - msg->buf) + msgLen;
		return msgLen + 3;
	}

	size_t SSU2Session::CreateFollowOnFragmentBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage> msg, uint8_t& fragmentNum, uint32_t msgID)
	{
		if (len < 8) return 0;
		bool isLast = true;
		auto msgLen = msg->len - msg->offset;
		if (msgLen + 8 > len)
		{
			msgLen = len - 8;
			isLast = false;
		}
		buf[0] = eSSU2BlkFollowOnFragment;
		htobe16buf (buf + 1, msgLen + 5); // size
		fragmentNum++;
		buf[3] = fragmentNum << 1;
		if (isLast) buf[3] |= 0x01;
		memcpy (buf + 4, &msgID, 4);
		memcpy (buf + 8, msg->buf + msg->offset, msgLen);
		msg->offset += msgLen;
		return msgLen + 8;
	}

	size_t SSU2Session::CreateRelayIntroBlock (uint8_t * buf, size_t len, const uint8_t * introData, size_t introDataLen)
	{
		buf[0] = eSSU2BlkRelayIntro;
		size_t payloadSize = 1/* flag */ + 32/* Alice router hash */ + introDataLen;
		if (payloadSize + 3 > len) return 0;
		htobe16buf (buf + 1, payloadSize); // size
		buf[3] = 0; // flag
		memcpy (buf + 4, GetRemoteIdentity ()->GetIdentHash (), 32); // Alice router hash
		memcpy (buf + 36, introData, introDataLen);
		return payloadSize + 3;
	}

	size_t SSU2Session::CreateRelayResponseBlock (uint8_t * buf, size_t len, 
		SSU2RelayResponseCode code, uint32_t nonce, bool endpoint, uint64_t token)
	{
		buf[0] = eSSU2BlkRelayResponse;
		buf[3] = 0; // flag
		buf[4] = code; // code
		htobe32buf (buf + 5, nonce); // nonce
		htobe32buf (buf + 9, i2p::util::GetSecondsSinceEpoch ()); // timestamp
		buf[13] = 2; // ver
		size_t csz = 0;
		if (endpoint)
		{	
			csz = CreateEndpoint (buf + 15, len - 15, boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port));
			if (!csz) return 0;
		}	
		buf[14] = csz; // csz
		// signature
		SignedData s;
		s.Insert ((const uint8_t *)"RelayAgreementOK", 16); // prologue
		s.Insert (endpoint ? GetRemoteIdentity ()->GetIdentHash () : i2p::context.GetIdentity ()->GetIdentHash (), 32); // bhash
		s.Insert (buf + 5, 10 + csz); // nonce, timestamp, ver, csz and Charlie's endpoint
		s.Sign (i2p::context.GetPrivateKeys (), buf + 15 + csz);
		size_t payloadSize = 12 + csz + i2p::context.GetIdentity ()->GetSignatureLen ();
		if (!code)
		{
			memcpy (buf + payloadSize, &token, 8);
			payloadSize += 8;
		}	
		htobe16buf (buf + 1, payloadSize); // size
		return payloadSize + 3;
	}
		
	size_t SSU2Session::CreatePeerTestBlock (uint8_t * buf, size_t len, uint8_t msg, SSU2PeerTestCode code,
		const uint8_t * routerHash, const uint8_t * signedData, size_t signedDataLen)
	{
		buf[0] = eSSU2BlkPeerTest;
		size_t payloadSize = 3/* msg, code, flag */ + signedDataLen;
		if (routerHash) payloadSize += 32; // router hash
		if (payloadSize + 3 > len) return 0;
		htobe16buf (buf + 1, payloadSize); // size
		buf[3] = msg; // msg
		buf[4] = (uint8_t)code; // code
		buf[5] = 0; //flag
		size_t offset = 6;
		if (routerHash)
		{	
			memcpy (buf + offset, routerHash, 32); // router hash
			offset += 32;
		}	
		memcpy (buf + offset, signedData, signedDataLen);
		return payloadSize + 3;
	}

	size_t SSU2Session::CreatePeerTestBlock (uint8_t * buf, size_t len, uint32_t nonce)
	{
		auto localAddress = FindLocalAddress ();  
		if (!localAddress || !localAddress->port || localAddress->host.is_unspecified ()) 
		{
			LogPrint (eLogWarning, "SSU2: Can't find local address for peer test");
			return 0;
		}	
		// signed data
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		uint8_t signedData[96];
		signedData[0] = 2; // ver
		htobe32buf (signedData + 1, nonce);
		htobe32buf (signedData + 5, ts);
		size_t asz = CreateEndpoint (signedData + 10, 86, boost::asio::ip::udp::endpoint (localAddress->host, localAddress->port));
		signedData[9] = asz;
		// signature
		SignedData s;
		s.Insert ((const uint8_t *)"PeerTestValidate", 16); // prologue
		s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
		s.Insert (signedData, 10 + asz); // ver, nonce, ts, asz, Alice's endpoint 	
		s.Sign (i2p::context.GetPrivateKeys (), signedData + 10 + asz);
		return CreatePeerTestBlock (buf, len, 1, eSSU2PeerTestCodeAccept, nullptr, 
			signedData, 10 + asz + i2p::context.GetIdentity ()->GetSignatureLen ());
	}	

	size_t SSU2Session::CreateTerminationBlock (uint8_t * buf, size_t len)
	{   
		buf[0] = eSSU2BlkTermination;
		htobe16buf (buf + 1, 9);
		htobe64buf (buf + 3, m_ReceivePacketNum);
		buf[11] = (uint8_t)m_TerminationReason;
		return 12;
	}
		
	std::shared_ptr<const i2p::data::RouterInfo> SSU2Session::ExtractRouterInfo (const uint8_t * buf, size_t size)
	{
		if (size < 2) return nullptr;
		// TODO: handle frag
		std::shared_ptr<const i2p::data::RouterInfo> ri;
		if (buf[0] & SSU2_ROUTER_INFO_FLAG_GZIP)
		{
			i2p::data::GzipInflator inflator;
			uint8_t uncompressed[i2p::data::MAX_RI_BUFFER_SIZE];
			size_t uncompressedSize = inflator.Inflate (buf + 2, size - 2, uncompressed, i2p::data::MAX_RI_BUFFER_SIZE);
			if (uncompressedSize && uncompressedSize < i2p::data::MAX_RI_BUFFER_SIZE)
				ri = std::make_shared<i2p::data::RouterInfo>(uncompressed, uncompressedSize);
			else
				LogPrint (eLogInfo, "SSU2: RouterInfo decompression failed ", uncompressedSize);
		}
		else
			ri = std::make_shared<i2p::data::RouterInfo>(buf + 2, size - 2);
		return ri;
	}

	void SSU2Session::CreateNonce (uint64_t seqn, uint8_t * nonce)
	{
		memset (nonce, 0, 4);
		htole64buf (nonce + 4, seqn);
	}

	bool SSU2Session::UpdateReceivePacketNum (uint32_t packetNum)
	{
		if (packetNum <= m_ReceivePacketNum) return false; // duplicate
		if (packetNum == m_ReceivePacketNum + 1)
		{
			for (auto it = m_OutOfSequencePackets.begin (); it != m_OutOfSequencePackets.end ();)
			{
				if (*it == packetNum + 1)
				{
					packetNum++;
					it = m_OutOfSequencePackets.erase (it);
				}
				else
					break;
			}
			m_ReceivePacketNum = packetNum;
		}
		else
			m_OutOfSequencePackets.insert (packetNum);
		return true;
	}

	void SSU2Session::SendQuickAck ()
	{
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = CreateAckBlock (payload, m_MaxPayloadSize);
		payloadSize += CreatePaddingBlock (payload + payloadSize, m_MaxPayloadSize - payloadSize);
		SendData (payload, payloadSize);
	}

	void SSU2Session::SendTermination ()
	{
		uint8_t payload[32];
		size_t payloadSize = CreateTerminationBlock (payload, 32);
		payloadSize += CreatePaddingBlock (payload + payloadSize, 32 - payloadSize);
		SendData (payload, payloadSize);
	}
		
	void SSU2Session::CleanUp (uint64_t ts)
	{
		for (auto it = m_IncompleteMessages.begin (); it != m_IncompleteMessages.end ();)
		{
			if (ts > it->second->lastFragmentInsertTime + SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT)
			{
				LogPrint (eLogWarning, "SSU2: message ", it->first, " was not completed in ", SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT, " seconds, deleted");
				it = m_IncompleteMessages.erase (it);
			}
			else
				++it;
		}
		if (!m_OutOfSequencePackets.empty ())
		{	
			if (m_OutOfSequencePackets.size () > 2*SSU2_MAX_NUM_ACK_RANGES || 
			    *m_OutOfSequencePackets.rbegin () > m_ReceivePacketNum + 255*8)
			{
				uint32_t packet = *m_OutOfSequencePackets.begin ();
				if (packet > m_ReceivePacketNum + 1)
				{
					// like we've just received all packets before first
					packet--;
					m_ReceivePacketNum = packet - 1;
					UpdateReceivePacketNum (packet);
				}	
				else
					LogPrint (eLogError, "SSU2: Out of sequence packet ", packet, " is less than last received ",  m_ReceivePacketNum);
			}
			if (m_OutOfSequencePackets.size () > 255*4)
			{
				// seems we have a serious network issue
				m_ReceivePacketNum = *m_OutOfSequencePackets.rbegin ();
				m_OutOfSequencePackets.clear ();
			}
		}	
		         
		for (auto it = m_RelaySessions.begin (); it != m_RelaySessions.end ();)
		{
			if (ts > it->second.second + SSU2_RELAY_NONCE_EXPIRATION_TIMEOUT)
			{
				LogPrint (eLogWarning, "SSU2: Relay nonce ", it->first, " was not responded in ", SSU2_RELAY_NONCE_EXPIRATION_TIMEOUT, " seconds, deleted");
				it = m_RelaySessions.erase (it);
			}
			else
				++it;
		}
		for (auto it = m_PeerTests.begin (); it != m_PeerTests.end ();)
		{
			if (ts > it->second.second + SSU2_PEER_TEST_EXPIRATION_TIMEOUT)
			{
				LogPrint (eLogWarning, "SSU2: Peer test nonce ", it->first, " was not responded in ", SSU2_PEER_TEST_EXPIRATION_TIMEOUT, " seconds, deleted");
				it = m_PeerTests.erase (it);
			}
			else
				++it;
		}
	}

	void SSU2Session::FlushData ()
	{
		bool sent = SendQueue (); // if we have something to send
		if (m_IsDataReceived)
		{
			if (!sent) SendQuickAck ();
			m_Handler.Flush ();
			m_IsDataReceived = false;
		}
	}

}
}
