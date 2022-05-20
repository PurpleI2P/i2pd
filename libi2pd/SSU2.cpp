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
#include "RouterContext.h"
#include "Transports.h"
#include "Config.h"
#include "Gzip.h"
#include "NetDb.hpp"
#include "SSU2.h"

namespace i2p
{
namespace transport
{
	static uint64_t CreateHeaderMask (const uint8_t * kh, const uint8_t * nonce)
	{
		uint64_t data = 0;
		i2p::crypto::ChaCha20 ((uint8_t *)&data, 8, kh, nonce, (uint8_t *)&data);
		return data;
	}

	SSU2Session::SSU2Session (SSU2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr):
		TransportSession (in_RemoteRouter, SSU2_CONNECT_TIMEOUT),
		m_Server (server), m_Address (addr), m_DestConnID (0), m_SourceConnID (0),
		m_State (eSSU2SessionStateUnknown), m_SendPacketNum (0), m_ReceivePacketNum (0),
		m_IsDataReceived (false), m_WindowSize (SSU2_MAX_WINDOW_SIZE), m_RelayTag (0)
	{
		m_NoiseState.reset (new i2p::crypto::NoiseSymmetricState);
		if (in_RemoteRouter && m_Address)
		{
			// outgoing
			InitNoiseXKState1 (*m_NoiseState, m_Address->s);
			m_RemoteEndpoint = boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port);
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
		auto token = m_Server.FindOutgoingToken (m_RemoteEndpoint);
		if (token)
			SendSessionRequest (token);
		else
			SendTokenRequest ();
	}

	bool SSU2Session::Introduce (std::shared_ptr<SSU2Session> session, uint32_t relayTag)
	{
		// we are Alice
		if (!session || !relayTag) return false;
		// find local adddress to introduce
		std::shared_ptr<const i2p::data::RouterInfo::Address> localAddress;
		if (session->m_Address->IsV4 ())
			localAddress = i2p::context.GetRouterInfo ().GetSSU2V4Address ();
		else if (session->m_Address->IsV6 ())
			localAddress = i2p::context.GetRouterInfo ().GetSSU2V6Address ();
		if (localAddress) return false;
		// create nonce
		uint32_t nonce;
		RAND_bytes ((uint8_t *)&nonce, 4);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		// payload
		uint8_t payload[SSU2_MAX_PAYLOAD_SIZE];
		size_t payloadSize = 0;
		payload[0] = eSSU2BlkRelayRequest;
		payload[3] = 0; // flag
		htobe32buf (payload + 4, nonce);
		htobe32buf (payload + 8, relayTag);
		htobe32buf (payload + 12, ts);
		payload[16] = 2; // ver
		size_t asz = CreateEndpoint (payload + 18, SSU2_MAX_PAYLOAD_SIZE - 18, boost::asio::ip::udp::endpoint (localAddress->host, localAddress->port));
		if (!asz) return false;
		payload[17] = asz;
		payloadSize += asz + 17;
		SignedData s;
		s.Insert ((const uint8_t *)"RelayRequestData", 16); // prologue
		s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
		s.Insert (session->GetRemoteIdentity ()->GetIdentHash (), 32); // chash
		s.Insert (payload + 4, 14 + asz); // nonce, relay tag, timestamp, ver, asz and Alice's endpoint
		s.Sign (i2p::context.GetPrivateKeys (), payload + 17 + asz);
		payloadSize += i2p::context.GetIdentity ()->GetSignatureLen ();
		htobe16buf (payload + 1, payloadSize - 3); // size
		payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize);
		// send
		m_RelaySessions.emplace (nonce, std::make_pair (session, ts));
		session->m_SourceConnID = htobe64 (((uint64_t)nonce << 32) | nonce);
		session->m_DestConnID = ~session->m_SourceConnID;
		m_Server.AddSession (session);
		SendData (payload, payloadSize);

		return true;
	}

	void SSU2Session::Terminate ()
	{
		if (m_State != eSSU2SessionStateTerminated)
		{
			m_State = eSSU2SessionStateTerminated;
			transports.PeerDisconnected (shared_from_this ());
			m_Server.RemoveSession (m_SourceConnID);
			if (m_RelayTag)
				m_Server.RemoveRelay (m_RelayTag);
			m_SendQueue.clear ();
			LogPrint (eLogDebug, "SSU2: Session terminated");
		}
	}

	void SSU2Session::TerminateByTimeout ()
	{
		SendTermination ();
		m_Server.GetService ().post (std::bind (&SSU2Session::Terminate, shared_from_this ()));
	}

	void SSU2Session::Established ()
	{
		m_State = eSSU2SessionStateEstablished;
		m_EphemeralKeys = nullptr;
		m_NoiseState.reset (nullptr);
		m_SessionConfirmedFragment1.reset (nullptr);
		SetTerminationTimeout (SSU2_TERMINATION_TIMEOUT);
		transports.PeerConnected (shared_from_this ());
		if (m_OnEstablished) m_OnEstablished ();
	}

	void SSU2Session::Done ()
	{
		m_Server.GetService ().post (std::bind (&SSU2Session::Terminate, shared_from_this ()));
	}

	void SSU2Session::SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		m_Server.GetService ().post (std::bind (&SSU2Session::PostI2NPMessages, shared_from_this (), msgs));
	}

	void SSU2Session::PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		for (auto it: msgs)
			m_SendQueue.push_back (it);
		SendQueue ();
	}

	bool SSU2Session::SendQueue ()
	{
		if (!m_SendQueue.empty () && m_SentPackets.size () <= m_WindowSize)
		{
			auto nextResend = i2p::util::GetSecondsSinceEpoch () + SSU2_RESEND_INTERVAL;
			auto packet = std::make_shared<SentPacket>();
			packet->payloadSize += CreateAckBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
			while (!m_SendQueue.empty () && m_SentPackets.size () <= m_WindowSize)
			{
				auto msg = m_SendQueue.front ();
				size_t len = msg->GetNTCP2Length ();
				if (len + 3 < SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize)
				{
					m_SendQueue.pop_front ();
					packet->payloadSize += CreateI2NPBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize, std::move (msg));
				}
				else if (len > SSU2_MAX_PAYLOAD_SIZE - 32) // message too long
				{
					m_SendQueue.pop_front ();
					SendFragmentedMessage (msg);
				}
				else
				{
					// send right a way
					if (packet->payloadSize + 16 < SSU2_MAX_PAYLOAD_SIZE)
						packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
					uint32_t packetNum = SendData (packet->payload, packet->payloadSize);
					packet->nextResendTime = nextResend;
					m_SentPackets.emplace (packetNum, packet);
					packet = std::make_shared<SentPacket>();
					packet->payloadSize += CreateAckBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
				}
			};
			if (packet->payloadSize)
			{
				if (packet->payloadSize + 16 < SSU2_MAX_PAYLOAD_SIZE)
					packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
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
		packet->payloadSize += CreateAckBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
		auto size = CreateFirstFragmentBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - 32 - packet->payloadSize, msg);
		if (!size) return;
		packet->payloadSize += size;
		packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
		uint32_t firstPacketNum = SendData (packet->payload, packet->payloadSize);
		packet->nextResendTime = nextResend;
		m_SentPackets.emplace (firstPacketNum, packet);
		uint8_t fragmentNum = 0;
		while (msg->offset < msg->len)
		{
			packet = std::make_shared<SentPacket>();
			packet->payloadSize += CreateFollowOnFragmentBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize - 16, msg, fragmentNum, msgID);
			packet->payloadSize += CreatePaddingBlock (packet->payload + packet->payloadSize, SSU2_MAX_PAYLOAD_SIZE - packet->payloadSize);
			uint32_t followonPacketNum = SendData (packet->payload, packet->payloadSize);
			packet->nextResendTime = nextResend;
			m_SentPackets.emplace (followonPacketNum, packet);
		}
	}

	void SSU2Session::Resend (uint64_t ts)
	{
		if (m_SentPackets.empty ()) return;
		std::map<uint32_t, std::shared_ptr<SentPacket> > resentPackets;
		for (auto it = m_SentPackets.begin (); it != m_SentPackets.end (); )
			if (ts > it->second->nextResendTime)
			{
				if (it->second->numResends > SSU2_MAX_NUM_RESENDS)
					it = m_SentPackets.erase (it);
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
			default:
			{
				LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type);
				return false;
			}
		}
		return true;
	}

	void SSU2Session::SendSessionRequest (uint64_t token)
	{
		// we are Alice
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();

		Header header;
		uint8_t headerX[48], payload[40];
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
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
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
		// send
		m_Server.AddPendingOutgoingSession (shared_from_this ());
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
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
		HandlePayload (decryptedPayload.data (), decryptedPayload.size ());

		m_Server.AddSession (shared_from_this ());
		SendSessionCreated (headerX + 16);
	}

	void SSU2Session::SendSessionCreated (const uint8_t * X)
	{
		// we are Bob
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessCreateHeader", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessCreateHeader", 32)

		// fill packet
		Header header;
		uint8_t headerX[48], payload[64];
		header.h.connID = m_DestConnID; // dest id
		header.h.packetNum = 0;
		header.h.type = eSSU2SessionCreated;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (headerX, &m_SourceConnID, 8); // source id
		RAND_bytes (headerX + 8, 8); // token
		memcpy (headerX + 16, m_EphemeralKeys->GetPublicKey (), 32); // Y
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (payload + payloadSize, 64 - payloadSize, m_RemoteEndpoint);
		if (m_RelayTag)
		{
			payload[payloadSize] = eSSU2BlkRelayTag;
			htobe16buf (payload + payloadSize + 1, 4);
			htobe32buf (payload + payloadSize + 3, m_RelayTag);
			payloadSize += 7;
		}
		payloadSize += CreatePaddingBlock (payload + payloadSize, 64 - payloadSize);
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
		// send
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
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
		SendSessionConfirmed (headerX + 16);
		KDFDataPhase (m_KeyDataSend, m_KeyDataReceive);
		Established ();

		return true;
	}

	void SSU2Session::SendSessionConfirmed (const uint8_t * Y)
	{
		// we are Alice
		uint8_t kh2[32];
		i2p::crypto::HKDF (m_NoiseState->m_CK, nullptr, 0, "SessionConfirmed", kh2, 32); // k_header_2 = HKDF(chainKey, ZEROLEN, "SessionConfirmed", 32)
		// fill packet
		Header header;
		header.h.connID = m_DestConnID; // dest id
		header.h.packetNum = 0;
		header.h.type = eSSU2SessionConfirmed;
		memset (header.h.flags, 0, 3);
		header.h.flags[0] = 1; // frag, total fragments always 1
		// payload
		const size_t maxPayloadSize = SSU2_MAX_PAYLOAD_SIZE - 48; // part 2
		uint8_t payload[maxPayloadSize + 16];
		size_t payloadSize = CreateRouterInfoBlock (payload, maxPayloadSize, i2p::context.GetSharedRouterInfo ());
		// TODO: check is RouterInfo doesn't fit and split by two fragments
		if (payloadSize < maxPayloadSize)
			payloadSize += CreatePaddingBlock (payload + payloadSize, maxPayloadSize - payloadSize);
		// KDF for Session Confirmed part 1
		m_NoiseState->MixHash (header.buf, 16); // h = SHA256(h || header)
		// Encrypt part 1
		uint8_t part1[48];
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
		// Encrypt header
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (kh2, payload + (payloadSize - 12));
		// send
		m_Server.Send (header.buf, 16, part1, 48, payload, payloadSize, m_RemoteEndpoint);
		m_SendPacketNum++;
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
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type);
			return false;
		}
		// check if fragmented
		if ((header.h.flags[0] & 0x0F) > 1)
		{
			// fragmented
			if (!(header.h.flags[0] & 0xF0))
			{
				// first fragment
				m_SessionConfirmedFragment1.reset (new SessionConfirmedFragment);
				m_SessionConfirmedFragment1->header = header;
				memcpy (m_SessionConfirmedFragment1->payload, buf + 16, len - 16);
				m_SessionConfirmedFragment1->payloadSize = len - 16;
				return true; // wait for second fragment
			}
			else
			{
				// second fragment
				if (!m_SessionConfirmedFragment1) return false; // out of sequence
				uint8_t fullMsg[2*SSU2_MTU];
				header = m_SessionConfirmedFragment1->header;
				memcpy (fullMsg + 16, m_SessionConfirmedFragment1->payload, m_SessionConfirmedFragment1->payloadSize);
				memcpy (fullMsg + 16 + m_SessionConfirmedFragment1->payloadSize, buf + 16, len - 16);
				buf = fullMsg;
				len += m_SessionConfirmedFragment1->payloadSize;
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
		// KDF for Session Confirmed part 2
		uint8_t sharedSecret[32];
		m_EphemeralKeys->Agree (S, sharedSecret);
		m_NoiseState->MixKey (sharedSecret);
		// decrypt part2
		memset (nonce, 0, 12);
		uint8_t * payload = buf + 64;
		std::vector<uint8_t> decryptedPayload(len - 80);
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len - 80, m_NoiseState->m_H, 32,
			m_NoiseState->m_CK + 32, nonce, decryptedPayload.data (), decryptedPayload.size (), false))
		{
			LogPrint (eLogWarning, "SSU2: SessionConfirmed part 2 AEAD verification failed ");
			return false;
		}
		m_NoiseState->MixHash (payload, len - 64); // h = SHA256(h || ciphertext);
		// payload
		// handle RouterInfo block that must be first
		if (decryptedPayload[0] != eSSU2BlkRouterInfo)
		{
			LogPrint (eLogError, "SSU2: SessionConfirmed unexpected first block type ", (int)decryptedPayload[0]);
			return false;
		}
		size_t riSize = bufbe16toh (decryptedPayload.data () + 1);
		if (riSize + 3 > decryptedPayload.size ())
		{
			LogPrint (eLogError, "SSU2: SessionConfirmed RouterInfo block is too long ", riSize);
			return false;
		}
		LogPrint (eLogDebug, "SSU2: RouterInfo in SessionConfirmed");
		auto ri = ExtractRouterInfo (decryptedPayload.data () + 3, riSize);
		if (!ri)
		{
			LogPrint (eLogError, "SSU2: SessionConfirmed malformed RouterInfo block");
			return false;
		}
		SetRemoteIdentity (ri->GetRouterIdentity ());
		m_Server.AddSessionByRouterHash (shared_from_this ()); // we know remote router now
		m_Address = ri->GetSSU2AddressWithStaticKey (S, m_RemoteEndpoint.address ().is_v6 ());
		if (!m_Address)
		{
			LogPrint (eLogError, "SSU2: No SSU2 address with static key found in SessionConfirmed");
			return false;
		}
		i2p::data::netdb.PostI2NPMsg (CreateI2NPMessage (eI2NPDummyMsg, ri->GetBuffer (), ri->GetBufferLen ())); // TODO: should insert ri
		// handle other blocks
		HandlePayload (decryptedPayload.data () + riSize + 3, decryptedPayload.size () - riSize - 3);
		KDFDataPhase (m_KeyDataReceive, m_KeyDataSend);
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
		uint8_t h[32], payload[40];
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
		payloadSize += CreatePaddingBlock (payload + payloadSize, 40 - payloadSize, 1);
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
		m_Server.AddPendingOutgoingSession (shared_from_this ());
		m_Server.Send (header.buf, 16, h + 16, 16, payload, payloadSize, m_RemoteEndpoint);
	}

	void SSU2Session::ProcessTokenRequest (Header& header, uint8_t * buf, size_t len)
	{
		// we are Bob
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
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type);
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

		InitNoiseXKState1 (*m_NoiseState, m_Address->s); // reset Noise TODO: check state
		SendSessionRequest (headerX[1]);
		return true;
	}

	void SSU2Session::SendHolePunch (uint32_t nonce, const boost::asio::ip::udp::endpoint& ep, const uint8_t * introKey)
	{
		// we are Charlie
		Header header;
		uint8_t h[32], payload[SSU2_MAX_PAYLOAD_SIZE];
		// fill packet
		header.h.connID = htobe64 (((uint64_t)nonce << 32) | nonce); // dest id
		RAND_bytes (header.buf + 8, 4); // random packet num
		header.h.type = eSSU2HolePunch;
		header.h.flags[0] = 2; // ver
		header.h.flags[1] = (uint8_t)i2p::context.GetNetID (); // netID
		header.h.flags[2] = 0; // flag
		memcpy (h, header.buf, 16);
		uint64_t c = !header.h.connID;
		memcpy (h + 16, &c, 8); // source id
		uint64_t token = m_Server.GetIncomingToken (ep);
		memcpy (h + 24, &token, 8); // token
		// payload
		payload[0] = eSSU2BlkDateTime;
		htobe16buf (payload + 1, 4);
		htobe32buf (payload + 3, i2p::util::GetSecondsSinceEpoch ());
		size_t payloadSize = 7;
		payloadSize += CreateAddressBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize, ep);
		payloadSize += CreateRelayResponseBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize, nonce);
		payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize);
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
		Header header;
		memcpy (header.buf, buf, 16);
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 12));
		if (header.h.type != eSSU2HolePunch)
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type);
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
		m_Server.UpdateOutgoingToken (m_RemoteEndpoint, headerX[1], i2p::util::GetSecondsSinceEpoch () + SSU2_TOKEN_EXPIRATION_TIMEOUT);
		HandlePayload (payload, len - 48);
		// connect to Charlie
		if (m_State == eSSU2SessionStateIntroduced)
		{
			m_State = eSSU2SessionStateUnknown;
			Connect ();
		}

		return true;
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
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type);
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
		uint8_t payload[SSU2_MTU];
		i2p::crypto::AEADChaCha20Poly1305 (buf, len, header.buf, 16, m_KeyDataSend, nonce, payload, SSU2_MTU, true);
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
			LogPrint (eLogWarning, "SSU2: Unexpected message type ", (int)header.h.type);
			return;
		}
		uint8_t payload[SSU2_MTU];
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
		if (UpdateReceivePacketNum (packetNum))
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
				break;
				case eSSU2BlkOptions:
					LogPrint (eLogDebug, "SSU2: Options");
				break;
				case eSSU2BlkRouterInfo:
				{
					// not from SessionConfirmed
					LogPrint (eLogDebug, "SSU2: RouterInfo");
					auto ri = ExtractRouterInfo (buf + offset, size);
					if (ri)
						i2p::data::netdb.PostI2NPMsg (CreateI2NPMessage (eI2NPDummyMsg, ri->GetBuffer (), ri->GetBufferLen ())); // TODO: should insert ri
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
					LogPrint (eLogDebug, "SSU2: Termination");
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
					LogPrint (eLogDebug, "SSU2: PeerTest");
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
						LogPrint (eLogInfo, "SSU2: Our external address is ", ep);
					break;
				}
				case eSSU2BlkIntroKey:
				break;
				case eSSU2BlkRelayTagRequest:
					LogPrint (eLogDebug, "SSU2: RelayTagRequest");
					HandleRelayRequest (buf + offset, size);
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
			if (*ranges > lastPacketNum) break;
			firstPacketNum = lastPacketNum - *ranges; ranges++; // acks
			len -= 2;
			HandleAckRange (firstPacketNum, lastPacketNum);
		}
	}

	void SSU2Session::HandleAckRange (uint32_t firstPacketNum, uint32_t lastPacketNum)
	{
		if (firstPacketNum > lastPacketNum) return;
		auto it = m_SentPackets.begin ();
		while (it != m_SentPackets.end () && it->first < firstPacketNum) it++; // find first acked packet
		if (it == m_SentPackets.end ()) return; // not found
		auto it1 = it;
		while (it1 != m_SentPackets.end () && it1->first <= lastPacketNum) it1++;
		if (it1 != m_SentPackets.end () && it1 != m_SentPackets.begin ()) it1--;
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
			LogPrint (eLogWarning, "SSU2: Session with relay tag ", relayTag, " not found");
			return; // TODO: send relay response
		}
		session->m_RelaySessions.emplace (bufbe32toh (buf + 1), // nonce
			std::make_pair (shared_from_this (), i2p::util::GetSecondsSinceEpoch ()) );

		// send relay intro to Charlie
		auto r = i2p::data::netdb.FindRouter (GetRemoteIdentity ()->GetIdentHash ()); // Alice's RI
		uint8_t payload[SSU2_MAX_PAYLOAD_SIZE];
		size_t payloadSize = r ? CreateRouterInfoBlock (payload, SSU2_MAX_PAYLOAD_SIZE - len - 32, r) : 0;
		if (!payloadSize && r)
			SendFragmentedMessage (CreateDatabaseStoreMsg (r));
		payloadSize += CreateRelayIntroBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize, buf + 1, len -1);
		if (payloadSize < SSU2_MAX_PAYLOAD_SIZE)
			payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize);
		session->SendData (payload, payloadSize);
	}

	void SSU2Session::HandleRelayIntro (const uint8_t * buf, size_t len)
	{
		// we are Charlie
		auto r = i2p::data::netdb.FindRouter (buf + 1); // Alice
		if (!r)
		{
			LogPrint (eLogError, "SSU2: RelayIntro unknown router to introduce");
			return;
		}
		SignedData s;
		s.Insert ((const uint8_t *)"RelayRequestData", 16); // prologue
		s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
		s.Insert (i2p::context.GetIdentHash (), 32); // chash
		s.Insert (buf + 33, 14); // nonce, relay tag, timestamp, ver, asz
		uint8_t asz = buf[46];
		s.Insert (buf + 47, asz); // Alice Port, Alice IP
		if (!s.Verify (r->GetIdentity (), buf + 47 + asz))
		{
			LogPrint (eLogWarning, "SSU2: RelayIntro signature verification failed");
			return; // TODO: send relay response
		}

		// send relay response to Bob
		uint8_t payload[SSU2_MAX_PAYLOAD_SIZE];
		size_t payloadSize = CreateRelayResponseBlock (payload, SSU2_MAX_PAYLOAD_SIZE, bufbe32toh (buf + 33));
		payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize);
		SendData (payload, payloadSize);

		// send HolePunch
		boost::asio::ip::udp::endpoint ep;
		if (ExtractEndpoint (buf + 47, asz, ep))
		{
			auto r = i2p::data::netdb.FindRouter (buf + 1); // Alice
			if (r)
			{
				auto addr = ep.address ().is_v6 () ? r->GetSSU2V6Address () : r->GetSSU2V4Address ();
				if (addr)
					SendHolePunch (bufbe32toh (buf + 33), ep, addr->i);
			}
		}
	}

	void SSU2Session::HandleRelayResponse (const uint8_t * buf, size_t len)
	{
		if (m_State == eSSU2SessionStateIntroduced) return; // HolePunch from Charlie, TODO: verify address and signature
		auto it = m_RelaySessions.find (bufbe32toh (buf + 2)); // nonce
		if (it != m_RelaySessions.end ())
		{
			if (it->second.first && it->second.first->IsEstablished ())
				// we are Bob, message from Charlie
				it->second.first->SendData (buf, len); // forward to Alice as is
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
						// update Charlie's endpoint and connect
						if (it->second.first->m_State == eSSU2SessionStateIntroduced &&
							ExtractEndpoint (buf + 12, csz, it->second.first->m_RemoteEndpoint))
						{
							it->second.first->m_State = eSSU2SessionStateUnknown;
							it->second.first->Connect ();
						}
					}
					else
						LogPrint (eLogWarning, "SSU2: RelayResponse signature verification failed");
				}
				else
					LogPrint (eLogWarning, "SSU2: RelayResponse status code=", (int)buf[1]);
			}
			m_RelaySessions.erase (it);
		}
		else
			LogPrint (eLogWarning, "SSU2: RelayResponse unknown nonce ", bufbe32toh (buf + 2));
	}

	void SSU2Session::HandlePeerTest (const uint8_t * buf, size_t len)
	{
		uint32_t nonce = bufbe32toh (buf + 37);
		switch (buf[0]) // msg
		{
			case 1: // Bob for Alice
			break;
			case 2: // Charlie from Bob
			break;
			case 3: // Bob from Charlie
			{
				auto it = m_PeerTests.find (nonce);
				if (it != m_PeerTests.end () && it->second.first)
				{
					uint8_t payload[SSU2_MAX_PAYLOAD_SIZE];
					size_t payloadSize = CreatePeerTestBlock (payload, SSU2_MAX_PAYLOAD_SIZE, 4, buf + 3, buf + 35, len -35);
					if (payloadSize < SSU2_MAX_PAYLOAD_SIZE)
						payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MAX_PAYLOAD_SIZE - payloadSize);
					it->second.first->SendData (payload, payloadSize);
				}
				break;
			}
			case 4: // Alice from Bob
			break;
			case 5: // Alice from Chralie 1
			break;
			case 6: // Chralie from Alice
			break;
			case 7: // Alice from Charlie 2
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
		if (!r || len < 5) return 0;
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
				it++;
				while (it != m_OutOfSequencePackets.rend () && lastNum > m_ReceivePacketNum && numRanges < 8)
				{
					if (lastNum - (*it) < 255)
					{
						buf[7 + numRanges*2] = lastNum - (*it); // NACKs
						lastNum = *it;
						uint8_t numAcks = 0;
						while (it != m_OutOfSequencePackets.rend () && numAcks < 255 && lastNum > m_ReceivePacketNum && *it == lastNum - 1)
						{
							numAcks++; lastNum--;
							it++;
						}
						buf[7 + numRanges*2 + 1] = numAcks; // Acks
						numRanges++; it++;
						if (numAcks == 255) break;
					}
					else
						break;
				}
			}
		}
		buf[7] = acnt; // acnt
		htobe16buf (buf + 1, 5 + numRanges*2);
		return 8;
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
		msg->offset = (msgBuf - buf) + msgLen;
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
		htobe16buf (buf + 1, msgLen); // size
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

	size_t SSU2Session::CreateRelayResponseBlock (uint8_t * buf, size_t len, uint32_t nonce)
	{
		buf[0] = eSSU2BlkRelayResponse;
		buf[3] = 0; // flag
		buf[4] = 0; // code, accept
		htobe32buf (buf + 5, nonce); // nonce
		htobe32buf (buf + 9, i2p::util::GetSecondsSinceEpoch ()); // timestamp
		buf[13] = 2; // ver
		size_t csz = CreateEndpoint (buf + 15, len - 15, boost::asio::ip::udp::endpoint (m_Address->host, m_Address->port));
		if (!csz) return 0;
		buf[14] = csz; // csz
		// signature
		SignedData s;
		s.Insert ((const uint8_t *)"RelayAgreementOK", 16); // prologue
		s.Insert (GetRemoteIdentity ()->GetIdentHash (), 32); // bhash
		s.Insert (buf + 5, 10 + csz); // nonce, timestamp, ver, csz and Charlie's endpoint
		s.Sign (i2p::context.GetPrivateKeys (), buf + 15 + csz);
		size_t payloadSize = 12 + csz + i2p::context.GetIdentity ()->GetSignatureLen ();
		htobe16buf (buf + 1, payloadSize); // size
		return payloadSize + 3;
	}

	size_t SSU2Session::CreatePeerTestBlock (uint8_t * buf, size_t len, uint8_t msg,
		const uint8_t * routerHash, const uint8_t * signedData, size_t signedDataLen)
	{
		buf[0] = eSSU2BlkPeerTest;
		size_t payloadSize = 3/* msg, code, flag */ + 32/* router hash */ + signedDataLen;
		if (payloadSize + 3 > len) return 0;
		htobe16buf (buf + 1, payloadSize); // size
		buf[3] = msg; // msg
		buf[4] = 0; // code, TODO:
		buf[5] = 0; //flag
		memcpy (buf + 6, routerHash, 32); // router hash
		memcpy (buf + 38, signedData, signedDataLen);
		return payloadSize + 3;
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
		uint8_t payload[SSU2_MTU];
		size_t payloadSize = CreateAckBlock (payload, SSU2_MTU);
		payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MTU - payloadSize);
		SendData (payload, payloadSize);
	}

	void SSU2Session::SendTermination ()
	{
		uint8_t payload[32];
		size_t payloadSize = 12;
		payload[0] = eSSU2BlkTermination;
		htobe16buf (payload + 1, 9);
		memset (payload + 3, 0, 9);
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
		if (m_OutOfSequencePackets.size () > 255)
		{
			m_ReceivePacketNum = *m_OutOfSequencePackets.rbegin ();
			m_OutOfSequencePackets.clear ();
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

	SSU2Server::SSU2Server ():
		RunnableServiceWithWork ("SSU2"), m_ReceiveService ("SSU2r"),
		m_SocketV4 (m_ReceiveService.GetService ()), m_SocketV6 (m_ReceiveService.GetService ()),
		m_TerminationTimer (GetService ()), m_ResendTimer (GetService ())
	{
	}

	void SSU2Server::Start ()
	{
		if (!IsRunning ())
		{
			StartIOService ();
			bool found = false;
			auto& addresses = i2p::context.GetRouterInfo ().GetAddresses ();
			for (const auto& address: addresses)
			{
				if (!address) continue;
				if (address->transportStyle == i2p::data::RouterInfo::eTransportSSU2)
				{
					auto port = address->port;
					if (!port)
					{
						uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
						if (ssu2Port) port = ssu2Port;
						else
						{
							uint16_t p; i2p::config::GetOption ("port", p);
							if (p) port = p;
						}
					}
					if (port)
					{
						if (address->IsV4 ())
						{
							found = true;
							OpenSocket (boost::asio::ip::udp::endpoint (boost::asio::ip::udp::v4(), port));
							m_ReceiveService.GetService ().post(
								[this]()
								{
									Receive (m_SocketV4);
								});
						}
						if (address->IsV6 ())
						{
							found = true;
							OpenSocket (boost::asio::ip::udp::endpoint (boost::asio::ip::udp::v6(), port));
							m_ReceiveService.GetService ().post(
							[this]()
								{
									Receive (m_SocketV6);
								});
						}
					}
					else
						LogPrint (eLogError, "SSU2: Can't start server because port not specified");
				}
			}
			if (found)
				m_ReceiveService.Start ();
			ScheduleTermination ();
		}
	}

	void SSU2Server::Stop ()
	{
		if (context.SupportsV4 () || context.SupportsV6 ())
			m_ReceiveService.Stop ();

		if (IsRunning ())
			m_TerminationTimer.cancel ();

		StopIOService ();
	}

	boost::asio::ip::udp::socket& SSU2Server::OpenSocket (const boost::asio::ip::udp::endpoint& localEndpoint)
	{
		boost::asio::ip::udp::socket& socket = localEndpoint.address ().is_v6 () ? m_SocketV6 : m_SocketV4;
		try
		{
			socket.open (localEndpoint.protocol ());
			if (localEndpoint.address ().is_v6 ())
				socket.set_option (boost::asio::ip::v6_only (true));
			socket.set_option (boost::asio::socket_base::receive_buffer_size (SSU2_SOCKET_RECEIVE_BUFFER_SIZE));
			socket.set_option (boost::asio::socket_base::send_buffer_size (SSU2_SOCKET_SEND_BUFFER_SIZE));
			socket.bind (localEndpoint);
			LogPrint (eLogInfo, "SSU2: Start listening on ", localEndpoint);
		}
		catch (std::exception& ex )
		{
			LogPrint (eLogError, "SSU2: Failed to bind to ", localEndpoint, ": ", ex.what());
			ThrowFatal ("Unable to start SSU2 transport on ", localEndpoint, ": ", ex.what ());
		}
		return socket;
	}

	void SSU2Server::Receive (boost::asio::ip::udp::socket& socket)
	{
		Packet * packet = m_PacketsPool.AcquireMt ();
		socket.async_receive_from (boost::asio::buffer (packet->buf, SSU2_MTU), packet->from,
			std::bind (&SSU2Server::HandleReceivedFrom, this, std::placeholders::_1, std::placeholders::_2, packet, std::ref (socket)));
	}

	void SSU2Server::HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred,
		Packet * packet, boost::asio::ip::udp::socket& socket)
	{
		if (!ecode)
		{
			i2p::transport::transports.UpdateReceivedBytes (bytes_transferred);
			packet->len = bytes_transferred;

			boost::system::error_code ec;
			size_t moreBytes = socket.available (ec);
			if (!ec && moreBytes)
			{
				std::vector<Packet *> packets;
				packets.push_back (packet);
				while (moreBytes && packets.size () < 32)
				{
					packet = m_PacketsPool.AcquireMt ();
					packet->len = socket.receive_from (boost::asio::buffer (packet->buf, SSU2_MTU), packet->from, 0, ec);
					if (!ec)
					{
						i2p::transport::transports.UpdateReceivedBytes (packet->len);
						packets.push_back (packet);
						moreBytes = socket.available(ec);
						if (ec) break;
					}
					else
					{
						LogPrint (eLogError, "SSU2: receive_from error: code ", ec.value(), ": ", ec.message ());
						m_PacketsPool.ReleaseMt (packet);
						break;
					}
				}
				GetService ().post (std::bind (&SSU2Server::HandleReceivedPackets, this, packets));
			}
			else
				GetService ().post (std::bind (&SSU2Server::HandleReceivedPacket, this, packet));
			Receive (socket);
		}
		else
		{
			m_PacketsPool.ReleaseMt (packet);
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU2: Receive error: code ", ecode.value(), ": ", ecode.message ());
				auto ep = socket.local_endpoint ();
				socket.close ();
				OpenSocket (ep);
				Receive (socket);
			}
		}
	}

	void SSU2Server::HandleReceivedPacket (Packet * packet)
	{
		if (packet)
		{
			ProcessNextPacket (packet->buf, packet->len, packet->from);
			m_PacketsPool.ReleaseMt (packet);
			if (m_LastSession) m_LastSession->FlushData ();
		}
	}

	void SSU2Server::HandleReceivedPackets (std::vector<Packet *> packets)
	{
		for (auto& packet: packets)
			ProcessNextPacket (packet->buf, packet->len, packet->from);
		m_PacketsPool.ReleaseMt (packets);
		if (m_LastSession) m_LastSession->FlushData ();
	}

	void SSU2Server::AddSession (std::shared_ptr<SSU2Session> session)
	{
		if (session)
		{
			m_Sessions.emplace (session->GetConnID (), session);
			AddSessionByRouterHash (session);
		}
	}

	void SSU2Server::RemoveSession (uint64_t connID)
	{
		auto it = m_Sessions.find (connID);
		if (it != m_Sessions.end ())
		{
			auto ident = it->second->GetRemoteIdentity ();
			if (ident)
				m_SessionsByRouterHash.erase (ident->GetIdentHash ());
			m_Sessions.erase (it);
		}
	}

	void SSU2Server::AddSessionByRouterHash (std::shared_ptr<SSU2Session> session)
	{
		if (session)
		{
			auto ident = session->GetRemoteIdentity ();
			if (ident)
			{
				auto ret = m_SessionsByRouterHash.emplace (ident->GetIdentHash (), session);
				if (!ret.second)
				{
					// session already exists
					LogPrint (eLogWarning, "SSU2: Session to ", ident->GetIdentHash ().ToBase64 (), " aready exists");
					// terminate existing
					GetService ().post (std::bind (&SSU2Session::Terminate, ret.first->second));
					// update session
					ret.first->second = session;
				}
			}
		}
	}

	void SSU2Server::AddPendingOutgoingSession (std::shared_ptr<SSU2Session> session)
	{
		if (session)
			m_PendingOutgoingSessions.emplace (session->GetRemoteEndpoint (), session);
	}

	void SSU2Server::AddRelay (uint32_t tag, std::shared_ptr<SSU2Session> relay)
	{
		m_Relays.emplace (tag, relay);
	}

	void SSU2Server::RemoveRelay (uint32_t tag)
	{
		m_Relays.erase (tag);
	}

	std::shared_ptr<SSU2Session> SSU2Server::FindRelaySession (uint32_t tag)
	{
		auto it = m_Relays.find (tag);
		if (it != m_Relays.end ())
		{
			if (it->second->IsEstablished ())
				return it->second;
			else
				m_Relays.erase (it);
		}
		return nullptr;
	}

	void SSU2Server::ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		if (len < 24) return;
		uint64_t connID;
		memcpy (&connID, buf, 8);
		connID ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		if (!m_LastSession || m_LastSession->GetConnID () != connID)
		{
			if (m_LastSession) m_LastSession->FlushData ();
			auto it = m_Sessions.find (connID);
			if (it != m_Sessions.end ())
				m_LastSession = it->second;
			else
				m_LastSession = nullptr;
		}
		if (m_LastSession)
		{
			switch (m_LastSession->GetState ())
			{
				case eSSU2SessionStateEstablished:
					m_LastSession->ProcessData (buf, len);
				break;
				case eSSU2SessionStateUnknown:
					m_LastSession->ProcessSessionConfirmed (buf, len);
				break;
				case eSSU2SessionStateIntroduced:
					m_LastSession->SetRemoteEndpoint (senderEndpoint);
					m_LastSession->ProcessHolePunch (buf, len);
				break;
				case eSSU2SessionStatePeerTest:
					m_LastSession->SetRemoteEndpoint (senderEndpoint);
					m_LastSession->ProcessPeerTest (buf, len);
				break;
				default:
					LogPrint (eLogWarning, "SSU2: Invalid session state ", (int)m_LastSession->GetState ());
			}
		}
		else
		{
			// check pending sessions if it's SessionCreated or Retry
			auto it1 = m_PendingOutgoingSessions.find (senderEndpoint);
			if (it1 != m_PendingOutgoingSessions.end ())
			{
				if (it1->second->ProcessSessionCreated (buf, len))
					m_PendingOutgoingSessions.erase (it1); // we are done with that endpoint
				else
					it1->second->ProcessRetry (buf, len);
			}
			else
			{
				// assume new incoming session
				auto session = std::make_shared<SSU2Session> (*this);
				session->SetRemoteEndpoint (senderEndpoint);
				session->ProcessFirstIncomingMessage (connID, buf, len);
			}
		}
	}

	void SSU2Server::Send (const uint8_t * header, size_t headerLen, const uint8_t * payload, size_t payloadLen,
		const boost::asio::ip::udp::endpoint& to)
	{
		std::vector<boost::asio::const_buffer> bufs
		{
			boost::asio::buffer (header, headerLen),
			boost::asio::buffer (payload, payloadLen)
		};
		boost::system::error_code ec;
		if (to.address ().is_v6 ())
			m_SocketV6.send_to (bufs, to, 0, ec);
		else
			m_SocketV4.send_to (bufs, to, 0, ec);
		if (!ec)
			i2p::transport::transports.UpdateSentBytes (headerLen + payloadLen);
		else
			LogPrint (eLogError, "SSU2: Send exception: ", ec.message (), " to ", to);
	}

	void SSU2Server::Send (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen,
		const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to)
	{
		std::vector<boost::asio::const_buffer> bufs
		{
			boost::asio::buffer (header, headerLen),
			boost::asio::buffer (headerX, headerXLen),
			boost::asio::buffer (payload, payloadLen)
		};
		boost::system::error_code ec;
		if (to.address ().is_v6 ())
			m_SocketV6.send_to (bufs, to, 0, ec);
		else
			m_SocketV4.send_to (bufs, to, 0, ec);

		if (!ec)
			i2p::transport::transports.UpdateSentBytes (headerLen + headerXLen + payloadLen);
		else
			LogPrint (eLogError, "SSU2: Send exception: ", ec.message (), " to ", to);
	}

	bool SSU2Server::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address)
	{
		if (router && address)
		{
			if (address->UsesIntroducer ())
				GetService ().post (std::bind (&SSU2Server::ConnectThroughIntroducer, this, router, address));
			else
				GetService ().post (
					[this, router, address]()
					{
						auto session = std::make_shared<SSU2Session> (*this, router, address);
						session->Connect ();
					});
		}
		else
			return false;
		return true;
	}

	void SSU2Server::ConnectThroughIntroducer (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address)
	{
		auto session = std::make_shared<SSU2Session> (*this, router, address);
		session->SetState (eSSU2SessionStateIntroduced);
		// try to find existing session first
		for (auto& it: address->ssu->introducers)
		{
			auto it1 = m_SessionsByRouterHash.find (it.iKey);
			if (it1 != m_SessionsByRouterHash.end ())
			{
				it1->second->Introduce (session, it.iTag);
				return;
			}
		}
		// we have to start a new session to an introducer
		std::shared_ptr<i2p::data::RouterInfo> r;
		uint32_t relayTag = 0;
		for (auto& it: address->ssu->introducers)
		{
			r = i2p::data::netdb.FindRouter (it.iKey);
			if (r && r->IsReachableFrom (i2p::context.GetRouterInfo ()))
			{
				relayTag = it.iTag;
				if (relayTag) break;
			}
		}
		if (r)
		{
			if (relayTag)
			{
				// introducer and tag found connect to it through SSU2
				auto addr = address->IsV6 () ? r->GetSSU2V6Address () : r->GetSSU2V4Address ();
				if (addr)
				{
					auto s = std::make_shared<SSU2Session> (*this, r, addr);
					s->SetOnEstablished (
						[session, s, relayTag]()
						{
							s->Introduce (session, relayTag);
						});
					s->Connect ();
				}
			}
		}
		else
		{
			// introducers not found, try to request them
			for (auto& it: address->ssu->introducers)
				i2p::data::netdb.RequestDestination (it.iKey);
		}
	}

	void SSU2Server::ScheduleTermination ()
	{
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(SSU2_TERMINATION_CHECK_TIMEOUT));
		m_TerminationTimer.async_wait (std::bind (&SSU2Server::HandleTerminationTimer,
			this, std::placeholders::_1));
	}

	void SSU2Server::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_PendingOutgoingSessions.begin (); it != m_PendingOutgoingSessions.end ();)
			{
				if (it->second->IsTerminationTimeoutExpired (ts))
				{
					//it->second->Terminate ();
					it = m_PendingOutgoingSessions.erase (it);
				}
				else
					it++;
			}

			for (auto it = m_Sessions.begin (); it != m_Sessions.end ();)
			{
				if (it->second->IsTerminationTimeoutExpired (ts))
				{
					if (it->second->IsEstablished ())
						it->second->TerminateByTimeout ();
					if (it->second == m_LastSession)
						m_LastSession = nullptr;
					it = m_Sessions.erase (it);
				}
				else
				{
					it->second->CleanUp (ts);
					it++;
				}
			}

			for (auto it = m_IncomingTokens.begin (); it != m_IncomingTokens.end (); )
			{
				if (ts > it->second.second)
					it = m_IncomingTokens.erase (it);
				else
					it++;
			}

			for (auto it = m_OutgoingTokens.begin (); it != m_OutgoingTokens.end (); )
			{
				if (ts > it->second.second)
					it = m_OutgoingTokens.erase (it);
				else
					it++;
			}

			ScheduleTermination ();
		}
	}

	void SSU2Server::ScheduleResend ()
	{
		m_ResendTimer.expires_from_now (boost::posix_time::seconds(SSU2_RESEND_INTERVAL));
		m_ResendTimer.async_wait (std::bind (&SSU2Server::HandleResendTimer,
			this, std::placeholders::_1));
	}

	void SSU2Server::HandleResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it: m_Sessions)
				it.second->Resend (ts);
			ScheduleResend ();
		}
	}

	void SSU2Server::UpdateOutgoingToken (const boost::asio::ip::udp::endpoint& ep, uint64_t token, uint32_t exp)
	{
		m_OutgoingTokens[ep] = {token, exp};
	}

	uint64_t SSU2Server::FindOutgoingToken (const boost::asio::ip::udp::endpoint& ep) const
	{
		auto it = m_OutgoingTokens.find (ep);
		if (it != m_OutgoingTokens.end ())
			return it->second.first;
		return 0;
	}

	uint64_t SSU2Server::GetIncomingToken (const boost::asio::ip::udp::endpoint& ep)
	{
		auto it = m_IncomingTokens.find (ep);
		if (it != m_IncomingTokens.end ())
			return it->second.first;
		uint64_t token;
		RAND_bytes ((uint8_t *)&token, 8);
		m_IncomingTokens.emplace (ep, std::make_pair (token, i2p::util::GetSecondsSinceEpoch () + SSU2_TOKEN_EXPIRATION_TIMEOUT));
		return token;
	}
}
}
