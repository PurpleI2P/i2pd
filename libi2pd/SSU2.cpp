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
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr, bool peerTest):
		TransportSession (in_RemoteRouter, SSU2_CONNECT_TIMEOUT),
		m_Server (server), m_Address (addr), m_DestConnID (0), m_SourceConnID (0),
		m_State (eSSU2SessionStateUnknown), m_SendPacketNum (0), m_ReceivePacketNum (0)
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

	void SSU2Session::Established ()
	{
		m_State = eSSU2SessionStateEstablished;
		m_EphemeralKeys = nullptr;
		m_NoiseState.reset (nullptr);
		SetTerminationTimeout (SSU2_TERMINATION_TIMEOUT);
	}	
		
	void SSU2Session::ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len)
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
				LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)header.h.type);
		}	
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
		m_Server.AddPendingOutgoingSession (m_RemoteEndpoint, shared_from_this ());
		m_Server.Send (header.buf, 16, headerX, 48, payload, payloadSize, m_RemoteEndpoint);
	}	

	void SSU2Session::ProcessSessionRequest (Header& header, uint8_t * buf, size_t len)
	{
		// we are Bob
		const uint8_t nonce[12] = {0};
		uint8_t headerX[48];
		i2p::crypto::ChaCha20 (buf + 16, 48, i2p::context.GetSSU2IntroKey (), nonce, headerX);
		memcpy (&m_DestConnID, headerX, 8); 
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
		
		m_Server.AddSession (m_SourceConnID, shared_from_this ());
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
		payloadSize += CreateAddressBlock (m_RemoteEndpoint, payload, 64 - payloadSize);
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
		
		m_Server.AddSession (m_SourceConnID, shared_from_this ());
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
		// payload
		uint8_t  payload[SSU2_MTU];
		size_t payloadSize = i2p::context.GetRouterInfo ().GetBufferLen ();
		payload[0] = eSSU2BlkRouterInfo;
		if (payloadSize < 1024)
		{	
			memcpy (payload + 5, i2p::context.GetRouterInfo ().GetBuffer (), payloadSize);
			payload[3] = 0; // flag
		}	
		else	
		{	
			i2p::data::GzipDeflator deflator;
			payloadSize = deflator.Deflate (i2p::context.GetRouterInfo ().GetBuffer (), 
				i2p::context.GetRouterInfo ().GetBufferLen (), payload + 5, SSU2_MTU -5);
			payload[3] = SSU2_ROUTER_INFO_FLAG_GZIP; // flag
		}	
		htobe16buf (payload + 1, payloadSize + 2);
		payload[4] = 1; // frag
		payloadSize += 5;
		payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MTU - payloadSize);
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
			LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)header.h.type);
			return false;
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
		m_Address = ri->GetSSU2AddressWithStaticKey (S); 
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
		header.h.packetNum = 0;
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
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, m_Address->i, nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (m_Address->i, payload + (payloadSize - 12));
		i2p::crypto::ChaCha20 (h + 16, 16, m_Address->i, nonce, h + 16);
		// send
		m_Server.AddPendingOutgoingSession (m_RemoteEndpoint, shared_from_this ());
		m_Server.Send (header.buf, 16, h + 16, 16, payload, payloadSize, m_RemoteEndpoint);
	}	

	void SSU2Session::ProcessTokenRequest (Header& header, uint8_t * buf, size_t len)
	{
		// we are Bob
		const uint8_t nonce[12] = {0};
		uint8_t h[32];
		memcpy (h, header.buf, 16);
		i2p::crypto::ChaCha20 (buf + 16, 16, i2p::context.GetSSU2IntroKey (), nonce, h + 16);
		memcpy (&m_DestConnID, h, 8); 
		// decrypt
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
		header.h.packetNum = 0;
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
		payloadSize += CreateAddressBlock (m_RemoteEndpoint, payload, 64 - payloadSize);
		payloadSize += CreatePaddingBlock (payload + payloadSize, 64 - payloadSize);
		// encrypt
		const uint8_t nonce[12] = {0};
		i2p::crypto::AEADChaCha20Poly1305 (payload, payloadSize, h, 32, i2p::context.GetSSU2IntroKey (), nonce, payload, payloadSize + 16, true);
		payloadSize += 16;
		header.ll[0] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), payload + (payloadSize - 24));
		header.ll[1] ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), payload + (payloadSize - 12));
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
			LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)header.h.type);
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

	void SSU2Session::SendData (const uint8_t * buf, size_t len)
	{
		if (len < 8)
		{
			LogPrint (eLogWarning, "SSU2: Data message payload is too short ", (int)len);
			return;
		}	
		Header header;
		header.h.connID = m_DestConnID;
		header.h.packetNum = htobe32 (m_SendPacketNum);
		header.h.type = eSSU2Data;
		memset (header.h.flags, 0, 3);
		uint8_t payload[SSU2_MTU];
		uint8_t nonce[12];
		CreateNonce (m_SendPacketNum, nonce);
		i2p::crypto::AEADChaCha20Poly1305 (buf, len, header.buf, 16, m_KeyDataSend, nonce, payload, SSU2_MTU, true);
		header.ll[0] ^= CreateHeaderMask (m_Address->i, payload + (len - 8));
		header.ll[1] ^= CreateHeaderMask (m_KeyDataSend + 32, payload + (len + 4));
		m_Server.Send (header.buf, 16, payload, len + 16, m_RemoteEndpoint);
		m_SendPacketNum++;
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		m_NumSentBytes += len + 32;
	}	
		
	void SSU2Session::ProcessData (uint8_t * buf, size_t len)
	{
		Header header;
		header.ll[0] = m_SourceConnID;
		memcpy (header.buf + 8, buf + 8, 8);
		header.ll[1] ^= CreateHeaderMask (m_KeyDataReceive + 32, buf + (len - 12));
		if (header.h.type != eSSU2Data) 
		{
			LogPrint (eLogWarning, "SSU2: Unexpected message type  ", (int)header.h.type);
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
		HandlePayload (payload, payloadSize);
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		m_NumReceivedBytes += len;
		if (packetNum > m_ReceivePacketNum)
		{	
			m_ReceivePacketNum = packetNum;
			SendQuickAck (); // TODO: don't send too requently
		}	
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
					break;	
				}	
				case eSSU2BlkFirstFragment:
				break;	
				case eSSU2BlkFollowOnFragment:
				break;	
				case eSSU2BlkTermination:
				break;	
				case eSSU2BlkRelayRequest:
				break;	
				case eSSU2BlkRelayResponse:
				break;	
				case eSSU2BlkRelayIntro:
				break;	
				case eSSU2BlkPeerTest:
				break;	
				case eSSU2BlkNextNonce:
				break;	
				case eSSU2BlkAck:
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
				break;	
				case eSSU2BlkRelayTag:
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
		m_Handler.Flush ();
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

	size_t SSU2Session::CreateAddressBlock (const boost::asio::ip::udp::endpoint& ep, uint8_t * buf, size_t len)
	{
		if (len < 9) return 0;
		buf[0] = eSSU2BlkAddress;
		htobe16buf (buf + 3, ep.port ());
		size_t size = 0;
		if (ep.address ().is_v4 ())
		{
			memcpy (buf + 5, ep.address ().to_v4 ().to_bytes ().data (), 4);
			size = 6;
		}	
		else if (ep.address ().is_v6 ())
		{
			if (len < 21) return 0;
			memcpy (buf + 5, ep.address ().to_v6 ().to_bytes ().data (), 16);
			size = 18;
		}	
		else
		{
			LogPrint (eLogWarning, "SSU2: Wrong address type ", ep.address ().to_string ());
			return 0;
		}	
		htobe16buf (buf + 1, size);
		return size + 3;	
	}	

	size_t SSU2Session::CreateAckBlock (uint8_t * buf, size_t len)
	{
		if (len < 8) return 0;
		buf[0] = eSSU2BlkAck;
		htobe16buf (buf + 1, 5);
		htobe32buf (buf + 3, m_ReceivePacketNum); // Ack Through
		buf[7] = 0; // acnt
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

	void SSU2Session::SendQuickAck ()
	{
		uint8_t payload[SSU2_MTU];
		size_t payloadSize = CreateAckBlock (payload, SSU2_MTU);
		payloadSize += CreatePaddingBlock (payload + payloadSize, SSU2_MTU - payloadSize);
		SendData (payload, payloadSize);
	}	
		
	SSU2Server::SSU2Server ():
		RunnableServiceWithWork ("SSU2"), m_Socket (GetService ()), m_SocketV6 (GetService ()),
		m_TerminationTimer (GetService ())
	{
	}

	void SSU2Server::Start ()
	{
		if (!IsRunning ())
		{
			StartIOService ();
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
							Receive (OpenSocket (boost::asio::ip::udp::endpoint (boost::asio::ip::udp::v4(), port)));
						if (address->IsV6 ())
							Receive (OpenSocket (boost::asio::ip::udp::endpoint (boost::asio::ip::udp::v6(), port)));
					}	
					else
						LogPrint (eLogError, "SSU2: Can't start server because port not specified");
				}
			}
			ScheduleTermination ();
		}	
	}
		
	void SSU2Server::Stop ()
	{
		if (IsRunning ())
			m_TerminationTimer.cancel ();
		
		StopIOService ();
	}	

	boost::asio::ip::udp::socket& SSU2Server::OpenSocket (const boost::asio::ip::udp::endpoint& localEndpoint)
	{
		boost::asio::ip::udp::socket& socket = localEndpoint.address ().is_v6 () ? m_SocketV6 : m_Socket;
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
			LogPrint (eLogError, "SSU2: Failed to bind to  ", localEndpoint, ": ", ex.what());
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
			ProcessNextPacket (packet->buf, packet->len, packet->from);
			m_PacketsPool.ReleaseMt (packet);
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
		
	void SSU2Server::AddSession (uint64_t connID, std::shared_ptr<SSU2Session> session)
	{
		m_Sessions.emplace (connID, session);
	}	

	void SSU2Server::AddPendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep, std::shared_ptr<SSU2Session> session)
	{
		m_PendingOutgoingSessions.emplace (ep, session);
	}
		
	void SSU2Server::ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		uint64_t connID;
		memcpy (&connID, buf, 8);
		connID ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		auto it = m_Sessions.find (connID);
		if (it != m_Sessions.end ())
		{
			if (it->second->IsEstablished ())
				it->second->ProcessData (buf, len);
			else	
				it->second->ProcessSessionConfirmed (buf, len);
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
			m_Socket.send_to (bufs, to, 0, ec);
		i2p::transport::transports.UpdateSentBytes (headerLen + payloadLen);
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
			m_Socket.send_to (bufs, to, 0, ec);
		i2p::transport::transports.UpdateSentBytes (headerLen + headerXLen + payloadLen);
	}	

	bool SSU2Server::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address)
	{
		if (router && address)
			GetService ().post (
				[this, router, address]()
			    {
					auto session = std::make_shared<SSU2Session> (*this, router, address);
					session->Connect ();
				});               
		else
			return false;
		return true;
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
					//it->second->Terminate ();
					it = m_Sessions.erase (it); 
				}
				else
					it++;
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
