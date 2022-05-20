/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "version.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "SSU.h"
#include "SSUSession.h"

namespace i2p
{
namespace transport
{
	SSUSession::SSUSession (SSUServer& server, boost::asio::ip::udp::endpoint& remoteEndpoint,
		std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest ):
		TransportSession (router, SSU_TERMINATION_TIMEOUT),
		m_Server (server), m_RemoteEndpoint (remoteEndpoint), m_ConnectTimer (GetService ()),
		m_IsPeerTest (peerTest),m_State (eSessionStateUnknown), m_IsSessionKey (false),
		m_RelayTag (0), m_SentRelayTag (0), m_Data (*this), m_IsDataReceived (false)
	{
		if (router)
		{
			// we are client
			auto address = IsV6 () ? router->GetSSUV6Address () : router->GetSSUAddress (true);
			if (address) m_IntroKey = address->i;
			m_Data.AdjustPacketSize (router); // mtu
		}
		else
		{
			// we are server
			auto address = IsV6 () ? i2p::context.GetRouterInfo ().GetSSUV6Address () :
				i2p::context.GetRouterInfo ().GetSSUAddress (true);
			if (address) m_IntroKey = address->i;
		}
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
	}

	SSUSession::~SSUSession ()
	{
	}

	boost::asio::io_service& SSUSession::GetService ()
	{
		return m_Server.GetService ();
	}

	void SSUSession::CreateAESandMacKey (const uint8_t * pubKey)
	{
		uint8_t sharedKey[256];
		m_DHKeysPair->Agree (pubKey, sharedKey);

		uint8_t * sessionKey = m_SessionKey, * macKey = m_MacKey;
		if (sharedKey[0] & 0x80)
		{
			sessionKey[0] = 0;
			memcpy (sessionKey + 1, sharedKey, 31);
			memcpy (macKey, sharedKey + 31, 32);
		}
		else if (sharedKey[0])
		{
			memcpy (sessionKey, sharedKey, 32);
			memcpy (macKey, sharedKey + 32, 32);
		}
		else
		{
			// find first non-zero byte
			uint8_t * nonZero = sharedKey + 1;
			while (!*nonZero)
			{
				nonZero++;
				if (nonZero - sharedKey > 32)
				{
					LogPrint (eLogWarning, "SSU: First 32 bytes of shared key is all zeros. Ignored");
					return;
				}
			}

			memcpy (sessionKey, nonZero, 32);
			SHA256(nonZero, 64 - (nonZero - sharedKey), macKey);
		}
		m_IsSessionKey = true;
		m_SessionKeyEncryption.SetKey (m_SessionKey);
		m_SessionKeyDecryption.SetKey (m_SessionKey);
	}

	void SSUSession::ProcessNextMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		m_NumReceivedBytes += len;
		i2p::transport::transports.UpdateReceivedBytes (len);
		if (m_State == eSessionStateIntroduced)
		{
			// HolePunch received
			LogPrint (eLogDebug, "SSU: HolePunch of ", len, " bytes received");
			m_State = eSessionStateUnknown;
			Connect ();
		}
		else
		{
			if (!len) return; // ignore zero-length packets
			if (m_State == eSessionStateEstablished)
				m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();

			if (m_IsSessionKey && Validate (buf, len, m_MacKey)) // try session key first
				DecryptSessionKey (buf, len);
			else
			{
				if (m_State == eSessionStateEstablished) Reset (); // new session key required
				// try intro key depending on side
				if (Validate (buf, len, m_IntroKey))
					Decrypt (buf, len, m_IntroKey);
				else
				{
					// try own intro key
					auto address = IsV6 () ? i2p::context.GetRouterInfo ().GetSSUV6Address () :
						i2p::context.GetRouterInfo ().GetSSUAddress (true);
					if (!address)
					{
						LogPrint (eLogInfo, "SSU: SSU is not supported");
						return;
					}
					if (Validate (buf, len, address->i))
						Decrypt (buf, len, address->i);
					else
					{
						LogPrint (eLogWarning, "SSU: MAC verification failed ", len, " bytes from ", senderEndpoint);
						m_Server.DeleteSession (shared_from_this ());
						return;
					}
				}
			}
			// successfully decrypted
			ProcessMessage (buf, len, senderEndpoint);
		}
	}

	size_t SSUSession::GetSSUHeaderSize (const uint8_t * buf) const
	{
		size_t s = sizeof (SSUHeader);
		if (((const SSUHeader *)buf)->IsExtendedOptions ())
			s += buf[s] + 1; // byte right after header is extended options length
		return s;
	}

	void SSUSession::ProcessMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		len -= (len & 0x0F); // %16, delete extra padding
		if (len <= sizeof (SSUHeader)) return; // drop empty message
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
		auto headerSize = GetSSUHeaderSize (buf);
		if (headerSize >= len)
		{
			LogPrint (eLogError, "SSU: SSU header size ", headerSize, " exceeds packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		switch (header->GetPayloadType ())
		{
			case PAYLOAD_TYPE_DATA:
				ProcessData (buf + headerSize, len - headerSize);
			break;
			case PAYLOAD_TYPE_SESSION_REQUEST:
				ProcessSessionRequest (buf, len); // buf with header
			break;
			case PAYLOAD_TYPE_SESSION_CREATED:
				ProcessSessionCreated (buf, len); // buf with header
			break;
			case PAYLOAD_TYPE_SESSION_CONFIRMED:
				ProcessSessionConfirmed (buf, len); // buf with header
			break;
			case PAYLOAD_TYPE_PEER_TEST:
				LogPrint (eLogDebug, "SSU: Peer test received");
				ProcessPeerTest (buf + headerSize, len - headerSize, senderEndpoint);
			break;
			case PAYLOAD_TYPE_SESSION_DESTROYED:
			{
				LogPrint (eLogDebug, "SSU: Session destroy received");
				m_Server.DeleteSession (shared_from_this ());
				break;
			}
			case PAYLOAD_TYPE_RELAY_RESPONSE:
				ProcessRelayResponse (buf + headerSize, len - headerSize);
				if (m_State != eSessionStateEstablished)
					m_Server.DeleteSession (shared_from_this ());
			break;
			case PAYLOAD_TYPE_RELAY_REQUEST:
				LogPrint (eLogDebug, "SSU: Relay request received");
				ProcessRelayRequest (buf + headerSize, len - headerSize, senderEndpoint);
			break;
			case PAYLOAD_TYPE_RELAY_INTRO:
				LogPrint (eLogDebug, "SSU: Relay intro received");
				ProcessRelayIntro (buf + headerSize, len - headerSize);
			break;
			default:
				LogPrint (eLogWarning, "SSU: Unexpected payload type ", (int)header->GetPayloadType ());
		}
	}

	void SSUSession::ProcessSessionRequest (const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "SSU message: Session request");
		bool sendRelayTag = true;
		auto headerSize = sizeof (SSUHeader);
		if (((SSUHeader *)buf)->IsExtendedOptions ())
		{
			uint8_t extendedOptionsLen = buf[headerSize];
			headerSize++;
			if (extendedOptionsLen >= 2) // options are presented
			{
				uint16_t flags = bufbe16toh (buf + headerSize);
				sendRelayTag = flags & EXTENDED_OPTIONS_FLAG_REQUEST_RELAY_TAG;
			}
			headerSize += extendedOptionsLen;
		}
		if (headerSize >= len)
		{
			LogPrint (eLogError, "SSU message: Session request header size ", headerSize, " exceeds packet length ", len);
			return;
		}
		if (!m_DHKeysPair)
		{
			auto pair = std::make_shared<i2p::crypto::DHKeys> ();
			pair->GenerateKeys ();
			m_DHKeysPair = pair;
		}
		CreateAESandMacKey (buf + headerSize);
		SendSessionCreated (buf + headerSize, sendRelayTag);
	}

	void SSUSession::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		if (!IsOutgoing () || !m_DHKeysPair)
		{
			LogPrint (eLogWarning, "SSU: Unsolicited session created message");
			return;
		}

		LogPrint (eLogDebug, "SSU message: session created");
		m_ConnectTimer.cancel (); // connect timer
		SignedData s; // x,y, our IP, our port, remote IP, remote port, relayTag, signed on time
		auto headerSize = GetSSUHeaderSize (buf);
		if (headerSize >= len)
		{
			LogPrint (eLogError, "SSU message: Session created header size ", headerSize, " exceeds packet length ", len);
			return;
		}
		uint8_t * payload = buf + headerSize;
		uint8_t * y = payload;
		CreateAESandMacKey (y);
		s.Insert (m_DHKeysPair->GetPublicKey (), 256); // x
		s.Insert (y, 256); // y
		payload += 256;
		boost::asio::ip::address ourIP;
		uint16_t ourPort = 0;
		auto addressAndPortLen = ExtractIPAddressAndPort (payload, len, ourIP, ourPort);
		if (!addressAndPortLen) return;
		uint8_t * ourAddressAndPort = payload + 1;
		payload += addressAndPortLen;
		addressAndPortLen--; // -1 byte address size
		s.Insert (ourAddressAndPort, addressAndPortLen); // address + port
		if (m_RemoteEndpoint.address ().is_v4 ())
			s.Insert (m_RemoteEndpoint.address ().to_v4 ().to_bytes ().data (), 4); // remote IP v4
		else
			s.Insert (m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data (), 16); // remote IP v6
		s.Insert<uint16_t> (htobe16 (m_RemoteEndpoint.port ())); // remote port
		s.Insert (payload, 8); // relayTag and signed on time
		m_RelayTag = bufbe32toh (payload);
		payload += 4; // relayTag
		uint32_t signedOnTime = bufbe32toh(payload);
		payload += 4; // signed on time
		// decrypt signature
		size_t signatureLen = m_RemoteIdentity->GetSignatureLen ();
		size_t paddingSize = signatureLen & 0x0F; // %16
		if (paddingSize > 0) signatureLen += (16 - paddingSize);
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
		m_SessionKeyDecryption.SetIV (((SSUHeader *)buf)->iv);
		m_SessionKeyDecryption.Decrypt (payload, signatureLen, payload); // TODO: non-const payload
		// verify signature
		if (s.Verify (m_RemoteIdentity, payload))
		{
			if (ourIP.is_v4 () && i2p::context.GetStatus () == eRouterStatusTesting)
			{
				auto ts = i2p::util::GetSecondsSinceEpoch ();
				int offset = (int)ts - signedOnTime;
				if (m_Server.IsSyncClockFromPeers ())
				{
					if (std::abs (offset) > SSU_CLOCK_THRESHOLD)
					{
						LogPrint (eLogWarning, "SSU: Clock adjusted by ", -offset, " seconds");
						i2p::util::AdjustTimeOffset (-offset);
					}
				}
				else if (std::abs (offset) > SSU_CLOCK_SKEW)
				{
					LogPrint (eLogError, "SSU: Clock skew detected ", offset, ". Check your clock");
					i2p::context.SetError (eRouterErrorClockSkew);
				}
			}
			LogPrint (eLogInfo, "SSU: Our external address is ", ourIP.to_string (), ":", ourPort);
			if (!i2p::util::net::IsInReservedRange (ourIP))
			{
				i2p::context.UpdateAddress (ourIP);
				SendSessionConfirmed (y, ourAddressAndPort, addressAndPortLen);
			}
			else
			{
				LogPrint (eLogError, "SSU: External address ", ourIP.to_string (), " is in reserved range");
				Failed ();
			}
		}
		else
		{
			LogPrint (eLogError, "SSU: Message 'created' signature verification failed");
			Failed ();
		}
	}

	void SSUSession::ProcessSessionConfirmed (const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "SSU: Session confirmed received");
		m_ConnectTimer.cancel ();
		auto headerSize = GetSSUHeaderSize (buf);
		if (headerSize >= len)
		{
			LogPrint (eLogError, "SSU: Session confirmed header size ", headerSize, " exceeds packet length ", len);
			return;
		}
		const uint8_t * payload = buf + headerSize;
		payload++; // identity fragment info
		uint16_t identitySize = bufbe16toh (payload);
		if (identitySize + headerSize + 7 > len) // 7 = fragment info + fragment size + signed on time
		{
			LogPrint (eLogError, "SSU: Session confirmed identity size ", identitySize, " exceeds packet length ", len);
			return;
		}
		payload += 2; // size of identity fragment
		auto identity = std::make_shared<i2p::data::IdentityEx> (payload, identitySize);
		auto existing = i2p::data::netdb.FindRouter (identity->GetIdentHash ()); // check if exists already
		SetRemoteIdentity (existing ? existing->GetRouterIdentity () : identity);
		m_Data.UpdatePacketSize (m_RemoteIdentity->GetIdentHash ());
		payload += identitySize; // identity
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		uint32_t signedOnTime = bufbe32toh(payload);
		if (signedOnTime < ts - SSU_CLOCK_SKEW || signedOnTime > ts + SSU_CLOCK_SKEW)
		{
			LogPrint (eLogError, "SSU: Message 'confirmed' time difference ", (int)ts - signedOnTime, " exceeds clock skew");
			Failed ();
			return;
		}
		if (m_SignedData)
			m_SignedData->Insert (payload, 4); // insert Alice's signed on time
		payload += 4; // signed-on time
		size_t fullSize = (payload - buf) + m_RemoteIdentity->GetSignatureLen ();
		size_t paddingSize = fullSize & 0x0F; // %16
		if (paddingSize > 0) paddingSize = 16 - paddingSize;
		payload += paddingSize;
		if (fullSize + paddingSize > len)
		{
			LogPrint (eLogError, "SSU: Session confirmed message is too short ", len);
			return;
		}
		// verify signature
		if (m_SignedData && m_SignedData->Verify (m_RemoteIdentity, payload))
		{
			m_Data.Send (CreateDeliveryStatusMsg (0));
			Established ();
		}
		else
		{
			LogPrint (eLogError, "SSU: Message 'confirmed' signature verification failed");
			Failed ();
		}
	}

	void SSUSession::SendSessionRequest ()
	{
		uint8_t buf[320 + 18] = {0}; // 304 bytes for ipv4, 320 for ipv6
		uint8_t * payload = buf + sizeof (SSUHeader);
		uint8_t flag = 0;
		// fill extended options, 3 bytes extended options don't change message size
		bool isV4 = m_RemoteEndpoint.address ().is_v4 ();
		if ((isV4 && i2p::context.GetStatus () == eRouterStatusOK) ||
			(!isV4 && i2p::context.GetStatusV6 () == eRouterStatusOK)) // we don't need relays
		{
			// tell out peer to now assign relay tag
			flag = SSU_HEADER_EXTENDED_OPTIONS_INCLUDED;
			*payload = 2; payload++; // 1 byte length
			uint16_t flags = 0; // clear EXTENDED_OPTIONS_FLAG_REQUEST_RELAY_TAG
			htobe16buf (payload, flags);
			payload += 2;
		}
		// fill payload
		memcpy (payload, m_DHKeysPair->GetPublicKey (), 256); // x
		if (isV4)
		{
			payload[256] = 4;
			memcpy (payload + 257, m_RemoteEndpoint.address ().to_v4 ().to_bytes ().data(), 4);
		}
		else
		{
			payload[256] = 16;
			memcpy (payload + 257, m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data(), 16);
		}
		// encrypt and send
		uint8_t iv[16];
		RAND_bytes (iv, 16); // random iv
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_REQUEST, buf, isV4 ? 304 : 320, m_IntroKey, iv, m_IntroKey, flag);
		m_Server.Send (buf, isV4 ? 304 : 320, m_RemoteEndpoint);
	}

	void SSUSession::SendRelayRequest (const i2p::data::RouterInfo::Introducer& introducer, uint32_t nonce)
	{
		auto address = IsV6 () ? i2p::context.GetRouterInfo ().GetSSUV6Address () :
			i2p::context.GetRouterInfo ().GetSSUAddress (true);
		if (!address)
		{
			LogPrint (eLogInfo, "SSU: SSU is not supported");
			return;
		}

		uint8_t buf[96 + 18] = {0};
		uint8_t * payload = buf + sizeof (SSUHeader);
		htobe32buf (payload, introducer.iTag);
		payload += 4;
		*payload = 0; // no address
		payload++;
		htobuf16(payload, 0); // port = 0
		payload += 2;
		*payload = 0; // challenge
		payload++;
		memcpy (payload, (const uint8_t *)address->i, 32);
		payload += 32;
		htobe32buf (payload, nonce); // nonce

		uint8_t iv[16];
		RAND_bytes (iv, 16); // random iv
		if (m_State == eSessionStateEstablished)
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_REQUEST, buf, 96, m_SessionKey, iv, m_MacKey);
		else
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_REQUEST, buf, 96, introducer.iKey, iv, introducer.iKey);
		m_Server.Send (buf, 96, m_RemoteEndpoint);
		LogPrint (eLogDebug, "SSU: Relay request sent");
	}

	void SSUSession::SendSessionCreated (const uint8_t * x, bool sendRelayTag)
	{
		auto address = IsV6 () ? i2p::context.GetRouterInfo ().GetSSUV6Address () :
			i2p::context.GetRouterInfo ().GetSSUAddress (true); //v4 only
		if (!address)
		{
			LogPrint (eLogInfo, "SSU: SSU is not supported");
			return;
		}
		SignedData s; // x,y, remote IP, remote port, our IP, our port, relayTag, signed on time
		s.Insert (x, 256); // x

		uint8_t buf[384 + 18] = {0};
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, m_DHKeysPair->GetPublicKey (), 256);
		s.Insert (payload, 256); // y
		payload += 256;
		if (m_RemoteEndpoint.address ().is_v4 ())
		{
			// ipv4
			*payload = 4;
			payload++;
			memcpy (payload, m_RemoteEndpoint.address ().to_v4 ().to_bytes ().data(), 4);
			s.Insert (payload, 4); // remote endpoint IP V4
			payload += 4;
		}
		else
		{
			// ipv6
			*payload = 16;
			payload++;
			memcpy (payload, m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data(), 16);
			s.Insert (payload, 16); // remote endpoint IP V6
			payload += 16;
		}
		htobe16buf (payload, m_RemoteEndpoint.port ());
		s.Insert (payload, 2); // remote port
		payload += 2;
		if (address->host.is_v4 ())
			s.Insert (address->host.to_v4 ().to_bytes ().data (), 4); // our IP V4
		else
			s.Insert (address->host.to_v6 ().to_bytes ().data (), 16); // our IP V6
		s.Insert<uint16_t> (htobe16 (address->port)); // our port
		if (sendRelayTag && i2p::context.GetRouterInfo ().IsIntroducer (!IsV6 ()))
		{
			RAND_bytes((uint8_t *)&m_SentRelayTag, 4);
			if (!m_SentRelayTag) m_SentRelayTag = 1;
		}
		htobe32buf (payload, m_SentRelayTag);
		payload += 4; // relay tag
		htobe32buf (payload, i2p::util::GetSecondsSinceEpoch ()); // signed on time
		payload += 4;
		s.Insert (payload - 8, 4); // relayTag
		// we have to store this signed data for session confirmed
		// same data but signed on time, it will Alice's there
		m_SignedData = std::unique_ptr<SignedData>(new SignedData (s));
		s.Insert (payload - 4, 4); // BOB's signed on time
		s.Sign (i2p::context.GetPrivateKeys (), payload); // DSA signature

		uint8_t iv[16];
		RAND_bytes (iv, 16); // random iv
		// encrypt signature and padding with newly created session key
		size_t signatureLen = i2p::context.GetIdentity ()->GetSignatureLen ();
		size_t paddingSize = signatureLen & 0x0F; // %16
		if (paddingSize > 0)
		{
			// fill random padding
			RAND_bytes(payload + signatureLen, (16 - paddingSize));
			signatureLen += (16 - paddingSize);
		}
		m_SessionKeyEncryption.SetIV (iv);
		m_SessionKeyEncryption.Encrypt (payload, signatureLen, payload);
		payload += signatureLen;
		size_t msgLen = payload - buf;

		// encrypt message with intro key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CREATED, buf, msgLen, m_IntroKey, iv, m_IntroKey);
		Send (buf, msgLen);
	}

	void SSUSession::SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress, size_t ourAddressLen)
	{
		uint8_t buf[512 + 18] = {0};
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = 1; // 1 fragment
		payload++; // info
		size_t identLen = i2p::context.GetIdentity ()->GetFullLen (); // 387+ bytes
		htobe16buf (payload, identLen);
		payload += 2; // cursize
		i2p::context.GetIdentity ()->ToBuffer (payload, identLen);
		payload += identLen;
		uint32_t signedOnTime = i2p::util::GetSecondsSinceEpoch ();
		htobe32buf (payload, signedOnTime); // signed on time
		payload += 4;
		auto signatureLen = i2p::context.GetIdentity ()->GetSignatureLen ();
		size_t paddingSize = ((payload - buf) + signatureLen)%16;
		if (paddingSize > 0) paddingSize = 16 - paddingSize;
		RAND_bytes(payload, paddingSize); // fill padding with random
		payload += paddingSize; // padding size
		// signature
		SignedData s; // x,y, our IP, our port, remote IP, remote port, relayTag, our signed on time
		s.Insert (m_DHKeysPair->GetPublicKey (), 256); // x
		s.Insert (y, 256); // y
		s.Insert (ourAddress, ourAddressLen); // our address/port as seem by party
		if (m_RemoteEndpoint.address ().is_v4 ())
			s.Insert (m_RemoteEndpoint.address ().to_v4 ().to_bytes ().data (), 4); // remote IP V4
		else
			s.Insert (m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data (), 16); // remote IP V6
		s.Insert<uint16_t> (htobe16 (m_RemoteEndpoint.port ())); // remote port
		s.Insert (htobe32 (m_RelayTag)); // relay tag
		s.Insert (htobe32 (signedOnTime)); // signed on time
		s.Sign (i2p::context.GetPrivateKeys (), payload); // DSA signature
		payload += signatureLen;

		size_t msgLen = payload - buf;
		uint8_t iv[16];
		RAND_bytes (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CONFIRMED, buf, msgLen, m_SessionKey, iv, m_MacKey);
		Send (buf, msgLen);
	}

	void SSUSession::ProcessRelayRequest (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& from)
	{
		uint32_t relayTag = bufbe32toh (buf);
		auto session = m_Server.FindRelaySession (relayTag);
		if (session)
		{
			buf += 4; // relay tag
			uint8_t size = *buf;
			buf++; // size
			buf += size; // address
			buf += 2; // port
			uint8_t challengeSize = *buf;
			buf++; // challenge size
			buf += challengeSize;
			const uint8_t * introKey = buf;
			buf += 32; // introkey
			uint32_t nonce = bufbe32toh (buf);
			SendRelayResponse (nonce, from, introKey, session->m_RemoteEndpoint);
			SendRelayIntro (session, from);
		}
	}

	void SSUSession::SendRelayResponse (uint32_t nonce, const boost::asio::ip::udp::endpoint& from,
		const uint8_t * introKey, const boost::asio::ip::udp::endpoint& to)
	{
		bool isV4 = to.address ().is_v4 (); // Charle's
		bool isV4A = from.address ().is_v4 (); // Alice's
		if ((isV4 && !isV4A) || (!isV4 && isV4A))
		{
			LogPrint (eLogWarning, "SSU: Charlie's IP and Alice's IP belong to different networks for relay response");
			return;
		}
		uint8_t buf[80 + 18] = {0}; // 64 for ipv4 and 80 for ipv6
		uint8_t * payload = buf + sizeof (SSUHeader);
		// Charlie
		if (isV4)
		{
			*payload = 4;
			payload++; // size
			memcpy (payload, to.address ().to_v4 ().to_bytes ().data (), 4); // Charlie's IP V4
			payload += 4; // address
		}
		else
		{
			*payload = 16;
			payload++; // size
			memcpy (payload, to.address ().to_v6 ().to_bytes ().data (), 16); // Charlie's IP V6
			payload += 16; // address
		}
		htobe16buf (payload, to.port ()); // Charlie's port
		payload += 2; // port
		// Alice
		if (isV4)
		{
			*payload = 4;
			payload++; // size
			memcpy (payload, from.address ().to_v4 ().to_bytes ().data (), 4); // Alice's IP V4
			payload += 4; // address
		}
		else
		{
			*payload = 16;
			payload++; // size
			memcpy (payload, from.address ().to_v6 ().to_bytes ().data (), 16); // Alice's IP V6
			payload += 16; // address
		}
		htobe16buf (payload, from.port ()); // Alice's port
		payload += 2; // port
		htobe32buf (payload, nonce);

		if (m_State == eSessionStateEstablished)
		{
			// encrypt with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_RESPONSE, buf, isV4 ? 64 : 80);
			Send (buf, isV4 ? 64 : 80);
		}
		else
		{
			// ecrypt with Alice's intro key
			uint8_t iv[16];
			RAND_bytes (iv, 16); // random iv
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_RESPONSE, buf, isV4 ? 64 : 80, introKey, iv, introKey);
			m_Server.Send (buf, isV4 ? 64 : 80, from);
		}
		LogPrint (eLogDebug, "SSU: Relay response sent");
	}

	void SSUSession::SendRelayIntro (std::shared_ptr<SSUSession> session, const boost::asio::ip::udp::endpoint& from)
	{
		if (!session) return;
		bool isV4 = from.address ().is_v4 (); // Alice's
		bool isV4C = session->m_RemoteEndpoint.address ().is_v4 (); // Charlie's
		if ((isV4 && !isV4C) || (!isV4 && isV4C))
		{
			LogPrint (eLogWarning, "SSU: Charlie's IP and Alice's IP belong to different networks for relay intro");
			return;
		}
		uint8_t buf[64 + 18] = {0}; // 48 for ipv4 and 64 for ipv6
		uint8_t * payload = buf + sizeof (SSUHeader);
		if (isV4)
		{
			*payload = 4;
			payload++; // size
			memcpy (payload, from.address ().to_v4 ().to_bytes ().data (), 4); // Alice's IP V4
			payload += 4; // address
		}
		else
		{
			*payload = 16;
			payload++; // size
			memcpy (payload, from.address ().to_v6 ().to_bytes ().data (), 16); // Alice's IP V6
			payload += 16; // address
		}
		htobe16buf (payload, from.port ()); // Alice's port
		payload += 2; // port
		*payload = 0; // challenge size
		uint8_t iv[16];
		RAND_bytes (iv, 16); // random iv
		FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_INTRO, buf, isV4 ? 48 : 64, session->m_SessionKey, iv, session->m_MacKey);
		m_Server.Send (buf, isV4 ? 48 : 64, session->m_RemoteEndpoint);
		LogPrint (eLogDebug, "SSU: Relay intro sent");
	}

	void SSUSession::ProcessRelayResponse (const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "SSU message: Relay response received");
		boost::asio::ip::address remoteIP;
		uint16_t remotePort = 0;
		auto remoteSize = ExtractIPAddressAndPort (buf, len, remoteIP, remotePort);
		if (!remoteSize) return;
		buf += remoteSize; len -= remoteSize;
		boost::asio::ip::address ourIP;
		uint16_t ourPort = 0;
		auto ourSize = ExtractIPAddressAndPort (buf, len, ourIP, ourPort);
		if (!ourSize) return;
		buf += ourSize; len -= ourSize;
		LogPrint (eLogInfo, "SSU: Our external address is ", ourIP.to_string (), ":", ourPort);
		if (!i2p::util::net::IsInReservedRange (ourIP))
			i2p::context.UpdateAddress (ourIP);
		else
			LogPrint (eLogError, "SSU: External address ", ourIP.to_string (), " is in reserved range");
		if (ourIP.is_v4 ())
		{
			if (ourPort != m_Server.GetPort ())
			{
				if (i2p::context.GetStatus () == eRouterStatusTesting)
					i2p::context.SetError (eRouterErrorSymmetricNAT);
			}
			else if (i2p::context.GetStatus () == eRouterStatusError && i2p::context.GetError () == eRouterErrorSymmetricNAT)
				i2p::context.SetStatus (eRouterStatusTesting);
		}
		uint32_t nonce = bufbe32toh (buf);
		buf += 4; // nonce
		auto it = m_RelayRequests.find (nonce);
		if (it != m_RelayRequests.end ())
		{
			// check if we are waiting for introduction
			boost::asio::ip::udp::endpoint remoteEndpoint (remoteIP, remotePort);
			if (!m_Server.FindSession (remoteEndpoint))
			{
				// we didn't have correct endpoint when sent relay request
				// now we do
				LogPrint (eLogInfo, "SSU: RelayReponse connecting to endpoint ", remoteEndpoint);
				if ((remoteIP.is_v4 () && i2p::context.GetStatus () == eRouterStatusFirewalled) ||
					(remoteIP.is_v6 () && i2p::context.GetStatusV6 () == eRouterStatusFirewalled))
					m_Server.Send (buf, 0, remoteEndpoint); // send HolePunch
				// we assume that HolePunch has been sent by this time and our SessionRequest will go through
				m_Server.CreateDirectSession (it->second.first, remoteEndpoint, false);
			}
			// delete request
			m_RelayRequests.erase (it);
			// cancel connect timer
			m_ConnectTimer.cancel ();
		}
		else
			LogPrint (eLogError, "SSU: Unsolicited RelayResponse, nonce=", nonce);
	}

	void SSUSession::ProcessRelayIntro (const uint8_t * buf, size_t len)
	{
		boost::asio::ip::address ip;
		uint16_t port = 0;
		ExtractIPAddressAndPort (buf, len, ip, port);
		if (!ip.is_unspecified () && port)
			// send hole punch of 0 bytes
			m_Server.Send (buf, 0, boost::asio::ip::udp::endpoint (ip, port));
	}

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len,
		const i2p::crypto::AESKey& aesKey, const uint8_t * iv, const i2p::crypto::MACKey& macKey, uint8_t flag)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "SSU: Unexpected packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		memcpy (header->iv, iv, 16);
		header->flag = flag | (payloadType << 4); // MSB is 0
		htobe32buf (header->time, i2p::util::GetSecondsSinceEpoch ());
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (aesKey);
		encryption.SetIV (iv);
		encryption.Encrypt (encrypted, encryptedLen, encrypted);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, iv, 16);
		uint16_t netid = i2p::context.GetNetID ();
		htobe16buf (buf + len + 16, (netid == I2PD_NET_ID) ? encryptedLen : encryptedLen ^ ((netid - 2) << 8));
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, header->mac);
	}

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len)
	{
		FillHeaderAndEncrypt (payloadType, buf, len, buf);
	}

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * in, size_t len, uint8_t * out)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "SSU: Unexpected packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)out;
		RAND_bytes (header->iv, 16); // random iv
		m_SessionKeyEncryption.SetIV (header->iv);
		SSUHeader * inHeader = (SSUHeader *)in;
		inHeader->flag = payloadType << 4; // MSB is 0
		htobe32buf (inHeader->time, i2p::util::GetSecondsSinceEpoch ());
		uint8_t * encrypted = &header->flag, * clear = &inHeader->flag;
		uint16_t encryptedLen = len - (encrypted - out);
		m_SessionKeyEncryption.Encrypt (clear, encryptedLen, encrypted);
		// assume actual out buffer size is 18 (16 + 2) bytes more
		memcpy (out + len, header->iv, 16);
		uint16_t netid = i2p::context.GetNetID ();
		htobe16buf (out + len + 16, (netid == I2PD_NET_ID) ? encryptedLen : encryptedLen ^ ((netid - 2) << 8));
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, m_MacKey, header->mac);
	}

	void SSUSession::Decrypt (uint8_t * buf, size_t len, const i2p::crypto::AESKey& aesKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "SSU: Unexpected packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		i2p::crypto::CBCDecryption decryption;
		decryption.SetKey (aesKey);
		decryption.SetIV (header->iv);
		decryption.Decrypt (encrypted, encryptedLen, encrypted);
	}

	void SSUSession::DecryptSessionKey (uint8_t * buf, size_t len)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "SSU: Unexpected packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		if (encryptedLen > 0)
		{
			m_SessionKeyDecryption.SetIV (header->iv);
			m_SessionKeyDecryption.Decrypt (encrypted, encryptedLen, encrypted);
		}
	}

	bool SSUSession::Validate (uint8_t * buf, size_t len, const i2p::crypto::MACKey& macKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "SSU: Unexpected packet length ", len);
			return false;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, header->iv, 16);
		uint16_t netid = i2p::context.GetNetID ();
		htobe16buf (buf + len + 16, (netid == I2PD_NET_ID) ? encryptedLen : encryptedLen ^ ((netid - 2) << 8));
		uint8_t digest[16];
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, digest);
		return !memcmp (header->mac, digest, 16);
	}

	void SSUSession::Connect ()
	{
		if (m_State == eSessionStateUnknown)
		{
			ScheduleConnectTimer (); // set connect timer
			m_DHKeysPair = std::make_shared<i2p::crypto::DHKeys> ();
			m_DHKeysPair->GenerateKeys ();
			SendSessionRequest ();
		}
	}

	void SSUSession::WaitForConnect ()
	{
		if (!IsOutgoing ()) // incoming session
			ScheduleConnectTimer ();
		else
			LogPrint (eLogError, "SSU: Wait for connect for outgoing session");
	}

	void SSUSession::ScheduleConnectTimer ()
	{
		m_ConnectTimer.cancel ();
		m_ConnectTimer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
		m_ConnectTimer.async_wait (std::bind (&SSUSession::HandleConnectTimer,
			shared_from_this (), std::placeholders::_1));
}

	void SSUSession::HandleConnectTimer (const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			// timeout expired
			LogPrint (eLogWarning, "SSU: Session with ", m_RemoteEndpoint, " was not established after ", SSU_CONNECT_TIMEOUT, " seconds");
			Failed ();
		}
	}

	void SSUSession::Introduce (const i2p::data::RouterInfo::Introducer& introducer,
		std::shared_ptr<const i2p::data::RouterInfo> to)
	{
		if (m_State == eSessionStateUnknown)
		{
			// set connect timer
			m_ConnectTimer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
			m_ConnectTimer.async_wait (std::bind (&SSUSession::HandleConnectTimer,
				shared_from_this (), std::placeholders::_1));
		}
		uint32_t nonce;
		RAND_bytes ((uint8_t *)&nonce, 4);
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		m_RelayRequests.emplace (nonce, std::make_pair (to, ts));
		SendRelayRequest (introducer, nonce);
	}

	void SSUSession::WaitForIntroduction ()
	{
		m_State = eSessionStateIntroduced;
		// set connect timer
		m_ConnectTimer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
		m_ConnectTimer.async_wait (std::bind (&SSUSession::HandleConnectTimer,
			shared_from_this (), std::placeholders::_1));
	}

	void SSUSession::Close ()
	{
		SendSessionDestroyed ();
		Reset ();
		m_State = eSessionStateClosed;
	}

	void SSUSession::Reset ()
	{
		m_State = eSessionStateUnknown;
		transports.PeerDisconnected (shared_from_this ());
		m_Data.Stop ();
		m_ConnectTimer.cancel ();
		if (m_SentRelayTag)
		{
			m_Server.RemoveRelay (m_SentRelayTag); // relay tag is not valid anymore
			m_SentRelayTag = 0;
		}
		m_DHKeysPair = nullptr;
		m_SignedData = nullptr;
		m_IsSessionKey = false;
	}

	void SSUSession::Done ()
	{
		GetService ().post (std::bind (&SSUSession::Failed, shared_from_this ()));
	}

	void SSUSession::Established ()
	{
		m_State = eSessionStateEstablished;
		m_DHKeysPair = nullptr;
		m_SignedData = nullptr;
		m_Data.Start ();
		transports.PeerConnected (shared_from_this ());
		if (m_IsPeerTest)
			SendPeerTest ();
		if (m_SentRelayTag)
			m_Server.AddRelay (m_SentRelayTag, shared_from_this ());
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
	}

	void SSUSession::Failed ()
	{
		if (m_State != eSessionStateFailed)
		{
			m_State = eSessionStateFailed;
			m_Server.DeleteSession (shared_from_this ());
		}
	}

	void SSUSession::SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		GetService ().post (std::bind (&SSUSession::PostI2NPMessages, shared_from_this (), msgs));
	}

	void SSUSession::PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		if (m_State == eSessionStateEstablished)
		{
			for (const auto& it: msgs)
				if (it)
				{
					if (it->GetLength () <= SSU_MAX_I2NP_MESSAGE_SIZE)
						m_Data.Send (it);
					else
						LogPrint (eLogError, "SSU: I2NP message of size ", it->GetLength (), " can't be sent. Dropped");
				}
		}
	}

	void SSUSession::ProcessData (uint8_t * buf, size_t len)
	{
		m_Data.ProcessMessage (buf, len);
		m_IsDataReceived = true;
	}

	void SSUSession::FlushData ()
	{
		if (m_IsDataReceived)
		{
			m_Data.FlushReceivedMessage ();
			m_IsDataReceived = false;
		}
	}

	void SSUSession::CleanUp (uint64_t ts)
	{
		m_Data.CleanUp (ts);
		for (auto it = m_RelayRequests.begin (); it != m_RelayRequests.end ();)
		{
			if (ts > it->second.second + SSU_CONNECT_TIMEOUT)
				it = m_RelayRequests.erase (it);
			else
				++it;
		}
	}

	void SSUSession::ProcessPeerTest (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		uint32_t nonce = bufbe32toh (buf); // 4 bytes
		boost::asio::ip::address addr; // Alice's address
		uint16_t port = 0; // and port
		auto size = ExtractIPAddressAndPort (buf + 4, len - 4, addr, port);
		if (port && (size != 7) && (size != 19))
		{
			LogPrint (eLogWarning, "SSU: Address of ", size - 3, " bytes not supported");
			return;
		}
		const uint8_t * introKey = buf + 4 + size;
		switch (m_Server.GetPeerTestParticipant (nonce))
		{
			// existing test
			case ePeerTestParticipantAlice1:
			{
				if (m_Server.GetPeerTestSession (nonce) == shared_from_this ()) // Alice-Bob
				{
					LogPrint (eLogDebug, "SSU: Peer test from Bob. We are Alice");
					if (IsV6 ())
					{
						if (i2p::context.GetStatusV6 () == eRouterStatusTesting)
						{
							i2p::context.SetStatusV6 (eRouterStatusFirewalled);
							m_Server.RescheduleIntroducersUpdateTimerV6 ();
						}
					}
					else if (i2p::context.GetStatus () == eRouterStatusTesting) // still not OK
					{
						i2p::context.SetStatus (eRouterStatusFirewalled);
						m_Server.RescheduleIntroducersUpdateTimer ();
					}
				}
				else
				{
					LogPrint (eLogDebug, "SSU: First peer test from Charlie. We are Alice");
					if (m_State == eSessionStateEstablished)
						LogPrint (eLogWarning, "SSU: First peer test from Charlie through established session. We are Alice");
					if (IsV6 ())
						i2p::context.SetStatusV6 (eRouterStatusOK);
					else
						i2p::context.SetStatus (eRouterStatusOK);
					m_Server.UpdatePeerTest (nonce, ePeerTestParticipantAlice2);
					SendPeerTest (nonce, senderEndpoint.address (), senderEndpoint.port (), introKey, true, false); // to Charlie
				}
				break;
			}
			case ePeerTestParticipantAlice2:
			{
				if (m_Server.GetPeerTestSession (nonce) == shared_from_this ()) // Alice-Bob
					LogPrint (eLogDebug, "SSU: Peer test from Bob. We are Alice");
				else
				{
					// peer test successive
					LogPrint (eLogDebug, "SSU: Second peer test from Charlie. We are Alice");
					if (IsV6 ())
						i2p::context.SetStatusV6 (eRouterStatusOK);
					else
						i2p::context.SetStatus (eRouterStatusOK);
					m_Server.RemovePeerTest (nonce);
				}
				break;
			}
			case ePeerTestParticipantBob:
			{
				LogPrint (eLogDebug, "SSU: Peer test from Charlie. We are Bob");
				auto session = m_Server.GetPeerTestSession (nonce); // session with Alice from PeerTest
				if (session && session->m_State == eSessionStateEstablished)
				{
					const auto& ep = session->GetRemoteEndpoint (); // Alice's endpoint as known to Bob
					session->SendPeerTest (nonce, ep.address (), ep.port (), introKey, false, true); // send back to Alice
				}
				m_Server.RemovePeerTest (nonce); // nonce has been used
				break;
			}
			case ePeerTestParticipantCharlie:
			{
				LogPrint (eLogDebug, "SSU: Peer test from Alice. We are Charlie");
				SendPeerTest (nonce, senderEndpoint.address (), senderEndpoint.port (), introKey); // to Alice with her actual address
				m_Server.RemovePeerTest (nonce); // nonce has been used
				break;
			}
			// test not found
			case ePeerTestParticipantUnknown:
			{
				if (m_State == eSessionStateEstablished)
				{
					// new test
					if (port)
					{
						LogPrint (eLogDebug, "SSU: Peer test from Bob. We are Charlie");
						Send (PAYLOAD_TYPE_PEER_TEST, buf, len); // back to Bob
						if (!addr.is_unspecified () && !i2p::util::net::IsInReservedRange(addr))
						{
							m_Server.NewPeerTest (nonce, ePeerTestParticipantCharlie);
							SendPeerTest (nonce, addr, port, introKey); // to Alice with her address received from Bob
						}
					}
					else
					{
					LogPrint (eLogDebug, "SSU: Peer test from Alice. We are Bob");
						auto session = senderEndpoint.address ().is_v4 () ? m_Server.GetRandomEstablishedV4Session (shared_from_this ()) : m_Server.GetRandomEstablishedV6Session (shared_from_this ()); // Charlie
						if (session)
						{
							m_Server.NewPeerTest (nonce, ePeerTestParticipantBob, shared_from_this ());
							session->SendPeerTest (nonce, senderEndpoint.address (), senderEndpoint.port (), introKey, false); // to Charlie with Alice's actual address
						}
					}
				}
				else
					LogPrint (eLogError, "SSU: Unexpected peer test");
			}
		}
	}

	void SSUSession::SendPeerTest (uint32_t nonce, const boost::asio::ip::address& address, uint16_t port,
		const uint8_t * introKey, bool toAddress, bool sendAddress)
	// toAddress is true for Alice<->Chalie communications only
	// sendAddress is false if message comes from Alice
	{
		uint8_t buf[80 + 18] = {0};
		uint8_t iv[16];
		uint8_t * payload = buf + sizeof (SSUHeader);
		htobe32buf (payload, nonce);
		payload += 4; // nonce
		// address and port
		if (sendAddress)
		{
			if (address.is_v4 ())
			{
				*payload = 4;
				memcpy (payload + 1, address.to_v4 ().to_bytes ().data (), 4); // our IP V4
			}
			else if (address.is_v6 ())
			{
				*payload = 16;
				memcpy (payload + 1, address.to_v6 ().to_bytes ().data (), 16); // our IP V6
			}
			else
				*payload = 0;
			payload += (payload[0] + 1);
		}
		else
		{
			*payload = 0;
			payload++; //size
		}
		htobe16buf (payload, port);
		payload += 2; // port
		// intro key
		if (toAddress)
		{
			// send our intro key to address instead of its own
			auto addr = address.is_v4 () ? i2p::context.GetRouterInfo ().GetSSUAddress (true) : // ipv4
				i2p::context.GetRouterInfo ().GetSSUV6Address ();
			if (addr)
				memcpy (payload, addr->i, 32); // intro key
			else
				LogPrint (eLogInfo, "SSU: SSU is not supported. Can't send peer test");
		}
		else
			memcpy (payload, introKey, 32); // intro key

		// send
		RAND_bytes (iv, 16); // random iv
		if (toAddress)
		{
			// encrypt message with specified intro key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_PEER_TEST, buf, 80, introKey, iv, introKey);
			boost::asio::ip::udp::endpoint e (address, port);
			m_Server.Send (buf, 80, e);
		}
		else
		{
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_PEER_TEST, buf, 80);
			Send (buf, 80);
		}
	}

	void SSUSession::SendPeerTest ()
	{
		// we are Alice
		LogPrint (eLogDebug, "SSU: Sending peer test");
		auto address = IsV6 () ? i2p::context.GetRouterInfo ().GetSSUV6Address () : i2p::context.GetRouterInfo ().GetSSUAddress (true);
		if (!address)
		{
			LogPrint (eLogInfo, "SSU: SSU is not supported. Can't send peer test");
			return;
		}
		uint32_t nonce;
		RAND_bytes ((uint8_t *)&nonce, 4);
		if (!nonce) nonce = 1;
		m_IsPeerTest = false;
		m_Server.NewPeerTest (nonce, ePeerTestParticipantAlice1, shared_from_this ());
		SendPeerTest (nonce, boost::asio::ip::address(), 0, address->i, false, false); // address and port always zero for Alice
	}

	void SSUSession::SendKeepAlive ()
	{
		if (m_State == eSessionStateEstablished)
		{
			uint8_t buf[48 + 18] = {0};
			uint8_t	* payload = buf + sizeof (SSUHeader);
			*payload = 0; // flags
			payload++;
			*payload = 0; // num fragments
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, 48);
			Send (buf, 48);
			LogPrint (eLogDebug, "SSU: keep-alive sent");
			m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		}
	}

	void SSUSession::SendSessionDestroyed ()
	{
		if (m_IsSessionKey)
		{
			uint8_t buf[48 + 18] = {0};
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_DESTROYED, buf, 48);
			try
			{
				Send (buf, 48);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogWarning, "SSU: Exception while sending session destoroyed: ", ex.what ());
			}
			LogPrint (eLogDebug, "SSU: Session destroyed sent");
		}
	}

	void SSUSession::Send (uint8_t type, const uint8_t * payload, size_t len)
	{
		uint8_t buf[SSU_MTU_V4 + 18] = {0};
		size_t msgSize = len + sizeof (SSUHeader);
		size_t paddingSize = msgSize & 0x0F; // %16
		if (paddingSize > 0) msgSize += (16 - paddingSize);
		if (msgSize > SSU_MTU_V4)
		{
			LogPrint (eLogWarning, "SSU: Payload size ", msgSize, " exceeds MTU");
			return;
		}
		memcpy (buf + sizeof (SSUHeader), payload, len);
		// encrypt message with session key
		FillHeaderAndEncrypt (type, buf, msgSize);
		Send (buf, msgSize);
	}

	void SSUSession::Send (const uint8_t * buf, size_t size)
	{
		m_NumSentBytes += size;
		i2p::transport::transports.UpdateSentBytes (size);
		m_Server.Send (buf, size, m_RemoteEndpoint);
	}

	size_t SSUSession::ExtractIPAddressAndPort (const uint8_t * buf, size_t len, boost::asio::ip::address& ip, uint16_t& port)
	{
		if (!len) return 0;
		uint8_t size = *buf;
		size_t s = 1 + size + 2; // size + address + port
		if (len < s)
		{
			LogPrint (eLogWarning, "SSU: Address is too short ", len);
			port = 0;
			return len;
		}
		buf++; // size
		if (size == 4)
		{
			boost::asio::ip::address_v4::bytes_type bytes;
			memcpy (bytes.data (), buf, 4);
			ip = boost::asio::ip::address_v4 (bytes);
		}
		else if (size == 16)
		{
			boost::asio::ip::address_v6::bytes_type bytes;
			memcpy (bytes.data (), buf, 16);
			ip = boost::asio::ip::address_v6 (bytes);
		}
		else
			LogPrint (eLogWarning, "SSU: Address size ", int(size), " is not supported");
		buf += size;
		port = bufbe16toh (buf);
		return s;
	}
}
}
