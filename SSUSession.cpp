#include <boost/bind.hpp>
#include <cryptopp/dh.h>
#include <cryptopp/sha.h>
#include "CryptoConst.h"
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "Transports.h"
#include "SSU.h"
#include "SSUSession.h"

namespace i2p
{
namespace transport
{
	SSUSession::SSUSession (SSUServer& server, boost::asio::ip::udp::endpoint& remoteEndpoint,
		std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest ): TransportSession (router), 
		m_Server (server), m_RemoteEndpoint (remoteEndpoint), 
		m_Timer (m_Server.GetService ()), m_PeerTest (peerTest),
 		m_State (eSessionStateUnknown), m_IsSessionKey (false), m_RelayTag (0),
		m_Data (*this), m_NumSentBytes (0), m_NumReceivedBytes (0)
	{
		m_CreationTime = i2p::util::GetSecondsSinceEpoch ();
	}

	SSUSession::~SSUSession ()
	{		
	}	
	
	void SSUSession::CreateAESandMacKey (const uint8_t * pubKey)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		uint8_t sharedKey[256];
		if (!dh.Agree (sharedKey, m_DHKeysPair->privateKey, pubKey))
		{    
		    LogPrint (eLogError, "Couldn't create shared key");
			return;
		};

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
					LogPrint ("First 32 bytes of shared key is all zeros. Ignored");
					return;
				}	
			}
			
			memcpy (sessionKey, nonZero, 32);
			CryptoPP::SHA256().CalculateDigest(macKey, nonZero, 64 - (nonZero - sharedKey));
		}
		m_IsSessionKey = true;
		m_SessionKeyEncryption.SetKey (m_SessionKey);
		m_SessionKeyDecryption.SetKey (m_SessionKey);
	}		

	void SSUSession::ProcessNextMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		m_NumReceivedBytes += len;
		if (m_State == eSessionStateIntroduced)
		{
			// HolePunch received
			LogPrint ("SSU HolePunch of ", len, " bytes received");
			m_State = eSessionStateUnknown;
			Connect ();
		}
		else
		{
			if (!len) return; // ignore zero-length packets	
			if (m_State == eSessionStateEstablished)
				ScheduleTermination ();		
			
			if (m_IsSessionKey && Validate (buf, len, m_MacKey)) // try session key first
				DecryptSessionKey (buf, len);	
			else 
			{
				// try intro key depending on side
				auto introKey = GetIntroKey ();
				if (introKey && Validate (buf, len, introKey))
					Decrypt (buf, len, introKey);
				else
				{    
					// try own intro key
					auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
					if (!address)
					{
						LogPrint (eLogError, "SSU is not supported");
						return;
					}	
					if (Validate (buf, len, address->key))
						Decrypt (buf, len, address->key);
					else
					{
						LogPrint (eLogError, "MAC verification failed ", len, " bytes from ", senderEndpoint);
						m_Server.DeleteSession (shared_from_this ()); 
						return;
					}	
				}	
			}	
			// successfully decrypted
			ProcessMessage (buf, len, senderEndpoint);
		}	
	}

	void SSUSession::ProcessMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
		SSUHeader * header = (SSUHeader *)buf;
		switch (header->GetPayloadType ())
		{
			case PAYLOAD_TYPE_DATA:
				LogPrint (eLogDebug, "SSU data received");
				ProcessData (buf + sizeof (SSUHeader), len - sizeof (SSUHeader));
			break;
			case PAYLOAD_TYPE_SESSION_REQUEST:
				ProcessSessionRequest (buf, len, senderEndpoint);				
			break;
			case PAYLOAD_TYPE_SESSION_CREATED:
				ProcessSessionCreated (buf, len);
			break;
			case PAYLOAD_TYPE_SESSION_CONFIRMED:
				ProcessSessionConfirmed (buf, len);
			break;	
			case PAYLOAD_TYPE_PEER_TEST:
				LogPrint (eLogDebug, "SSU peer test received");
				ProcessPeerTest (buf + sizeof (SSUHeader), len - sizeof (SSUHeader), senderEndpoint);
			break;
			case PAYLOAD_TYPE_SESSION_DESTROYED:
			{
				LogPrint (eLogDebug, "SSU session destroy received");
				m_Server.DeleteSession (shared_from_this ()); 
				break;
			}	
			case PAYLOAD_TYPE_RELAY_RESPONSE:
				ProcessRelayResponse (buf, len);
				if (m_State != eSessionStateEstablished)
					m_Server.DeleteSession (shared_from_this ());
			break;
			case PAYLOAD_TYPE_RELAY_REQUEST:
				LogPrint (eLogDebug, "SSU relay request received");
				ProcessRelayRequest (buf + sizeof (SSUHeader), len - sizeof (SSUHeader), senderEndpoint);
			break;
			case PAYLOAD_TYPE_RELAY_INTRO:
				LogPrint (eLogDebug, "SSU relay intro received");
				ProcessRelayIntro (buf + sizeof (SSUHeader), len - sizeof (SSUHeader));
			break;
			default:
				LogPrint (eLogWarning, "Unexpected SSU payload type ", (int)header->GetPayloadType ());
		}
	}

	void SSUSession::ProcessSessionRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		LogPrint (eLogDebug, "Session request received");	
		m_RemoteEndpoint = senderEndpoint;
		if (!m_DHKeysPair)
			m_DHKeysPair = transports.GetNextDHKeysPair ();
		CreateAESandMacKey (buf + sizeof (SSUHeader));
		SendSessionCreated (buf + sizeof (SSUHeader));
	}

	void SSUSession::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		if (!m_RemoteRouter || !m_DHKeysPair)
		{
			LogPrint (eLogWarning, "Unsolicited session created message");
			return;
		}

		LogPrint (eLogDebug, "Session created received");	
		m_Timer.cancel (); // connect timer
		SignedData s; // x,y, our IP, our port, remote IP, remote port, relayTag, signed on time 
		uint8_t * payload = buf + sizeof (SSUHeader);	
		uint8_t * y = payload;
		CreateAESandMacKey (y);
		s.Insert (m_DHKeysPair->publicKey, 256); // x
		s.Insert (y, 256); // y
		payload += 256;
		uint8_t addressSize = *payload;
		payload += 1; // size
		uint8_t * ourAddress = payload;
		boost::asio::ip::address ourIP;
		if (addressSize == 4) // v4
		{	
			boost::asio::ip::address_v4::bytes_type bytes;
			memcpy (bytes.data (), ourAddress, 4);
			ourIP = boost::asio::ip::address_v4 (bytes);
		}	
		else // v6
		{
			boost::asio::ip::address_v6::bytes_type bytes;
			memcpy (bytes.data (), ourAddress, 16);
			ourIP = boost::asio::ip::address_v6 (bytes);
		}	
		s.Insert (ourAddress, addressSize); // our IP 
		payload += addressSize; // address
		uint16_t ourPort = bufbe16toh (payload);
		s.Insert (payload, 2); // our port
		payload += 2; // port
		LogPrint ("Our external address is ", ourIP.to_string (), ":", ourPort);
		i2p::context.UpdateAddress (ourIP);
		if (m_RemoteEndpoint.address ().is_v4 ())
			s.Insert (m_RemoteEndpoint.address ().to_v4 ().to_bytes ().data (), 4); // remote IP v4
		else
			s.Insert (m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data (), 16); // remote IP v6
		s.Insert (htobe16 (m_RemoteEndpoint.port ())); // remote port
		s.Insert (payload, 8); // relayTag and signed on time 
		m_RelayTag = bufbe32toh (payload);
		payload += 4; // relayTag
		payload += 4; // signed on time
		// decrypt signature
		size_t signatureLen = m_RemoteIdentity.GetSignatureLen ();
		size_t paddingSize = signatureLen & 0x0F; // %16
		if (paddingSize > 0) signatureLen += (16 - paddingSize);
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
		m_SessionKeyDecryption.SetIV (((SSUHeader *)buf)->iv);
		m_SessionKeyDecryption.Decrypt (payload, signatureLen, payload);
		// verify
		if (!s.Verify (m_RemoteIdentity, payload))
			LogPrint (eLogError, "SSU signature verification failed");
		
		SendSessionConfirmed (y, ourAddress, addressSize + 2);
	}	

	void SSUSession::ProcessSessionConfirmed (uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "Session confirmed received");	
		uint8_t * payload = buf + sizeof (SSUHeader);
		payload++; // identity fragment info
		uint16_t identitySize = bufbe16toh (payload);	
		payload += 2; // size of identity fragment
		m_RemoteIdentity.FromBuffer (payload, identitySize);
		m_Data.UpdatePacketSize (m_RemoteIdentity.GetIdentHash ());
		payload += identitySize; // identity	
		payload += 4; // signed-on time
		size_t paddingSize = (payload - buf) + m_RemoteIdentity.GetSignatureLen ();
		paddingSize &= 0x0F;  // %16
		if (paddingSize > 0) paddingSize = 16 - paddingSize;
		payload += paddingSize;
		// TODO: verify signature (need data from session request), payload points to signature
		SendI2NPMessage (CreateDeliveryStatusMsg (0));
		Established ();
	}

	void SSUSession::SendSessionRequest ()
	{
		auto introKey = GetIntroKey ();
		if (!introKey)
		{
			LogPrint (eLogError, "SSU is not supported");
			return;
		}
	
		uint8_t buf[320 + 18]; // 304 bytes for ipv4, 320 for ipv6
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, m_DHKeysPair->publicKey, 256); // x
		bool isV4 = m_RemoteEndpoint.address ().is_v4 ();
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
		
		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_REQUEST, buf, isV4 ? 304 : 320, introKey, iv, introKey);
		m_Server.Send (buf, isV4 ? 304 : 320, m_RemoteEndpoint);
	}

	void SSUSession::SendRelayRequest (uint32_t iTag, const uint8_t * iKey)
	{
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (!address)
		{
			LogPrint (eLogError, "SSU is not supported");
			return;
		}
	
		uint8_t buf[96 + 18]; 
		uint8_t * payload = buf + sizeof (SSUHeader);
		htobe32buf (payload, iTag);
		payload += 4;
		*payload = 0; // no address
		payload++;
		htobuf16(payload, 0); // port = 0
		payload += 2;
		*payload = 0; // challenge
		payload++;	
		memcpy (payload, (const uint8_t *)address->key, 32);
		payload += 32;
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		htobe32buf (payload, rnd.GenerateWord32 ()); // nonce	

		uint8_t iv[16];
		rnd.GenerateBlock (iv, 16); // random iv
		if (m_State == eSessionStateEstablished)
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_REQUEST, buf, 96, m_SessionKey, iv, m_MacKey);
		else
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_REQUEST, buf, 96, iKey, iv, iKey);			
		m_Server.Send (buf, 96, m_RemoteEndpoint);
	}

	void SSUSession::SendSessionCreated (const uint8_t * x)
	{
		auto introKey = GetIntroKey ();
		auto address = IsV6 () ? i2p::context.GetRouterInfo ().GetSSUV6Address () :
			i2p::context.GetRouterInfo ().GetSSUAddress (true); //v4 only
		if (!introKey || !address)
		{
			LogPrint (eLogError, "SSU is not supported");
			return;
		}
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		SignedData s; // x,y, remote IP, remote port, our IP, our port, relayTag, signed on time 
		s.Insert (x, 256); // x

		uint8_t buf[384 + 18];	
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, m_DHKeysPair->publicKey, 256);
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
		s.Insert (htobe16 (address->port)); // our port
		uint32_t relayTag = 0;
		if (i2p::context.GetRouterInfo ().IsIntroducer ())
		{
			relayTag = rnd.GenerateWord32 ();
			if (!relayTag) relayTag = 1;
			m_Server.AddRelay (relayTag, m_RemoteEndpoint);
		}
		htobe32buf (payload, relayTag); 
		payload += 4; // relay tag 
		htobe32buf (payload, i2p::util::GetSecondsSinceEpoch ()); // signed on time
		payload += 4;
		s.Insert (payload - 8, 8); // relayTag and signed on time 
		s.Sign (i2p::context.GetPrivateKeys (), payload); // DSA signature
		// TODO: fill padding with random data	

		uint8_t iv[16];
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt signature and padding with newly created session key	
		size_t signatureLen = i2p::context.GetIdentity ().GetSignatureLen ();
		size_t paddingSize = signatureLen & 0x0F; // %16
		if (paddingSize > 0) signatureLen += (16 - paddingSize);
		m_SessionKeyEncryption.SetIV (iv);
		m_SessionKeyEncryption.Encrypt (payload, signatureLen, payload);
		payload += signatureLen;
		size_t msgLen = payload - buf;
		
		// encrypt message with intro key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CREATED, buf, msgLen, introKey, iv, introKey);	
		Send (buf, msgLen);
	}

	void SSUSession::SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress, size_t ourAddressLen)
	{
		uint8_t buf[512 + 18];
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = 1; // 1 fragment
		payload++; // info
		size_t identLen = i2p::context.GetIdentity ().GetFullLen (); // 387+ bytes
		htobe16buf (payload, identLen);
		payload += 2; // cursize
		i2p::context.GetIdentity ().ToBuffer (payload, identLen);
		payload += identLen;
		uint32_t signedOnTime = i2p::util::GetSecondsSinceEpoch ();
		htobe32buf (payload, signedOnTime); // signed on time
		payload += 4;
		auto signatureLen = i2p::context.GetIdentity ().GetSignatureLen ();
		size_t paddingSize = ((payload - buf) + signatureLen)%16;
		if (paddingSize > 0) paddingSize = 16 - paddingSize;
		// TODO: fill padding	
		payload += paddingSize; // padding size

		// signature		
		SignedData s; // x,y, our IP, our port, remote IP, remote port, relayTag, our signed on time 
		s.Insert (m_DHKeysPair->publicKey, 256); // x
		s.Insert (y, 256); // y
		s.Insert (ourAddress, ourAddressLen); // our address/port as seem by party
		if (m_RemoteEndpoint.address ().is_v4 ())
			s.Insert (m_RemoteEndpoint.address ().to_v4 ().to_bytes ().data (), 4); // remote IP V4
		else
			s.Insert (m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data (), 16); // remote IP V6	
		s.Insert (htobe16 (m_RemoteEndpoint.port ())); // remote port
		s.Insert (htobe32 (m_RelayTag)); // relay tag
		s.Insert (htobe32 (signedOnTime)); // signed on time
		s.Sign (i2p::context.GetPrivateKeys (), payload); // DSA signature	
		payload += signatureLen;
		
		size_t msgLen = payload - buf;
		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CONFIRMED, buf, msgLen, m_SessionKey, iv, m_MacKey);
		Send (buf, msgLen);
	}

	void SSUSession::ProcessRelayRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& from)
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
			uint8_t * introKey = buf;
			buf += 32; // introkey
			uint32_t nonce = bufbe32toh (buf);
			SendRelayResponse (nonce, from, introKey, session->m_RemoteEndpoint);
			SendRelayIntro (session.get (), from);
		}	
	}

	void SSUSession::SendRelayResponse (uint32_t nonce, const boost::asio::ip::udp::endpoint& from,
		const uint8_t * introKey, const boost::asio::ip::udp::endpoint& to)
	{
		uint8_t buf[80 + 18]; // 64 Alice's ipv4 and 80 Alice's ipv6
		uint8_t * payload = buf + sizeof (SSUHeader);
		// Charlie's address always v4
		if (!to.address ().is_v4 ())
		{
			LogPrint (eLogError, "Charlie's IP must be v4");
			return;
		}
		*payload = 4;
		payload++; // size
		htobe32buf (payload, to.address ().to_v4 ().to_ulong ()); // Charlie's IP
		payload += 4; // address	
		htobe16buf (payload, to.port ()); // Charlie's port
		payload += 2; // port
		// Alice
		bool isV4 = from.address ().is_v4 (); // Alice's
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
			CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
			rnd.GenerateBlock (iv, 16); // random iv
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_RESPONSE, buf, isV4 ? 64 : 80, introKey, iv, introKey);
			m_Server.Send (buf, isV4 ? 64 : 80, from);
		}	
		LogPrint (eLogDebug, "SSU relay response sent");
	}	

	void SSUSession::SendRelayIntro (SSUSession * session, const boost::asio::ip::udp::endpoint& from)
	{
		if (!session) return;	
		// Alice's address always v4
		if (!from.address ().is_v4 ())
		{
			LogPrint (eLogError, "Alice's IP must be v4");
			return;
		}	
		uint8_t buf[48 + 18];
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = 4;
		payload++; // size
		htobe32buf (payload, from.address ().to_v4 ().to_ulong ()); // Alice's IP
		payload += 4; // address	
		htobe16buf (payload, from.port ()); // Alice's port
		payload += 2; // port
		*payload = 0; // challenge size	
		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_INTRO, buf, 48, session->m_SessionKey, iv, session->m_MacKey);
		m_Server.Send (buf, 48, session->m_RemoteEndpoint);
		LogPrint (eLogDebug, "SSU relay intro sent");
	}
	
	void SSUSession::ProcessRelayResponse (uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "Relay response received");		
		uint8_t * payload = buf + sizeof (SSUHeader);
		uint8_t remoteSize = *payload; 
		payload++; // remote size
		//boost::asio::ip::address_v4 remoteIP (bufbe32toh (payload));
		payload += remoteSize; // remote address
		//uint16_t remotePort = bufbe16toh (payload);
		payload += 2; // remote port
		uint8_t ourSize = *payload; 
		payload++; // our size
		boost::asio::ip::address ourIP;
		if (ourSize == 4)
		{
			boost::asio::ip::address_v4::bytes_type bytes;
			memcpy (bytes.data (), payload, 4);
			ourIP = boost::asio::ip::address_v4 (bytes);
		}
		else
		{
			boost::asio::ip::address_v6::bytes_type bytes;
			memcpy (bytes.data (), payload, 16);
			ourIP = boost::asio::ip::address_v6 (bytes);
		}
		payload += ourSize; // our address
		uint16_t ourPort = bufbe16toh (payload);
		payload += 2; // our port
		LogPrint ("Our external address is ", ourIP.to_string (), ":", ourPort);
		i2p::context.UpdateAddress (ourIP);
	}

	void SSUSession::ProcessRelayIntro (uint8_t * buf, size_t len)
	{
		uint8_t size = *buf;
		if (size == 4)
		{
			buf++; // size
			boost::asio::ip::address_v4 address (bufbe32toh (buf));
			buf += 4; // address
			uint16_t port = bufbe16toh (buf);
			// send hole punch of 1 byte
			m_Server.Send (buf, 0, boost::asio::ip::udp::endpoint (address, port));
		}
		else
			LogPrint (eLogWarning, "Address size ", size, " is not supported"); 	
	}		

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len, 
		const uint8_t * aesKey, const uint8_t * iv, const uint8_t * macKey)
	{	
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "Unexpected SSU packet length ", len);
			return;
		}
		//TODO: we are using a dirty solution here but should work for now
		SSUHeader * header = (SSUHeader *)buf;
		memcpy (header->iv, iv, 16);
		header->flag = payloadType << 4; // MSB is 0
		htobe32buf (&(header->time), i2p::util::GetSecondsSinceEpoch ());
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (aesKey);
		encryption.SetIV (iv);
		encryption.Encrypt (encrypted, encryptedLen, encrypted);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, iv, 16);
		htobe16buf (buf + len + 16, encryptedLen);
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, header->mac);
	}

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "Unexpected SSU packet length ", len);
			return;
		}
		//TODO: we are using a dirty solution here but should work for now
		SSUHeader * header = (SSUHeader *)buf;
		i2p::context.GetRandomNumberGenerator ().GenerateBlock (header->iv, 16); // random iv
		m_SessionKeyEncryption.SetIV (header->iv);
		header->flag = payloadType << 4; // MSB is 0
		htobe32buf (&(header->time), i2p::util::GetSecondsSinceEpoch ());
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		m_SessionKeyEncryption.Encrypt (encrypted, encryptedLen, encrypted);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, header->iv, 16);
		htobe16buf (buf + len + 16, encryptedLen);
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, m_MacKey, header->mac);
	}	
		
	void SSUSession::Decrypt (uint8_t * buf, size_t len, const uint8_t * aesKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "Unexpected SSU packet length ", len);
			return;
		}
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
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
			LogPrint (eLogError, "Unexpected SSU packet length ", len);
			return;
		}
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);	
		if (encryptedLen > 0)
		{	
			m_SessionKeyDecryption.SetIV (header->iv);
			m_SessionKeyDecryption.Decrypt (encrypted, encryptedLen, encrypted);
		}	
	}	
		
	bool SSUSession::Validate (uint8_t * buf, size_t len, const uint8_t * macKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint (eLogError, "Unexpected SSU packet length ", len);
			return false;
		}
		//TODO: since we are accessing a uint8_t this is unlikely to crash due to alignment but should be improved
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, header->iv, 16);
		htobe16buf (buf + len + 16, encryptedLen);
		uint8_t digest[16];
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, digest);
		return !memcmp (header->mac, digest, 16);
	}

	void SSUSession::Connect ()
	{
		if (m_State == eSessionStateUnknown)
		{	
			// set connect timer
			ScheduleConnectTimer ();
			m_DHKeysPair = transports.GetNextDHKeysPair ();
			SendSessionRequest ();
		}	
	}

	void SSUSession::WaitForConnect ()
	{
		if (!m_RemoteRouter) // incoming session
			ScheduleConnectTimer ();
		else
			LogPrint (eLogError, "SSU wait for connect for outgoing session");	
	}

	void SSUSession::ScheduleConnectTimer ()
	{
		m_Timer.cancel ();
		m_Timer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
		m_Timer.async_wait (std::bind (&SSUSession::HandleConnectTimer,
			shared_from_this (), std::placeholders::_1));	
}

	void SSUSession::HandleConnectTimer (const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			// timeout expired
			LogPrint ("SSU session was not established after ", SSU_CONNECT_TIMEOUT, " second");
			Failed ();
		}	
	}	
	
	void SSUSession::Introduce (uint32_t iTag, const uint8_t * iKey)
	{
		if (m_State == eSessionStateUnknown)
		{	
			// set connect timer
			m_Timer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
			m_Timer.async_wait (std::bind (&SSUSession::HandleConnectTimer,
				shared_from_this (), std::placeholders::_1));
		}	
		SendRelayRequest (iTag, iKey);
	}

	void SSUSession::WaitForIntroduction ()
	{
		m_State = eSessionStateIntroduced;
		// set connect timer
		m_Timer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
		m_Timer.async_wait (std::bind (&SSUSession::HandleConnectTimer,
			shared_from_this (), std::placeholders::_1));			
	}

	void SSUSession::Close ()
	{
		SendSesionDestroyed ();
		transports.PeerDisconnected (shared_from_this ());
	}	

	void SSUSession::Established ()
	{
		m_State = eSessionStateEstablished;
		if (m_DHKeysPair)
		{
			delete m_DHKeysPair;
			m_DHKeysPair = nullptr;
		}
		SendI2NPMessage (CreateDatabaseStoreMsg ());
		transports.PeerConnected (shared_from_this ());
		if (m_PeerTest && (m_RemoteRouter && m_RemoteRouter->IsPeerTesting ()))
			SendPeerTest ();
		ScheduleTermination ();
	}	

	void SSUSession::Failed ()
	{
		if (m_State != eSessionStateFailed)
		{	
			m_State = eSessionStateFailed;
			m_Server.DeleteSession (shared_from_this ());  
		}	
	}	

	void SSUSession::ScheduleTermination ()
	{
		m_Timer.cancel ();
		m_Timer.expires_from_now (boost::posix_time::seconds(SSU_TERMINATION_TIMEOUT));
		m_Timer.async_wait (std::bind (&SSUSession::HandleTerminationTimer,
			shared_from_this (), std::placeholders::_1));
	}

	void SSUSession::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			LogPrint ("SSU no activity fo ", SSU_TERMINATION_TIMEOUT, " seconds");
			Failed ();
		}	
	}	
	
	const uint8_t * SSUSession::GetIntroKey () const
	{
		if (m_RemoteRouter)
		{
			// we are client
			auto address = m_RemoteRouter->GetSSUAddress ();
			return address ? (const uint8_t *)address->key : nullptr;
		}
		else
		{
			// we are server
			auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
			return address ? (const uint8_t *)address->key : nullptr;
		}
	}	

	void SSUSession::SendI2NPMessage (I2NPMessage * msg)
	{
		boost::asio::io_service& service = IsV6 () ? m_Server.GetServiceV6 () : m_Server.GetService ();
		service.post (std::bind (&SSUSession::PostI2NPMessage, shared_from_this (), msg));    
	}	

	void SSUSession::PostI2NPMessage (I2NPMessage * msg)
	{
		if (msg)
			m_Data.Send (msg);
	}		

	void SSUSession::SendI2NPMessages (const std::vector<I2NPMessage *>& msgs)
	{
		boost::asio::io_service& service = IsV6 () ? m_Server.GetServiceV6 () : m_Server.GetService ();
		service.post (std::bind (&SSUSession::PostI2NPMessages, shared_from_this (), msgs));    
	}

	void SSUSession::PostI2NPMessages (std::vector<I2NPMessage *> msgs)
	{
		for (auto it: msgs)
			if (it) m_Data.Send (it);
	}	

	void SSUSession::ProcessData (uint8_t * buf, size_t len)
	{
		m_Data.ProcessMessage (buf, len);
	}


	void SSUSession::ProcessPeerTest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		uint8_t * buf1 = buf;
		uint32_t nonce = bufbe32toh (buf);
		buf += 4; // nonce
		uint8_t size = *buf;
		buf++; // size
		
		uint32_t address = (size == 4) ? buf32toh(buf) : 0; // use it as is
		buf += size; // address
		uint16_t port = buf16toh(buf); // use it as is
		buf += 2; // port
		uint8_t * introKey = buf;
		if (port && !address)
		{
			LogPrint (eLogWarning, "Address of ", size, " bytes not supported");	
			return;
		}	
		if (m_PeerTestNonces.count (nonce) > 0)
		{
			// existing test
			if (m_PeerTest)
			{
				LogPrint (eLogDebug, "SSU peer test from Bob. We are Alice");
				m_PeerTestNonces.erase (nonce);
				m_PeerTest = false;
			}
			else if (port)
			{
				LogPrint (eLogDebug, "SSU peer test from Charlie. We are Bob");
				boost::asio::ip::udp::endpoint ep (boost::asio::ip::address_v4 (be32toh (address)), be16toh (port)); // Alice's address/port
				auto session = m_Server.FindSession (ep); // find session with Alice
				if (session)
					session->Send (PAYLOAD_TYPE_PEER_TEST, buf1, len); // back to Alice
			}
			else
			{
				LogPrint (eLogDebug, "SSU peer test from Alice. We are Charlie");
				SendPeerTest (nonce, senderEndpoint.address ().to_v4 ().to_ulong (),
						senderEndpoint.port (), introKey); // to Alice
			}
		}
		else
		{
			if (m_State == eSessionStateEstablished)
			{
				// new test
				m_PeerTestNonces.insert (nonce);
				if (port)
				{
					LogPrint (eLogDebug, "SSU peer test from Bob. We are Charlie");
					Send (PAYLOAD_TYPE_PEER_TEST, buf1, len); // back to Bob
					SendPeerTest (nonce, be32toh (address), be16toh (port), introKey); // to Alice
				}
				else
				{
					LogPrint (eLogDebug, "SSU peer test from Alice. We are Bob");
					auto session = m_Server.GetRandomEstablishedSession (shared_from_this ()); // charlie
					if (session)
						session->SendPeerTest (nonce, senderEndpoint.address ().to_v4 ().to_ulong (),
							senderEndpoint.port (), introKey, false); 		
				}
			}
			else
				LogPrint (eLogDebug, "SSU peer test from Charlie. We are Alice");
		}	
	}
	
	void SSUSession::SendPeerTest (uint32_t nonce, uint32_t address, uint16_t port, 
		const uint8_t * introKey, bool toAddress)
	{
		uint8_t buf[80 + 18];
		uint8_t iv[16];
		uint8_t * payload = buf + sizeof (SSUHeader);
		htobe32buf (payload, nonce);
		payload += 4; // nonce	
		if (address)
		{					
			*payload = 4;
			payload++; // size
			htobe32buf (payload, address);
			payload += 4; // address
		}
		else
		{
			*payload = 0;
			payload++; //size
		}
		htobe16buf (payload, port);
		payload += 2; // port
		memcpy (payload, introKey, 32); // intro key

		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		if (toAddress)
		{	
			// encrypt message with specified intro key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_PEER_TEST, buf, 80, introKey, iv, introKey);
			boost::asio::ip::udp::endpoint e (boost::asio::ip::address_v4 (address), port);
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
		LogPrint (eLogDebug, "SSU sending peer test");
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (!address)
		{
			LogPrint (eLogError, "SSU is not supported. Can't send peer test");
			return;
		}
		uint32_t nonce = i2p::context.GetRandomNumberGenerator ().GenerateWord32 ();
		if (!nonce) nonce = 1;
		m_PeerTestNonces.insert (nonce);
		SendPeerTest (nonce, 0, 0, address->key, false); // address and port always zero for Alice
	}	

	void SSUSession::SendKeepAlive ()
	{
		if (m_State == eSessionStateEstablished)
		{	
			uint8_t buf[48 + 18];	
			uint8_t	* payload = buf + sizeof (SSUHeader);
			*payload = 0; // flags
			payload++;
			*payload = 0; // num fragments  
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, 48);
			Send (buf, 48);
			LogPrint (eLogDebug, "SSU keep-alive sent");
			ScheduleTermination ();
		}	
	}

	void SSUSession::SendSesionDestroyed ()
	{
		if (m_IsSessionKey)
		{
			uint8_t buf[48 + 18];
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_DESTROYED, buf, 48);
			Send (buf, 48);
			LogPrint (eLogDebug, "SSU session destroyed sent");
		}
	}	

	void SSUSession::Send (uint8_t type, const uint8_t * payload, size_t len)
	{
		uint8_t buf[SSU_MTU_V4 + 18];
		size_t msgSize = len + sizeof (SSUHeader); 
		if (msgSize > SSU_MTU_V4)
		{
			LogPrint (eLogWarning, "SSU payload size ", msgSize, " exceeds MTU");
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
		m_Server.Send (buf, size, m_RemoteEndpoint);
	}	
}
}

