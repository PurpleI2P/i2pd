#include <string.h>
#include <boost/bind.hpp>
#include <cryptopp/dh.h>
#include <cryptopp/secblock.h>
#include "CryptoConst.h"
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "Transports.h"
#include "hmac.h"
#include "SSU.h"

namespace i2p
{
namespace ssu
{

	SSUSession::SSUSession (SSUServer& server, boost::asio::ip::udp::endpoint& remoteEndpoint,
		const i2p::data::RouterInfo * router, bool peerTest ): 
		m_Server (server), m_RemoteEndpoint (remoteEndpoint), m_RemoteRouter (router), 
		m_Timer (m_Server.GetService ()), m_PeerTest (peerTest), m_State (eSessionStateUnknown),
		m_RelayTag (0)
	{
		m_DHKeysPair = i2p::transports.GetNextDHKeysPair ();
	}

	SSUSession::~SSUSession ()
	{
		delete m_DHKeysPair;
	}	
	
	void SSUSession::CreateAESandMacKey (uint8_t * pubKey, uint8_t * aesKey, uint8_t * macKey)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		CryptoPP::SecByteBlock secretKey(dh.AgreedValueLength());
		if (!dh.Agree (secretKey, m_DHKeysPair->privateKey, pubKey))
		{    
		    LogPrint ("Couldn't create shared key");
			return;
		};

		if (secretKey[0] & 0x80)
		{
			aesKey[0] = 0;
			memcpy (aesKey + 1, secretKey, 31);
			memcpy (macKey, secretKey + 31, 32);
		}	
		else
		{	
			memcpy (aesKey, secretKey, 32);
			memcpy (macKey, secretKey + 32, 32);
		}
	}		

	void SSUSession::ProcessNextMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		switch (m_State)
		{
			case eSessionStateConfirmedSent:
			case eSessionStateEstablished:
				// most common case
				ScheduleTermination ();
				ProcessMessage (buf, len, senderEndpoint);
			break;
			// establishing or testing
			case eSessionStateUnknown:
			case eSessionStateRequestSent:
				// we must use intro key
				ProcessIntroKeyMessage (buf, len, senderEndpoint);
			break;
			case eSessionStateCreatedSent:
				// session confirmed
				ProcessSessionConfirmed (buf, len);
			break;
			case eSessionStateRelayRequestSent:
				// relay response
				ProcessRelayResponse (buf, len);
				m_Server.DeleteSession (this); 
			break;
			case eSessionStateIntroduced:
				// HolePunch received
				LogPrint ("SSU HolePuch of ", len, " bytes received");
				m_State = eSessionStateUnknown;
				Connect ();
			break;	
			default:
				LogPrint ("SSU state not implemented yet");
		}
	}

	void SSUSession::ProcessMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		if (Validate (buf, len, m_MacKey))
		{
			Decrypt (buf, len, m_SessionKey);
			SSUHeader * header = (SSUHeader *)buf;
			switch (header->GetPayloadType ())
			{
				case PAYLOAD_TYPE_DATA:
					LogPrint ("SSU data received");
					ProcessData (buf + sizeof (SSUHeader), len - sizeof (SSUHeader));
				break;
				case PAYLOAD_TYPE_PEER_TEST:
					LogPrint ("SSU peer test received");
					ProcessPeerTest (buf + sizeof (SSUHeader), len - sizeof (SSUHeader), senderEndpoint);
				break;
				case PAYLOAD_TYPE_SESSION_DESTROYED:
				{
					LogPrint ("SSU session destroy received");
					m_Server.DeleteSession (this); // delete this 
					break;
				}	
				case PAYLOAD_TYPE_RELAY_RESPONSE:
					LogPrint ("SSU relay response received though established session");
					// Ignore it for now
				break;
				case PAYLOAD_TYPE_RELAY_INTRO:
					LogPrint ("SSU relay intro received");
					ProcessRelayIntro (buf + sizeof (SSUHeader), len - sizeof (SSUHeader));
				break;
				default:
					LogPrint ("Unexpected SSU payload type ", (int)header->GetPayloadType ());
			}
		}
		else
		{
			LogPrint ("MAC key failed. Trying intro key");	
			auto introKey = GetIntroKey ();
			if (introKey && Validate (buf, len, introKey))
			{
				Decrypt (buf, len, introKey);
				SSUHeader * header = (SSUHeader *)buf;
				LogPrint ("Unexpected SSU payload type ", (int)(header->flag >> 4));
				// TODO:
			}	
			else	
				LogPrint ("MAC verifcation failed");	
			m_State = eSessionStateUnknown;
		}
	}

	void SSUSession::ProcessIntroKeyMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		auto introKey = GetIntroKey ();
		if (!introKey)
		{
			LogPrint ("SSU is not supported");
			return;
		}	
		// use intro key for verification and decryption
		if (!Validate (buf, len, introKey))
		{
			LogPrint ("MAC verification intro key failed");	
			m_Server.DeleteSession (this); 
			return;
		}	
		
		Decrypt (buf, len, introKey);
		CreateAESandMacKey (buf + sizeof (SSUHeader), m_SessionKey, m_MacKey);
		SSUHeader * header = (SSUHeader *)buf;
		switch (header->GetPayloadType ())
		{
			case PAYLOAD_TYPE_SESSION_REQUEST:
				ProcessSessionRequest (buf, len, senderEndpoint);				
			break;
			case PAYLOAD_TYPE_SESSION_CREATED:
				ProcessSessionCreated (buf, len);
			break;
			case PAYLOAD_TYPE_PEER_TEST:
				LogPrint ("SSU peer test received");
				// TODO:
			break;	
			default: ;
		}	
	}

	void SSUSession::ProcessSessionRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		m_State = eSessionStateRequestReceived;
		LogPrint ("Session request received");	
		m_RemoteEndpoint = senderEndpoint;
		SendSessionCreated (buf + sizeof (SSUHeader));
	}

	void SSUSession::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		if (!m_RemoteRouter)
		{
			LogPrint ("Unsolicited session created message");
			return;
		}

		m_State = eSessionStateCreatedReceived;
		LogPrint ("Session created received");	
		m_Timer.cancel (); // connect timer
		uint8_t signedData[532]; // x,y, our IP, our port, remote IP, remote port, relayTag, signed on time 
		uint8_t * payload = buf + sizeof (SSUHeader);	
		uint8_t * y = payload;
		memcpy (signedData, m_DHKeysPair->publicKey, 256); // x
		memcpy (signedData + 256, y, 256); // y
		payload += 256;
		payload += 1; // size, assume 4
		uint8_t * ourAddress = payload;
		boost::asio::ip::address_v4 ourIP (be32toh (*(uint32_t* )ourAddress));
		payload += 4; // address
		uint16_t ourPort = be16toh (*(uint16_t *)payload);
		payload += 2; // port
		memcpy (signedData + 512, ourAddress, 6); // our IP and port 
		LogPrint ("Our external address is ", ourIP.to_string (), ":", ourPort);
		i2p::context.UpdateAddress (ourIP.to_string ().c_str ());
		*(uint32_t *)(signedData + 518) = htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); // remote IP
		*(uint16_t *)(signedData + 522) = htobe16 (m_RemoteEndpoint.port ()); // remote port
		memcpy (signedData + 524, payload, 8); // relayTag and signed on time 
		m_RelayTag = be32toh (*(uint32_t *)payload);
		payload += 4; // relayTag
		payload += 4; // signed on time
		// decrypt DSA signature
		m_Decryption.SetKeyWithIV (m_SessionKey, 32, ((SSUHeader *)buf)->iv);
		m_Decryption.ProcessData (payload, payload, 48);
		// verify
		CryptoPP::DSA::PublicKey pubKey;
		pubKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, CryptoPP::Integer (m_RemoteRouter->GetRouterIdentity ().signingKey, 128));
		CryptoPP::DSA::Verifier verifier (pubKey);
		if (!verifier.VerifyMessage (signedData, 532, payload, 40))
			LogPrint ("SSU signature verification failed");
		
		SendSessionConfirmed (y, ourAddress);
	}	

	void SSUSession::ProcessSessionConfirmed (uint8_t * buf, size_t len)
	{
		LogPrint ("Process session confirmed");
		if (Validate (buf, len, m_MacKey))
		{
			Decrypt (buf, len, m_SessionKey);
			SSUHeader * header = (SSUHeader *)buf;
			if (header->GetPayloadType () == PAYLOAD_TYPE_SESSION_CONFIRMED)
			{
				m_State = eSessionStateConfirmedReceived;
				LogPrint ("Session confirmed received");		
				m_State = eSessionStateEstablished;
				SendI2NPMessage (CreateDeliveryStatusMsg (0));
				Established ();
			}
			else
				LogPrint ("Unexpected payload type ", (int)(header->flag >> 4));	
		}
		else
			LogPrint ("MAC verifcation failed");	
	}

	void SSUSession::SendSessionRequest ()
	{
		auto introKey = GetIntroKey ();
		if (!introKey)
		{
			LogPrint ("SSU is not supported");
			return;
		}
	
		uint8_t buf[304 + 18]; // 304 bytes for ipv4 (320 for ipv6)
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, m_DHKeysPair->publicKey, 256); // x
		payload[256] = 4; // we assume ipv4
		*(uint32_t *)(payload + 257) =  htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); 
		
		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_REQUEST, buf, 304, introKey, iv, introKey);
		
		m_State = eSessionStateRequestSent;		
		m_Server.Send (buf, 304, m_RemoteEndpoint);
	}

	void SSUSession::SendRelayRequest (uint32_t iTag, const uint8_t * iKey)
	{
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (!address)
		{
			LogPrint ("SSU is not supported");
			return;
		}
	
		uint8_t buf[96 + 18]; 
		uint8_t * payload = buf + sizeof (SSUHeader);
		*(uint32_t *)payload = htobe32 (iTag);
		payload += 4;
		*payload = 0; // no address
		payload++;
		*(uint16_t *)payload = 0; // port = 0
		payload += 2;
		*payload = 0; // challenge
		payload++;	
		memcpy (payload, address->key, 32);
		payload += 32;
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		*(uint32_t *)payload = htobe32 (rnd.GenerateWord32 ()); // nonce	

		uint8_t iv[16];
		rnd.GenerateBlock (iv, 16); // random iv
		if (m_State == eSessionStateEstablished)
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_REQUEST, buf, 96, m_SessionKey, iv, m_MacKey);
		else
		{
			FillHeaderAndEncrypt (PAYLOAD_TYPE_RELAY_REQUEST, buf, 96, iKey, iv, iKey);
			m_State = eSessionStateRelayRequestSent;
		}			
		m_Server.Send (buf, 96, m_RemoteEndpoint);
	}

	void SSUSession::SendSessionCreated (const uint8_t * x)
	{
		auto introKey = GetIntroKey ();
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (!introKey || !address)
		{
			LogPrint ("SSU is not supported");
			return;
		}
		uint8_t signedData[532]; // x,y, remote IP, remote port, our IP, our port, relayTag, signed on time 
		memcpy (signedData, x, 256); // x

		uint8_t buf[368 + 18];	
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, m_DHKeysPair->publicKey, 256);
		memcpy (signedData + 256, payload, 256); // y
		payload += 256;
		*payload = 4; // we assume ipv4
		payload++;
		*(uint32_t *)(payload) = htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); 
		payload += 4;
		*(uint16_t *)(payload) = htobe16 (m_RemoteEndpoint.port ());
		payload += 2;
		memcpy (signedData + 512, payload - 6, 6); // remote endpoint IP and port 
		*(uint32_t *)(signedData + 518) = htobe32 (address->host.to_v4 ().to_ulong ()); // our IP
		*(uint16_t *)(signedData + 522) = htobe16 (address->port); // our port
		*(uint32_t *)(payload) = 0; //  relay tag, always 0 for now
		payload += 4; 
		*(uint32_t *)(payload) = htobe32 (i2p::util::GetSecondsSinceEpoch ()); // signed on time
		payload += 4;
		memcpy (signedData + 524, payload - 8, 8); // relayTag and signed on time 
		i2p::context.Sign (signedData, 532, payload); // DSA signature
		// TODO: fill padding with random data	

		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt signature and 8 bytes padding with newly created session key	
		m_Encryption.SetKeyWithIV (m_SessionKey, 32, iv);
		m_Encryption.ProcessData (payload, payload, 48);

		// encrypt message with intro key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CREATED, buf, 368, introKey, iv, introKey);
		m_State = eSessionStateCreatedSent;		
		m_Server.Send (buf, 368, m_RemoteEndpoint);
	}

	void SSUSession::SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress)
	{
		uint8_t buf[480 + 18];
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = 1; // 1 fragment
		payload++; // info
		size_t identLen = sizeof (i2p::context.GetRouterIdentity ()); // 387 bytes
		*(uint16_t *)(payload) =  htobe16 (identLen);
		payload += 2; // cursize
		memcpy (payload, (uint8_t *)&i2p::context.GetRouterIdentity (), identLen);
		payload += identLen;
		uint32_t signedOnTime = i2p::util::GetSecondsSinceEpoch ();
		*(uint32_t *)(payload) = htobe32 (signedOnTime); // signed on time
		payload += 4;
		size_t paddingSize = ((payload - buf) + 40)%16;
		if (paddingSize > 0) paddingSize = 16 - paddingSize;
		// TODO: fill padding	
		payload += paddingSize; // padding size

		// signature		
		uint8_t signedData[532]; // x,y, our IP, our port, remote IP, remote port, relayTag, our signed on time 
		memcpy (signedData, m_DHKeysPair->publicKey, 256); // x
		memcpy (signedData + 256, y, 256); // y
		memcpy (signedData + 512, ourAddress, 6); // our address/port as seem by party
		*(uint32_t *)(signedData + 518) = htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); // remote IP
		*(uint16_t *)(signedData + 522) = htobe16 (m_RemoteEndpoint.port ()); // remote port
		*(uint32_t *)(signedData + 524) = htobe32 (m_RelayTag); // relay tag
		*(uint32_t *)(signedData + 528) = htobe32 (signedOnTime); // signed on time
		i2p::context.Sign (signedData, 532, payload); // DSA signature	

		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CONFIRMED, buf, 480, m_SessionKey, iv, m_MacKey);
		m_State = eSessionStateConfirmedSent;	
		m_Server.Send (buf, 480, m_RemoteEndpoint);
	}

	void SSUSession::ProcessRelayResponse (uint8_t * buf, size_t len)
	{
		LogPrint ("Process relay response");
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (!address)
		{
			LogPrint ("SSU is not supported");
			return;
		}

		if (Validate (buf, len, address->key))
		{
			Decrypt (buf, len, address->key);
			SSUHeader * header = (SSUHeader *)buf;
			if (header->GetPayloadType () == PAYLOAD_TYPE_RELAY_RESPONSE)
			{
				LogPrint ("Relay response received");		
				uint8_t * payload = buf + sizeof (SSUHeader);
				payload++; // remote size
				//boost::asio::ip::address_v4 remoteIP (be32toh (*(uint32_t* )(payload)));
				payload += 4; // remote address
				//uint16_t remotePort = be16toh (*(uint16_t *)(payload));
				payload += 2; // remote port
				payload++; // our size
				boost::asio::ip::address_v4 ourIP (be32toh (*(uint32_t* )(payload)));
				payload += 4; // our address
				uint16_t ourPort = be16toh (*(uint16_t *)(payload));
				payload += 2; // our port
				LogPrint ("Our external address is ", ourIP.to_string (), ":", ourPort);
				i2p::context.UpdateAddress (ourIP.to_string ().c_str ());
			}
			else
				LogPrint ("Unexpected payload type ", (int)(header->flag >> 4));
		}
	}

	void SSUSession::ProcessRelayIntro (uint8_t * buf, size_t len)
	{
		uint8_t size = *buf;
		if (size == 4)
		{
			buf++; // size
			boost::asio::ip::address_v4 address (be32toh (*(uint32_t* )buf));
			buf += 4; // address
			uint16_t port = be16toh (*(uint16_t *)buf);
			// send hole punch of 1 byte
			m_Server.Send (buf, 1, boost::asio::ip::udp::endpoint (address, port));
		}
		else
			LogPrint ("Address size ", size, " is not supported"); 	
	}		

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len, 
		const uint8_t * aesKey, const uint8_t * iv, const uint8_t * macKey)
	{	
		if (len < sizeof (SSUHeader))
		{
			LogPrint ("Unexpected SSU packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		memcpy (header->iv, iv, 16);
		header->flag = payloadType << 4; // MSB is 0
		header->time = htobe32 (i2p::util::GetSecondsSinceEpoch ());
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		m_Encryption.SetKeyWithIV (aesKey, 32, iv);
		m_Encryption.ProcessData (encrypted, encrypted, encryptedLen);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, iv, 16);
		*(uint16_t *)(buf + len + 16) = htobe16 (encryptedLen);
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, header->mac);
	}

	void SSUSession::Decrypt (uint8_t * buf, size_t len, const uint8_t * aesKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint ("Unexpected SSU packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);	
		m_Decryption.SetKeyWithIV (aesKey, 32, header->iv);
		encryptedLen = (encryptedLen/16)*16; // make sure 16 bytes boundary
		m_Decryption.ProcessData (encrypted, encrypted, encryptedLen);
	}

	bool SSUSession::Validate (uint8_t * buf, size_t len, const uint8_t * macKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint ("Unexpected SSU packet length ", len);
			return false;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, header->iv, 16);
		*(uint16_t *)(buf + len + 16) = htobe16 (encryptedLen);
		uint8_t digest[16];
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, digest);
		return !memcmp (header->mac, digest, 16);
	}

	void SSUSession::Connect ()
	{
		if (m_State == eSessionStateUnknown)
		{	
			// set connect timer
			m_Timer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
			m_Timer.async_wait (boost::bind (&SSUSession::HandleConnectTimer,
				this, boost::asio::placeholders::error));	
			SendSessionRequest ();
		}	
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
			m_Timer.async_wait (boost::bind (&SSUSession::HandleConnectTimer,
				this, boost::asio::placeholders::error));
		}	
		SendRelayRequest (iTag, iKey);
	}

	void SSUSession::WaitForIntroduction ()
	{
		m_State = eSessionStateIntroduced;
		// set connect timer
		m_Timer.expires_from_now (boost::posix_time::seconds(SSU_CONNECT_TIMEOUT));
		m_Timer.async_wait (boost::bind (&SSUSession::HandleConnectTimer,
			this, boost::asio::placeholders::error));			
	}

	void SSUSession::Close ()
	{
		SendSesionDestroyed ();
		if (!m_DelayedMessages.empty ())
		{
			for (auto it :m_DelayedMessages)
				delete it;
			m_DelayedMessages.clear ();
		}	
	}	

	void SSUSession::Established ()
	{
		SendI2NPMessage (CreateDatabaseStoreMsg ());
		if (!m_DelayedMessages.empty ())
		{
			for (auto it :m_DelayedMessages)
				Send (it);
			m_DelayedMessages.clear ();
		}
		if (m_PeerTest)
			SendPeerTest ();
		ScheduleTermination ();
	}	

	void SSUSession::Failed ()
	{
		if (m_State != eSessionStateFailed)
		{	
			m_State = eSessionStateFailed;
			Close ();
			m_Server.DeleteSession (this); // delete this 
		}	
	}	

	void SSUSession::ScheduleTermination ()
	{
		m_Timer.cancel ();
		m_Timer.expires_from_now (boost::posix_time::seconds(SSU_TERMINATION_TIMEOUT));
		m_Timer.async_wait (boost::bind (&SSUSession::HandleTerminationTimer,
			this, boost::asio::placeholders::error));
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
			return address ? address->key : nullptr;
		}
		else
		{
			// we are server
			auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
			return address ? address->key : nullptr;
		}
	}	

	void SSUSession::SendI2NPMessage (I2NPMessage * msg)
	{
		if (msg)
		{	
			if (m_State == eSessionStateEstablished)
				Send (msg);
			else
				m_DelayedMessages.push_back (msg);
		}	
	}	
	
	void SSUSession::ProcessData (uint8_t * buf, size_t len)
	{
		//uint8_t * start = buf;
		uint8_t flag = *buf;
		buf++;
		LogPrint ("Process SSU data flags=", (int)flag);
		if (flag & DATA_FLAG_EXPLICIT_ACKS_INCLUDED)
		{
			// explicit ACKs
			uint8_t numAcks =*buf;
			buf++;
			// TODO: process ACKs
			buf += numAcks*4;
		}
		if (flag & DATA_FLAG_ACK_BITFIELDS_INCLUDED)
		{
			// explicit ACK bitfields
			uint8_t numBitfields =*buf;
			buf++;
			for (int i = 0; i < numBitfields; i++)
			{
				buf += 4; // msgID
				// TODO: process ACH bitfields
				while (*buf & 0x80) // not last
					buf++;
				buf++; // last byte
			}	
		}	
		uint8_t numFragments = *buf; // number of fragments
		buf++;
		for (int i = 0; i < numFragments; i++)
		{	
			uint32_t msgID = be32toh (*(uint32_t *)buf); // message ID
			buf += 4;
			uint8_t frag[4];
			frag[0] = 0;
			memcpy (frag + 1, buf, 3);
			buf += 3;
			uint32_t fragmentInfo = be32toh (*(uint32_t *)frag); // fragment info
			uint16_t fragmentSize = fragmentInfo & 0x1FFF; // bits 0 - 13
			bool isLast = fragmentInfo & 0x010000; // bit 16	
			uint8_t fragmentNum = fragmentInfo >> 17; // bits 23 - 17
			LogPrint ("SSU data fragment ", (int)fragmentNum, " of message ", msgID, " size=", (int)fragmentSize, isLast ? " last" : " non-last"); 		
			I2NPMessage * msg = nullptr;
			if (fragmentNum > 0) // follow-up fragment
			{
				auto it = m_IncomleteMessages.find (msgID);
				if (it != m_IncomleteMessages.end ())
				{
					msg = it->second;
					memcpy (msg->buf + msg->len, buf, fragmentSize);
					msg->len += fragmentSize;
				}
				else
					// TODO:
					LogPrint ("Unexpected follow-on fragment ", fragmentNum, " of message ", msgID);	
			}
			else // first fragment
			{
				msg = NewI2NPMessage ();
				memcpy (msg->GetSSUHeader (), buf, fragmentSize);
				msg->len += fragmentSize - sizeof (I2NPHeaderShort);
			}

			if (msg)
			{					
				if (!fragmentNum && !isLast)
					m_IncomleteMessages[msgID] = msg;
				if (isLast)
				{
					SendMsgAck (msgID);
					if (fragmentNum > 0)	
						m_IncomleteMessages.erase (msgID);
					msg->FromSSU (msgID);
					if (m_State == eSessionStateEstablished)
						i2p::HandleI2NPMessage (msg);
					else
					{
						// we expect DeliveryStatus
						if (msg->GetHeader ()->typeID == eI2NPDeliveryStatus)
						{
							LogPrint ("SSU session established");
							m_State = eSessionStateEstablished;
							Established ();
						}	
						else
							LogPrint ("SSU unexpected message ", (int)msg->GetHeader ()->typeID);
						DeleteI2NPMessage (msg);
					}	
				}
			}
			buf += fragmentSize;
		}	
	}


	void SSUSession::ProcessPeerTest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		uint8_t * buf1 = buf;
		uint32_t nonce = be32toh (*(uint32_t *)buf);
		buf += 4; // nonce
		uint8_t size = *buf;
		buf++; // size
		uint8_t * address = (size == 4) ? buf : nullptr;
		buf += size; // address
		uint16_t port = *(uint16_t *)buf; // use it as is
		buf += 2; // port
		uint8_t * introKey = buf;
		if (port && !address)
		{
			LogPrint ("Address of ", size, " bytes not supported");	
			return;
		}	
		if (m_PeerTestNonces.count (nonce) > 0)
		{
			// existing test
			if (port)
			{
				LogPrint ("SSU peer test from Charlie. We are Bob");
				// TODO:  back to Alice
			}
			else
			{
				LogPrint ("SSU peer test from Alice. We are Charlie");
				//SendPeerTest (nonce, be32toh (*(uint32_t *)address), be16toh (port), introKey); // to Alice
			}
		}
		else
		{
			// new test
			m_PeerTestNonces.insert (nonce);
			if (port)
			{
				LogPrint ("SSU peer test from Bob. We are Charlie");
				Send (PAYLOAD_TYPE_PEER_TEST, buf1, len); // back to Bob
				SendPeerTest (nonce, be32toh (*(uint32_t *)address), be16toh (port), introKey); // to Alice
			}
			else
			{
				LogPrint ("SSU peer test from Alice. We are Bob");
				// TODO: find Charlie
			}
		}	
	}
	
	void SSUSession::SendPeerTest (uint32_t nonce, uint32_t address, uint16_t port, uint8_t * introKey)
	{
		uint8_t buf[80 + 18];
		uint8_t iv[16];
		uint8_t * payload = buf + sizeof (SSUHeader);
		*(uint32_t *)payload = htobe32 (nonce);
		payload += 4; // nonce					
		*payload = 4;
		payload++; // size
		*(uint32_t *)payload = htobe32 (address);
		payload += 4; // address
		*(uint16_t *)payload = htobe32 (port);
		payload += 2; // port
		memcpy (payload, introKey, 32); // intro key

		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with specified intro key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_PEER_TEST, buf, 80, introKey, iv, introKey);
		boost::asio::ip::udp::endpoint e (boost::asio::ip::address_v4 (address), port);
		m_Server.Send (buf, 80, e);
	}	

	void SSUSession::SendPeerTest ()
	{
		LogPrint ("SSU sending peer test");
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (!address)
		{
			LogPrint ("SSU is not supported. Can't send peer test");
			return;
		}
		auto introKey = address->key;
		uint8_t buf[80 + 18];
		uint8_t * payload = buf + sizeof (SSUHeader);
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t nonce = 0;
		rnd.GenerateWord32 (nonce);
		*(uint32_t *)payload = htobe32 (nonce);
		payload += 4; // nonce					
		*payload = 4;
		payload++; // size
		memset (payload, 0, 6); // address and port always zero for Alice
		payload += 6; // address and port
		memcpy (payload, introKey, 32); // intro key	
		uint8_t iv[16];	
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_PEER_TEST, buf, 80, m_SessionKey, iv, m_MacKey);
		m_Server.Send (buf, 80, m_RemoteEndpoint);
	}	

	void SSUSession::SendMsgAck (uint32_t msgID)
	{
		uint8_t buf[48 + 18]; // actual length is 44 = 37 + 7 but pad it to multiple of 16
		uint8_t iv[16];
		uint8_t * payload = buf + sizeof (SSUHeader);
		*payload = DATA_FLAG_EXPLICIT_ACKS_INCLUDED; // flag
		payload++;
		*payload = 1; // number of ACKs
		payload++;
		*(uint32_t *)(payload) = htobe32 (msgID); // msgID	
		payload += 4;
		*payload = 0; // number of fragments

		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, 48, m_SessionKey, iv, m_MacKey);
		m_Server.Send (buf, 48, m_RemoteEndpoint);
	}

	void SSUSession::SendSesionDestroyed ()
	{
		uint8_t buf[48 + 18], iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		if (m_State == eSessionStateEstablished)
		{
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_DESTROYED, buf, 48, m_SessionKey, iv, m_MacKey);
			m_Server.Send (buf, 48, m_RemoteEndpoint);
		}
	}	

	void SSUSession::Send (i2p::I2NPMessage * msg)
	{
		uint32_t msgID = htobe32 (msg->ToSSU ());
		size_t payloadSize = SSU_MTU - sizeof (SSUHeader) - 9; // 9  =  flag + #frg(1) + messageID(4) + frag info (3) 
		size_t len = msg->GetLength ();
		uint8_t * msgBuf = msg->GetSSUHeader ();

		uint32_t fragmentNum = 0;
		while (len > 0)
		{	
			uint8_t buf[SSU_MTU + 18], iv[16], * payload = buf + sizeof (SSUHeader);
			*payload = DATA_FLAG_WANT_REPLY; // for compatibility
			payload++;
			*payload = 1; // always 1 message fragment per message
			payload++;
			*(uint32_t *)payload = msgID;
			payload += 4;
			bool isLast = (len <= payloadSize);
			size_t size = isLast ? len : payloadSize;
			uint32_t fragmentInfo = (fragmentNum << 17);
			if (isLast)
				fragmentInfo |= 0x010000;
			
			fragmentInfo |= size;
			fragmentInfo = htobe32 (fragmentInfo);
			memcpy (payload, (uint8_t *)(&fragmentInfo) + 1, 3);
			payload += 3;
			memcpy (payload, msgBuf, size);
			
			size += payload - buf;
			if (size % 16) // make sure 16 bytes boundary
				size = (size/16 + 1)*16;
			
			CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
			rnd.GenerateBlock (iv, 16); // random iv
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, size, m_SessionKey, iv, m_MacKey);
			m_Server.Send (buf, size, m_RemoteEndpoint);

			if (!isLast)
			{	
				len -= payloadSize;
				msgBuf += payloadSize;
			}	
			else
				len = 0;
			fragmentNum++;
		}	
	}		

	void SSUSession::Send (uint8_t type, const uint8_t * payload, size_t len)
	{
		uint8_t buf[SSU_MTU + 18];
		uint8_t iv[16];
		size_t msgSize = len + sizeof (SSUHeader); 
		if (msgSize > SSU_MTU)
		{
			LogPrint ("SSU payload size ", msgSize, " exceeds MTU");
			return;
		} 
		memcpy (buf + sizeof (SSUHeader), payload, len);
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (type, buf, msgSize, m_SessionKey, iv, m_MacKey);
		m_Server.Send (buf, msgSize, m_RemoteEndpoint);
	}			

	SSUServer::SSUServer (boost::asio::io_service& service, int port):
		m_Endpoint (boost::asio::ip::udp::v4 (), port), m_Socket (service, m_Endpoint)
	{
		m_Socket.set_option (boost::asio::socket_base::receive_buffer_size (65535));
		m_Socket.set_option (boost::asio::socket_base::send_buffer_size (65535));
	}
	
	SSUServer::~SSUServer ()
	{
		for (auto it: m_Sessions)
			delete it.second;
	}

	void SSUServer::Start ()
	{
		Receive ();
	}

	void SSUServer::Stop ()
	{
		DeleteAllSessions ();
		m_Socket.close ();
	}

	void SSUServer::Send (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& to)
	{
		m_Socket.send_to (boost::asio::buffer (buf, len), to);
		LogPrint ("SSU sent ", len, " bytes");
	}	

	void SSUServer::Receive ()
	{
		m_Socket.async_receive_from (boost::asio::buffer (m_ReceiveBuffer, SSU_MTU), m_SenderEndpoint,
			boost::bind (&SSUServer::HandleReceivedFrom, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}

	void SSUServer::HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			LogPrint ("SSU received ", bytes_transferred, " bytes");
			SSUSession * session = nullptr;
			auto it = m_Sessions.find (m_SenderEndpoint);
			if (it != m_Sessions.end ())
				session = it->second;
			if (!session)
			{
				session = new SSUSession (*this, m_SenderEndpoint);
				m_Sessions[m_SenderEndpoint] = session;
				LogPrint ("New SSU session from ", m_SenderEndpoint.address ().to_string (), ":", m_SenderEndpoint.port (), " created");
			}
			session->ProcessNextMessage (m_ReceiveBuffer, bytes_transferred, m_SenderEndpoint);
			Receive ();
		}
		else
			LogPrint ("SSU receive error: ", ecode.message ());
	}

	SSUSession * SSUServer::FindSession (const i2p::data::RouterInfo * router)
	{
		if (!router) return nullptr;
		auto address = router->GetSSUAddress ();
		if (!address) return nullptr;
		auto it = m_Sessions.find (boost::asio::ip::udp::endpoint (address->host, address->port));
		if (it != m_Sessions.end ())
			return it->second;
		else
			return nullptr;
	}	
		
	SSUSession * SSUServer::GetSession (const i2p::data::RouterInfo * router, bool peerTest)
	{
		SSUSession * session = nullptr;
		if (router)
		{
			auto address = router->GetSSUAddress ();
			if (address)
			{
				boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
				auto it = m_Sessions.find (remoteEndpoint);
				if (it != m_Sessions.end ())
					session = it->second;
				else
				{
					// otherwise create new session					
					session = new SSUSession (*this, remoteEndpoint, router, peerTest);
					m_Sessions[remoteEndpoint] = session;
					
					if (!router->UsesIntroducer ())
					{
						// connect directly						
						LogPrint ("Creating new SSU session to [", router->GetIdentHashAbbreviation (), "] ",
							remoteEndpoint.address ().to_string (), ":", remoteEndpoint.port ());
						session->Connect ();
					}
					else
					{
						// connect through introducer
						session->WaitForIntroduction ();
						if (address->introducers.size () > 0)
						{
							auto& introducer = address->introducers[0]; // TODO:
							boost::asio::ip::udp::endpoint introducerEndpoint (introducer.iHost, introducer.iPort);
							LogPrint ("Creating new SSU session to [", router->GetIdentHashAbbreviation (), 
									"] through introducer ", introducerEndpoint.address ().to_string (), ":", introducerEndpoint.port ());
							it = m_Sessions.find (introducerEndpoint);
							SSUSession * introducerSession = nullptr;
							if (it != m_Sessions.end ())
							{
								LogPrint ("Session to introducer already exists");
								introducerSession = it->second; 
							}	
							else
							{
								LogPrint ("New session to introducer created");
								introducerSession = new SSUSession (*this, introducerEndpoint, router);
								m_Sessions[introducerEndpoint] = introducerSession;																
							}
							introducerSession->Introduce (introducer.iTag, introducer.iKey);
						}
						else
							LogPrint ("Router is unreachable, but not introducers presentd. Ignored");
					}
				}
			}
			else
				LogPrint ("Router ", router->GetIdentHashAbbreviation (), " doesn't have SSU address");
		}
		return session;
	}

	void SSUServer::DeleteSession (SSUSession * session)
	{
		if (session)
		{
			session->Close ();
			m_Sessions.erase (session->GetRemoteEndpoint ());
			delete session;
		}	
	}	

	void SSUServer::DeleteAllSessions ()
	{
		for (auto it: m_Sessions)
		{
			it.second->Close ();
			delete it.second;			
		}	
		m_Sessions.clear ();
	}
}
}

