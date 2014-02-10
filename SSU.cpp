#include <string.h>
#include <boost/bind.hpp>
#include <cryptopp/dh.h>
#include <cryptopp/secblock.h>
#include "CryptoConst.h"
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "hmac.h"
#include "SSU.h"

namespace i2p
{
namespace ssu
{

	SSUSession::SSUSession (SSUServer * server, boost::asio::ip::udp::endpoint& remoteEndpoint,
		const i2p::data::RouterInfo * router): m_Server (server), m_RemoteEndpoint (remoteEndpoint), 
		m_RemoteRouter (router), m_State (eSessionStateUnknown)
	{
	}

	void SSUSession::CreateAESandMacKey (uint8_t * pubKey, uint8_t * aesKey, uint8_t * macKey)
	{
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		CryptoPP::SecByteBlock secretKey(dh.AgreedValueLength());
		if (!dh.Agree (secretKey, i2p::context.GetPrivateKey (), pubKey))
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
				ProcessMessage (buf, len);
			break;
			// establishing
			case eSessionStateUnknown:
				// session request
				ProcessSessionRequest (buf, len, senderEndpoint);
			break;
			case eSessionStateRequestSent:
				// session created
				ProcessSessionCreated (buf, len);
			break;
			case eSessionStateCreatedSent:
				// session confirmed
				ProcessSessionConfirmed (buf, len);
			break;
			default:
				LogPrint ("SSU state not implemented yet");
		}
	}

	void SSUSession::ProcessMessage (uint8_t * buf, size_t len)
	{
		if (Validate (buf, len, m_MacKey))
		{
			Decrypt (buf, len, m_SessionKey);
			SSUHeader * header = (SSUHeader *)buf;
			uint8_t payloadType = header->flag >> 4;
			switch (payloadType)
			{
				case PAYLOAD_TYPE_DATA:
					LogPrint ("SSU data received");
					ProcessData (buf + sizeof (SSUHeader), len - sizeof (SSUHeader));
				break;
				case PAYLOAD_TYPE_TEST:
					LogPrint ("SSU test received");
				break;
				case PAYLOAD_TYPE_SESSION_DESTROYED:
					LogPrint ("SSU session destroy received");
				break;	
				default:
					LogPrint ("Unexpected SSU payload type ", (int)payloadType);
			}
		}
		// TODO: try intro key as well
		else
			LogPrint ("MAC verifcation failed");	
	}

	void SSUSession::ProcessSessionRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		LogPrint ("Process session request");
		// use our intro key
		if (ProcessIntroKeyEncryptedMessage (PAYLOAD_TYPE_SESSION_REQUEST, 
			i2p::context.GetRouterInfo (), buf, len))
		{
			m_State = eSessionStateRequestReceived;
			LogPrint ("Session request received");	
			m_RemoteEndpoint = senderEndpoint;
			SendSessionCreated (buf + sizeof (SSUHeader));
		}
	}

	void SSUSession::ProcessSessionCreated (uint8_t * buf, size_t len)
	{
		LogPrint ("Process session created");
		if (!m_RemoteRouter)
		{
			LogPrint ("Unsolicited session created message");
			return;
		}

		// use remote intro key
		if (ProcessIntroKeyEncryptedMessage (PAYLOAD_TYPE_SESSION_CREATED, *m_RemoteRouter, buf, len))
		{
			m_State = eSessionStateCreatedReceived;
			LogPrint ("Session created received");	
			uint8_t * ourAddress = buf + sizeof (SSUHeader) + 257;
			boost::asio::ip::address_v4 ourIP (be32toh (*(uint32_t* )(ourAddress)));
			uint16_t ourPort = be16toh (*(uint16_t *)(ourAddress + 4));
			LogPrint ("Our external address is ", ourIP.to_string (), ":", ourPort);
			i2p::context.UpdateAddress (ourIP.to_string ().c_str ());
			uint32_t relayTag = be32toh (*(uint32_t *)(buf + sizeof (SSUHeader) + 263));
			SendSessionConfirmed (buf + sizeof (SSUHeader), ourAddress, relayTag);
		}
	}	

	void SSUSession::ProcessSessionConfirmed (uint8_t * buf, size_t len)
	{
		LogPrint ("Process session confirmed");
		if (Validate (buf, len, m_MacKey))
		{
			Decrypt (buf, len, m_SessionKey);
			SSUHeader * header = (SSUHeader *)buf;
			if ((header->flag >> 4) == PAYLOAD_TYPE_SESSION_CONFIRMED)
			{
				m_State = eSessionStateConfirmedReceived;
				LogPrint ("Session confirmed received");		
				m_State = eSessionStateEstablished;
				// TODO: send DeliverStatus	
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
		auto address = m_RemoteRouter ? m_RemoteRouter->GetSSUAddress () : nullptr;
		if (!address)
		{
			LogPrint ("Missing remote SSU address");
			return;
		}
	
		uint8_t buf[304 + 18]; // 304 bytes for ipv4 (320 for ipv6)
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, i2p::context.GetRouterIdentity ().publicKey, 256);
		payload[256] = 4; // we assume ipv4
		*(uint32_t *)(payload + 257) =  htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); 
		
		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_REQUEST, buf, 304, address->key, iv, address->key);
		
		m_State = eSessionStateRequestSent;		
		m_Server->Send (buf, 304, m_RemoteEndpoint);
	}

	void SSUSession::SendSessionCreated (const uint8_t * x)
	{
		auto address = m_RemoteRouter ? m_RemoteRouter->GetSSUAddress () : nullptr;
		if (!address)
		{
			LogPrint ("Missing remote SSU address");
			return;
		}
		uint8_t signedData[532]; // x,y, remote IP, remote port, our IP, our port, relayTag, signed on time 
		memcpy (signedData, x, 256); // x

		uint8_t buf[368 + 18];	
		uint8_t * payload = buf + sizeof (SSUHeader);
		memcpy (payload, i2p::context.GetRouterIdentity ().publicKey, 256);
		memcpy (signedData + 256, payload, 256); // y
		payload += 256;
		*payload = 4; // we assume ipv4
		payload++;
		*(uint32_t *)(payload) = htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); 
		payload += 4;
		*(uint16_t *)(payload) = htobe16 (m_RemoteEndpoint.port ());
		payload += 2;
		memcpy (signedData + 512, payload - 6, 6); // remote endpoint IP and port 
		*(uint32_t *)(signedData + 518) = htobe32 (m_Server->GetEndpoint ().address ().to_v4 ().to_ulong ()); // our IP
		*(uint16_t *)(signedData + 522) = htobe16 (m_Server->GetEndpoint ().port ()); // our port
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
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CREATED, buf, 368, address->key, iv, address->key);
		m_State = eSessionStateRequestSent;		
		m_Server->Send (buf, 368, m_RemoteEndpoint);
	}

	void SSUSession::SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress, uint32_t relayTag)
	{
		auto address = m_RemoteRouter ? m_RemoteRouter->GetSSUAddress () : nullptr;
		if (!address)
		{
			LogPrint ("Missing remote SSU address");
			return;
		}

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
		memcpy (signedData, i2p::context.GetRouterIdentity ().publicKey, 256); // x
		memcpy (signedData + 256, y, 256); // y
		memcpy (signedData + 512, ourAddress, 6); // our address/port as seem by party
		*(uint32_t *)(signedData + 518) = htobe32 (m_RemoteEndpoint.address ().to_v4 ().to_ulong ()); // remote IP
		*(uint16_t *)(signedData + 522) = htobe16 (m_RemoteEndpoint.port ()); // remote port
		*(uint32_t *)(signedData + 524) = htobe32 (relayTag); // relay tag
		*(uint32_t *)(signedData + 528) = htobe32 (signedOnTime); // signed on time
		i2p::context.Sign (signedData, 532, payload); // DSA signature	

		uint8_t iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_CONFIRMED, buf, 480, m_SessionKey, iv, m_MacKey);
		m_State = eSessionStateConfirmedSent;	
		m_Server->Send (buf, 480, m_RemoteEndpoint);
	}

	bool SSUSession::ProcessIntroKeyEncryptedMessage (uint8_t expectedPayloadType, const i2p::data::RouterInfo& r, uint8_t * buf, size_t len)
	{
		auto address = r.GetSSUAddress ();
		if (address)
		{
			// use intro key for verification and decryption
			if (Validate (buf, len, address->key))
			{
				Decrypt (buf, len, address->key);
				SSUHeader * header = (SSUHeader *)buf;
				if ((header->flag >> 4) == expectedPayloadType)
				{
					CreateAESandMacKey (buf + sizeof (SSUHeader), m_SessionKey, m_MacKey);	
					return true;				
				}
				else
					LogPrint ("Unexpected payload type ", (int)(header->flag >> 4));	
			}
			else
				LogPrint ("MAC verifcation failed");	
		}
		else
			LogPrint ("SSU is not supported by ", r.GetIdentHashAbbreviation ());
		return false;
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
		SendSessionRequest ();
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
						i2p::HandleI2NPMessage (msg, false);
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
		m_Server->Send (buf, 48, m_RemoteEndpoint);
	}

	void SSUSession::SendSesionDestroyed ()
	{
		uint8_t buf[48 + 18], iv[16];
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		rnd.GenerateBlock (iv, 16); // random iv
		// encrypt message with session key
		FillHeaderAndEncrypt (PAYLOAD_TYPE_SESSION_DESTROYED, buf, 48, m_SessionKey, iv, m_MacKey);
		m_Server->Send (buf, 48, m_RemoteEndpoint);
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
			uint8_t buf[SSU_MTU + 18], iv[16];
			buf[0] = DATA_FLAG_WANT_REPLY; // for compatibility
			buf[1] = 1; // always 1 message fragment per message
			*(uint32_t *)(buf + 2) =  msgID;
			bool isLast = (len <= payloadSize);
			size_t size = isLast ? len : payloadSize;
			uint32_t fragmentInfo = (fragmentNum << 17);
			if (isLast)
				fragmentInfo |= 0x010000;
			
			fragmentInfo |= size;
			fragmentInfo = htobe32 (fragmentInfo);
			memcpy (buf + 6, (uint8_t *)(&fragmentInfo) + 1, 3);
			memcpy (buf + 9, msgBuf, size);
			
			size += sizeof (SSUHeader) + 9;
			if (size % 16) // make sure 16 bytes boundary
				size = (size/16 + 1)*16;
			
			CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
			rnd.GenerateBlock (iv, 16); // random iv
			// encrypt message with session key
			FillHeaderAndEncrypt (PAYLOAD_TYPE_DATA, buf, size, m_SessionKey, iv, m_MacKey);
			m_Server->Send (buf, size, m_RemoteEndpoint);

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
				session = new SSUSession (this, m_SenderEndpoint);
				m_Sessions[m_SenderEndpoint] = session;
				LogPrint ("New SSU session from ", m_SenderEndpoint.address ().to_string (), ":", m_SenderEndpoint.port (), " created");
			}
			session->ProcessNextMessage (m_ReceiveBuffer, bytes_transferred, m_SenderEndpoint);
			Receive ();
		}
		else
			LogPrint ("SSU receive error: ", ecode.message ());
	}

	SSUSession * SSUServer::GetSession (const i2p::data::RouterInfo * router)
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
					session = new SSUSession (this, remoteEndpoint, router);
					m_Sessions[remoteEndpoint] = session;
					LogPrint ("New SSU session to [", router->GetIdentHashAbbreviation (), "] ",
						remoteEndpoint.address ().to_string (), ":", remoteEndpoint.port (), " created");
					session->Connect ();
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

