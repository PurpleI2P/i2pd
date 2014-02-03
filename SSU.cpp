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

	SSUSession::SSUSession (SSUServer * server, const boost::asio::ip::udp::endpoint& remoteEndpoint,
		i2p::data::RouterInfo * router): m_Server (server), m_RemoteEndpoint (remoteEndpoint), 
		m_RemoteRouter (router), m_State (eSessionStateUnknown)
	{
	}

	void SSUSession::CreateAESKey (uint8_t * pubKey, uint8_t * aesKey) // TODO: move it to base class for NTCP and SSU
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
		}	
		else	
			memcpy (aesKey, secretKey, 32);
	}		

	void SSUSession::ProcessNextMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		switch (m_State)
		{
			case eSessionStateUnknown:
				// session request
				ProcessSessionRequest (buf, len, senderEndpoint);
			break;
			case eSessionStateRequestSent:
				// session created
				ProcessSessionCreated (buf, len);
			break;
			default:
				LogPrint ("SSU state not implemented yet");
		}
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
			boost::asio::ip::address_v4 ourAddress (be32toh (*(uint32_t* )(buf + sizeof (SSUHeader) + 257)));
			uint16_t ourPort = be16toh (*(uint16_t *)(buf + sizeof (SSUHeader) + 261));
			LogPrint ("Our external address is ", ourAddress.to_string (), ":", ourPort);
		}
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
		*(uint32_t *)(payload + 257) =  htobe32 (address->host.to_v4 ().to_ulong ()); 
		
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
		*(uint32_t *)(signedData + 518) = m_Server->GetEndpoint ().address ().to_v4 ().to_ulong (); // our IP
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

	bool SSUSession::ProcessIntroKeyEncryptedMessage (uint8_t expectedPayloadType, i2p::data::RouterInfo& r, uint8_t * buf, size_t len)
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
					CreateAESKey (buf + sizeof (SSUHeader), m_SessionKey);	
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

	void SSUSession::FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len, uint8_t * aesKey, uint8_t * iv, uint8_t * macKey)
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

	void SSUSession::Decrypt (uint8_t * buf, size_t len, uint8_t * aesKey)
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

	bool SSUSession::Validate (uint8_t * buf, size_t len, uint8_t * macKey)
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

	void SSUSession::SendI2NPMessage (I2NPMessage * msg)
	{
		// TODO:
	}	

	SSUServer::SSUServer (boost::asio::io_service& service, int port):
		m_Endpoint (boost::asio::ip::udp::v4 (), port), m_Socket (service, m_Endpoint)
	{
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

	SSUSession * SSUServer::GetSession (i2p::data::RouterInfo * router)
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
}
}

