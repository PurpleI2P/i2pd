#include <string.h>
#include <stdlib.h>
#include "I2PEndian.h"
#include <boost/bind.hpp>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "base64.h"
#include "Log.h"
#include "Timestamp.h"
#include "CryptoConst.h"
#include "I2NPProtocol.h"
#include "RouterContext.h"
#include "Transports.h"
#include "NTCPSession.h"

using namespace i2p::crypto;

namespace i2p
{
namespace ntcp
{
	NTCPSession::NTCPSession (boost::asio::io_service& service, i2p::data::RouterInfo& in_RemoteRouterInfo): 
		m_Socket (service), m_TerminationTimer (service), m_IsEstablished (false), 
		m_RemoteRouterInfo (in_RemoteRouterInfo), m_ReceiveBufferOffset (0), m_NextMessage (nullptr),
		m_NumSentBytes (0), m_NumReceivedBytes (0)
	{		
		m_DHKeysPair = i2p::transports.GetNextDHKeysPair ();
	}
	
	NTCPSession::~NTCPSession ()
	{
		delete m_DHKeysPair;
		if (m_NextMessage)	
			i2p::DeleteI2NPMessage (m_NextMessage);
	}

	void NTCPSession::CreateAESKey (uint8_t * pubKey, uint8_t * aesKey)
	{
		CryptoPP::DH dh (elgp, elgg);
		uint8_t sharedKey[256];
		if (!dh.Agree (sharedKey, m_DHKeysPair->privateKey, pubKey))
		{    
		    LogPrint ("Couldn't create shared key");
			Terminate ();
			return;
		};

		if (sharedKey[0] & 0x80)
		{
			aesKey[0] = 0;
			memcpy (aesKey + 1, sharedKey, 31);
		}	
		else if (sharedKey[0])	
			memcpy (aesKey, sharedKey, 32);
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
			memcpy (aesKey, nonZero, 32);
		}
	}	

	void NTCPSession::Terminate ()
	{
		m_IsEstablished = false;
		m_Socket.close ();
		i2p::transports.RemoveNTCPSession (this);
		int numDelayed = 0;
		for (auto it :m_DelayedMessages)
		{	
			// try to send them again
			i2p::transports.SendMessage (m_RemoteRouterInfo.GetIdentHash (), it);
			numDelayed++;
		}	
		m_DelayedMessages.clear ();
		if (numDelayed > 0)
			LogPrint ("NTCP session ", numDelayed, " not sent");
		// TODO: notify tunnels
		
		delete this;
		LogPrint ("NTCP session terminated");
	}	

	void NTCPSession::Connected ()
	{
		LogPrint ("NTCP session connected");
		m_IsEstablished = true;

		SendTimeSyncMessage ();
		SendI2NPMessage (CreateDatabaseStoreMsg ()); // we tell immediately who we are		

		if (!m_DelayedMessages.empty ())
		{
			for (auto it :m_DelayedMessages)
				SendI2NPMessage (it);
			m_DelayedMessages.clear ();
		}	
	}	
		
	void NTCPSession::ClientLogin ()
	{
		// send Phase1
		const uint8_t * x = m_DHKeysPair->publicKey;
		memcpy (m_Phase1.pubKey, x, 256);
		CryptoPP::SHA256().CalculateDigest(m_Phase1.HXxorHI, x, 256);
		const uint8_t * ident = m_RemoteRouterInfo.GetIdentHash ();
		for (int i = 0; i < 32; i++)
			m_Phase1.HXxorHI[i] ^= ident[i];
		
		boost::asio::async_write (m_Socket, boost::asio::buffer (&m_Phase1, sizeof (m_Phase1)), boost::asio::transfer_all (),
        	boost::bind(&NTCPSession::HandlePhase1Sent, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}	

	void NTCPSession::ServerLogin ()
	{
		// receive Phase1
		boost::asio::async_read (m_Socket, boost::asio::buffer(&m_Phase1, sizeof (m_Phase1)),                     
			boost::bind(&NTCPSession::HandlePhase1Received, this, 
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}	
		
	void NTCPSession::HandlePhase1Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("Couldn't send Phase 1 message: ", ecode.message ());
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 1 sent: ", bytes_transferred);
			boost::asio::async_read (m_Socket, boost::asio::buffer(&m_Phase2, sizeof (m_Phase2)),                  
				boost::bind(&NTCPSession::HandlePhase2Received, this, 
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
		}	
	}	

	void NTCPSession::HandlePhase1Received (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("Phase 1 read error: ", ecode.message ());
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 1 received: ", bytes_transferred);
			// verify ident
			uint8_t digest[32];
			CryptoPP::SHA256().CalculateDigest(digest, m_Phase1.pubKey, 256);
			const uint8_t * ident = i2p::context.GetRouterInfo ().GetIdentHash ();
			for (int i = 0; i < 32; i++)
			{	
				if ((m_Phase1.HXxorHI[i] ^ ident[i]) != digest[i])
				{
					LogPrint ("Wrong ident");
					Terminate ();
					return;
				}	
			}	
			
			SendPhase2 ();
		}	
	}	

	void NTCPSession::SendPhase2 ()
	{
		const uint8_t * y = m_DHKeysPair->publicKey;
		memcpy (m_Phase2.pubKey, y, 256);
		uint8_t xy[512];
		memcpy (xy, m_Phase1.pubKey, 256);
		memcpy (xy + 256, y, 256);
		CryptoPP::SHA256().CalculateDigest(m_Phase2.encrypted.hxy, xy, 512); 
		uint32_t tsB = htobe32 (i2p::util::GetSecondsSinceEpoch ());
		m_Phase2.encrypted.timestamp = tsB;
		// TODO: fill filler

		uint8_t aesKey[32];
		CreateAESKey (m_Phase1.pubKey, aesKey);
		m_Encryption.SetKey (aesKey);
		m_Encryption.SetIV (y + 240);
		m_Decryption.SetKey (aesKey);
		m_Decryption.SetIV (m_Phase1.HXxorHI + 16);
		
		m_Encryption.Encrypt ((uint8_t *)&m_Phase2.encrypted, sizeof(m_Phase2.encrypted), (uint8_t *)&m_Phase2.encrypted);
		boost::asio::async_write (m_Socket, boost::asio::buffer (&m_Phase2, sizeof (m_Phase2)), boost::asio::transfer_all (),
        	boost::bind(&NTCPSession::HandlePhase2Sent, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, tsB));

	}	
		
	void NTCPSession::HandlePhase2Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB)
	{
		if (ecode)
        {
			LogPrint ("Couldn't send Phase 2 message: ", ecode.message ());
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 2 sent: ", bytes_transferred);
			boost::asio::async_read (m_Socket, boost::asio::buffer(&m_Phase3, sizeof (m_Phase3)),                   
				boost::bind(&NTCPSession::HandlePhase3Received, this, 
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, tsB));
		}	
	}	
		
	void NTCPSession::HandlePhase2Received (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("Phase 2 read error: ", ecode.message (), ". Wrong ident assumed");
			GetRemoteRouterInfo ().SetUnreachable (true); // this RouterInfo is not valid
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 2 received: ", bytes_transferred);
		
			uint8_t aesKey[32];
			CreateAESKey (m_Phase2.pubKey, aesKey);
			m_Decryption.SetKey (aesKey);
			m_Decryption.SetIV (m_Phase2.pubKey + 240);
			m_Encryption.SetKey (aesKey);
			m_Encryption.SetIV (m_Phase1.HXxorHI + 16);
			
			m_Decryption.Decrypt((uint8_t *)&m_Phase2.encrypted, sizeof(m_Phase2.encrypted), (uint8_t *)&m_Phase2.encrypted);
			// verify
			uint8_t xy[512], hxy[32];
			memcpy (xy, m_DHKeysPair->publicKey, 256);
			memcpy (xy + 256, m_Phase2.pubKey, 256);
			CryptoPP::SHA256().CalculateDigest(hxy, xy, 512); 
			if (memcmp (hxy, m_Phase2.encrypted.hxy, 32))
			{
				LogPrint ("Incorrect hash");
				Terminate ();
				return ;
			}	
			SendPhase3 ();
		}	
	}	

	void NTCPSession::SendPhase3 ()
	{
		m_Phase3.size = htons (sizeof (m_Phase3.ident));
		memcpy (&m_Phase3.ident, &i2p::context.GetRouterIdentity (), sizeof (m_Phase3.ident));		
		uint32_t tsA = htobe32 (i2p::util::GetSecondsSinceEpoch ());
		m_Phase3.timestamp = tsA;
		
		SignedData s;
		memcpy (s.x, m_Phase1.pubKey, 256);
		memcpy (s.y, m_Phase2.pubKey, 256);
		memcpy (s.ident, m_RemoteRouterInfo.GetIdentHash (), 32);
		s.tsA = tsA;
		s.tsB = m_Phase2.encrypted.timestamp;
		i2p::context.Sign ((uint8_t *)&s, sizeof (s), m_Phase3.signature);

		m_Encryption.Encrypt((uint8_t *)&m_Phase3, sizeof(m_Phase3), (uint8_t *)&m_Phase3);
		        
		boost::asio::async_write (m_Socket, boost::asio::buffer (&m_Phase3, sizeof (m_Phase3)), boost::asio::transfer_all (),
        	boost::bind(&NTCPSession::HandlePhase3Sent, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, tsA));				
	}	
		
	void NTCPSession::HandlePhase3Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA)
	{
		if (ecode)
        {
			LogPrint ("Couldn't send Phase 3 message: ", ecode.message ());
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 3 sent: ", bytes_transferred);
			boost::asio::async_read (m_Socket, boost::asio::buffer(&m_Phase4, sizeof (m_Phase4)),                  
				boost::bind(&NTCPSession::HandlePhase4Received, this, 
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, tsA));
		}	
	}	

	void NTCPSession::HandlePhase3Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB)
	{	
		if (ecode)
        {
			LogPrint ("Phase 3 read error: ", ecode.message ());
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 3 received: ", bytes_transferred);
			m_Decryption.Decrypt ((uint8_t *)&m_Phase3, sizeof(m_Phase3), (uint8_t *)&m_Phase3);
			m_RemoteRouterInfo.SetRouterIdentity (m_Phase3.ident);

			SignedData s;
			memcpy (s.x, m_Phase1.pubKey, 256);
			memcpy (s.y, m_Phase2.pubKey, 256);
			memcpy (s.ident, i2p::context.GetRouterInfo ().GetIdentHash (), 32);
			s.tsA = m_Phase3.timestamp;
			s.tsB = tsB;
			
			CryptoPP::DSA::PublicKey pubKey;
			pubKey.Initialize (dsap, dsaq, dsag, CryptoPP::Integer (m_RemoteRouterInfo.GetRouterIdentity ().signingKey, 128));
			CryptoPP::DSA::Verifier verifier (pubKey);
			if (!verifier.VerifyMessage ((uint8_t *)&s, sizeof(s), m_Phase3.signature, 40))
			{	
				LogPrint ("signature verification failed");
				Terminate ();
				return;
			}	

			SendPhase4 (tsB);
		}	
	}

	void NTCPSession::SendPhase4 (uint32_t tsB)
	{
		SignedData s;
		memcpy (s.x, m_Phase1.pubKey, 256);
		memcpy (s.y, m_Phase2.pubKey, 256);
		memcpy (s.ident, m_RemoteRouterInfo.GetIdentHash (), 32);
		s.tsA = m_Phase3.timestamp;
		s.tsB = tsB;
		i2p::context.Sign ((uint8_t *)&s, sizeof (s), m_Phase4.signature);
		m_Encryption.Encrypt ((uint8_t *)&m_Phase4, sizeof(m_Phase4), (uint8_t *)&m_Phase4);

		boost::asio::async_write (m_Socket, boost::asio::buffer (&m_Phase4, sizeof (m_Phase4)), boost::asio::transfer_all (),
        	boost::bind(&NTCPSession::HandlePhase4Sent, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}	

	void NTCPSession::HandlePhase4Sent (const boost::system::error_code& ecode,  std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("Couldn't send Phase 4 message: ", ecode.message ());
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 4 sent: ", bytes_transferred);
			Connected ();
			m_ReceiveBufferOffset = 0;
			m_NextMessage = nullptr;
			Receive ();
		}	
	}	
		
	void NTCPSession::HandlePhase4Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA)
	{
		if (ecode)
        {
			LogPrint ("Phase 4 read error: ", ecode.message ());
			GetRemoteRouterInfo ().SetUnreachable (true); // this router doesn't like us
			Terminate ();
		}
		else
		{	
			LogPrint ("Phase 4 received: ", bytes_transferred);
			m_Decryption.Decrypt((uint8_t *)&m_Phase4, sizeof(m_Phase4), (uint8_t *)&m_Phase4);

			// verify signature
			SignedData s;
			memcpy (s.x, m_Phase1.pubKey, 256);
			memcpy (s.y, m_Phase2.pubKey, 256);
			memcpy (s.ident, i2p::context.GetRouterInfo ().GetIdentHash (), 32);
			s.tsA = tsA;
			s.tsB = m_Phase2.encrypted.timestamp;

			CryptoPP::DSA::PublicKey pubKey;
			pubKey.Initialize (dsap, dsaq, dsag, CryptoPP::Integer (m_RemoteRouterInfo.GetRouterIdentity ().signingKey, 128));
			CryptoPP::DSA::Verifier verifier (pubKey);
			if (!verifier.VerifyMessage ((uint8_t *)&s, sizeof(s), m_Phase4.signature, 40))
			{	
				LogPrint ("signature verification failed");
				Terminate ();
				return;
			}	
			Connected ();
						
			m_ReceiveBufferOffset = 0;
			m_NextMessage = nullptr;
			Receive ();
		}
	}

	void NTCPSession::Receive ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_ReceiveBuffer + m_ReceiveBufferOffset, NTCP_MAX_MESSAGE_SIZE*2 -m_ReceiveBufferOffset),                
			boost::bind(&NTCPSession::HandleReceived, this, 
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}	
		
	void NTCPSession::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("Read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_NumReceivedBytes += bytes_transferred;
			m_ReceiveBufferOffset += bytes_transferred;

			if (m_ReceiveBufferOffset >= 16)
			{	
				uint8_t * nextBlock = m_ReceiveBuffer;
				while (m_ReceiveBufferOffset >= 16)
				{
					DecryptNextBlock (nextBlock); // 16 bytes
					nextBlock += 16;
					m_ReceiveBufferOffset -= 16;
				}	
				if (m_ReceiveBufferOffset > 0)
					memcpy (m_ReceiveBuffer, nextBlock, m_ReceiveBufferOffset);
			}	
			
			ScheduleTermination (); // reset termination timer
			Receive ();
		}	
	}	

	void NTCPSession::DecryptNextBlock (const uint8_t * encrypted) // 16 bytes
	{
		if (!m_NextMessage) // new message, header expected
		{	
			m_NextMessage = i2p::NewI2NPMessage ();
			m_NextMessageOffset = 0;
			
			m_Decryption.Decrypt (encrypted, m_NextMessage->buf);
			uint16_t dataSize = be16toh (*(uint16_t *)m_NextMessage->buf);
			if (dataSize)
			{
				// new message
				if (dataSize > NTCP_MAX_MESSAGE_SIZE)
				{
					LogPrint ("NTCP data size ", dataSize, " exceeds max size");
					i2p::DeleteI2NPMessage (m_NextMessage);
					m_NextMessage = nullptr;
					Terminate ();
					return;
				}
				m_NextMessageOffset += 16;
				m_NextMessage->offset = 2; // size field
				m_NextMessage->len = dataSize + 2; 
			}	
			else
			{	
				// timestamp
				LogPrint ("Timestamp");	
				i2p::DeleteI2NPMessage (m_NextMessage);
				m_NextMessage = nullptr;
				return;
			}	
		}	
		else // message continues
		{	
			m_Decryption.Decrypt (encrypted, m_NextMessage->buf + m_NextMessageOffset);
			m_NextMessageOffset += 16;
		}		
		
		if (m_NextMessageOffset >= m_NextMessage->len + 4) // +checksum
		{	
			// we have a complete I2NP message
			i2p::HandleI2NPMessage (m_NextMessage);	
			m_NextMessage = nullptr;
		}	
 	}	

	void NTCPSession::Send (i2p::I2NPMessage * msg)
	{
		uint8_t * sendBuffer;
		int len;

		if (msg)
		{	
			// regular I2NP
			if (msg->offset < 2)
			{
				LogPrint ("Malformed I2NP message");
				i2p::DeleteI2NPMessage (msg);
			}	
			sendBuffer = msg->GetBuffer () - 2; 
			len = msg->GetLength ();
			*((uint16_t *)sendBuffer) = htobe16 (len);
		}	
		else
		{
			// prepare timestamp
			sendBuffer = m_TimeSyncBuffer;
			len = 4;
			*((uint16_t *)sendBuffer) = 0;
			*((uint32_t *)(sendBuffer + 2)) = htobe32 (time (0));
		}	
		int rem = (len + 6) & 0x0F; // %16
		int padding = 0;
		if (rem > 0) padding = 16 - rem;
		// TODO: fill padding 
		m_Adler.CalculateDigest (sendBuffer + len + 2 + padding, sendBuffer, len + 2+ padding);

		int l = len + padding + 6;
		m_Encryption.Encrypt(sendBuffer, l, sendBuffer);	

		boost::asio::async_write (m_Socket, boost::asio::buffer (sendBuffer, l), boost::asio::transfer_all (),                      
        	boost::bind(&NTCPSession::HandleSent, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, msg));	
	}
		
	void NTCPSession::HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, i2p::I2NPMessage * msg)
	{		
		if (msg)
			i2p::DeleteI2NPMessage (msg);
		if (ecode)
        {
			LogPrint ("Couldn't send msg: ", ecode.message ());
			// we shouldn't call Terminate () here, because HandleReceive takes care
			// TODO: 'delete this' statement in Terminate () must be eliminated later
			// Terminate ();
		}
		else
		{	
			m_NumSentBytes += bytes_transferred;
			ScheduleTermination (); // reset termination timer
		}	
	}

	void NTCPSession::SendTimeSyncMessage ()
	{
		Send (nullptr);
	}	

	void NTCPSession::SendI2NPMessage (I2NPMessage * msg)
	{
		if (msg)
		{
			if (m_IsEstablished)
				Send (msg);
			else
				m_DelayedMessages.push_back (msg);	
		}	
	}	

	void NTCPSession::ScheduleTermination ()
	{
		m_TerminationTimer.cancel ();
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(NTCP_TERMINATION_TIMEOUT));
		m_TerminationTimer.async_wait (boost::bind (&NTCPSession::HandleTerminationTimer,
			this, boost::asio::placeholders::error));
	}

	void NTCPSession::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			LogPrint ("No activity fo ", NTCP_TERMINATION_TIMEOUT, " seconds");
			m_Socket.close ();
		}	
	}	
		
		
	NTCPClient::NTCPClient (boost::asio::io_service& service, const boost::asio::ip::address& address, 
		int port, i2p::data::RouterInfo& in_RouterInfo): 
		NTCPSession (service, in_RouterInfo),
		m_Endpoint (address, port)	
	{
		Connect ();
	}

	void NTCPClient::Connect ()
	{
		LogPrint ("Connecting to ", m_Endpoint.address ().to_string (),":",  m_Endpoint.port ());
		 GetSocket ().async_connect (m_Endpoint, boost::bind (&NTCPClient::HandleConnect,
			this, boost::asio::placeholders::error));
	}	

	void NTCPClient::HandleConnect (const boost::system::error_code& ecode)
	{
		if (ecode)
        {
			LogPrint ("Connect error: ", ecode.message ());
			GetRemoteRouterInfo ().SetUnreachable (true);
			Terminate ();
		}
		else
		{
			LogPrint ("Connected");
			ClientLogin ();
		}	
	}	

	void NTCPServerConnection::Connected ()
	{
		LogPrint ("NTCP server session connected");
		SetIsEstablished (true);
		i2p::transports.AddNTCPSession (this);

		SendTimeSyncMessage ();
		SendI2NPMessage (CreateDatabaseStoreMsg ()); // we tell immediately who we are		
	}	
}	
}	
