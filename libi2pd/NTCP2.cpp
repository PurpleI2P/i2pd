#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <vector>
#include "Log.h"
#include "I2PEndian.h"
#include "Crypto.h"
#include "Ed25519.h"
#include "RouterContext.h"
#include "NTCP2.h"

namespace i2p
{
namespace transport
{
	NTCP2Session::NTCP2Session (NTCP2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter):
		TransportSession (in_RemoteRouter, 30), 
		m_Server (server), m_Socket (m_Server.GetService ()), 
		m_IsEstablished (false), m_IsTerminated (false),
		m_SessionRequestBuffer (nullptr), m_SessionCreatedBuffer (nullptr), m_SessionConfirmedBuffer (nullptr)
	{
		auto addr = in_RemoteRouter->GetNTCPAddress ();
		if (addr->ntcp2)
		{
			memcpy (m_RemoteStaticKey, addr->ntcp2->staticKey, 32);
			memcpy (m_IV, addr->ntcp2->iv, 16);
		}
		else
			LogPrint (eLogWarning, "NTCP2: Missing NTCP2 parameters"); 
	}

	NTCP2Session::~NTCP2Session ()
	{
		delete[] m_SessionRequestBuffer; 
		delete[] m_SessionCreatedBuffer;
		delete[] m_SessionConfirmedBuffer;
	}

	void NTCP2Session::Terminate ()
	{
		if (!m_IsTerminated)
		{
			m_IsTerminated = true;
			m_IsEstablished = false;
			m_Socket.close ();
			LogPrint (eLogDebug, "NTCP2: session terminated");
		}
	}

	void NTCP2Session::Done ()
	{
		m_Server.GetService ().post (std::bind (&NTCP2Session::Terminate, shared_from_this ()));
	}

	void NTCP2Session::MixKey (const uint8_t * inputKeyMaterial, uint8_t * derived)
	{
		// temp_key = HMAC-SHA256(ck, input_key_material)
		uint8_t tempKey[32]; unsigned int len;
		HMAC(EVP_sha256(), m_CK, 32, inputKeyMaterial, 32, tempKey, &len); 	
		// ck = HMAC-SHA256(temp_key, byte(0x01)) 
		static uint8_t one[1] =  { 1 };
		HMAC(EVP_sha256(), tempKey, 32, one, 1, m_CK, &len); 	
		// derived = HMAC-SHA256(temp_key, ck || byte(0x02))
		m_CK[32] = 2;
		HMAC(EVP_sha256(), tempKey, 32, m_CK, 33, derived, &len); 	
	}

	void NTCP2Session::KeyDerivationFunction1 (const uint8_t * rs, const uint8_t * pub, uint8_t * derived)
	{
		static const char protocolName[] = "Noise_XK_25519_ChaChaPoly_SHA256"; // 32 bytes
		uint8_t h[64];
		memcpy (m_CK, protocolName, 32);
		SHA256 ((const uint8_t *)protocolName, 32, h);	
		// h = SHA256(h || rs)
		memcpy (h + 32, rs, 32); 
		SHA256 (h, 64, h); 
		// h = SHA256(h || pub)
		memcpy (h + 32, pub, 32); 
		SHA256 (h, 64, m_H); 
		// x25519 between rs and priv
		uint8_t inputKeyMaterial[32];
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->ScalarMul (rs, m_ExpandedPrivateKey, inputKeyMaterial, ctx); // rs*priv
		BN_CTX_free (ctx);
		MixKey (inputKeyMaterial, derived);
	}

	void NTCP2Session::KeyDerivationFunction2 (const uint8_t * pub, const uint8_t * sessionRequest, size_t sessionRequestLen, uint8_t * derived)
	{
		uint8_t h[64];
		memcpy (h, m_H, 32);
		memcpy (h + 32, sessionRequest + 32, 32); // encrypted payload
		SHA256 (h, 64, h); 
		int paddingLength =  sessionRequestLen - 64;
		if (paddingLength > 0)
		{
			std::vector<uint8_t> h1(paddingLength + 32);
			memcpy (h1.data (), h, 32);
			memcpy (h1.data () + 32, sessionRequest + 64, paddingLength);
			SHA256 (h1.data (), paddingLength + 32, h); 
		}	
		memcpy (h + 32, pub, 32);
		SHA256 (h, 64, m_H);  

		// x25519 between remote pub and priv
		uint8_t inputKeyMaterial[32];
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->ScalarMul (pub, m_ExpandedPrivateKey, inputKeyMaterial, ctx); 
		BN_CTX_free (ctx);
		MixKey (inputKeyMaterial, derived);
	}

	void NTCP2Session::KeyDerivationFunction3 (const uint8_t * staticPrivKey, uint8_t * derived)
	{
		uint8_t inputKeyMaterial[32];
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->ScalarMul (m_Y, staticPrivKey, inputKeyMaterial, ctx); 
		BN_CTX_free (ctx);
		MixKey (inputKeyMaterial, derived);
	}

	void NTCP2Session::CreateEphemeralKey (uint8_t * pub)
	{
		uint8_t key[32];
		RAND_bytes (key, 32);
		i2p::crypto::Ed25519::ExpandPrivateKey (key, m_ExpandedPrivateKey);
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->ScalarMulB (m_ExpandedPrivateKey, pub, ctx);
		BN_CTX_free (ctx);
	}

	void NTCP2Session::SendSessionRequest ()
	{
		// create buffer and fill padding
		auto paddingLength = rand () % (287 - 64); // message length doesn't exceed 287 bytes
		m_SessionRequestBufferLen = paddingLength + 64;
		m_SessionRequestBuffer = new uint8_t[m_SessionRequestBufferLen];
		RAND_bytes (m_SessionRequestBuffer + 64, paddingLength);
		// generate key pair (X)
		uint8_t x[32];
		CreateEphemeralKey (x);
		// encrypt X
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (GetRemoteIdentity ()->GetIdentHash ());
		encryption.SetIV (m_IV);
		encryption.Encrypt (x, 32, m_SessionRequestBuffer);
		encryption.GetIV (m_IV); // save IV for SessionCreated	
		// encryption key for next block
		uint8_t key[32];
		KeyDerivationFunction1 (m_RemoteStaticKey, x, key);
		// fill options
		uint8_t options[32]; // actual options size is 16 bytes
		memset (options, 0, 16);
		htobe16buf (options, 2); // ver	
		htobe16buf (options + 2, paddingLength); // padLen
		htobe16buf (options + 4, i2p::context.GetRouterInfo ().GetBufferLen () + 20); // m3p2Len (RI header + RI + MAC for now) TODO: implement options
		// 2 bytes reserved
		htobe32buf (options + 8, i2p::util::GetSecondsSinceEpoch ()); // tsA
		// 4 bytes reserved
		// sign and encrypt options, use m_H as AD			
		uint8_t nonce[12];
		memset (nonce, 0, 12); // set nonce to zero
		i2p::crypto::AEADChaCha20Poly1305 (options, 16, m_H, 32, key, nonce, m_SessionRequestBuffer + 32, 32, true); // encrypt
		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_SessionRequestBuffer, m_SessionRequestBufferLen), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionRequestSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));		
	}	

	void NTCP2Session::HandleSessionRequestSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: couldn't send SessionRequest message: ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_SessionCreatedBuffer = new uint8_t[287]; // TODO: determine actual max size
			// we receive first 56 bytes (32 Y, and 24 ChaCha/Poly frame) first
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_SessionCreatedBuffer, 56), boost::asio::transfer_all (),
				std::bind(&NTCP2Session::HandleSessionCreatedReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
		}
	}

	void NTCP2Session::HandleSessionCreatedReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionCreated read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP2: SessionCreated received ", bytes_transferred);
			m_SessionCreatedBufferLen = 56;
			// decrypt Y
			i2p::crypto::CBCDecryption decryption;
			decryption.SetKey (GetRemoteIdentity ()->GetIdentHash ());
			decryption.SetIV (m_IV);
			decryption.Decrypt (m_SessionCreatedBuffer, 32, m_Y);
			// decryption key for next block (m_K)
			KeyDerivationFunction2 (m_Y, m_SessionRequestBuffer, m_SessionRequestBufferLen, m_K);
			// decrypt and verify MAC
			uint8_t payload[8];
			uint8_t nonce[12];
			memset (nonce, 0, 12); // set nonce to zero
			if (i2p::crypto::AEADChaCha20Poly1305 (m_SessionCreatedBuffer + 32, 8, m_H, 32, m_K, nonce, payload, 8, false)) // decrypt
			{		
				uint16_t paddingLen = bufbe16toh(payload);
				LogPrint (eLogDebug, "NTCP2: padding length ", paddingLen);
				if (paddingLen > 0)
				{
					boost::asio::async_read (m_Socket, boost::asio::buffer(m_SessionCreatedBuffer + 56, paddingLen), boost::asio::transfer_all (),
						std::bind(&NTCP2Session::HandleSessionCreatedPaddingReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
				}
				else
					SendSessionConfirmed ();
			}
			else
			{	
				LogPrint (eLogWarning, "NTCP2: SessionCreated MAC verification failed ");
				Terminate ();
			}	
		}
	}

	void NTCP2Session::HandleSessionCreatedPaddingReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionCreated padding read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_SessionCreatedBufferLen += bytes_transferred;
			SendSessionConfirmed ();
		}
	}

	void NTCP2Session::SendSessionConfirmed ()
	{
		// update AD
		uint8_t h[80];
		memcpy (h, m_H, 32);
		memcpy (h + 32, m_SessionCreatedBuffer + 32, 24); // encrypted payload
		SHA256 (h, 56, h); 
		int paddingLength = m_SessionCreatedBufferLen - 56;
		if (paddingLength > 0)
		{
			std::vector<uint8_t> h1(paddingLength + 32);
			memcpy (h1.data (), h, 32);
			memcpy (h1.data () + 32, m_SessionCreatedBuffer + 56, paddingLength);
			SHA256 (h1.data (), paddingLength + 32, h); 
		}	
		// part1 48 bytes 
		m_SessionConfirmedBuffer = new uint8_t[2048]; // TODO: actual size
		uint8_t nonce[12];
		memset (nonce, 0, 4); htole64buf (nonce + 4, 1); // set nonce to 1
		i2p::crypto::AEADChaCha20Poly1305 (i2p::context.GetNTCP2StaticPublicKey (), 32, h, 32, m_K, nonce, m_SessionConfirmedBuffer, 48, true); // encrypt
		// part 2
		// update AD again
		memcpy (h + 32, m_SessionConfirmedBuffer, 48);
		SHA256 (h, 80, m_H); 			

		size_t m3p2Len = i2p::context.GetRouterInfo ().GetBufferLen () + 20;
		std::vector<uint8_t> buf(m3p2Len - 16);
		buf[0] = 2; // block
		htobe16buf (buf.data () + 1, i2p::context.GetRouterInfo ().GetBufferLen () + 1); // flag + RI
		buf[3] = 0; // flag 	
		memcpy (buf.data () + 4, i2p::context.GetRouterInfo ().GetBuffer (), i2p::context.GetRouterInfo ().GetBufferLen ());
		uint8_t key[32];
		KeyDerivationFunction3 (i2p::context.GetNTCP2StaticPrivateKey (), key); 
		memset (nonce, 0, 12); // set nonce to 0 again
		i2p::crypto::AEADChaCha20Poly1305 (buf.data (), m3p2Len - 16, m_H, 32, key, nonce, m_SessionConfirmedBuffer + 48, m3p2Len, true); // encrypt

		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_SessionConfirmedBuffer, m3p2Len + 48), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionConfirmedSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleSessionConfirmedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		LogPrint (eLogDebug, "NTCP2: SessionConfirmed sent");
		Terminate (); // TODO
	}

	void NTCP2Session::ClientLogin ()
	{
		SendSessionRequest ();
	}

	NTCP2Server::NTCP2Server ():
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service)	
	{
	}

	NTCP2Server::~NTCP2Server ()
	{
		Stop ();
	}

	void NTCP2Server::Start ()
	{
		if (!m_IsRunning)
		{
			m_IsRunning = true;
			m_Thread = new std::thread (std::bind (&NTCP2Server::Run, this));
		}
	}

	void NTCP2Server::Stop ()
	{
		if (m_IsRunning)
		{
			m_IsRunning = false;
			m_Service.stop ();
			if (m_Thread)
			{
				m_Thread->join ();
				delete m_Thread;
				m_Thread = nullptr;
			}
		}
	}

	void NTCP2Server::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "NTCP2: runtime exception: ", ex.what ());
			}
		}
	}

	void NTCP2Server::Connect(const boost::asio::ip::address & address, uint16_t port, std::shared_ptr<NTCP2Session> conn)
	{
		LogPrint (eLogDebug, "NTCP2: Connecting to ", address ,":",  port);
		m_Service.post([this, address, port, conn]() 
			{
				conn->GetSocket ().async_connect (boost::asio::ip::tcp::endpoint (address, port), std::bind (&NTCP2Server::HandleConnect, this, std::placeholders::_1, conn));
			});
	}

	void NTCP2Server::HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn)
	{
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP2: Connect error ", ecode.message ());
			conn->Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP2: Connected to ", conn->GetSocket ().remote_endpoint ());
			conn->ClientLogin ();
		}
	}
}
}

