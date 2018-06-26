#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <vector>
#include "Log.h"
#include "I2PEndian.h"
#include "Crypto.h"
#include "Ed25519.h"
#include "Siphash.h"
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
		m_SessionRequestBuffer (nullptr), m_SessionCreatedBuffer (nullptr), m_SessionConfirmedBuffer (nullptr),
		m_NextReceivedBuffer (nullptr), m_NextSendBuffer (nullptr),
		m_ReceiveSequenceNumber (0), m_SendSequenceNumber (0)
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
		delete[] m_NextReceivedBuffer;
		delete[] m_NextSendBuffer;
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

	void NTCP2Session::CreateNonce (uint64_t seqn, uint8_t * nonce)
	{
		memset (nonce, 0, 4); 
		htole64buf (nonce + 4, seqn); 
	}

	void NTCP2Session::KeyDerivationFunction1 (const uint8_t * rs, const uint8_t * priv, const uint8_t * pub, uint8_t * derived)
	{
		static const uint8_t protocolNameHash[] = 
		{ 
			0x72, 0xe8, 0x42, 0xc5, 0x45, 0xe1, 0x80, 0x80, 0xd3, 0x9c, 0x44, 0x93, 0xbb, 0x91, 0xd7, 0xed, 
			0xf2, 0x28, 0x98, 0x17, 0x71, 0x21, 0x8c, 0x1f, 0x62, 0x4e, 0x20, 0x6f, 0x28, 0xd3, 0x2f, 0x71 
		}; // SHA256 ("Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256")
		static uint8_t h[64] = 
		{ 
			0x49, 0xff, 0x48, 0x3f, 0xc4, 0x04, 0xb9, 0xb2, 0x6b, 0x11, 0x94, 0x36, 0x72, 0xff, 0x05, 0xb5, 
			0x61, 0x27, 0x03, 0x31, 0xba, 0x89, 0xb8, 0xfc, 0x33, 0x15, 0x93, 0x87, 0x57, 0xdd, 0x3d, 0x1e 
		}; // SHA256 (protocolNameHash)
		memcpy (m_CK, protocolNameHash, 32); 
		// h = SHA256(h || rs)
		memcpy (h + 32, rs, 32); 
		SHA256 (h, 64, h); 
		// h = SHA256(h || pub)
		memcpy (h + 32, pub, 32); 
		SHA256 (h, 64, m_H); 
		// x25519 between rs and priv
		uint8_t inputKeyMaterial[32];
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->ScalarMul (rs, priv, inputKeyMaterial, ctx); // rs*priv
		BN_CTX_free (ctx);
		MixKey (inputKeyMaterial, derived);
	}

	void NTCP2Session::KeyDerivationFunction2 (const uint8_t * priv, const uint8_t * pub, const uint8_t * sessionRequest, size_t sessionRequestLen, uint8_t * derived)
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
		i2p::crypto::GetEd25519 ()->ScalarMul (pub, priv, inputKeyMaterial, ctx); 
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

	void NTCP2Session::KeyDerivationFunctionDataPhase ()
	{
		uint8_t tempKey[32]; unsigned int len;
		HMAC(EVP_sha256(), m_CK, 32, nullptr, 0, tempKey, &len); // temp_key = HMAC-SHA256(ck, zerolen)
		static uint8_t one[1] =  { 1 };
		HMAC(EVP_sha256(), tempKey, 32, one, 1, m_Kab, &len);  // k_ab = HMAC-SHA256(temp_key, byte(0x01)).
		m_Kab[32] = 2;
		HMAC(EVP_sha256(), tempKey, 32, m_Kab, 33, m_Kba, &len);  // k_ba = HMAC-SHA256(temp_key, k_ab || byte(0x02))
		static uint8_t ask[4] = { 'a', 's', 'k', 1 }, master[32];
		HMAC(EVP_sha256(), tempKey, 32, ask, 4, master, &len); // ask_master = HMAC-SHA256(temp_key, "ask" || byte(0x01))
		uint8_t h[39];
		memcpy (h, m_H, 32);
		memcpy (h + 32, "siphash", 7);
		HMAC(EVP_sha256(), master, 32, h, 39, tempKey, &len); // temp_key = HMAC-SHA256(ask_master, h || "siphash")
		HMAC(EVP_sha256(), tempKey, 32, one, 1, master, &len); // sip_master = HMAC-SHA256(temp_key, byte(0x01))  
		HMAC(EVP_sha256(), master, 32, nullptr, 0, tempKey, &len); // temp_key = HMAC-SHA256(sip_master, zerolen)
		HMAC(EVP_sha256(), tempKey, 32, one, 1, m_Sipkeysab, &len); // sipkeys_ab = HMAC-SHA256(temp_key, byte(0x01)).
		m_Sipkeysab[32] = 2;
		HMAC(EVP_sha256(), tempKey, 32, m_Sipkeysab, 33, m_Sipkeysba, &len); // sipkeys_ba = HMAC-SHA256(temp_key, sipkeys_ab || byte(0x02)) 
	}

	void NTCP2Session::CreateEphemeralKey (uint8_t * pub)
	{
		RAND_bytes (m_EphemeralPrivateKey, 32);
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->ScalarMulB (m_EphemeralPrivateKey, pub, ctx);
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
		KeyDerivationFunction1 (m_RemoteStaticKey, m_EphemeralPrivateKey, x, key);
		// fill options
		uint8_t options[32]; // actual options size is 16 bytes
		memset (options, 0, 16);
		options[1] = 2; // ver	
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
			// we receive first 64 bytes (32 Y, and 32 ChaCha/Poly frame) first
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_SessionCreatedBuffer, 64), boost::asio::transfer_all (),
				std::bind(&NTCP2Session::HandleSessionCreatedReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
		}
	}

	void NTCP2Session::HandleSessionRequestReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			// decrypt X
			i2p::crypto::CBCDecryption decryption;
			decryption.SetKey (i2p::context.GetIdentHash ());
			decryption.SetIV (i2p::context.GetNTCP2IV ());
			decryption.Decrypt (m_SessionRequestBuffer, 32, m_Y);
			decryption.GetIV (m_IV); // save IV for SessionCreated	
			// decryption key for next block
			uint8_t key[32];
			KeyDerivationFunction1 (m_Y, i2p::context.GetNTCP2StaticPrivateKey (), m_Y, key);
			// verify MAC and decrypt options block (32 bytes), use m_H as AD
			uint8_t nonce[12], options[16];
			memset (nonce, 0, 12); // set nonce to zero
			if (i2p::crypto::AEADChaCha20Poly1305 (m_SessionRequestBuffer + 32, 16, m_H, 32, key, nonce, options, 16, false)) // decrypt
			{
				if (options[1] == 2)
				{
					uint16_t paddingLen = bufbe16toh (options + 2);
					m_SessionRequestBufferLen = paddingLen + 64;
					// TODO: check tsA
					if (paddingLen > 0)
						boost::asio::async_read (m_Socket, boost::asio::buffer(m_SessionRequestBuffer + 64, paddingLen), boost::asio::transfer_all (),
						std::bind(&NTCP2Session::HandleSessionRequestPaddingReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
					else
						SendSessionCreated ();
				}
				else
				{
					LogPrint (eLogWarning, "NTCP2: SessionRequest version mismatch ", (int)options[1]);
					Terminate ();
				}
			}
			else
			{
				LogPrint (eLogWarning, "NTCP2: SessionRequest AEAD verification failed ");
				Terminate ();
			}	
		}
	}

	void NTCP2Session::HandleSessionRequestPaddingReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest padding read error: ", ecode.message ());
			Terminate ();
		}
		else
			SendSessionCreated ();
	}

	void NTCP2Session::SendSessionCreated ()
	{
		m_SessionCreatedBuffer = new uint8_t[287]; // TODO: determine actual max size
		// generate key pair (y)
		uint8_t y[32];
		CreateEphemeralKey (y);
		// encrypt Y
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (i2p::context.GetIdentHash ());
		encryption.SetIV (m_IV);
		encryption.Encrypt (y, 32, m_SessionCreatedBuffer);
		// encryption key for next block (m_K)
		KeyDerivationFunction2 (m_EphemeralPrivateKey, m_Y, m_SessionRequestBuffer, m_SessionRequestBufferLen, m_K);	
		auto paddingLen = rand () % (287 - 64);
		uint8_t options[16];
		memset (options, 0, 16);
		htobe16buf (options + 2, paddingLen); // padLen
		htobe32buf (options + 8, i2p::util::GetSecondsSinceEpoch ()); // tsB
		// sign and encrypt options, use m_H as AD			
		uint8_t nonce[12];
		memset (nonce, 0, 12); // set nonce to zero
		i2p::crypto::AEADChaCha20Poly1305 (options, 16, m_H, 32, m_K, nonce, m_SessionCreatedBuffer + 32, 32, true); // encrypt
		// fill padding
		RAND_bytes (m_SessionCreatedBuffer + 56, paddingLen);
		// send message		
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_SessionCreatedBuffer, paddingLen + 64), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionCreatedSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));	
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
			m_SessionCreatedBufferLen = 64;
			// decrypt Y
			i2p::crypto::CBCDecryption decryption;
			decryption.SetKey (GetRemoteIdentity ()->GetIdentHash ());
			decryption.SetIV (m_IV);
			decryption.Decrypt (m_SessionCreatedBuffer, 32, m_Y);
			// decryption key for next block (m_K)
			KeyDerivationFunction2 (m_EphemeralPrivateKey, m_Y, m_SessionRequestBuffer, m_SessionRequestBufferLen, m_K);
			// decrypt and verify MAC
			uint8_t payload[16];
			uint8_t nonce[12];
			memset (nonce, 0, 12); // set nonce to zero
			if (i2p::crypto::AEADChaCha20Poly1305 (m_SessionCreatedBuffer + 32, 16, m_H, 32, m_K, nonce, payload, 16, false)) // decrypt
			{		
				uint16_t paddingLen = bufbe16toh(payload + 2);
				LogPrint (eLogDebug, "NTCP2: padding length ", paddingLen);
				// TODO: check tsB
				if (paddingLen > 0)
				{
					boost::asio::async_read (m_Socket, boost::asio::buffer(m_SessionCreatedBuffer + 64, paddingLen), boost::asio::transfer_all (),
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
		memcpy (h + 32, m_SessionCreatedBuffer + 32, 32); // encrypted payload
		SHA256 (h, 64, h); 
		int paddingLength = m_SessionCreatedBufferLen - 64;
		if (paddingLength > 0)
		{
			std::vector<uint8_t> h1(paddingLength + 32);
			memcpy (h1.data (), h, 32);
			memcpy (h1.data () + 32, m_SessionCreatedBuffer + 64, paddingLength);
			SHA256 (h1.data (), paddingLength + 32, h); 
		}	
		// part1 48 bytes 
		m_SessionConfirmedBuffer = new uint8_t[2048]; // TODO: actual size
		uint8_t nonce[12];
		CreateNonce (1, nonce);
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
		uint8_t tmp[48];
		memcpy (tmp, m_SessionConfirmedBuffer, 48);
		memcpy (m_SessionConfirmedBuffer + 16, m_H, 32); // h || ciphertext
		SHA256 (m_SessionConfirmedBuffer + 16, m3p2Len + 32, m_H); //h = SHA256(h || ciphertext);
		memcpy (m_SessionConfirmedBuffer, tmp, 48);	

		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_SessionConfirmedBuffer, m3p2Len + 48), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionConfirmedSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleSessionConfirmedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		LogPrint (eLogDebug, "NTCP2: SessionConfirmed sent");
		KeyDerivationFunctionDataPhase ();
		memcpy (m_ReceiveIV, m_Sipkeysba + 16, 8); //Alice
		memcpy (m_SendIV, m_Sipkeysab + 16, 8); //Alice
		ReceiveLength ();

		// TODO: remove
		uint8_t pad[1024];	
		auto paddingLength = rand () % 1000;
		RAND_bytes (pad + 3, paddingLength);
		pad[0] = 254;
		htobe16buf (pad + 1, paddingLength);
		SendNextFrame (pad, paddingLength + 3);
	}

	void NTCP2Session::HandleSessionCreatedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		LogPrint (eLogDebug, "NTCP2: SessionCreated sent");
		Terminate (); // TODO
	}

	void NTCP2Session::ClientLogin ()
	{
		SendSessionRequest ();
	}

	void NTCP2Session::ServerLogin ()
	{
		m_SessionRequestBuffer = new uint8_t[287]; // 287 bytes max for now
		boost::asio::async_read (m_Socket, boost::asio::buffer(m_SessionRequestBuffer, 64), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionRequestReceived, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::ReceiveLength ()
	{
		boost::asio::async_read (m_Socket, boost::asio::buffer(&m_NextReceivedLen, 2), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleReceivedLength, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleReceivedLength (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: receive length read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			i2p::crypto::Siphash<8> (m_ReceiveIV, m_ReceiveIV, 8, m_Sipkeysba); // assume Alice TODO:
			m_NextReceivedLen = be16toh (m_NextReceivedLen ^ bufbe16toh(m_ReceiveIV));
			LogPrint (eLogDebug, "NTCP2: received length ", m_NextReceivedLen);
			delete[] m_NextReceivedBuffer;
			m_NextReceivedBuffer = new uint8_t[m_NextReceivedLen];
			Receive ();
		}
	}

	void NTCP2Session::Receive ()
	{
		boost::asio::async_read (m_Socket, boost::asio::buffer(m_NextReceivedBuffer, m_NextReceivedLen), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: receive read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			uint8_t nonce[12];
			CreateNonce (m_ReceiveSequenceNumber, nonce); m_ReceiveSequenceNumber++;
			uint8_t * decrypted = new uint8_t[m_NextReceivedLen];
			if (i2p::crypto::AEADChaCha20Poly1305 (m_NextReceivedBuffer, m_NextReceivedLen-16, nullptr, 0, m_Kba, nonce, decrypted, m_NextReceivedLen, false)) // decrypt. assume Alice TODO:
			{	
				LogPrint (eLogInfo, "NTCP2: received message decrypted");
				ProcessNextFrame (decrypted, m_NextReceivedLen-16);
				ReceiveLength ();
			}
			else
			{
				LogPrint (eLogWarning, "NTCP2: Received MAC verification failed ");
				Terminate ();
			}	
			delete[] decrypted;
		}
	}

	void NTCP2Session::ProcessNextFrame (const uint8_t * frame, size_t len)
	{
		size_t offset = 0;
		while (offset < len)
		{
			uint8_t blk = frame[offset];
			offset++;
			auto size = bufbe16toh (frame + offset);
			offset += 2;
			LogPrint (eLogDebug, "NTCP2: Block type ", (int)blk, " of size ", size);
			if (size > len)
			{
				LogPrint (eLogError, "NTCP2: Unexpected block length ", size);
				break;
			}
			offset += size;
		}
	}

	void NTCP2Session::SendNextFrame (const uint8_t * payload, size_t len)
	{
		uint8_t nonce[12];
		CreateNonce (m_SendSequenceNumber, nonce); m_SendSequenceNumber++;
		m_NextSendBuffer = new uint8_t[len + 16 + 2];
		i2p::crypto::AEADChaCha20Poly1305 (payload, len, nullptr, 0, m_Kab, nonce, m_NextSendBuffer + 2, len + 16, true); // encrypt. assume Alice TODO:	
		i2p::crypto::Siphash<8> (m_SendIV, m_SendIV, 8, m_Sipkeysab); // assume Alice TODO:
		htobuf16 (m_NextSendBuffer, bufbe16toh (m_SendIV) ^ htobe16(len + 16));
		LogPrint (eLogDebug, "NTCP2: sent length ", len + 16);

		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_NextSendBuffer, len + 16 + 2), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleNextFrameSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleNextFrameSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		delete[] m_NextSendBuffer; m_NextSendBuffer = nullptr;
		LogPrint (eLogDebug, "NTCP2: Next frame sent");
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

