/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
*/

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <vector>
#include "Log.h"
#include "I2PEndian.h"
#include "Crypto.h"
#include "Siphash.h"
#include "RouterContext.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "NTCP2.h"
#include "HTTP.h"
#include "util.h"

namespace i2p
{
namespace transport
{
	NTCP2Establisher::NTCP2Establisher ():
		m_SessionRequestBuffer (nullptr), m_SessionCreatedBuffer (nullptr), m_SessionConfirmedBuffer (nullptr)
	{
	}

	NTCP2Establisher::~NTCP2Establisher ()
	{
		delete[] m_SessionRequestBuffer;
		delete[] m_SessionCreatedBuffer;
		delete[] m_SessionConfirmedBuffer;
	}

	void NTCP2Establisher::MixKey (const uint8_t * inputKeyMaterial)
	{
		i2p::crypto::HKDF (m_CK, inputKeyMaterial, 32, "", m_CK);
		// ck is m_CK[0:31], k is m_CK[32:63]
	}

	void NTCP2Establisher::MixHash (const uint8_t * buf, size_t len)
	{
		SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, m_H, 32);
		SHA256_Update (&ctx, buf, len);
		SHA256_Final (m_H, &ctx);
	}

	void NTCP2Establisher::KeyDerivationFunction1 (const uint8_t * pub, i2p::crypto::X25519Keys& priv, const uint8_t * rs, const uint8_t * epub)
	{
		static const uint8_t protocolNameHash[] =
		{
			0x72, 0xe8, 0x42, 0xc5, 0x45, 0xe1, 0x80, 0x80, 0xd3, 0x9c, 0x44, 0x93, 0xbb, 0x91, 0xd7, 0xed,
			0xf2, 0x28, 0x98, 0x17, 0x71, 0x21, 0x8c, 0x1f, 0x62, 0x4e, 0x20, 0x6f, 0x28, 0xd3, 0x2f, 0x71
		}; // SHA256 ("Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256")
		static const uint8_t hh[32] =
		{
			0x49, 0xff, 0x48, 0x3f, 0xc4, 0x04, 0xb9, 0xb2, 0x6b, 0x11, 0x94, 0x36, 0x72, 0xff, 0x05, 0xb5,
			0x61, 0x27, 0x03, 0x31, 0xba, 0x89, 0xb8, 0xfc, 0x33, 0x15, 0x93, 0x87, 0x57, 0xdd, 0x3d, 0x1e
		}; // SHA256 (protocolNameHash)
		memcpy (m_CK, protocolNameHash, 32);
		// h = SHA256(hh || rs)
		SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, hh, 32);
		SHA256_Update (&ctx, rs, 32);
		SHA256_Final (m_H, &ctx);
		// h = SHA256(h || epub)
		MixHash (epub, 32);
		// x25519 between pub and priv
		uint8_t inputKeyMaterial[32];
		priv.Agree (pub, inputKeyMaterial);
		MixKey (inputKeyMaterial);
	}

	void NTCP2Establisher::KDF1Alice ()
	{
		KeyDerivationFunction1 (m_RemoteStaticKey, *m_EphemeralKeys, m_RemoteStaticKey, GetPub ());
	}

	void NTCP2Establisher::KDF1Bob ()
	{
		KeyDerivationFunction1 (GetRemotePub (), i2p::context.GetStaticKeys (), i2p::context.GetNTCP2StaticPublicKey (), GetRemotePub ());
	}

	void NTCP2Establisher::KeyDerivationFunction2 (const uint8_t * sessionRequest, size_t sessionRequestLen, const uint8_t * epub)
	{
		MixHash (sessionRequest + 32, 32); // encrypted payload

		int paddingLength =  sessionRequestLen - 64;
		if (paddingLength > 0)
			MixHash (sessionRequest + 64, paddingLength);
		MixHash (epub, 32);

		// x25519 between remote pub and ephemaral priv
		uint8_t inputKeyMaterial[32];
		m_EphemeralKeys->Agree (GetRemotePub (), inputKeyMaterial);

		MixKey (inputKeyMaterial);
	}

	void NTCP2Establisher::KDF2Alice ()
	{
		KeyDerivationFunction2 (m_SessionRequestBuffer, m_SessionRequestBufferLen, GetRemotePub ());
	}

	void NTCP2Establisher::KDF2Bob ()
	{
		KeyDerivationFunction2 (m_SessionRequestBuffer, m_SessionRequestBufferLen, GetPub ());
	}

	void NTCP2Establisher::KDF3Alice ()
	{
		uint8_t inputKeyMaterial[32];
		i2p::context.GetStaticKeys ().Agree (GetRemotePub (), inputKeyMaterial);
		MixKey (inputKeyMaterial);
	}

	void NTCP2Establisher::KDF3Bob ()
	{
		uint8_t inputKeyMaterial[32];
		m_EphemeralKeys->Agree (m_RemoteStaticKey, inputKeyMaterial);
		MixKey (inputKeyMaterial);
	}

	void NTCP2Establisher::CreateEphemeralKey ()
	{
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
	}

	void NTCP2Establisher::CreateSessionRequestMessage ()
	{
		// create buffer and fill padding
		auto paddingLength = rand () % (287 - 64); // message length doesn't exceed 287 bytes
		m_SessionRequestBufferLen = paddingLength + 64;
		m_SessionRequestBuffer = new uint8_t[m_SessionRequestBufferLen];
		RAND_bytes (m_SessionRequestBuffer + 64, paddingLength);
		// encrypt X
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (m_RemoteIdentHash);
		encryption.SetIV (m_IV);
		encryption.Encrypt (GetPub (), 32, m_SessionRequestBuffer); // X
		encryption.GetIV (m_IV); // save IV for SessionCreated
		// encryption key for next block
		KDF1Alice ();
		// fill options
		uint8_t options[32]; // actual options size is 16 bytes
		memset (options, 0, 16);
		options[0] = i2p::context.GetNetID (); // network ID
		options[1] = 2; // ver
		htobe16buf (options + 2, paddingLength); // padLen
		// m3p2Len
		auto bufLen = i2p::context.GetRouterInfo ().GetBufferLen ();
		m3p2Len = bufLen + 4 + 16; // (RI header + RI + MAC for now) TODO: implement options
		htobe16buf (options + 4,  m3p2Len);
		// fill m3p2 payload (RouterInfo block)
		m_SessionConfirmedBuffer = new uint8_t[m3p2Len + 48]; // m3p1 is 48 bytes
		uint8_t * m3p2 = m_SessionConfirmedBuffer + 48;
		m3p2[0] = eNTCP2BlkRouterInfo; // block
		htobe16buf (m3p2 + 1, bufLen + 1); // flag + RI
		m3p2[3] = 0; // flag
		memcpy (m3p2 + 4, i2p::context.GetRouterInfo ().GetBuffer (), bufLen); // TODO: own RI should be protected by mutex
		// 2 bytes reserved
		htobe32buf (options + 8, i2p::util::GetSecondsSinceEpoch ()); // tsA
		// 4 bytes reserved
		// sign and encrypt options, use m_H as AD
		uint8_t nonce[12];
		memset (nonce, 0, 12); // set nonce to zero
		i2p::crypto::AEADChaCha20Poly1305 (options, 16, GetH (), 32, GetK (), nonce, m_SessionRequestBuffer + 32, 32, true); // encrypt
	}

	void NTCP2Establisher::CreateSessionCreatedMessage ()
	{
		auto paddingLen = rand () % (287 - 64);
		m_SessionCreatedBufferLen = paddingLen + 64;
		m_SessionCreatedBuffer = new uint8_t[m_SessionCreatedBufferLen];
		RAND_bytes (m_SessionCreatedBuffer + 64, paddingLen);
		// encrypt Y
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (i2p::context.GetIdentHash ());
		encryption.SetIV (m_IV);
		encryption.Encrypt (GetPub (), 32, m_SessionCreatedBuffer); // Y
		// encryption key for next block (m_K)
		KDF2Bob ();
		uint8_t options[16];
		memset (options, 0, 16);
		htobe16buf (options + 2, paddingLen); // padLen
		htobe32buf (options + 8, i2p::util::GetSecondsSinceEpoch ()); // tsB
		// sign and encrypt options, use m_H as AD
		uint8_t nonce[12];
		memset (nonce, 0, 12); // set nonce to zero
		i2p::crypto::AEADChaCha20Poly1305 (options, 16, GetH (), 32, GetK (), nonce, m_SessionCreatedBuffer + 32, 32, true); // encrypt

	}

	void NTCP2Establisher::CreateSessionConfirmedMessagePart1 (const uint8_t * nonce)
	{
		// update AD
		MixHash (m_SessionCreatedBuffer + 32, 32);	// encrypted payload
		int paddingLength = m_SessionCreatedBufferLen - 64;
		if (paddingLength > 0)
			MixHash (m_SessionCreatedBuffer + 64, paddingLength);

		// part1 48 bytes
		i2p::crypto::AEADChaCha20Poly1305 (i2p::context.GetNTCP2StaticPublicKey (), 32, GetH (), 32, GetK (), nonce, m_SessionConfirmedBuffer, 48, true); // encrypt
	}

	void NTCP2Establisher::CreateSessionConfirmedMessagePart2 (const uint8_t * nonce)
	{
		// part 2
		// update AD again
		MixHash (m_SessionConfirmedBuffer, 48);
		// encrypt m3p2, it must be filled in SessionRequest
		KDF3Alice ();
		uint8_t * m3p2 = m_SessionConfirmedBuffer + 48;
		i2p::crypto::AEADChaCha20Poly1305 (m3p2, m3p2Len - 16, GetH (), 32, GetK (), nonce, m3p2, m3p2Len, true); // encrypt
		// update h again
		MixHash (m3p2, m3p2Len); //h = SHA256(h || ciphertext)
	}

	bool NTCP2Establisher::ProcessSessionRequestMessage (uint16_t& paddingLen)
	{
		// decrypt X
		i2p::crypto::CBCDecryption decryption;
		decryption.SetKey (i2p::context.GetIdentHash ());
		decryption.SetIV (i2p::context.GetNTCP2IV ());
		decryption.Decrypt (m_SessionRequestBuffer, 32, GetRemotePub ());
		decryption.GetIV (m_IV); // save IV for SessionCreated
		// decryption key for next block
		KDF1Bob ();
		// verify MAC and decrypt options block (32 bytes), use m_H as AD
		uint8_t nonce[12], options[16];
		memset (nonce, 0, 12); // set nonce to zero
		if (i2p::crypto::AEADChaCha20Poly1305 (m_SessionRequestBuffer + 32, 16, GetH (), 32, GetK (), nonce, options, 16, false)) // decrypt
		{
			// options
			if (options[0] && options[0] != i2p::context.GetNetID ())
			{
				LogPrint (eLogWarning, "NTCP2: SessionRequest networkID ", (int)options[0], " mismatch. Expected ", i2p::context.GetNetID ());
				return false;
			}
			if (options[1] == 2) // ver is always 2
			{
				paddingLen = bufbe16toh (options + 2);
				m_SessionRequestBufferLen = paddingLen + 64;
				m3p2Len = bufbe16toh (options + 4);
				if (m3p2Len < 16)
				{
					LogPrint (eLogWarning, "NTCP2: SessionRequest m3p2len=", m3p2Len, " is too short");
					return false;
				}
				// check timestamp
				auto ts = i2p::util::GetSecondsSinceEpoch ();
				uint32_t tsA = bufbe32toh (options + 8);
				if (tsA < ts - NTCP2_CLOCK_SKEW || tsA > ts + NTCP2_CLOCK_SKEW)
				{
					LogPrint (eLogWarning, "NTCP2: SessionRequest time difference ", (int)(ts - tsA), " exceeds clock skew");
					return false;
				}
			}
			else
			{
				LogPrint (eLogWarning, "NTCP2: SessionRequest version mismatch ", (int)options[1]);
				return false;
			}
		}
		else
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest AEAD verification failed ");
			return false;
		}
		return true;
	}

	bool NTCP2Establisher::ProcessSessionCreatedMessage (uint16_t& paddingLen)
	{
		m_SessionCreatedBufferLen = 64;
		// decrypt Y
		i2p::crypto::CBCDecryption decryption;
		decryption.SetKey (m_RemoteIdentHash);
		decryption.SetIV (m_IV);
		decryption.Decrypt (m_SessionCreatedBuffer, 32, GetRemotePub ());
		// decryption key for next block (m_K)
		KDF2Alice ();
		// decrypt and verify MAC
		uint8_t payload[16];
		uint8_t nonce[12];
		memset (nonce, 0, 12); // set nonce to zero
		if (i2p::crypto::AEADChaCha20Poly1305 (m_SessionCreatedBuffer + 32, 16, GetH (), 32, GetK (), nonce, payload, 16, false)) // decrypt
		{
			// options
			paddingLen = bufbe16toh(payload + 2);
			// check timestamp
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			uint32_t tsB = bufbe32toh (payload + 8);
			if (tsB < ts - NTCP2_CLOCK_SKEW || tsB > ts + NTCP2_CLOCK_SKEW)
			{
				LogPrint (eLogWarning, "NTCP2: SessionCreated time difference ", (int)(ts - tsB), " exceeds clock skew");
				return false;
			}
		}
		else
		{
			LogPrint (eLogWarning, "NTCP2: SessionCreated AEAD verification failed ");
			return false;
		}
		return true;
	}

	bool NTCP2Establisher::ProcessSessionConfirmedMessagePart1 (const uint8_t * nonce)
	{
		// update AD
		MixHash (m_SessionCreatedBuffer + 32, 32);	// encrypted payload
		int paddingLength = m_SessionCreatedBufferLen - 64;
		if (paddingLength > 0)
			MixHash (m_SessionCreatedBuffer + 64, paddingLength);

		if (!i2p::crypto::AEADChaCha20Poly1305 (m_SessionConfirmedBuffer, 32, GetH (), 32, GetK (), nonce, m_RemoteStaticKey, 32, false)) // decrypt S
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed Part1 AEAD verification failed ");
			return false;
		}
		return true;
	}

	bool NTCP2Establisher::ProcessSessionConfirmedMessagePart2 (const uint8_t * nonce, uint8_t * m3p2Buf)
	{
		// update AD again
		MixHash (m_SessionConfirmedBuffer, 48);

		KDF3Bob ();
		if (i2p::crypto::AEADChaCha20Poly1305 (m_SessionConfirmedBuffer + 48, m3p2Len - 16, GetH (), 32, GetK (), nonce, m3p2Buf, m3p2Len - 16, false)) // decrypt
			// caclulate new h again for KDF data
			MixHash (m_SessionConfirmedBuffer + 48, m3p2Len); // h = SHA256(h || ciphertext)
		else
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed Part2 AEAD verification failed ");
			return false;
		}
		return true;
	}

	NTCP2Session::NTCP2Session (NTCP2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter):
		TransportSession (in_RemoteRouter, NTCP2_ESTABLISH_TIMEOUT),
		m_Server (server), m_Socket (m_Server.GetService ()),
		m_IsEstablished (false), m_IsTerminated (false),
		m_Establisher (new NTCP2Establisher),
		m_SendSipKey (nullptr), m_ReceiveSipKey (nullptr),
#if OPENSSL_SIPHASH
		m_SendMDCtx(nullptr), m_ReceiveMDCtx (nullptr),
#endif
		m_NextReceivedLen (0), m_NextReceivedBuffer (nullptr), m_NextSendBuffer (nullptr),
		m_ReceiveSequenceNumber (0), m_SendSequenceNumber (0), m_IsSending (false)
	{
		if (in_RemoteRouter) // Alice
		{
			m_Establisher->m_RemoteIdentHash = GetRemoteIdentity ()->GetIdentHash ();
			auto addr = in_RemoteRouter->GetNTCP2Address (true); // we need a published address
			if (addr)
			{
				memcpy (m_Establisher->m_RemoteStaticKey, addr->ntcp2->staticKey, 32);
				memcpy (m_Establisher->m_IV, addr->ntcp2->iv, 16);
			}
			else
				LogPrint (eLogWarning, "NTCP2: Missing NTCP2 parameters");
		}
	}

	NTCP2Session::~NTCP2Session ()
	{
		delete[] m_NextReceivedBuffer;
		delete[] m_NextSendBuffer;
#if OPENSSL_SIPHASH
		if (m_SendSipKey) EVP_PKEY_free (m_SendSipKey);
		if (m_ReceiveSipKey) EVP_PKEY_free (m_ReceiveSipKey);
		if (m_SendMDCtx) EVP_MD_CTX_destroy (m_SendMDCtx);
		if (m_ReceiveMDCtx) EVP_MD_CTX_destroy (m_ReceiveMDCtx);
#endif
	}

	void NTCP2Session::Terminate ()
	{
		if (!m_IsTerminated)
		{
			m_IsTerminated = true;
			m_IsEstablished = false;
			boost::system::error_code ec;
			m_Socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
			if (ec)
				LogPrint (eLogDebug, "NTCP2: Couldn't shutdown socket: ", ec.message ());
			m_Socket.close ();
			transports.PeerDisconnected (shared_from_this ());
			m_Server.RemoveNTCP2Session (shared_from_this ());
			m_SendQueue.clear ();
			LogPrint (eLogDebug, "NTCP2: session terminated");
		}
	}

	void NTCP2Session::TerminateByTimeout ()
	{
		SendTerminationAndTerminate (eNTCP2IdleTimeout);
	}

	void NTCP2Session::Done ()
	{
		m_Server.GetService ().post (std::bind (&NTCP2Session::Terminate, shared_from_this ()));
	}

	void NTCP2Session::Established ()
	{
		m_IsEstablished = true;
		m_Establisher.reset (nullptr);
		SetTerminationTimeout (NTCP2_TERMINATION_TIMEOUT);
		transports.PeerConnected (shared_from_this ());
	}

	void NTCP2Session::CreateNonce (uint64_t seqn, uint8_t * nonce)
	{
		memset (nonce, 0, 4);
		htole64buf (nonce + 4, seqn);
	}


	void NTCP2Session::KeyDerivationFunctionDataPhase ()
	{
		uint8_t k[64];
		i2p::crypto::HKDF (m_Establisher->GetCK (), nullptr, 0, "", k); // k_ab, k_ba = HKDF(ck, zerolen)
		memcpy (m_Kab, k, 32); memcpy (m_Kba, k + 32, 32);
		uint8_t master[32];
		i2p::crypto::HKDF (m_Establisher->GetCK (), nullptr, 0, "ask", master, 32); // ask_master = HKDF(ck, zerolen, info="ask")
		uint8_t h[39];
		memcpy (h, m_Establisher->GetH (), 32);
		memcpy (h + 32, "siphash", 7);
		i2p::crypto::HKDF (master, h, 39, "", master, 32); // sip_master = HKDF(ask_master, h || "siphash")
		i2p::crypto::HKDF (master, nullptr, 0, "", k); // sipkeys_ab, sipkeys_ba = HKDF(sip_master, zerolen)
		memcpy (m_Sipkeysab, k, 32); memcpy (m_Sipkeysba, k + 32, 32);
	}


	void NTCP2Session::SendSessionRequest ()
	{
		m_Establisher->CreateSessionRequestMessage ();
		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_Establisher->m_SessionRequestBuffer, m_Establisher->m_SessionRequestBufferLen), boost::asio::transfer_all (),
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
			m_Establisher->m_SessionCreatedBuffer = new uint8_t[287]; // TODO: determine actual max size
			// we receive first 64 bytes (32 Y, and 32 ChaCha/Poly frame) first
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_SessionCreatedBuffer, 64), boost::asio::transfer_all (),
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
			LogPrint (eLogDebug, "NTCP2: SessionRequest received ", bytes_transferred);
			uint16_t paddingLen = 0;
			if (m_Establisher->ProcessSessionRequestMessage (paddingLen))
			{
				if (paddingLen > 0)
				{
					if (paddingLen <= 287 - 64) // session request is 287 bytes max
					{
						boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_SessionRequestBuffer + 64, paddingLen), boost::asio::transfer_all (),
							std::bind(&NTCP2Session::HandleSessionRequestPaddingReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
					}
					else
					{
						LogPrint (eLogWarning, "NTCP2: SessionRequest padding length ", (int)paddingLen,  " is too long");
						Terminate ();
					}
				}
				else
					SendSessionCreated ();
			}
			else
				Terminate ();
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
		m_Establisher->CreateSessionCreatedMessage ();
		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_Establisher->m_SessionCreatedBuffer, m_Establisher->m_SessionCreatedBufferLen), boost::asio::transfer_all (),
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
			uint16_t paddingLen = 0;
			if (m_Establisher->ProcessSessionCreatedMessage (paddingLen))
			{
				if (paddingLen > 0)
				{
					if (paddingLen <= 287 - 64) // session created is 287 bytes max
					{
						boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_SessionCreatedBuffer + 64, paddingLen), boost::asio::transfer_all (),
							std::bind(&NTCP2Session::HandleSessionCreatedPaddingReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
					}
					else
					{
						LogPrint (eLogWarning, "NTCP2: SessionCreated padding length ", (int)paddingLen,  " is too long");
						Terminate ();
					}
				}
				else
					SendSessionConfirmed ();
			}
			else
				Terminate ();
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
			m_Establisher->m_SessionCreatedBufferLen += bytes_transferred;
			SendSessionConfirmed ();
		}
	}

	void NTCP2Session::SendSessionConfirmed ()
	{
		uint8_t nonce[12];
		CreateNonce (1, nonce); // set nonce to 1
		m_Establisher->CreateSessionConfirmedMessagePart1 (nonce);
		memset (nonce, 0, 12); // set nonce back to 0
		m_Establisher->CreateSessionConfirmedMessagePart2 (nonce);
		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_Establisher->m_SessionConfirmedBuffer, m_Establisher->m3p2Len + 48), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionConfirmedSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleSessionConfirmedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: couldn't send SessionConfirmed message: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP2: SessionConfirmed sent");
			KeyDerivationFunctionDataPhase ();
			// Alice data phase keys
			m_SendKey = m_Kab;
			m_ReceiveKey = m_Kba;
			SetSipKeys (m_Sipkeysab, m_Sipkeysba);
			memcpy (m_ReceiveIV.buf, m_Sipkeysba + 16, 8);
			memcpy (m_SendIV.buf, m_Sipkeysab + 16, 8);
			Established ();
			ReceiveLength ();

			// TODO: remove
			// m_SendQueue.push_back (CreateDeliveryStatusMsg (1));
			// SendQueue ();
		}
	}

	void NTCP2Session::HandleSessionCreatedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: couldn't send SessionCreated message: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP2: SessionCreated sent");
			m_Establisher->m_SessionConfirmedBuffer = new uint8_t[m_Establisher->m3p2Len + 48];
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_SessionConfirmedBuffer, m_Establisher->m3p2Len + 48), boost::asio::transfer_all (),
				std::bind(&NTCP2Session::HandleSessionConfirmedReceived , shared_from_this (), std::placeholders::_1, std::placeholders::_2));
		}
	}

	void NTCP2Session::HandleSessionConfirmedReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP2: SessionConfirmed received");
			// part 1
			uint8_t nonce[12];
			CreateNonce (1, nonce);
			if (m_Establisher->ProcessSessionConfirmedMessagePart1 (nonce))
			{
				// part 2
				std::vector<uint8_t> buf(m_Establisher->m3p2Len - 16); // -MAC
				memset (nonce, 0, 12); // set nonce to 0 again
				if (m_Establisher->ProcessSessionConfirmedMessagePart2 (nonce, buf.data ()))
				{
					KeyDerivationFunctionDataPhase ();
					// Bob data phase keys
					m_SendKey = m_Kba;
					m_ReceiveKey = m_Kab;
					SetSipKeys (m_Sipkeysba, m_Sipkeysab);
					memcpy (m_ReceiveIV.buf, m_Sipkeysab + 16, 8);
					memcpy (m_SendIV.buf, m_Sipkeysba + 16, 8);
					// payload
					// process RI
					if (buf[0] != eNTCP2BlkRouterInfo)
					{
						LogPrint (eLogWarning, "NTCP2: unexpected block ", (int)buf[0], " in SessionConfirmed");
						Terminate ();
						return;
					}
					auto size = bufbe16toh (buf.data () + 1);
					if (size > buf.size () - 3)
					{
						LogPrint (eLogError, "NTCP2: Unexpected RouterInfo size ", size, " in SessionConfirmed");
						Terminate ();
						return;
					}
					// TODO: check flag
					i2p::data::RouterInfo ri (buf.data () + 4, size - 1); // 1 byte block type + 2 bytes size + 1 byte flag
					if (ri.IsUnreachable ())
					{
						LogPrint (eLogError, "NTCP2: Signature verification failed in SessionConfirmed");
						SendTerminationAndTerminate (eNTCP2RouterInfoSignatureVerificationFail);
						return;
					}
					if (i2p::util::GetMillisecondsSinceEpoch () > ri.GetTimestamp () + i2p::data::NETDB_MIN_EXPIRATION_TIMEOUT*1000LL) // 90 minutes
					{
						LogPrint (eLogError, "NTCP2: RouterInfo is too old in SessionConfirmed");
						SendTerminationAndTerminate (eNTCP2Message3Error);
						return;
					}
					auto addr = ri.GetNTCP2Address (false); // any NTCP2 address
					if (!addr)
					{
						LogPrint (eLogError, "NTCP2: No NTCP2 address found in SessionConfirmed");
						Terminate ();
						return;
					}
					if (memcmp (addr->ntcp2->staticKey, m_Establisher->m_RemoteStaticKey, 32))
					{
						LogPrint (eLogError, "NTCP2: Static key mismatch in SessionConfirmed");
						SendTerminationAndTerminate (eNTCP2IncorrectSParameter);
						return;
					}
					i2p::data::netdb.PostI2NPMsg (CreateI2NPMessage (eI2NPDummyMsg, buf.data () + 3, size)); // TODO: should insert ri and not parse it twice
					// TODO: process options

					// ready to communicate
					auto existing = i2p::data::netdb.FindRouter (ri.GetRouterIdentity ()->GetIdentHash ()); // check if exists already
					SetRemoteIdentity (existing ? existing->GetRouterIdentity () : ri.GetRouterIdentity ());
					if (m_Server.AddNTCP2Session (shared_from_this (), true))
					{
						Established ();
						ReceiveLength ();
					}
					else
						Terminate ();
				}
				else
					Terminate ();
			}
			else
				Terminate ();
		}
	}

	void NTCP2Session::SetSipKeys (const uint8_t * sendSipKey, const uint8_t * receiveSipKey)
	{
#if OPENSSL_SIPHASH
		m_SendSipKey = EVP_PKEY_new_raw_private_key (EVP_PKEY_SIPHASH, nullptr, sendSipKey, 16);
		m_SendMDCtx = EVP_MD_CTX_create ();
		EVP_PKEY_CTX *ctx = nullptr;
		EVP_DigestSignInit (m_SendMDCtx, &ctx, nullptr, nullptr, m_SendSipKey);
		EVP_PKEY_CTX_ctrl (ctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, nullptr);

		m_ReceiveSipKey = EVP_PKEY_new_raw_private_key (EVP_PKEY_SIPHASH, nullptr, receiveSipKey, 16);
		m_ReceiveMDCtx = EVP_MD_CTX_create ();
		ctx = nullptr;
		EVP_DigestSignInit (m_ReceiveMDCtx, &ctx, NULL, NULL, m_ReceiveSipKey);
		EVP_PKEY_CTX_ctrl (ctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, nullptr);
#else
		m_SendSipKey = sendSipKey;
		m_ReceiveSipKey = receiveSipKey;
#endif
	}

	void NTCP2Session::ClientLogin ()
	{
		m_Establisher->CreateEphemeralKey ();
		SendSessionRequest ();
	}

	void NTCP2Session::ServerLogin ()
	{
		m_Establisher->CreateEphemeralKey ();
		m_Establisher->m_SessionRequestBuffer = new uint8_t[287]; // 287 bytes max for now
		boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_SessionRequestBuffer, 64), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionRequestReceived, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::ReceiveLength ()
	{
		if (IsTerminated ()) return;
		boost::asio::async_read (m_Socket, boost::asio::buffer(&m_NextReceivedLen, 2), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleReceivedLength, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleReceivedLength (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogWarning, "NTCP2: receive length read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
#if OPENSSL_SIPHASH
			EVP_DigestSignInit (m_ReceiveMDCtx, nullptr, nullptr, nullptr, nullptr);
			EVP_DigestSignUpdate (m_ReceiveMDCtx, m_ReceiveIV.buf, 8);
			size_t l = 8;
			EVP_DigestSignFinal (m_ReceiveMDCtx, m_ReceiveIV.buf, &l);
#else
			i2p::crypto::Siphash<8> (m_ReceiveIV.buf, m_ReceiveIV.buf, 8, m_ReceiveSipKey);
#endif
			// m_NextReceivedLen comes from the network in BigEndian
			m_NextReceivedLen = be16toh (m_NextReceivedLen) ^ le16toh (m_ReceiveIV.key);
			LogPrint (eLogDebug, "NTCP2: received length ", m_NextReceivedLen);
			if (m_NextReceivedLen >= 16)
			{
				if (m_NextReceivedBuffer) delete[] m_NextReceivedBuffer;
				m_NextReceivedBuffer = new uint8_t[m_NextReceivedLen];
				boost::system::error_code ec;
				size_t moreBytes = m_Socket.available(ec);
				if (!ec && moreBytes >= m_NextReceivedLen)
				{
					// read and process message immediately if available
					moreBytes = boost::asio::read (m_Socket, boost::asio::buffer(m_NextReceivedBuffer, m_NextReceivedLen), boost::asio::transfer_all (), ec);
					HandleReceived (ec, moreBytes);
				}
				else
					Receive ();
			}
			else
			{
				LogPrint (eLogError, "NTCP2: received length ", m_NextReceivedLen, " is too short");
				Terminate ();
			}
		}
	}

	void NTCP2Session::Receive ()
	{
		if (IsTerminated ()) return;
		boost::asio::async_read (m_Socket, boost::asio::buffer(m_NextReceivedBuffer, m_NextReceivedLen), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogWarning, "NTCP2: receive read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
			m_NumReceivedBytes += bytes_transferred + 2; // + length
			i2p::transport::transports.UpdateReceivedBytes (bytes_transferred);
			uint8_t nonce[12];
			CreateNonce (m_ReceiveSequenceNumber, nonce); m_ReceiveSequenceNumber++;
			if (i2p::crypto::AEADChaCha20Poly1305 (m_NextReceivedBuffer, m_NextReceivedLen-16, nullptr, 0, m_ReceiveKey, nonce, m_NextReceivedBuffer, m_NextReceivedLen, false))
			{
				LogPrint (eLogDebug, "NTCP2: received message decrypted");
				ProcessNextFrame (m_NextReceivedBuffer, m_NextReceivedLen-16);
				delete[] m_NextReceivedBuffer; m_NextReceivedBuffer = nullptr; // we don't need received buffer anymore
				ReceiveLength ();
			}
			else
			{
				LogPrint (eLogWarning, "NTCP2: Received AEAD verification failed ");
				SendTerminationAndTerminate (eNTCP2DataPhaseAEADFailure);
			}
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
			switch (blk)
			{
				case eNTCP2BlkDateTime:
					LogPrint (eLogDebug, "NTCP2: datetime");
				break;
				case eNTCP2BlkOptions:
					LogPrint (eLogDebug, "NTCP2: options");
				break;
				case eNTCP2BlkRouterInfo:
				{
					LogPrint (eLogDebug, "NTCP2: RouterInfo flag=", (int)frame[offset]);
					i2p::data::netdb.PostI2NPMsg (CreateI2NPMessage (eI2NPDummyMsg, frame + offset, size));
					break;
				}
				case eNTCP2BlkI2NPMessage:
				{
					LogPrint (eLogDebug, "NTCP2: I2NP");
					if (size > I2NP_MAX_MESSAGE_SIZE)
					{
						LogPrint (eLogError, "NTCP2: I2NP block is too long ", size);
						break;
					}
					auto nextMsg = NewI2NPMessage (size);
					nextMsg->Align (12); // for possible tunnel msg
					nextMsg->len = nextMsg->offset + size + 7; // 7 more bytes for full I2NP header
					memcpy (nextMsg->GetNTCP2Header (), frame + offset, size);
					nextMsg->FromNTCP2 ();
					m_Handler.PutNextMessage (nextMsg);
					break;
				}
				case eNTCP2BlkTermination:
					if (size >= 9)
					{
						LogPrint (eLogDebug, "NTCP2: termination. reason=", (int)(frame[offset + 8]));
						Terminate ();
					}
					else
						LogPrint (eLogWarning, "NTCP2: Unexpected termination block size ", size);
				break;
				case eNTCP2BlkPadding:
					LogPrint (eLogDebug, "NTCP2: padding");
				break;
				default:
					LogPrint (eLogWarning, "NTCP2: Unknown block type ", (int)blk);
			}
			offset += size;
		}
		m_Handler.Flush ();
	}

	void NTCP2Session::SetNextSentFrameLength (size_t frameLen, uint8_t * lengthBuf)
	{
		#if OPENSSL_SIPHASH
		EVP_DigestSignInit (m_SendMDCtx, nullptr, nullptr, nullptr, nullptr);
		EVP_DigestSignUpdate (m_SendMDCtx, m_SendIV.buf, 8);
		size_t l = 8;
		EVP_DigestSignFinal (m_SendMDCtx, m_SendIV.buf, &l);
#else
		i2p::crypto::Siphash<8> (m_SendIV.buf, m_SendIV.buf, 8, m_SendSipKey);
#endif
		// length must be in BigEndian
		htobe16buf (lengthBuf, frameLen ^ le16toh (m_SendIV.key));
		LogPrint (eLogDebug, "NTCP2: sent length ", frameLen);
	}

	void NTCP2Session::SendI2NPMsgs (std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		if (msgs.empty () || IsTerminated ()) return;

		size_t totalLen = 0;
		std::vector<std::pair<uint8_t *, size_t> > encryptBufs;
		std::vector<boost::asio::const_buffer> bufs;
		std::shared_ptr<I2NPMessage> first;
		uint8_t * macBuf = nullptr;
		for (auto& it: msgs)
		{
			it->ToNTCP2 ();
			auto buf = it->GetNTCP2Header ();
			auto len = it->GetNTCP2Length ();
			// block header
			buf -= 3;
			buf[0] = eNTCP2BlkI2NPMessage; // blk
			htobe16buf (buf + 1, len); // size
			len += 3;
			totalLen += len;
			encryptBufs.push_back ( {buf, len} );
			if (&it == &msgs.front ()) // first message
			{
				// allocate two bytes for length
				buf -= 2; len += 2;
				first = it;
			}
			if (&it == &msgs.back () && it->len + 16 < it->maxLen) // last message
			{
				// if it's long enough we add padding and MAC to it
				// create padding block
				auto paddingLen = CreatePaddingBlock (totalLen, buf + len, it->maxLen - it->len - 16);
				if (paddingLen)
				{
					encryptBufs.push_back ( {buf + len, paddingLen} );
					len += paddingLen;
					totalLen += paddingLen;
				}
				macBuf = buf + len;
				// allocate 16 bytes for MAC
				len += 16;
			}

			bufs.push_back (boost::asio::buffer (buf, len));
		}

		if (!macBuf) // last block was not enough for MAC
		{
			// allocate send buffer
			m_NextSendBuffer = new uint8_t[287]; // can be any size > 16, we just allocate 287 frequently
			// crate padding block
			auto paddingLen = CreatePaddingBlock (totalLen, m_NextSendBuffer, 287 - 16);
			// and padding block to encrypt and send
			if (paddingLen)
				encryptBufs.push_back ( {m_NextSendBuffer, paddingLen} );
			bufs.push_back (boost::asio::buffer (m_NextSendBuffer, paddingLen + 16));
			macBuf = m_NextSendBuffer + paddingLen;
			totalLen += paddingLen;
		}
		uint8_t nonce[12];
		CreateNonce (m_SendSequenceNumber, nonce); m_SendSequenceNumber++;
		i2p::crypto::AEADChaCha20Poly1305Encrypt (encryptBufs, m_SendKey, nonce, macBuf); // encrypt buffers
		SetNextSentFrameLength (totalLen + 16, first->GetNTCP2Header () - 5); // frame length right before first block

		// send buffers
		m_IsSending = true;
		boost::asio::async_write (m_Socket, bufs, boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleI2NPMsgsSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2, msgs));
	}

	void NTCP2Session::HandleI2NPMsgsSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		HandleNextFrameSent (ecode, bytes_transferred);
		// msgs get destroyed here
	}

	void NTCP2Session::EncryptAndSendNextBuffer (size_t payloadLen)
	{
		if (IsTerminated ())
		{
			delete[] m_NextSendBuffer; m_NextSendBuffer = nullptr;
			return;
		}
		// encrypt
		uint8_t nonce[12];
		CreateNonce (m_SendSequenceNumber, nonce); m_SendSequenceNumber++;
		i2p::crypto::AEADChaCha20Poly1305Encrypt ({ {m_NextSendBuffer + 2, payloadLen} }, m_SendKey, nonce, m_NextSendBuffer + payloadLen + 2);
		SetNextSentFrameLength (payloadLen + 16, m_NextSendBuffer);
		// send
		m_IsSending = true;
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_NextSendBuffer, payloadLen + 16 + 2), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleNextFrameSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleNextFrameSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		m_IsSending = false;
		delete[] m_NextSendBuffer; m_NextSendBuffer = nullptr;

		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogWarning, "NTCP2: Couldn't send frame ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
			m_NumSentBytes += bytes_transferred;
			i2p::transport::transports.UpdateSentBytes (bytes_transferred);
			LogPrint (eLogDebug, "NTCP2: Next frame sent ", bytes_transferred);
			SendQueue ();
		}
	}

	void NTCP2Session::SendQueue ()
	{
		if (!m_SendQueue.empty ())
		{
			std::vector<std::shared_ptr<I2NPMessage> > msgs;
			size_t s = 0;
			while (!m_SendQueue.empty ())
			{
				auto msg = m_SendQueue.front ();
				size_t len = msg->GetNTCP2Length ();
				if (s + len + 3 <= NTCP2_UNENCRYPTED_FRAME_MAX_SIZE) // 3 bytes block header
				{
					msgs.push_back (msg);
					s += (len + 3);
					m_SendQueue.pop_front ();
				}
				else if (len + 3 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE)
				{
					LogPrint (eLogError, "NTCP2: I2NP message of size ", len, " can't be sent. Dropped");
					m_SendQueue.pop_front ();
				}
				else
					break;
			}
			SendI2NPMsgs (msgs);
		}
	}

	size_t NTCP2Session::CreatePaddingBlock (size_t msgLen, uint8_t * buf, size_t len)
	{
		if (len < 3) return 0;
		len -= 3;
		if (msgLen < 256) msgLen = 256; // for short message padding should not be always zero
		size_t paddingSize = (msgLen*NTCP2_MAX_PADDING_RATIO)/100;
		if (msgLen + paddingSize + 3 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE) paddingSize = NTCP2_UNENCRYPTED_FRAME_MAX_SIZE - msgLen -3;
		if (paddingSize > len) paddingSize = len;
		if (paddingSize) paddingSize = rand () % paddingSize;
		buf[0] = eNTCP2BlkPadding; // blk
		htobe16buf (buf + 1, paddingSize); // size
		memset (buf + 3, 0, paddingSize);
		return paddingSize + 3;
	}

	void NTCP2Session::SendRouterInfo ()
	{
		if (!IsEstablished ()) return;
		auto riLen = i2p::context.GetRouterInfo ().GetBufferLen ();
		size_t payloadLen = riLen + 4; // 3 bytes block header + 1 byte RI flag
		m_NextSendBuffer = new uint8_t[payloadLen + 16 + 2 + 64]; // up to 64 bytes padding
		m_NextSendBuffer[2] = eNTCP2BlkRouterInfo;
		htobe16buf (m_NextSendBuffer + 3, riLen + 1); // size
		m_NextSendBuffer[5] = 0; // flag
		memcpy (m_NextSendBuffer + 6, i2p::context.GetRouterInfo ().GetBuffer (), riLen);
		// padding block
		auto paddingSize = CreatePaddingBlock (payloadLen, m_NextSendBuffer + 2 + payloadLen, 64);
		payloadLen += paddingSize;
		// encrypt and send
		EncryptAndSendNextBuffer (payloadLen);
	}

	void NTCP2Session::SendTermination (NTCP2TerminationReason reason)
	{
		if (!m_SendKey || !m_SendSipKey) return;
		m_NextSendBuffer = new uint8_t[49]; // 49 = 12 bytes message + 16 bytes MAC + 2 bytes size + up to 19 padding block
		// termination block
		m_NextSendBuffer[2] = eNTCP2BlkTermination;
		m_NextSendBuffer[3] = 0; m_NextSendBuffer[4] = 9; // 9 bytes block size
		htobe64buf (m_NextSendBuffer + 5, m_ReceiveSequenceNumber);
		m_NextSendBuffer[13] = (uint8_t)reason;
		// padding block
		auto paddingSize = CreatePaddingBlock (12, m_NextSendBuffer + 14, 19);
		// encrypt and send
		EncryptAndSendNextBuffer (paddingSize + 12);
	}

	void NTCP2Session::SendTerminationAndTerminate (NTCP2TerminationReason reason)
	{
		SendTermination (reason);
		m_Server.GetService ().post (std::bind (&NTCP2Session::Terminate, shared_from_this ())); // let termination message go
	}

	void NTCP2Session::SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		m_Server.GetService ().post (std::bind (&NTCP2Session::PostI2NPMessages, shared_from_this (), msgs));
	}

	void NTCP2Session::PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		if (m_IsTerminated) return;
		for (auto it: msgs)
			m_SendQueue.push_back (it);
		if (!m_IsSending)
			SendQueue ();
		else if (m_SendQueue.size () > NTCP2_MAX_OUTGOING_QUEUE_SIZE)
		{
			LogPrint (eLogWarning, "NTCP2: outgoing messages queue size to ", 
			   	GetIdentHashBase64(), " exceeds ",  NTCP2_MAX_OUTGOING_QUEUE_SIZE);
			Terminate ();
		}
	}

	void NTCP2Session::SendLocalRouterInfo ()
	{
		if (!IsOutgoing ()) // we send it in SessionConfirmed
			m_Server.GetService ().post (std::bind (&NTCP2Session::SendRouterInfo, shared_from_this ()));
	}

	NTCP2Server::NTCP2Server ():
		RunnableServiceWithWork ("NTCP2"), m_TerminationTimer (GetService ()),
		 m_ProxyType(eNoProxy), m_Resolver(GetService ())
	{
	}

	NTCP2Server::~NTCP2Server ()
	{
		Stop ();
	}

	void NTCP2Server::Start ()
	{
		if (!IsRunning ())
		{
			StartIOService ();
			if(UsingProxy())
			{
				LogPrint(eLogInfo, "NTCP2: Using proxy to connect to peers");
				// TODO: resolve proxy until it is resolved
				boost::asio::ip::tcp::resolver::query q(m_ProxyAddress, std::to_string(m_ProxyPort));
				boost::system::error_code e;
				auto itr = m_Resolver.resolve(q, e);
				if(e)
					LogPrint(eLogError, "NTCP2: Failed to resolve proxy ", e.message());
				else
				{
					m_ProxyEndpoint.reset (new boost::asio::ip::tcp::endpoint(*itr));
					if (m_ProxyEndpoint)
						LogPrint(eLogDebug, "NTCP2: m_ProxyEndpoint ", *m_ProxyEndpoint);
				}
			}
			else
			{
				LogPrint(eLogInfo, "NTCP2: Proxy is not used");
				auto& addresses = context.GetRouterInfo ().GetAddresses ();
				for (const auto& address: addresses)
				{
					if (!address) continue;
					if (address->IsPublishedNTCP2 ())
					{
						if (address->host.is_v4())
						{
							try
							{
								m_NTCP2Acceptor.reset (new boost::asio::ip::tcp::acceptor (GetService (), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), address->port)));
							}
							catch ( std::exception & ex )
							{
								LogPrint(eLogError, "NTCP2: Failed to bind to v4 port ", address->port, ex.what());
								ThrowFatal ("Unable to start IPv4 NTCP2 transport at port ", address->port, ": ", ex.what ());
								continue;
							}

							LogPrint (eLogInfo, "NTCP2: Start listening v4 TCP port ", address->port);
							auto conn = std::make_shared<NTCP2Session>(*this);
							m_NTCP2Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAccept, this, conn, std::placeholders::_1));
						}
						else if (address->host.is_v6() && context.SupportsV6 ())
						{
							m_NTCP2V6Acceptor.reset (new boost::asio::ip::tcp::acceptor (GetService ()));
							try
							{
								m_NTCP2V6Acceptor->open (boost::asio::ip::tcp::v6());
								m_NTCP2V6Acceptor->set_option (boost::asio::ip::v6_only (true));
								m_NTCP2V6Acceptor->set_option (boost::asio::socket_base::reuse_address (true));
								m_NTCP2V6Acceptor->bind (boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), address->port));
								m_NTCP2V6Acceptor->listen ();

								LogPrint (eLogInfo, "NTCP2: Start listening v6 TCP port ", address->port);
								auto conn = std::make_shared<NTCP2Session> (*this);
								m_NTCP2V6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAcceptV6, this, conn, std::placeholders::_1));
							}
							catch ( std::exception & ex )
							{
								LogPrint(eLogError, "NTCP2: failed to bind to v6 port ", address->port, ": ", ex.what());
								ThrowFatal ("Unable to start IPv6 NTCP2 transport at port ", address->port, ": ", ex.what ());
								continue;
							}
						}
					}
				}
			}
			ScheduleTermination ();
		}
	}

	void NTCP2Server::Stop ()
	{
		{
			// we have to copy it because Terminate changes m_NTCP2Sessions
			auto ntcpSessions = m_NTCP2Sessions;
			for (auto& it: ntcpSessions)
				it.second->Terminate ();
			for (auto& it: m_PendingIncomingSessions)
				it->Terminate ();
		}
		m_NTCP2Sessions.clear ();

		if (IsRunning ())
		{
			m_TerminationTimer.cancel ();
			m_ProxyEndpoint = nullptr;
		}
		StopIOService ();
	}

	bool NTCP2Server::AddNTCP2Session (std::shared_ptr<NTCP2Session> session, bool incoming)
	{
		if (!session) return false;
		if (incoming)
			m_PendingIncomingSessions.remove (session);
		if (!session->GetRemoteIdentity ()) return false;
		auto& ident = session->GetRemoteIdentity ()->GetIdentHash ();
		auto it = m_NTCP2Sessions.find (ident);
		if (it != m_NTCP2Sessions.end ())
		{
			LogPrint (eLogWarning, "NTCP2: session to ", ident.ToBase64 (), " already exists");
			if (incoming)
				// replace by new session
				it->second->Terminate ();
			else
				return false;
		}
		m_NTCP2Sessions.insert (std::make_pair (ident, session));
		return true;
	}

	void NTCP2Server::RemoveNTCP2Session (std::shared_ptr<NTCP2Session> session)
	{
		if (session && session->GetRemoteIdentity ())
			m_NTCP2Sessions.erase (session->GetRemoteIdentity ()->GetIdentHash ());
	}

	std::shared_ptr<NTCP2Session> NTCP2Server::FindNTCP2Session (const i2p::data::IdentHash& ident)
	{
		auto it = m_NTCP2Sessions.find (ident);
		if (it != m_NTCP2Sessions.end ())
			return it->second;
		return nullptr;
	}

	void NTCP2Server::Connect(const boost::asio::ip::address & address, uint16_t port, std::shared_ptr<NTCP2Session> conn)
	{
		LogPrint (eLogDebug, "NTCP2: Connecting to ", address ,":",  port);
		GetService ().post([this, address, port, conn]()
			{
				if (this->AddNTCP2Session (conn))
				{
					auto timer = std::make_shared<boost::asio::deadline_timer>(GetService ());
					auto timeout = NTCP2_CONNECT_TIMEOUT * 5;
					conn->SetTerminationTimeout(timeout * 2);
					timer->expires_from_now (boost::posix_time::seconds(timeout));
					timer->async_wait ([conn, timeout](const boost::system::error_code& ecode)
					{
						if (ecode != boost::asio::error::operation_aborted)
						{
							LogPrint (eLogInfo, "NTCP2: Not connected in ", timeout, " seconds");
							if (conn->GetRemoteIdentity ())
								i2p::data::netdb.SetUnreachable (conn->GetRemoteIdentity ()->GetIdentHash (), true);
							conn->Terminate ();
						}
					});
					conn->GetSocket ().async_connect (boost::asio::ip::tcp::endpoint (address, port), std::bind (&NTCP2Server::HandleConnect, this, std::placeholders::_1, conn, timer));
				}
				else
					conn->Terminate ();
			});
	}

	void NTCP2Server::HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn, std::shared_ptr<boost::asio::deadline_timer> timer)
	{
		timer->cancel ();
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

	void NTCP2Server::HandleAccept (std::shared_ptr<NTCP2Session> conn, const boost::system::error_code& error)
	{
		if (!error)
		{
			boost::system::error_code ec;
			auto ep = conn->GetSocket ().remote_endpoint(ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "NTCP2: Connected from ", ep);
				if (conn)
				{
					conn->ServerLogin ();
					m_PendingIncomingSessions.push_back (conn);
					conn = nullptr;
				}
			}
			else
				LogPrint (eLogError, "NTCP2: Connected from error ", ec.message ());
		}
		else
			LogPrint (eLogError, "NTCP2: Accept error ", error.message ());

		if (error != boost::asio::error::operation_aborted)
		{
			if (!conn) // connection is used, create new one
				conn = std::make_shared<NTCP2Session> (*this);
			else // reuse failed
				conn->Close ();
			m_NTCP2Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAccept, this,
				conn, std::placeholders::_1));
		}
	}

	void NTCP2Server::HandleAcceptV6 (std::shared_ptr<NTCP2Session> conn, const boost::system::error_code& error)
	{
		if (!error)
		{
			boost::system::error_code ec;
			auto ep = conn->GetSocket ().remote_endpoint(ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "NTCP2: Connected from ", ep);
				if (conn)
				{
					conn->ServerLogin ();
					m_PendingIncomingSessions.push_back (conn);
				}
			}
			else
				LogPrint (eLogError, "NTCP2: Connected from error ", ec.message ());
		}

		if (error != boost::asio::error::operation_aborted)
		{
			conn = std::make_shared<NTCP2Session> (*this);
			m_NTCP2V6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAcceptV6, this,
				conn, std::placeholders::_1));
		}
	}

	void NTCP2Server::ScheduleTermination ()
	{
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(NTCP2_TERMINATION_CHECK_TIMEOUT));
		m_TerminationTimer.async_wait (std::bind (&NTCP2Server::HandleTerminationTimer,
			this, std::placeholders::_1));
	}

	void NTCP2Server::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			// established
			for (auto& it: m_NTCP2Sessions)
				if (it.second->IsTerminationTimeoutExpired (ts))
				{
					auto session = it.second;
					LogPrint (eLogDebug, "NTCP2: No activity for ", session->GetTerminationTimeout (), " seconds");
					session->TerminateByTimeout (); // it doesn't change m_NTCP2Session right a way
				}
			// pending
			for (auto it = m_PendingIncomingSessions.begin (); it != m_PendingIncomingSessions.end ();)
			{
				if ((*it)->IsEstablished () || (*it)->IsTerminationTimeoutExpired (ts))
				{
					(*it)->Terminate ();
					it = m_PendingIncomingSessions.erase (it); // established of expired
				}
				else if ((*it)->IsTerminated ())
					it = m_PendingIncomingSessions.erase (it); // already terminated
				else
					it++;
			}

			ScheduleTermination ();
		}
	}

	void NTCP2Server::ConnectWithProxy (const std::string& host, uint16_t port, RemoteAddressType addrtype, std::shared_ptr<NTCP2Session> conn)
	{
		if(!m_ProxyEndpoint) return;
		GetService().post([this, host, port, addrtype, conn]() {
			if (this->AddNTCP2Session (conn))
			{

				auto timer = std::make_shared<boost::asio::deadline_timer>(GetService());
				auto timeout = NTCP_CONNECT_TIMEOUT * 5;
				conn->SetTerminationTimeout(timeout * 2);
				timer->expires_from_now (boost::posix_time::seconds(timeout));
				timer->async_wait ([conn, timeout](const boost::system::error_code& ecode)
				{
					if (ecode != boost::asio::error::operation_aborted)
					{
						LogPrint (eLogInfo, "NTCP2: Not connected in ", timeout, " seconds");
						i2p::data::netdb.SetUnreachable (conn->GetRemoteIdentity ()->GetIdentHash (), true);
						conn->Terminate ();
					}
				});
				conn->GetSocket ().async_connect (*m_ProxyEndpoint, std::bind (&NTCP2Server::HandleProxyConnect, this, std::placeholders::_1, conn, timer, host, port, addrtype));
			}
		});
	}

	void NTCP2Server::UseProxy(ProxyType proxytype, const std::string & addr, uint16_t port)
	{
		m_ProxyType = proxytype;
		m_ProxyAddress = addr;
		m_ProxyPort = port;
	}

	void NTCP2Server::HandleProxyConnect(const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn, std::shared_ptr<boost::asio::deadline_timer> timer, const std::string & host, uint16_t port, RemoteAddressType addrtype)
	{
		if (ecode)
		{
			LogPrint(eLogWarning, "NTCP2: failed to connect to proxy ", ecode.message());
			timer->cancel();
			conn->Terminate();
			return;
		}
		switch (m_ProxyType)
		{
			case eSocksProxy:
			{
				// TODO: support username/password auth etc
				static const uint8_t buff[3] = {0x05, 0x01, 0x00};
				boost::asio::async_write(conn->GetSocket(), boost::asio::buffer(buff, 3), boost::asio::transfer_all(),
					[] (const boost::system::error_code & ec, std::size_t transferred)
					{
						(void) transferred;
						if(ec)
						{
							LogPrint(eLogWarning, "NTCP2: socks5 write error ", ec.message());
						}
					});
				auto readbuff = std::make_shared<std::vector<uint8_t> >(2);
				boost::asio::async_read(conn->GetSocket(), boost::asio::buffer(readbuff->data (), 2),
					[this, readbuff, timer, conn, host, port, addrtype](const boost::system::error_code & ec, std::size_t transferred)
					{
						if(ec)
						{
							LogPrint(eLogError, "NTCP2: socks5 read error ", ec.message());
							timer->cancel();
							conn->Terminate();
							return;
						}
						else if(transferred == 2)
						{
							if((*readbuff)[1] == 0x00)
							{
								AfterSocksHandshake(conn, timer, host, port, addrtype);
								return;
							}
							else if ((*readbuff)[1] == 0xff)
							{
								LogPrint(eLogError, "NTCP2: socks5 proxy rejected authentication");
								timer->cancel();
								conn->Terminate();
								return;
							}
							LogPrint(eLogError, "NTCP2:", (int)(*readbuff)[1]);
						}
						LogPrint(eLogError, "NTCP2: socks5 server gave invalid response");
						timer->cancel();
						conn->Terminate();
					});
				break;
			}
			case eHTTPProxy:
			{
				i2p::http::HTTPReq req;
				req.method = "CONNECT";
				req.version ="HTTP/1.1";
				if(addrtype == eIP6Address)
					req.uri = "[" + host + "]:" + std::to_string(port);
				else
					req.uri = host + ":" + std::to_string(port);

				boost::asio::streambuf writebuff;
				std::ostream out(&writebuff);
				out << req.to_string();

				boost::asio::async_write(conn->GetSocket(), writebuff.data(), boost::asio::transfer_all(),
					[](const boost::system::error_code & ec, std::size_t transferred)
					{
						(void) transferred;
						if(ec)
							LogPrint(eLogError, "NTCP2: http proxy write error ", ec.message());
					});

				boost::asio::streambuf * readbuff = new boost::asio::streambuf;
				boost::asio::async_read_until(conn->GetSocket(), *readbuff, "\r\n\r\n",
					[this, readbuff, timer, conn] (const boost::system::error_code & ec, std::size_t transferred)
					{
						if(ec)
						{
							LogPrint(eLogError, "NTCP2: http proxy read error ", ec.message());
							timer->cancel();
							conn->Terminate();
						}
						else
						{
							readbuff->commit(transferred);
							i2p::http::HTTPRes res;
							if(res.parse(boost::asio::buffer_cast<const char*>(readbuff->data()), readbuff->size()) > 0)
							{
								if(res.code == 200)
								{
									timer->cancel();
									conn->ClientLogin();
									delete readbuff;
									return;
								}
								else
									LogPrint(eLogError, "NTCP2: http proxy rejected request ", res.code);
							}
							else
								LogPrint(eLogError, "NTCP2: http proxy gave malformed response");
							timer->cancel();
							conn->Terminate();
							delete readbuff;
						}
					});
				break;
			}
			default:
				LogPrint(eLogError, "NTCP2: unknown proxy type, invalid state");
		}
	}

	void NTCP2Server::AfterSocksHandshake(std::shared_ptr<NTCP2Session> conn, std::shared_ptr<boost::asio::deadline_timer> timer, const std::string & host, uint16_t port, RemoteAddressType addrtype)
	{
		// build request
		size_t sz = 6; // header + port
		auto buff = std::make_shared<std::vector<int8_t> >(256);
		auto readbuff = std::make_shared<std::vector<int8_t> >(256);
		(*buff)[0] = 0x05;
		(*buff)[1] = 0x01;
		(*buff)[2] = 0x00;

		if(addrtype == eIP4Address)
		{
			(*buff)[3] = 0x01;
			auto addrbytes = boost::asio::ip::address::from_string(host).to_v4().to_bytes();
			sz += 4;
			memcpy(buff->data () + 4, addrbytes.data(), 4);
		}
		else if (addrtype == eIP6Address)
		{
			(*buff)[3] = 0x04;
			auto addrbytes = boost::asio::ip::address::from_string(host).to_v6().to_bytes();
			sz += 16;
			memcpy(buff->data () + 4, addrbytes.data(), 16);
		}
		else if (addrtype == eHostname)
		{
			// We mustn't really fall here because all connections are made to IP addresses
			LogPrint(eLogError, "NTCP2: Tried to connect to domain name via socks proxy");
			return;
		}
		htobe16buf(buff->data () + sz - 2, port);
		boost::asio::async_write(conn->GetSocket(), boost::asio::buffer(buff->data (), sz), boost::asio::transfer_all(),
			[buff](const boost::system::error_code & ec, std::size_t written)
			{
				if(ec)
				{
					LogPrint(eLogError, "NTCP2: failed to write handshake to socks proxy ", ec.message());
					return;
				}
			});

		boost::asio::async_read(conn->GetSocket(), boost::asio::buffer(readbuff->data (), 10),
			[timer, conn, sz, readbuff](const boost::system::error_code & e, std::size_t transferred)
			{
				if(e)
				{
					LogPrint(eLogError, "NTCP2: socks proxy read error ", e.message());
				}
				else if(transferred == sz)
				{
					if((*readbuff)[1] == 0x00)
					{
						timer->cancel();
						conn->ClientLogin();
						return;
					}
				}
				if(!e)
					i2p::data::netdb.SetUnreachable (conn->GetRemoteIdentity ()->GetIdentHash (), true);
				timer->cancel();
				conn->Terminate();
			});
	}
}
}
