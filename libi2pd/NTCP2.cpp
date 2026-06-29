/*
* Copyright (c) 2013-2026, The PurpleI2P Project
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
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "Log.h"
#include "I2PEndian.h"
#include "Crypto.h"
#include "Siphash.h"
#include "RouterContext.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "HTTP.h"
#include "util.h"
#include "Socks5.h"
#include "NTCP2.h"

#if defined(__linux__) && !defined(_NETINET_IN_H)
	#include <linux/in6.h>
#endif

namespace i2p
{
namespace transport
{
	namespace
	{
		std::string HexSnippet (const uint8_t * data, size_t len, size_t maxLen = 24)
		{
			std::ostringstream s;
			s << std::hex << std::setfill ('0');
			auto n = std::min (len, maxLen);
			for (size_t i = 0; i < n; i++)
			{
				if (i) s << ' ';
				s << std::setw (2) << (int)data[i];
			}
			if (len > n) s << " ...";
			return s.str ();
		}
	}

	NTCP2Establisher::NTCP2Establisher ():
		m_SessionConfirmedBuffer (nullptr), m_BufferLen (0), m_IsLongPadding (false)
	{
        SetVersion (2);
	}

	NTCP2Establisher::~NTCP2Establisher ()
	{
		delete[] m_SessionConfirmedBuffer;
	}

	void NTCP2Establisher::SetVersion (int version)
	{
#if OPENSSL_MLKEM
        switch (version)
        {
            case 3:
#if defined(LIBRESSL_VERSION_NUMBER)
                 m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD; // ML-KEM-512 is not available on LibreSSL
#else
                 m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM512_X25519_AEAD;
#endif
            break;
            case 4:
                 m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD;
            break;
            case 5:
                 m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM1024_X25519_AEAD;
            break;
            default:
                m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD;
                m_IsLongPadding = false;
        }
#else
        m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD;
#endif
	}

	bool NTCP2Establisher::KeyDerivationFunction1 (const uint8_t * pub, i2p::crypto::X25519Keys& priv, const uint8_t * rs, const uint8_t * epub)
	{
#if OPENSSL_MLKEM
        if (m_CryptoType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
            i2p::crypto::InitNoiseXKState (*this, rs);
        else
            i2p::crypto::InitNoiseXKStateMLKEM (*this, m_CryptoType, rs);
#else
		i2p::crypto::InitNoiseXKState (*this, rs);
#endif
		// h = SHA256(h || epub)
		MixHash (epub, 32);
		// x25519 between pub and priv
		uint8_t inputKeyMaterial[32];
		if (!priv.Agree (pub, inputKeyMaterial)) return false;
		MixKey (inputKeyMaterial);
		return true;
	}

	bool NTCP2Establisher::KDF1Alice ()
	{
		return KeyDerivationFunction1 (m_RemoteStaticKey, *m_EphemeralKeys, m_RemoteStaticKey, GetPub ());
	}

	bool NTCP2Establisher::KDF1Bob ()
	{
		return KeyDerivationFunction1 (GetRemotePub (), i2p::context.GetNTCP2StaticKeys (), i2p::context.GetNTCP2StaticPublicKey (), GetRemotePub ());
	}

	bool NTCP2Establisher::KeyDerivationFunction2 (const uint8_t * epub)
	{
		MixHash (epub, 32);

		// x25519 between remote pub and ephemaral priv
		uint8_t inputKeyMaterial[32];
		if (!m_EphemeralKeys->Agree (GetRemotePub (), inputKeyMaterial)) return false;
		MixKey (inputKeyMaterial);
		return true;
	}

	bool NTCP2Establisher::KDF2Alice ()
	{
		return KeyDerivationFunction2 (GetRemotePub ());
	}

	bool NTCP2Establisher::KDF2Bob ()
	{
		return KeyDerivationFunction2 (GetPub ());
	}

	bool NTCP2Establisher::KDF3Alice ()
	{
		uint8_t inputKeyMaterial[32];
		if (!i2p::context.GetNTCP2StaticKeys ().Agree (GetRemotePub (), inputKeyMaterial)) return false;
		MixKey (inputKeyMaterial);
		return true;
	}

	bool NTCP2Establisher::KDF3Bob ()
	{
		uint8_t inputKeyMaterial[32];
		if (!m_EphemeralKeys->Agree (m_RemoteStaticKey, inputKeyMaterial)) return false;
		MixKey (inputKeyMaterial);
		return true;
	}

	void NTCP2Establisher::CreateEphemeralKey ()
	{
		m_EphemeralKeys = i2p::transport::transports.GetNextX25519KeysPair ();
	}

	void NTCP2Establisher::ApplyPadding (uint8_t * padding, size_t paddingLength)
	{
        MixHash (padding, paddingLength);
	}

	bool NTCP2Establisher::CreateSessionRequestMessage (std::mt19937& rng)
	{
		size_t offset  = 0;
		size_t pqKeyLen = 0;
		// encrypt X
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (m_RemoteIdentHash);
#if OPENSSL_MLKEM
        if (m_CryptoType > i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
        {
            m_PQKeys = i2p::crypto::CreateMLKEMKeys (m_CryptoType);
            if (m_PQKeys)
            {
                m_PQKeys->GenerateKeys ();
                uint8_t pub[32];
                memcpy (pub, GetPub (), 32);
                pub[31] |= 0x80; // set highest bit
                encryption.Encrypt (pub, 32, m_IV, m_Buffer); // X
            }
            else
            {
                LogPrint (eLogWarning, "NTCP2: ML-KEM type ", (int)m_CryptoType, " is not available, fallback to X25519");
                m_CryptoType = i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD;
                m_IsLongPadding = false;
                encryption.Encrypt (GetPub (), 32, m_IV, m_Buffer); // X
            }
        }
        else
            encryption.Encrypt (GetPub (), 32, m_IV, m_Buffer); // X
#else
		encryption.Encrypt (GetPub (), 32, m_IV, m_Buffer); // X
#endif
		memcpy (m_IV, m_Buffer + 16, 16); // save last block as IV for SessionCreated
		offset += 32;
		// encryption key for next block
		if (!KDF1Alice ()) return false;
		size_t maxPaddingLength = m_IsLongPadding ? NTCP2_SESSION_HANDSHAKE_LONG_MAX_SIZE : NTCP2_SESSION_HANDSHAKE_MAX_SIZE;
		maxPaddingLength -= 64;
		size_t maxMsgSize = m_MaxMsgSize;
#if OPENSSL_MLKEM
        if (m_PQKeys)
        {
            // ML-KEM frame
            auto keyLen = i2p::crypto::GetMLKEMPublicKeyLen (m_CryptoType);
            pqKeyLen = keyLen;
            std::vector<uint8_t> encapsKey(keyLen);
            m_PQKeys->GetPublicKey (encapsKey.data ());
			// encrypt encapsKey
			if (!Encrypt (encapsKey.data (), m_Buffer + offset, keyLen))
			{
				LogPrint (eLogWarning, "NTCP2: SessionRequest ML-KEM encap_key frame AEAD encryption failed ");
				return false;
			}
			MixHash (m_Buffer + offset, keyLen + 16); // h = SHA256(h || ciphertext)
			offset += keyLen + 16;
			maxPaddingLength = offset + 32; // 32 bytes following options block size
			// adjust max msg size because we might send smaller message that we can receive
			maxMsgSize = NTCP2_SESSION_HANDSHAKE_LONG_MAX_SIZE + i2p::crypto::MLKEM1024_KEY_LENGTH + 16;
			if (maxMsgSize > m_MaxMsgSize) maxMsgSize = m_MaxMsgSize;
        }
#endif
        // calculate padding length
        if (offset + 32 + maxPaddingLength > maxMsgSize) maxPaddingLength = maxMsgSize - offset - 32;
		auto paddingLength = maxPaddingLength ? rng () % maxPaddingLength : 0;
		// fill options
		uint8_t options[32]; // actual options size is 16 bytes
		memset (options, 0, 16);
		options[0] = i2p::context.GetNetID (); // network ID
		options[1] = 2; // ver, always 2 regardless actual version
		htobe16buf (options + 2, paddingLength); // padLen
		// calculate m3p2Len
		auto riBuffer = i2p::context.CopyRouterInfoBuffer ();
		auto bufLen = riBuffer->GetBufferLen ();
		m3p2Len = bufLen + 4 + 16; // (RI header + RI + MAC for now) TODO: implement options
		htobe16buf (options + 4, m3p2Len);
		// 2 bytes reserved
		htobe32buf (options + 8, (i2p::util::GetMillisecondsSinceEpoch () + 500)/1000); // tsA, rounded to seconds
		// 4 bytes reserved
		// encrypt options
		if (!Encrypt (options, m_Buffer + offset, 16))
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest options frame AEAD encryption failed");
			return false;
		}
		MixHash (m_Buffer + offset, 32);
		offset += 32;
        // padding
        if (paddingLength)
        {
            RAND_bytes (m_Buffer + offset, paddingLength);
            MixHash (m_Buffer + offset, paddingLength);
		}
		m_BufferLen = offset + paddingLength;
		LogPrint (eLogDebug, "NTCP2: SessionRequest built crypto=", (int)m_CryptoType,
			" pq=", m_PQKeys ? 1 : 0, " pqKeyLen=", pqKeyLen, " totalLen=", m_BufferLen,
			" head=", HexSnippet (m_Buffer, m_BufferLen));
		// create m3p2 payload (RouterInfo block) for SessionConfirmed
		m_SessionConfirmedBuffer = new uint8_t[m3p2Len + 48]; // m3p1 is 48 bytes
		uint8_t * m3p2 = m_SessionConfirmedBuffer + 48;
		m3p2[0] = eNTCP2BlkRouterInfo; // block
		htobe16buf (m3p2 + 1, bufLen + 1); // flag + RI
		m3p2[3] = 0; // flag
		memcpy (m3p2 + 4, riBuffer->data (), bufLen); // TODO: eliminate extra copy

		return true;
	}

	bool NTCP2Establisher::CreateSessionCreatedMessage (std::mt19937& rng)
	{
		size_t offset = 0;
		// encrypt Y
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (i2p::context.GetIdentHash ());
		encryption.Encrypt (GetPub (), 32, m_IV, m_Buffer); // Y
		offset += 32;
		// encryption key for next block (m_K)
		if (!KDF2Bob ()) return false;
		size_t maxPaddingLength = m_IsLongPadding ? NTCP2_SESSION_HANDSHAKE_LONG_MAX_SIZE : NTCP2_SESSION_HANDSHAKE_MAX_SIZE;
		maxPaddingLength -= 64;
		size_t maxMsgSize = m_MaxMsgSize;
#if OPENSSL_MLKEM
        if (m_PQKeys)
        {
            size_t cipherTextLen = i2p::crypto::GetMLKEMCipherTextLen (m_CryptoType);
			std::vector<uint8_t> kemCiphertext(cipherTextLen);
			uint8_t sharedSecret[32];
			m_PQKeys->Encaps (kemCiphertext.data (), sharedSecret);
			if (!Encrypt (kemCiphertext.data (), m_Buffer + offset, cipherTextLen))
			{
				LogPrint (eLogWarning, "NTCP2: SessionCreated ML-KEM ciphertext section AEAD encryption failed");
				return false;
			}
			MixHash (m_Buffer + offset, cipherTextLen + 16); // encrypt ML-KEM frame
			MixKey (sharedSecret);
            offset += cipherTextLen + 16;
            maxPaddingLength= offset + 32; // 32 bytes following options block size
			// adjust max msg size because we might send smaller message that we can receive
			maxMsgSize = NTCP2_SESSION_HANDSHAKE_LONG_MAX_SIZE + i2p::crypto::MLKEM1024_KEY_LENGTH + 16;
			if (maxMsgSize > m_MaxMsgSize) maxMsgSize = m_MaxMsgSize;
        }
#endif
		// calculate padding length
		if (offset + 32 + maxPaddingLength > maxMsgSize) maxPaddingLength = maxMsgSize - offset - 32;
		auto paddingLength = maxPaddingLength ? rng () % maxPaddingLength : 0;
		uint8_t options[16];
		memset (options, 0, 16);
		htobe16buf (options + 2, paddingLength); // padLen
		htobe32buf (options + 8, (i2p::util::GetMillisecondsSinceEpoch () + 500)/1000); // tsB, rounded to seconds
		// encrypt options
		if (!Encrypt (options, m_Buffer + offset, 16))
		{
			LogPrint (eLogWarning, "NTCP2: SessionCreated failed to encrypt options");
			return false;
		}
		MixHash (m_Buffer + offset, 32);	// encrypted options
		offset += 32;
        // padding
        if (paddingLength)
        {
            RAND_bytes (m_Buffer + offset, paddingLength);
            MixHash (m_Buffer + offset, paddingLength);
        }
        m_BufferLen = offset + paddingLength;
		return true;
	}

	bool NTCP2Establisher::CreateSessionConfirmedMessagePart1 ()
	{
		// part1 48 bytes, n = 1
		if (!Encrypt (i2p::context.GetNTCP2StaticPublicKey (), m_SessionConfirmedBuffer, 32))
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed failed to encrypt part1");
			return false;
		}
		return true;
	}

	bool NTCP2Establisher::CreateSessionConfirmedMessagePart2 ()
	{
		// part 2
		// update AD again
		MixHash (m_SessionConfirmedBuffer, 48);
		// encrypt m3p2, it must be filled in SessionRequest
		if (!KDF3Alice ()) return false; // MixKey, n = 0
		uint8_t * m3p2 = m_SessionConfirmedBuffer + 48;
		if (!Encrypt (m3p2, m3p2, m3p2Len - 16))
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed failed to encrypt part2");
			return false;
		}
		// update h again
		MixHash (m3p2, m3p2Len); //h = SHA256(h || ciphertext)
		return true;
	}

	bool NTCP2Establisher::ProcessSessionRequestMessage (uint16_t& paddingLen, bool& clockSkew, bool& pq, bool decryptX)
	{
		clockSkew = false;
		pq = false;
		size_t offset = 0;
		if (decryptX)
		{
            // decrypt X
            auto x = GetRemotePub ();
            i2p::crypto::CBCDecryption decryption;
            decryption.SetKey (i2p::context.GetIdentHash ());
            decryption.Decrypt (m_Buffer, 32, i2p::context.GetNTCP2IV (), x);
            memcpy (m_IV, m_Buffer + 16, 16); // save last block as IV for SessionCreated
            if (x[31] & 0x80)
            {
#if OPENSSL_MLKEM
                if (m_CryptoType > i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
                {
                    pq = true;
                    x[31] &= 0x7F;
                }
#endif
                if (!pq)
                {
                    LogPrint (eLogWarning, "NTCP2: SessionRequest ML-KEM requested but not supported");
                    return false;
                }
            }
            else
                SetVersion (2); // regular x25519 requested
            // decryption key for next block
            if (!KDF1Bob ())
            {
                LogPrint (eLogWarning, "NTCP2: SessionRequest KDF failed");
                return false;
            }
		}
		offset += 32;
#if OPENSSL_MLKEM
        if (pq) return true; // we need to read extra ML-KEM block first
        if (m_CryptoType > i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
        {
            auto keyLen = i2p::crypto::GetMLKEMPublicKeyLen (m_CryptoType);
            std::vector<uint8_t> encapsKey(keyLen);
            if (Decrypt (m_Buffer + offset, encapsKey.data (), keyLen))
            {
                MixHash (m_Buffer + offset, keyLen + 16);
                offset += keyLen + 16;
                m_PQKeys = i2p::crypto::CreateMLKEMKeys (m_CryptoType);
                if (!m_PQKeys)
                {
                    LogPrint (eLogWarning, "NTCP2: ML-KEM type ", (int)m_CryptoType, " is not available");
                    return false;
                }
                m_PQKeys->SetPublicKey (encapsKey.data ());
            }
        }
#endif
		// verify MAC and decrypt options block (32 bytes)
		uint8_t options[16];
		if (Decrypt (m_Buffer + offset, options, 16))
		{
            MixHash (m_Buffer + offset, 32);
            offset += 32;
			// options
			if (options[0] && options[0] != i2p::context.GetNetID ())
			{
				LogPrint (eLogWarning, "NTCP2: SessionRequest networkID ", (int)options[0], " mismatch. Expected ", i2p::context.GetNetID ());
				return false;
			}
			if (options[1] == 2) // ver is always 2
			{
				paddingLen = bufbe16toh (options + 2);
				m_BufferLen = paddingLen + offset;
				// actual padding is not known yet, apply MixHash later
				if (m_BufferLen > NTCP2_SESSION_HANDSHAKE_MAX_SIZE) m_IsLongPadding = true;
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
					clockSkew = true;
					// we send SessionCreate to let Alice know our time and then close session
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
		LogPrint (eLogDebug, "NTCP2: SessionRequest parsed crypto=", (int)m_CryptoType,
			" pq=", pq ? 1 : 0, " padLen=", paddingLen, " m3p2Len=", m3p2Len, " totalLen=", m_BufferLen,
			" head=", HexSnippet (m_Buffer, m_BufferLen));
		return true;
	}

	bool NTCP2Establisher::ProcessSessionCreatedMessage (uint16_t& paddingLen)
	{
		size_t offset = 0;
		// decrypt Y
		i2p::crypto::CBCDecryption decryption;
		decryption.SetKey (m_RemoteIdentHash);
		decryption.Decrypt (m_Buffer + offset, 32, m_IV, GetRemotePub ());
		offset = 32;
		// decryption key for next block (m_K)
		if (!KDF2Alice ())
		{
			LogPrint (eLogWarning, "NTCP2: SessionCreated KDF failed");
			return false;
		}
#if OPENSSL_MLKEM
        if (m_CryptoType > i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD && m_PQKeys)
		{
			// decrypt kem_ciphertext  frame
			size_t cipherTextLen = i2p::crypto::GetMLKEMCipherTextLen (m_CryptoType);
			std::vector<uint8_t> kemCiphertext(cipherTextLen);
			if (!Decrypt (m_Buffer + offset, kemCiphertext.data (), cipherTextLen))
			{
				LogPrint (eLogWarning, "NTCP2: SessionCreated ML-KEM ciphertext section AEAD decryption failed");
				return false;
			}

			MixHash (m_Buffer + offset, cipherTextLen + 16);
			offset += cipherTextLen + 16;
			// decaps
			uint8_t sharedSecret[32];
			m_PQKeys->Decaps (kemCiphertext.data (), sharedSecret);
			MixKey (sharedSecret);
		}
#endif
		// decrypt options and verify MAC
		uint8_t options[16];
		if (Decrypt (m_Buffer + offset, options, 16))
		{
            MixHash (m_Buffer + offset, 32); // encrypted options
			// options
			paddingLen = bufbe16toh(options + 2);
			// actual padding is not known yet, apply MixHash later
			// check timestamp
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			uint32_t tsB = bufbe32toh (options + 8);
			if (tsB < ts - NTCP2_CLOCK_SKEW || tsB > ts + NTCP2_CLOCK_SKEW)
			{
				LogPrint (eLogWarning, "NTCP2: SessionCreated time difference ", (int)(ts - tsB), " exceeds clock skew");
				return false;
			}
			offset += 32;
		}
		else
		{
			LogPrint (eLogWarning, "NTCP2: SessionCreated AEAD verification failed ");
			return false;
		}
		m_BufferLen = offset;
		return true;
	}

	bool NTCP2Establisher::ProcessSessionConfirmedMessagePart1 ()
	{
		// decrypt S, n = 1
		if (!Decrypt (m_SessionConfirmedBuffer, m_RemoteStaticKey, 32))
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed Part1 AEAD verification failed ");
			return false;
		}
		MixHash (m_SessionConfirmedBuffer, 48);
		return true;
	}

	bool NTCP2Establisher::ProcessSessionConfirmedMessagePart2 (uint8_t * m3p2Buf)
	{
		if (!KDF3Bob ()) // MixKey, n = 0
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed Part2 KDF failed");
			return false;
		}
		if (Decrypt (m_SessionConfirmedBuffer + 48, m3p2Buf, m3p2Len - 16))
			// calculate new h again for KDF data
			MixHash (m_SessionConfirmedBuffer + 48, m3p2Len); // h = SHA256(h || ciphertext)
		else
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed Part2 AEAD verification failed ");
			return false;
		}
		return true;
	}

	NTCP2Session::NTCP2Session (NTCP2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr):
		TransportSession (in_RemoteRouter, NTCP2_ESTABLISH_TIMEOUT),
		m_Server (server), m_Socket (m_Server.GetService ()),
		m_IsEstablished (false), m_IsTerminated (false),
		m_Establisher (new NTCP2Establisher),
		m_SendKey (nullptr), m_ReceiveKey (nullptr),
#if OPENSSL_SIPHASH
		m_SendMDCtx(nullptr), m_ReceiveMDCtx (nullptr),
#else
		m_SendSipKey (nullptr), m_ReceiveSipKey (nullptr),
#endif
		m_NextReceivedLen (0), m_NextReceivedBuffer (nullptr), m_NextSendBuffer (nullptr),
		m_NextReceivedBufferSize (0), m_ReceiveSequenceNumber (0), m_SendSequenceNumber (0),
		m_IsSending (false), m_IsReceiving (false), m_NextRouterInfoResendTime (0),
		m_NextPaddingSize (16)
	{
		if (in_RemoteRouter) // Alice
		{
			m_Establisher->m_RemoteIdentHash = GetRemoteIdentity ()->GetIdentHash ();
			if (addr)
			{
				memcpy (m_Establisher->m_RemoteStaticKey, addr->s, 32);
				memcpy (m_Establisher->m_IV, addr->i, 16);
				m_RemoteEndpoint = boost::asio::ip::tcp::endpoint (addr->host, addr->port);
#if OPENSSL_MLKEM
                if (m_Server.GetVersion () > 2) // we support post quantum in config
                    m_Establisher->SetVersion (addr->v);
				LogPrint (eLogDebug, "NTCP2: PQ selection server=", m_Server.GetVersion (),
					" remote=", (int)addr->v, " crypto=", (int)m_Establisher->m_CryptoType);
#endif
				if (addr->v > 2 && in_RemoteRouter->GetVersion () >= MAKE_VERSION_NUMBER(0, 9, 69)) // 0.9.69
					m_Establisher->m_IsLongPadding = true;
			}
			else
				LogPrint (eLogWarning, "NTCP2: Missing NTCP2 address");
		}
	}

	NTCP2Session::~NTCP2Session ()
	{
		delete[] m_NextReceivedBuffer;
		delete[] m_NextSendBuffer;
#if OPENSSL_SIPHASH
		if (m_SendMDCtx) EVP_MD_CTX_destroy (m_SendMDCtx);
		if (m_ReceiveMDCtx) EVP_MD_CTX_destroy (m_ReceiveMDCtx);
#endif
	}

	void NTCP2Session::Terminate ()
	{
		bool isTerminated = m_IsTerminated.exchange (true);
		if (!isTerminated)
		{
			m_IsEstablished = false;
			boost::system::error_code ec;
			m_Socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
			if (ec)
				LogPrint (eLogDebug, "NTCP2: Couldn't shutdown socket: ", ec.message ());
			m_Socket.close ();
			transports.PeerDisconnected (shared_from_this ());
			m_Server.RemoveNTCP2Session (shared_from_this ());
			{
				std::lock_guard<std::mutex> l(m_IntermediateQueueMutex);
				if (!m_IntermediateQueue.empty ())
					m_SendQueue.splice (m_SendQueue.end (), m_IntermediateQueue);
			}
			for (auto& it: m_SendQueue)
				it->Drop ();
			m_SendQueue.clear ();
			SetSendQueueSize (0);
			auto remoteIdentity = GetRemoteIdentity ();
			if (remoteIdentity)
			{
				LogPrint (eLogDebug, "NTCP2: Session with ", GetRemoteEndpoint (),
					" (", i2p::data::GetIdentHashAbbreviation (remoteIdentity->GetIdentHash ()), ") terminated");
			}
			else
			{
				LogPrint (eLogDebug, "NTCP2: Session with ", GetRemoteEndpoint (), " terminated");
			}
		}
	}

	void NTCP2Session::Close ()
	{
		m_Socket.close ();
	}

	void NTCP2Session::TerminateByTimeout ()
	{
		SendTerminationAndTerminate (eNTCP2IdleTimeout);
	}

	void NTCP2Session::Done ()
	{
		boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
	}

	void NTCP2Session::Established ()
	{
		m_IsEstablished = true;
		m_Version = (uint8_t)m_Establisher->m_CryptoType - 2;
		m_Establisher.reset (nullptr);
		SetTerminationTimeout (NTCP2_TERMINATION_TIMEOUT + m_Server.GetRng ()() % NTCP2_TERMINATION_TIMEOUT_VARIANCE);
		m_NextRouterInfoResendTime = i2p::util::GetSecondsSinceEpoch () + NTCP2_ROUTERINFO_RESEND_INTERVAL +
			m_Server.GetRng ()() % NTCP2_ROUTERINFO_RESEND_INTERVAL_VARIANCE;
		SendQueue ();
		transports.PeerConnected (shared_from_this ());
	}

	void NTCP2Session::CreateNonce (uint64_t seqn, uint8_t * nonce)
	{
		memset (nonce, 0, 4);
		htole64buf (nonce + 4, seqn);
	}

	void NTCP2Session::CreateNextReceivedBuffer (size_t size)
	{
		if (m_NextReceivedBuffer)
		{
			if (size <= m_NextReceivedBufferSize)
				return; // buffer is good, do nothing
			else
				delete[] m_NextReceivedBuffer;
		}
		m_NextReceivedBuffer = new uint8_t[size];
		m_NextReceivedBufferSize = size;
	}

	void NTCP2Session::DeleteNextReceiveBuffer (uint64_t ts)
	{
		if (m_NextReceivedBuffer && !m_IsReceiving &&
			ts > GetLastActivityTimestamp () + NTCP2_RECEIVE_BUFFER_DELETION_TIMEOUT)
		{
			delete[] m_NextReceivedBuffer;
			m_NextReceivedBuffer = nullptr;
			m_NextReceivedBufferSize = 0;
		}
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
		if (!m_Establisher->CreateSessionRequestMessage (m_Server.GetEstablisherRng ()))
		{
			LogPrint (eLogWarning, "NTCP2: Send SessionRequest KDF failed");
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
			return;
		}
		// send message
		m_HandshakeInterval = i2p::util::GetMillisecondsSinceEpoch ();
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_Establisher->m_Buffer, m_Establisher->m_BufferLen), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionRequestSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleSessionRequestSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: Couldn't send SessionRequest message: ", ecode.message ());
			Terminate ();
		}
		else
		{
			// we receive first 64 bytes (32 Y, and 32 ChaCha/Poly frame) first and ML-KEM frame if post quantum
			size_t len = 64;
#if OPENSSL_MLKEM
			if (m_Establisher->m_CryptoType > i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
                len += i2p::crypto::GetMLKEMCipherTextLen (m_Establisher->m_CryptoType) + 16;
#endif
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_Buffer, len), boost::asio::transfer_all (),
				std::bind(&NTCP2Session::HandleSessionCreatedReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
		}
	}

	void NTCP2Session::HandleSessionRequestReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_Establisher->CreateEphemeralKey ();
			boost::asio::post (m_Server.GetEstablisherService (),
				[s = shared_from_this (), bytes_transferred] ()
				{
					s->ProcessSessionRequest (bytes_transferred);;
				});
		}
	}

	void NTCP2Session::ProcessSessionRequest (size_t len, bool first)
	{
		LogPrint (eLogDebug, "NTCP2: SessionRequest ", first ? "received " : "updated ", len);
		uint16_t paddingLen = 0;
		bool clockSkew = false, pq = false;
		if (m_Establisher->ProcessSessionRequestMessage (paddingLen, clockSkew, pq, first))
		{
			if (clockSkew)
			{
				// we don't care about padding, send SessionCreated and close session
				SendSessionCreated ();
				boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
			}
#if OPENSSL_MLKEM
			else if (pq)
			{
                auto keyLen = i2p::crypto::GetMLKEMPublicKeyLen (m_Establisher->m_CryptoType);
                boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_Buffer + 64, keyLen + 16), boost::asio::transfer_all (),
						std::bind(&NTCP2Session::HandleSessionRequestMLKEMReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
			}
#endif
			else if (paddingLen > 0)
			{
				if (len + paddingLen <= m_Establisher->m_MaxMsgSize)
				{
					boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_Buffer + len, paddingLen), boost::asio::transfer_all (),
						std::bind(&NTCP2Session::HandleSessionRequestPaddingReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
				}
				else
				{
					LogPrint (eLogWarning, "NTCP2: SessionRequest padding length ", (int)paddingLen, " is too long");
					boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
				}
			}
			else
				SendSessionCreated ();
		}
		else
			ReadSomethingAndTerminate (); // probing resistance
	}

	void NTCP2Session::HandleSessionRequestPaddingReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest padding read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
            boost::asio::post (m_Server.GetEstablisherService (),
				[s = shared_from_this (), paddingLength = bytes_transferred] ()
				{
                    if (paddingLength < s->m_Establisher->m_BufferLen)
                        s->m_Establisher->ApplyPadding (s->m_Establisher->m_Buffer + s->m_Establisher->m_BufferLen - paddingLength, paddingLength);
					s->SendSessionCreated ();
				});
		}
	}

#if OPENSSL_MLKEM
    void NTCP2Session::HandleSessionRequestMLKEMReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
    {
        if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionRequest ML-KEM read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
             boost::asio::post (m_Server.GetEstablisherService (),
				[s = shared_from_this (), bytes_transferred] ()
				{
                    s->ProcessSessionRequest (bytes_transferred + 64, false);
                });
		}
    }
#endif

	void NTCP2Session::SendSessionCreated ()
	{
		if (!m_Establisher->CreateSessionCreatedMessage (m_Server.GetEstablisherRng ()))
		{
			LogPrint (eLogWarning, "NTCP2: Send SessionCreated KDF failed");
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
			return;
		}
		// send message
		m_HandshakeInterval = i2p::util::GetMillisecondsSinceEpoch ();
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_Establisher->m_Buffer, m_Establisher->m_BufferLen), boost::asio::transfer_all (),
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
			m_HandshakeInterval = i2p::util::GetMillisecondsSinceEpoch () - m_HandshakeInterval;
			boost::asio::post (m_Server.GetEstablisherService (),
				[s = shared_from_this (), bytes_transferred] ()
				{
					s->ProcessSessionCreated (bytes_transferred);
				});
		}
	}

	void NTCP2Session::ProcessSessionCreated (size_t len)
	{
		LogPrint (eLogDebug, "NTCP2: SessionCreated received ", len);
		uint16_t paddingLen = 0;
		if (m_Establisher->ProcessSessionCreatedMessage (paddingLen))
		{
			if (paddingLen > 0)
			{
#if OPENSSL_MLKEM
				if (paddingLen <= m_Establisher->m_MaxMsgSize - 80)
#else
				if (paddingLen <= m_Establisher->m_MaxMsgSize - 64)
#endif
				{
					boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_Buffer + m_Establisher->m_BufferLen, paddingLen), boost::asio::transfer_all (),
						std::bind(&NTCP2Session::HandleSessionCreatedPaddingReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
				}
				else
				{
					LogPrint (eLogWarning, "NTCP2: SessionCreated padding length ", (int)paddingLen, " is too long");
					boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
				}
			}
			else
				SendSessionConfirmed ();
		}
		else
		{
			if (GetRemoteIdentity ())
				i2p::data::netdb.SetUnreachable (GetRemoteIdentity ()->GetIdentHash (), true);  // assume wrong s key
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
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
			boost::asio::post (m_Server.GetEstablisherService (),
				[s = shared_from_this (), paddingLength = bytes_transferred] ()
				{
                    s->m_Establisher->ApplyPadding (s->m_Establisher->m_Buffer + s->m_Establisher->m_BufferLen, paddingLength);
                    s->m_Establisher->m_BufferLen += paddingLength;
					s->SendSessionConfirmed ();
				});
		}
	}

	void NTCP2Session::SendSessionConfirmed ()
	{
		if (!m_Establisher->CreateSessionConfirmedMessagePart1 ())
		{
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
			return;
		}
		if (!m_Establisher->CreateSessionConfirmedMessagePart2 ())
		{
			LogPrint (eLogWarning, "NTCP2: Send SessionConfirmed Part2 KDF failed");
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
			return;
		}
		// send message
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_Establisher->m_SessionConfirmedBuffer, m_Establisher->m3p2Len + 48), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionConfirmedSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleSessionConfirmedSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: Couldn't send SessionConfirmed message: ", ecode.message ());
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
			LogPrint (eLogWarning, "NTCP2: Couldn't send SessionCreated message: ", ecode.message ());
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
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP2: SessionConfirmed read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			m_HandshakeInterval = i2p::util::GetMillisecondsSinceEpoch () - m_HandshakeInterval;
			boost::asio::post (m_Server.GetEstablisherService (),
				[s = shared_from_this ()] ()
				{
					s->ProcessSessionConfirmed ();;
				});
		}
	}

	void NTCP2Session::ProcessSessionConfirmed ()
	{
		// run on establisher thread
		LogPrint (eLogDebug, "NTCP2: SessionConfirmed received");
		// part 1
		if (m_Establisher->ProcessSessionConfirmedMessagePart1 ())
		{
			// part 2
			auto buf = std::make_shared<std::vector<uint8_t> > (m_Establisher->m3p2Len - 16); // -MAC
			if (m_Establisher->ProcessSessionConfirmedMessagePart2 (buf->data ())) // TODO:handle in establisher thread
			{
				// payload
				// RI block must be first
				if ((*buf)[0] != eNTCP2BlkRouterInfo)
				{
					LogPrint (eLogWarning, "NTCP2: Unexpected block ", (int)(*buf)[0], " in SessionConfirmed");
					boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
					return;
				}
				auto size = bufbe16toh (buf->data () + 1);
				if (size > buf->size () - 3 || size > i2p::data::MAX_RI_BUFFER_SIZE + 1)
				{
					LogPrint (eLogError, "NTCP2: Unexpected RouterInfo size ", size, " in SessionConfirmed");
					boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
					return;
				}
				boost::asio::post (m_Server.GetService (),
					[s = shared_from_this (), buf, size] ()
					{
						s->EstablishSessionAfterSessionConfirmed (buf, size);
					});
			}
			else
				boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
		}
		else
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
	}

	void NTCP2Session::EstablishSessionAfterSessionConfirmed (std::shared_ptr<std::vector<uint8_t> > buf, size_t size)
	{
		// run on main NTCP2 thread
		KeyDerivationFunctionDataPhase ();
		// Bob data phase keys
		m_SendKey = m_Kba;
		m_ReceiveKey = m_Kab;
		SetSipKeys (m_Sipkeysba, m_Sipkeysab);
		memcpy (m_ReceiveIV.buf, m_Sipkeysab + 16, 8);
		memcpy (m_SendIV.buf, m_Sipkeysba + 16, 8);
		// we need to set keys for SendTerminationAndTerminate
		// TODO: check flag
		i2p::data::RouterInfo ri (buf->data () + 4, size - 1); // 1 byte block type + 2 bytes size + 1 byte flag
		if (ri.IsUnreachable ())
		{
			LogPrint (eLogError, "NTCP2: RouterInfo verification failed in SessionConfirmed from ", GetRemoteEndpoint ());
			SendTerminationAndTerminate (eNTCP2RouterInfoSignatureVerificationFail);
			return;
		}
		LogPrint(eLogDebug, "NTCP2: SessionConfirmed from ", GetRemoteEndpoint (),
			" (", i2p::data::GetIdentHashAbbreviation (ri.GetIdentHash ()), ")");
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (ts > ri.GetTimestamp () + i2p::data::NETDB_MIN_EXPIRATION_TIMEOUT*1000LL) // 90 minutes
		{
			LogPrint (eLogError, "NTCP2: RouterInfo is too old in SessionConfirmed for ", (ts - ri.GetTimestamp ())/1000LL, " seconds");
			SendTerminationAndTerminate (eNTCP2Message3Error);
			return;
		}
		if (ts + i2p::data::NETDB_EXPIRATION_TIMEOUT_THRESHOLD*1000LL < ri.GetTimestamp ()) // 2 minutes
		{
			LogPrint (eLogError, "NTCP2: RouterInfo is from future for ", (ri.GetTimestamp () - ts)/1000LL, " seconds");
			SendTerminationAndTerminate (eNTCP2Message3Error);
			return;
		}
		if (ri.GetVersion () < i2p::data::NETDB_MIN_ALLOWED_VERSION && !ri.IsHighBandwidth ())
		{
			LogPrint (eLogInfo, "NTCP2: Router version ", ri.GetVersion (), " is too old in SessionConfirmed");
			SendTerminationAndTerminate (eNTCP2Banned);
			return;
		}
		// update RouterInfo in netdb
		auto ri1 = i2p::data::netdb.AddRouterInfo (ri.GetBuffer (), ri.GetBufferLen ()); // ri1 points to one from netdb now
		if (!ri1)
		{
			LogPrint (eLogError, "NTCP2: Couldn't update RouterInfo from SessionConfirmed in netdb");
			Terminate ();
			return;
		}

		bool isOlder = false;
		if (ri.GetTimestamp () + i2p::data::NETDB_EXPIRATION_TIMEOUT_THRESHOLD*1000LL < ri1->GetTimestamp ())
		{
			// received RouterInfo is older than one in netdb
			isOlder = true;
			if (ri1->HasProfile ())
			{
				auto profile = i2p::data::GetRouterProfile (ri1->GetIdentHash ()); // retrieve profile
				if (profile && profile->IsDuplicated ())
				{
					SendTerminationAndTerminate (eNTCP2Banned);
					return;
				}
			}
		}

		auto addr = m_RemoteEndpoint.address ().is_v4 () ? ri1->GetNTCP2V4Address () :
			(i2p::util::net::IsYggdrasilAddress (m_RemoteEndpoint.address ()) ? ri1->GetYggdrasilAddress () : ri1->GetNTCP2V6Address ());
		if (!addr)
		{
			LogPrint (eLogError, "NTCP2: Address not found in SessionConfirmed");
			Terminate ();
			return;
		}
		if (addr->IsPublishedNTCP2 () && m_RemoteEndpoint.address () != addr->host &&
		    (!m_RemoteEndpoint.address ().is_v6 () || (i2p::util::net::IsYggdrasilAddress (m_RemoteEndpoint.address ()) ?
		     memcmp (m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data () + 1, addr->host.to_v6 ().to_bytes ().data () + 1, 7) : // from the same yggdrasil subnet
		     memcmp (m_RemoteEndpoint.address ().to_v6 ().to_bytes ().data (), addr->host.to_v6 ().to_bytes ().data (), 8)))) // temporary address
		{
			if (isOlder) // older router?
				i2p::data::UpdateRouterProfile (ri1->GetIdentHash (),
					[](std::shared_ptr<i2p::data::RouterProfile> profile)
					{
						if (profile) profile->Duplicated (); // mark router as duplicated in profile
					});
			else
				LogPrint (eLogInfo, "NTCP2: Host mismatch between published address ", addr->host, " and actual endpoint ", m_RemoteEndpoint.address ());
			SendTerminationAndTerminate (eNTCP2Banned);
			return;
		}
		if (memcmp (m_Establisher->m_RemoteStaticKey, addr->s, 32))
		{
			LogPrint (eLogError, "NTCP2: Wrong static key in SessionConfirmed");
			if (addr->IsPublishedNTCP2 ())
				i2p::transport::transports.AddBan (m_RemoteEndpoint.address ());
			Terminate ();
			return;
		}
		// TODO: process options block

		// ready to communicate
		SetRemoteIdentity (ri1->GetRouterIdentity ());
		if (m_Server.AddNTCP2Session (shared_from_this (), true))
		{
			Established ();
			if (ri1->GetCongestion () == i2p::data::RouterInfo::eRejectAll)
			{
				auto terminationTimeout = GetTerminationTimeout ()/2;
				if (terminationTimeout < NTCP2_ESTABLISH_TIMEOUT) terminationTimeout = NTCP2_ESTABLISH_TIMEOUT;
				SetTerminationTimeout (terminationTimeout);
			}
			ReceiveLength ();
		}
		else
			Terminate ();
	}

	void NTCP2Session::SetSipKeys (const uint8_t * sendSipKey, const uint8_t * receiveSipKey)
	{
#if OPENSSL_SIPHASH
		EVP_PKEY * sipKey = EVP_PKEY_new_raw_private_key (EVP_PKEY_SIPHASH, nullptr, sendSipKey, 16);
		m_SendMDCtx = EVP_MD_CTX_create ();
		EVP_PKEY_CTX *ctx = nullptr;
		EVP_DigestSignInit (m_SendMDCtx, &ctx, nullptr, nullptr, sipKey);
		EVP_PKEY_CTX_ctrl (ctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, nullptr);
		EVP_PKEY_free (sipKey);

		sipKey = EVP_PKEY_new_raw_private_key (EVP_PKEY_SIPHASH, nullptr, receiveSipKey, 16);
		m_ReceiveMDCtx = EVP_MD_CTX_create ();
		ctx = nullptr;
		EVP_DigestSignInit (m_ReceiveMDCtx, &ctx, NULL, NULL, sipKey);
		EVP_PKEY_CTX_ctrl (ctx, -1, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_CTRL_SET_DIGEST_SIZE, 8, nullptr);
		EVP_PKEY_free (sipKey);
#else
		m_SendSipKey = sendSipKey;
		m_ReceiveSipKey = receiveSipKey;
#endif
	}

	void NTCP2Session::ClientLogin ()
	{
		if (m_Establisher->m_CryptoType > i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD && !(m_Server.GetRng ()() & 0x03))
			m_Establisher->SetVersion (2); // switch to non-PQ  with a probability of one in four
		LogPrint (eLogDebug, "NTCP2: Login crypto type ", (int)m_Establisher->m_CryptoType);
		m_Establisher->CreateEphemeralKey ();
		boost::asio::post (m_Server.GetEstablisherService (),
		    [s = shared_from_this ()] ()
			{
				s->SendSessionRequest ();
			});
	}

	void NTCP2Session::ServerLogin (int version)
	{
        if (m_Establisher) m_Establisher->SetVersion (version);
		SetTerminationTimeout (NTCP2_ESTABLISH_TIMEOUT);
		SetLastActivityTimestamp (i2p::util::GetSecondsSinceEpoch ());
		boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_Buffer, 64), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleSessionRequestReceived, shared_from_this (),
			std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::ReceiveLength ()
	{
		if (IsTerminated ()) return;
#ifdef __linux__
		const int one = 1;
		setsockopt(m_Socket.native_handle(), IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
		boost::asio::async_read (m_Socket, boost::asio::buffer(&m_NextReceivedLen, 2), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleReceivedLength, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleReceivedLength (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogWarning, "NTCP2: Receive length read error: ", ecode.message ());
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
			LogPrint (eLogDebug, "NTCP2: Received length ", m_NextReceivedLen);
			if (m_NextReceivedLen >= 16)
			{
				CreateNextReceivedBuffer (m_NextReceivedLen);
				boost::system::error_code ec;
				size_t moreBytes = m_Socket.available(ec);
				if (!ec)
				{
					if (moreBytes >= m_NextReceivedLen)
					{
						// read and process message immediately if available
						moreBytes = boost::asio::read (m_Socket, boost::asio::buffer(m_NextReceivedBuffer, m_NextReceivedLen), boost::asio::transfer_all (), ec);
						HandleReceived (ec, moreBytes);
					}
					else
						Receive ();
				}
				else
					LogPrint (eLogWarning, "NTCP2: Socket error: ", ec.message ());
			}
			else
			{
				LogPrint (eLogError, "NTCP2: Received length ", m_NextReceivedLen, " is too short");
				Terminate ();
			}
		}
	}

	void NTCP2Session::Receive ()
	{
		if (IsTerminated ()) return;
#ifdef __linux__
		const int one = 1;
		setsockopt(m_Socket.native_handle(), IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
		m_IsReceiving = true;
		boost::asio::async_read (m_Socket, boost::asio::buffer(m_NextReceivedBuffer, m_NextReceivedLen), boost::asio::transfer_all (),
			std::bind(&NTCP2Session::HandleReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCP2Session::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogWarning, "NTCP2: Receive read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			UpdateNumReceivedBytes (bytes_transferred + 2);
			i2p::transport::transports.UpdateReceivedBytes (bytes_transferred + 2);
			uint8_t nonce[12];
			CreateNonce (m_ReceiveSequenceNumber, nonce); m_ReceiveSequenceNumber++;
			if (m_Server.AEADChaCha20Poly1305Decrypt (m_NextReceivedBuffer, m_NextReceivedLen-16, nullptr, 0, m_ReceiveKey, nonce, m_NextReceivedBuffer, m_NextReceivedLen))
			{
				LogPrint (eLogDebug, "NTCP2: Received message decrypted");
				ProcessNextFrame (m_NextReceivedBuffer, m_NextReceivedLen-16);
				m_IsReceiving = false;
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
			if (offset + size > len)
			{
				LogPrint (eLogError, "NTCP2: Unexpected block length ", size);
				break;
			}
			switch (blk)
			{
				case eNTCP2BlkDateTime:
				{
					LogPrint (eLogDebug, "NTCP2: Datetime");
					if (m_IsEstablished)
					{
						uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
						uint64_t tsA = bufbe32toh (frame + offset);
						if (tsA < ts - NTCP2_CLOCK_SKEW || tsA > ts + NTCP2_CLOCK_SKEW)
						{
							LogPrint (eLogWarning, "NTCP2: Established session time difference ", (int)(ts - tsA), " exceeds clock skew");
							SendTerminationAndTerminate (eNTCP2ClockSkew);
						}
					}
					break;
				}
				case eNTCP2BlkOptions:
					LogPrint (eLogDebug, "NTCP2: Options");
				break;
				case eNTCP2BlkRouterInfo:
				{
					LogPrint (eLogDebug, "NTCP2: RouterInfo flag=", (int)frame[offset]);
					if (size <= i2p::data::MAX_RI_BUFFER_SIZE + 1)
					{
						auto newRi = i2p::data::netdb.AddRouterInfo (frame + offset + 1, size - 1);
						if (newRi)
						{
							auto remoteIdentity = GetRemoteIdentity ();
							if (remoteIdentity && remoteIdentity->GetIdentHash () == newRi->GetIdentHash ())
								// peer's RouterInfo update
								SetRemoteIdentity (newRi->GetIdentity ());
							i2p::transport::transports.UpdatePeerParams (newRi);
						}
					}
					else
						LogPrint (eLogInfo, "NTCP2: RouterInfo block is too long ", size);
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
					auto nextMsg = (frame[offset] == eI2NPTunnelData) ? NewI2NPTunnelMessage (true) : NewI2NPMessage (size);
					nextMsg->len = nextMsg->offset + size + 7; // 7 more bytes for full I2NP header
					if (nextMsg->len <= nextMsg->maxLen)
					{
						memcpy (nextMsg->GetNTCP2Header (), frame + offset, size);
						nextMsg->FromNTCP2 ();
						m_Handler.PutNextMessage (std::move (nextMsg));
					}
					else
						LogPrint (eLogError, "NTCP2: I2NP block is too long for I2NP message");
					break;
				}
				case eNTCP2BlkTermination:
					if (size >= 9)
					{
						LogPrint (eLogDebug, "NTCP2: Termination. reason=", (int)(frame[offset + 8]));
						Terminate ();
					}
					else
						LogPrint (eLogWarning, "NTCP2: Unexpected termination block size ", size);
				break;
				case eNTCP2BlkPadding:
					LogPrint (eLogDebug, "NTCP2: Padding");
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
		LogPrint (eLogDebug, "NTCP2: Sent length ", frameLen);
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
			// create padding block
			auto paddingLen = CreatePaddingBlock (totalLen, m_NextSendBuffer, 287 - 16);
			// and padding block to encrypt and send
			if (paddingLen)
				encryptBufs.push_back ( {m_NextSendBuffer, paddingLen} );
			bufs.push_back (boost::asio::buffer (m_NextSendBuffer, paddingLen + 16));
			macBuf = m_NextSendBuffer + paddingLen;
			totalLen += paddingLen;
		}
		if (totalLen > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE)
		{
			LogPrint (eLogError, "NTCP2: Frame to send is too long ", totalLen);
			return;
		}
		uint8_t nonce[12];
		CreateNonce (m_SendSequenceNumber, nonce); m_SendSequenceNumber++;
		m_Server.AEADChaCha20Poly1305Encrypt (encryptBufs, m_SendKey, nonce, macBuf); // encrypt buffers
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
		if (payloadLen > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE)
		{
			LogPrint (eLogError, "NTCP2: Buffer to send is too long ", payloadLen);
			delete[] m_NextSendBuffer; m_NextSendBuffer = nullptr;
			return;
		}
		// encrypt
		uint8_t nonce[12];
		CreateNonce (m_SendSequenceNumber, nonce); m_SendSequenceNumber++;
		m_Server.AEADChaCha20Poly1305Encrypt ({ {m_NextSendBuffer + 2, payloadLen} }, m_SendKey, nonce, m_NextSendBuffer + payloadLen + 2);
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
			UpdateNumSentBytes (bytes_transferred);
			i2p::transport::transports.UpdateSentBytes (bytes_transferred);
			LogPrint (eLogDebug, "NTCP2: Next frame sent ", bytes_transferred);
			if (GetLastActivityTimestamp () > m_NextRouterInfoResendTime && m_NextRouterInfoResendTime)
			{
				m_NextRouterInfoResendTime += NTCP2_ROUTERINFO_RESEND_INTERVAL +
					m_Server.GetRng ()() % NTCP2_ROUTERINFO_RESEND_INTERVAL_VARIANCE;
				SendRouterInfo ();
			}
			else
			{
				SendQueue ();
				SetSendQueueSize (m_SendQueue.size ());
			}
		}
	}

	void NTCP2Session::SendQueue ()
	{
		if (!m_SendQueue.empty () && m_IsEstablished)
		{
			std::vector<std::shared_ptr<I2NPMessage> > msgs;
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			size_t s = 0;
			while (!m_SendQueue.empty ())
			{
				auto msg = m_SendQueue.front ();
				if (!msg || msg->IsExpired (ts))
				{
					// drop null or expired message
					if (msg) msg->Drop ();
					m_SendQueue.pop_front ();
					continue;
				}
				size_t len = msg->GetNTCP2Length ();
				if (s + len + 3 <= NTCP2_UNENCRYPTED_FRAME_MAX_SIZE) // 3 bytes block header
				{
					msgs.push_back (msg);
					s += (len + 3);
					m_SendQueue.pop_front ();
					if (s >= NTCP2_SEND_AFTER_FRAME_SIZE)
						break; // send frame right a way
				}
				else if (len + 3 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE)
				{
					LogPrint (eLogError, "NTCP2: I2NP message of size ", len, " can't be sent. Dropped");
					msg->Drop ();
					m_SendQueue.pop_front ();
				}
				else
					break;
			}
			SendI2NPMsgs (msgs);
		}
	}

	void NTCP2Session::MoveSendQueue (std::shared_ptr<NTCP2Session> other)
	{
		if (!other || m_SendQueue.empty ()) return;
		std::list<std::shared_ptr<I2NPMessage> > msgs;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (auto it: m_SendQueue)
			if (!it->IsExpired (ts))
				msgs.push_back (it);
			else
				it->Drop ();
		m_SendQueue.clear ();
		if (!msgs.empty ())
			other->SendI2NPMessages (msgs);
	}

	size_t NTCP2Session::CreatePaddingBlock (size_t msgLen, uint8_t * buf, size_t len)
	{
		if (len < 3) return 0;
		len -= 3;
		if (msgLen < 256) msgLen = 256; // for short message padding should not be always zero
		size_t paddingSize = (msgLen*NTCP2_MAX_PADDING_RATIO)/100;
		if (msgLen + paddingSize + 3 > NTCP2_UNENCRYPTED_FRAME_MAX_SIZE)
		{
			int l = (int)NTCP2_UNENCRYPTED_FRAME_MAX_SIZE - msgLen -3;
			if (l <= 0) return 0;
			paddingSize = l;
		}
		if (paddingSize > len) paddingSize = len;
		if (paddingSize)
		{
			if (m_NextPaddingSize >= 16)
			{
				RAND_bytes ((uint8_t *)m_PaddingSizes, sizeof (m_PaddingSizes));
				m_NextPaddingSize = 0;
			}
			paddingSize = m_PaddingSizes[m_NextPaddingSize++] % (paddingSize + 1);
		}
		buf[0] = eNTCP2BlkPadding; // blk
		htobe16buf (buf + 1, paddingSize); // size
		memset (buf + 3, 0, paddingSize);
		return paddingSize + 3;
	}

	void NTCP2Session::SendRouterInfo ()
	{
		if (!IsEstablished ()) return;
		auto riBuffer =  i2p::context.CopyRouterInfoBuffer ();
		auto riLen = riBuffer->GetBufferLen ();
		size_t payloadLen = riLen + 3 + 1 + 7; // 3 bytes block header + 1 byte RI flag + 7 bytes DateTime
		m_NextSendBuffer = new uint8_t[payloadLen + 16 + 2 + 64]; // up to 64 bytes padding
		// DateTime	block
		m_NextSendBuffer[2] = eNTCP2BlkDateTime;
		htobe16buf (m_NextSendBuffer + 3, 4);
		htobe32buf (m_NextSendBuffer + 5, (i2p::util::GetMillisecondsSinceEpoch () + 500)/1000);
		// RouterInfo block
		m_NextSendBuffer[9] = eNTCP2BlkRouterInfo;
		htobe16buf (m_NextSendBuffer + 10, riLen + 1); // size
		m_NextSendBuffer[12] = 0; // flag
		memcpy (m_NextSendBuffer + 13, riBuffer->data (), riLen); // TODO: eliminate extra copy
		// padding block
		auto paddingSize = CreatePaddingBlock (payloadLen, m_NextSendBuffer + 2 + payloadLen, 64);
		payloadLen += paddingSize;
		// encrypt and send
		EncryptAndSendNextBuffer (payloadLen);
	}

	void NTCP2Session::SendTermination (NTCP2TerminationReason reason)
	{
		if (!m_SendKey ||
#if OPENSSL_SIPHASH
			!m_SendMDCtx
#else
			!m_SendSipKey
#endif
		) return;
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
		boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ())); // let termination message go
	}

	void NTCP2Session::ReadSomethingAndTerminate ()
	{
		size_t len = m_Server.GetRng ()() % NTCP2_SESSION_HANDSHAKE_MAX_SIZE;
		if (len > 0 && m_Establisher)
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_Establisher->m_Buffer, len), boost::asio::transfer_all (),
				[s = shared_from_this()](const boost::system::error_code& ecode, size_t bytes_transferred)
			    {
					s->Terminate ();
				});
		else
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::Terminate, shared_from_this ()));
	}

	void NTCP2Session::SendI2NPMessages (std::list<std::shared_ptr<I2NPMessage> >& msgs)
	{
		if (m_IsTerminated || msgs.empty ())
		{
			msgs.clear ();
			return;
		}
		bool empty = false;
		{
			std::lock_guard<std::mutex> l(m_IntermediateQueueMutex);
			empty = m_IntermediateQueue.empty ();
			m_IntermediateQueue.splice (m_IntermediateQueue.end (), msgs);
		}
		if (empty)
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::PostI2NPMessages, shared_from_this ()));
	}

	void NTCP2Session::PostI2NPMessages ()
	{
		if (m_IsTerminated) return;
		std::list<std::shared_ptr<I2NPMessage> > msgs;
		{
			std::lock_guard<std::mutex> l(m_IntermediateQueueMutex);
			m_IntermediateQueue.swap (msgs);
		}
		bool isSemiFull = m_SendQueue.size () > NTCP2_MAX_OUTGOING_QUEUE_SIZE/2;
		if (isSemiFull)
		{
			for (auto it: msgs)
				if (it->onDrop)
					it->Drop (); // drop earlier because we can handle it
				else
					m_SendQueue.push_back (std::move (it));
		}
		else
			m_SendQueue.splice (m_SendQueue.end (), msgs);

		if (!m_IsSending && m_IsEstablished)
			SendQueue ();
		else if (m_SendQueue.size () > NTCP2_MAX_OUTGOING_QUEUE_SIZE)
		{
			LogPrint (eLogWarning, "NTCP2: Outgoing messages queue size to ",
				GetIdentHashBase64(), " exceeds ", NTCP2_MAX_OUTGOING_QUEUE_SIZE);
			Terminate ();
		}
		SetSendQueueSize (m_SendQueue.size ());
	}

	void NTCP2Session::SendLocalRouterInfo (bool update)
	{
		if (update || !IsOutgoing ()) // we send it in SessionConfirmed for outgoing session
			boost::asio::post (m_Server.GetService (), std::bind (&NTCP2Session::SendRouterInfo, shared_from_this ()));
	}

	i2p::data::RouterInfo::SupportedTransports NTCP2Session::GetTransportType () const
	{
		if (m_RemoteEndpoint.address ().is_v4 ()) return i2p::data::RouterInfo::eNTCP2V4;
		return i2p::util::net::IsYggdrasilAddress (m_RemoteEndpoint.address ()) ? i2p::data::RouterInfo::eNTCP2V6Mesh : i2p::data::RouterInfo::eNTCP2V6;
	}

	NTCP2Server::NTCP2Server ():
		RunnableServiceWithWork ("NTCP2"), m_TerminationTimer (GetService ()),
		m_ProxyType(eNoProxy), m_Resolver(GetService ()),
		m_Rng(i2p::util::GetMonotonicMicroseconds ()%1000000LL),
		m_EstablisherService (m_Rng ()),
		m_Version (2)
	{
	}

	NTCP2Server::~NTCP2Server ()
	{
		Stop ();
	}

	void NTCP2Server::Start ()
	{
		m_EstablisherService.Start ();
		if (!IsRunning ())
		{
			StartIOService ();
			if(UsingProxy())
			{
				LogPrint(eLogInfo, "NTCP2: Using proxy to connect to peers");
				// TODO: resolve proxy until it is resolved
				boost::system::error_code e;
				auto itr = m_Resolver.resolve(m_ProxyAddress, std::to_string(m_ProxyPort), e);
				if(e)
					LogPrint(eLogCritical, "NTCP2: Failed to resolve proxy ", e.message());
				else
				{
					m_ProxyEndpoint.reset (new boost::asio::ip::tcp::endpoint(*itr.begin ()));
					if (m_ProxyEndpoint)
						LogPrint(eLogDebug, "NTCP2: m_ProxyEndpoint ", *m_ProxyEndpoint);
				}
			}
			else
				LogPrint(eLogInfo, "NTCP2: Proxy is not used");
			// start acceptors
			auto addresses = context.GetRouterInfo ().GetAddresses ();
			if (!addresses) return;
			for (const auto& address: *addresses)
			{
				if (!address) continue;
				if (address->IsPublishedNTCP2 () && address->port)
				{
					if (address->IsV4())
					{
						try
						{
							auto ep = m_Address4 ? boost::asio::ip::tcp::endpoint (m_Address4->address(), address->port):
								boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), address->port);
							m_NTCP2Acceptor.reset (new boost::asio::ip::tcp::acceptor (GetService (), ep));
						}
						catch ( std::exception & ex )
						{
							LogPrint(eLogCritical, "NTCP2: Failed to bind to v4 port ", address->port, ex.what());
							ThrowFatal ("Unable to start IPv4 NTCP2 transport at port ", address->port, ": ", ex.what ());
							continue;
						}

						LogPrint (eLogInfo, "NTCP2: Start listening v4 TCP port ", address->port);
						auto conn = std::make_shared<NTCP2Session>(*this);
						m_NTCP2Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAccept, this, conn, std::placeholders::_1));
					}
					else if (address->IsV6() && (context.SupportsV6 () || context.SupportsMesh ()))
					{
#if defined(__HAIKU__)
						LogPrint (eLogInfo, "NTCP2: Can't listen v6 TCP port ", address->port, ". IPV6_V6ONLY is not supported");
						continue; // IPV6_V6ONLY is not supported. Don't listen ipv6
#endif
						m_NTCP2V6Acceptor.reset (new boost::asio::ip::tcp::acceptor (GetService ()));
						try
						{
							m_NTCP2V6Acceptor->open (boost::asio::ip::tcp::v6());
							m_NTCP2V6Acceptor->set_option (boost::asio::ip::v6_only (true));
							m_NTCP2V6Acceptor->set_option (boost::asio::socket_base::reuse_address (true));
#if defined(__linux__) && !defined(_NETINET_IN_H)
							if (!m_Address6 && !m_YggdrasilAddress) // only if not binded to address
							{
								// Set preference to use public IPv6 address -- tested on linux, not works on windows, and not tested on others
#if (BOOST_VERSION >= 105500)
								typedef boost::asio::detail::socket_option::integer<BOOST_ASIO_OS_DEF(IPPROTO_IPV6), IPV6_ADDR_PREFERENCES> ipv6PreferAddr;
#else
								typedef boost::asio::detail::socket_option::integer<IPPROTO_IPV6, IPV6_ADDR_PREFERENCES> ipv6PreferAddr;
#endif
								m_NTCP2V6Acceptor->set_option (ipv6PreferAddr(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_NONCGA));
							}
#endif
							auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), address->port);
							if (m_Address6 && !context.SupportsMesh ())
								ep = boost::asio::ip::tcp::endpoint (m_Address6->address(), address->port);
							else if (m_YggdrasilAddress && !context.SupportsV6 ())
								ep = boost::asio::ip::tcp::endpoint (m_YggdrasilAddress->address(), address->port);
							m_NTCP2V6Acceptor->bind (ep);
							m_NTCP2V6Acceptor->listen ();

							LogPrint (eLogInfo, "NTCP2: Start listening v6 TCP port ", address->port);
							auto conn = std::make_shared<NTCP2Session> (*this);
							m_NTCP2V6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAcceptV6, this, conn, std::placeholders::_1));
						}
						catch ( std::exception & ex )
						{
							LogPrint(eLogCritical, "NTCP2: Failed to bind to v6 port ", address->port, ": ", ex.what());
							ThrowFatal ("Unable to start IPv6 NTCP2 transport at port ", address->port, ": ", ex.what ());
							continue;
						}
					}
				}
			}
			ScheduleTermination ();
		}
	}

	void NTCP2Server::Stop ()
	{
		m_EstablisherService.Stop ();
		{
			// we have to copy it because Terminate changes m_NTCP2Sessions
			auto ntcpSessions = m_NTCP2Sessions;
			for (auto& it: ntcpSessions)
				it.second->Terminate ();
			for (auto& it: m_PendingIncomingSessions)
				it.second->Terminate ();
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
			m_PendingIncomingSessions.erase (session->GetRemoteEndpoint ().address ());
		if (!session->GetRemoteIdentity ())
		{
			LogPrint (eLogWarning, "NTCP2: Unknown identity for ", session->GetRemoteEndpoint ());
			session->Terminate ();
			return false;
		}
		auto& ident = session->GetRemoteIdentity ()->GetIdentHash ();
		auto it = m_NTCP2Sessions.find (ident);
		if (it != m_NTCP2Sessions.end ())
		{
			LogPrint (eLogWarning, "NTCP2: Session with ", ident.ToBase64 (), " already exists. ", incoming ? "Replaced" : "Dropped");
			if (incoming)
			{
				// replace by new session
				auto s = it->second;
				s->MoveSendQueue (session);
				m_NTCP2Sessions.erase (it);
				s->Terminate ();
			}
			else
			{
				session->Terminate ();
				return false;
			}
		}
		m_NTCP2Sessions.emplace (ident, session);
		return true;
	}

	void NTCP2Server::RemoveNTCP2Session (std::shared_ptr<NTCP2Session> session)
	{
		if (session && session->GetRemoteIdentity ())
		{
			auto it = m_NTCP2Sessions.find (session->GetRemoteIdentity ()->GetIdentHash ());
			if (it != m_NTCP2Sessions.end () && it->second == session)
				m_NTCP2Sessions.erase (it);
		}
	}

	std::shared_ptr<NTCP2Session> NTCP2Server::FindNTCP2Session (const i2p::data::IdentHash& ident)
	{
		auto it = m_NTCP2Sessions.find (ident);
		if (it != m_NTCP2Sessions.end ())
			return it->second;
		return nullptr;
	}

	void NTCP2Server::Connect(std::shared_ptr<NTCP2Session> conn)
	{
		if (!conn || conn->GetRemoteEndpoint ().address ().is_unspecified ())
		{
			LogPrint (eLogError, "NTCP2: Can't connect to unspecified address");
			return;
		}
		LogPrint (eLogDebug, "NTCP2: Connecting to ", conn->GetRemoteEndpoint (),
			" (", i2p::data::GetIdentHashAbbreviation (conn->GetRemoteIdentity ()->GetIdentHash ()), ")");
		boost::asio::post (GetService (), [this, conn]()
			{
				if (this->AddNTCP2Session (conn))
				{
					auto timer = std::make_shared<boost::asio::steady_timer>(GetService ());
					auto timeout = NTCP2_CONNECT_TIMEOUT * 5;
					conn->SetTerminationTimeout(timeout * 2);
					timer->expires_after (std::chrono::seconds(timeout));
					timer->async_wait ([conn, timeout](const boost::system::error_code& ecode)
					{
						if (ecode != boost::asio::error::operation_aborted)
						{
							LogPrint (eLogInfo, "NTCP2: Not connected in ", timeout, " seconds");
							conn->Terminate ();
						}
					});
					// bind to local address
					std::shared_ptr<boost::asio::ip::tcp::endpoint> localAddress;
					if (conn->GetRemoteEndpoint ().address ().is_v6 ())
					{
						if (i2p::util::net::IsYggdrasilAddress (conn->GetRemoteEndpoint ().address ()))
							localAddress = m_YggdrasilAddress;
						else
							localAddress = m_Address6;
						conn->GetSocket ().open (boost::asio::ip::tcp::v6 ());
					}
					else
					{
						localAddress = m_Address4;
						conn->GetSocket ().open (boost::asio::ip::tcp::v4 ());
					}
					if (localAddress)
					{
						boost::system::error_code ec;
						conn->GetSocket ().bind (*localAddress, ec);
						if (ec)
							LogPrint (eLogError, "NTCP2: Can't bind to ", localAddress->address ().to_string (), ": ", ec.message ());
					}
					conn->GetSocket ().async_connect (conn->GetRemoteEndpoint (), std::bind (&NTCP2Server::HandleConnect, this, std::placeholders::_1, conn, timer));
				}
				else
					conn->Terminate ();
			});
	}

	void NTCP2Server::HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn, std::shared_ptr<boost::asio::steady_timer> timer)
	{
		timer->cancel ();
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP2: Connect error ", ecode.message ());
			conn->Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP2: Connected to ", conn->GetRemoteEndpoint (),
				" (", i2p::data::GetIdentHashAbbreviation (conn->GetRemoteIdentity ()->GetIdentHash ()), ")");
			conn->ClientLogin ();
		}
	}

	void NTCP2Server::HandleAccept (std::shared_ptr<NTCP2Session> conn, const boost::system::error_code& error)
	{
		if (!error && conn)
		{
			boost::system::error_code ec;
			auto ep = conn->GetSocket ().remote_endpoint(ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "NTCP2: Connected from ", ep);
				if (!i2p::transport::transports.IsInReservedRange(ep.address ()) && !i2p::transport::transports.IsBanned(ep.address ()))
				{
					if (m_PendingIncomingSessions.emplace (ep.address (), conn).second)
					{
						conn->SetRemoteEndpoint (ep);
						conn->ServerLogin (m_Version);
						conn = nullptr;
					}
					else
						LogPrint (eLogInfo, "NTCP2: Incoming session from ", ep.address (), " is already pending");
				}
				else
					LogPrint (eLogError, "NTCP2: Incoming connection from invalid or banned IP ", ep.address ());
			}
			else
				LogPrint (eLogError, "NTCP2: Connected from error ", ec.message ());
		}
		else
		{
			LogPrint (eLogError, "NTCP2: Accept error ", error.message ());
			if (error == boost::asio::error::no_descriptors)
			{
				i2p::context.SetError (eRouterErrorNoDescriptors);
				return;
			}
		}

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
		if (!error && conn)
		{
			boost::system::error_code ec;
			auto ep = conn->GetSocket ().remote_endpoint(ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "NTCP2: Connected from ", ep);
				if ((!i2p::transport::transports.IsInReservedRange(ep.address ()) ||
				    i2p::util::net::IsYggdrasilAddress (ep.address ())) &&
				    !i2p::transport::transports.IsBanned(ep.address ()))
				{
					if (m_PendingIncomingSessions.emplace (ep.address (), conn).second)
					{
						conn->SetRemoteEndpoint (ep);
						conn->ServerLogin (i2p::util::net::IsYggdrasilAddress (ep.address ()) ? 2 : m_Version); // yggdrasil is always 2 for now
						conn = nullptr;
					}
					else
						LogPrint (eLogInfo, "NTCP2: Incoming session from ", ep.address (), " is already pending");
				}
				else
					LogPrint (eLogError, "NTCP2: Incoming connection from invalid or banned IP ", ep.address ());
			}
			else
				LogPrint (eLogError, "NTCP2: Connected from error ", ec.message ());
		}
		else
		{
			LogPrint (eLogError, "NTCP2: Accept ipv6 error ", error.message ());
			if (error == boost::asio::error::no_descriptors)
			{
				i2p::context.SetErrorV6 (eRouterErrorNoDescriptors);
				return;
			}
		}

		if (error != boost::asio::error::operation_aborted)
		{
			if (!conn) // connection is used, create new one
				conn = std::make_shared<NTCP2Session> (*this);
			else // reuse failed
				conn->Close ();
			m_NTCP2V6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAcceptV6, this,
				conn, std::placeholders::_1));
		}
	}

	void NTCP2Server::ScheduleTermination ()
	{
		m_TerminationTimer.expires_after (std::chrono::seconds(
			NTCP2_TERMINATION_CHECK_TIMEOUT + m_Rng () % NTCP2_TERMINATION_CHECK_TIMEOUT_VARIANCE));
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
				else
					it.second->DeleteNextReceiveBuffer (ts);
			// pending
			for (auto it = m_PendingIncomingSessions.begin (); it != m_PendingIncomingSessions.end ();)
			{
				if (it->second->IsEstablished () || it->second->IsTerminationTimeoutExpired (ts))
				{
					it->second->Terminate ();
					it = m_PendingIncomingSessions.erase (it); // established of expired
				}
				else if (it->second->IsTerminated ())
					it = m_PendingIncomingSessions.erase (it); // already terminated
				else
					it++;
			}
			ScheduleTermination ();

			// try to restart acceptors if no description
			// we do it after timer to let timer take descriptor first
			if (i2p::context.GetError () == eRouterErrorNoDescriptors)
			{
				i2p::context.SetError (eRouterErrorNone);
				auto conn = std::make_shared<NTCP2Session> (*this);
				m_NTCP2Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAccept, this,
					conn, std::placeholders::_1));
			}
			if (i2p::context.GetErrorV6 () == eRouterErrorNoDescriptors)
			{
				i2p::context.SetErrorV6 (eRouterErrorNone);
				auto conn = std::make_shared<NTCP2Session> (*this);
				m_NTCP2V6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCP2Server::HandleAcceptV6, this,
					conn, std::placeholders::_1));
			}
		}
	}

	void NTCP2Server::ConnectWithProxy (std::shared_ptr<NTCP2Session> conn)
	{
		if(!m_ProxyEndpoint) return;
		if (!conn || conn->GetRemoteEndpoint ().address ().is_unspecified ())
		{
			LogPrint (eLogError, "NTCP2: Can't connect to unspecified address");
			return;
		}
		boost::asio::post (GetService(), [this, conn]()
		{
			if (this->AddNTCP2Session (conn))
			{
				auto timer = std::make_shared<boost::asio::steady_timer>(GetService());
				auto timeout = NTCP2_CONNECT_TIMEOUT * 5;
				conn->SetTerminationTimeout(timeout * 2);
				timer->expires_after (std::chrono::seconds(timeout));
				timer->async_wait ([conn, timeout](const boost::system::error_code& ecode)
				{
					if (ecode != boost::asio::error::operation_aborted)
					{
						LogPrint (eLogInfo, "NTCP2: Not connected in ", timeout, " seconds");
						conn->Terminate ();
					}
				});
				conn->GetSocket ().async_connect (*m_ProxyEndpoint, std::bind (&NTCP2Server::HandleProxyConnect, this, std::placeholders::_1, conn, timer));
			}
		});
	}

	void NTCP2Server::UseProxy(ProxyType proxytype, const std::string& addr, uint16_t port,
		const std::string& user, const std::string& pass)
	{
		m_ProxyType = proxytype;
		m_ProxyAddress = addr;
		m_ProxyPort = port;
		if (m_ProxyType == eHTTPProxy )
			m_ProxyAuthorization = i2p::http::CreateBasicAuthorizationString (user, pass);
	}

	void NTCP2Server::HandleProxyConnect(const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn, std::shared_ptr<boost::asio::steady_timer> timer)
	{
		if (ecode)
		{
			LogPrint(eLogWarning, "NTCP2: Failed to connect to proxy ", ecode.message());
			timer->cancel();
			conn->Terminate();
			return;
		}
		switch (m_ProxyType)
		{
			case eSocksProxy:
			{
				// TODO: support username/password auth etc
				Socks5Handshake (conn->GetSocket(), conn->GetRemoteEndpoint (),
					[conn, timer](const boost::system::error_code& ec)
				    {
						timer->cancel();
						if (!ec)
							conn->ClientLogin();
						else
						{
							LogPrint(eLogError, "NTCP2: SOCKS proxy handshake error ", ec.message());
							conn->Terminate();
						}
					});
				break;
			}
			case eHTTPProxy:
			{
				auto& ep = conn->GetRemoteEndpoint ();
				i2p::http::HTTPReq req;
				req.method = "CONNECT";
				req.version ="HTTP/1.1";
				if(ep.address ().is_v6 ())
					req.uri = "[" + ep.address ().to_string() + "]:" + std::to_string(ep.port ());
				else
					req.uri = ep.address ().to_string() + ":" + std::to_string(ep.port ());
				if (!m_ProxyAuthorization.empty ())
					req.AddHeader("Proxy-Authorization", m_ProxyAuthorization);

				boost::asio::streambuf writebuff;
				std::ostream out(&writebuff);
				out << req.to_string();

				boost::asio::async_write(conn->GetSocket(), writebuff.data(), boost::asio::transfer_all(),
					[](const boost::system::error_code & ec, std::size_t transferred)
					{
						(void) transferred;
						if(ec)
							LogPrint(eLogError, "NTCP2: HTTP proxy write error ", ec.message());
					});

				auto readbuff = std::make_shared<boost::asio::streambuf>();
				boost::asio::async_read_until(conn->GetSocket(), *readbuff, "\r\n\r\n",
					[readbuff, timer, conn] (const boost::system::error_code & ec, std::size_t transferred)
					{
						if(ec)
						{
							LogPrint(eLogError, "NTCP2: HTTP proxy read error ", ec.message());
							timer->cancel();
							conn->Terminate();
						}
						else
						{
							readbuff->commit(transferred);
							i2p::http::HTTPRes res;
							if(res.parse(std::string {boost::asio::buffers_begin(readbuff->data ()), boost::asio::buffers_begin(readbuff->data ()) + readbuff->size ()}) > 0)
							{
								if(res.code == 200)
								{
									timer->cancel();
									conn->ClientLogin();
									return;
								}
								else
									LogPrint(eLogError, "NTCP2: HTTP proxy rejected request ", res.code);
							}
							else
								LogPrint(eLogError, "NTCP2: HTTP proxy gave malformed response");
							timer->cancel();
							conn->Terminate();
						}
					});
				break;
			}
			default:
				LogPrint(eLogError, "NTCP2: Unknown proxy type, invalid state");
		}
	}

	void NTCP2Server::SetLocalAddress (const boost::asio::ip::address& localAddress)
	{
		auto addr = std::make_shared<boost::asio::ip::tcp::endpoint>(boost::asio::ip::tcp::endpoint(localAddress, 0));
		if (localAddress.is_v6 ())
		{
			if (i2p::util::net::IsYggdrasilAddress (localAddress))
				m_YggdrasilAddress = addr;
			else
				m_Address6 = addr;
		}
		else
			m_Address4 = addr;
	}

	void NTCP2Server::AEADChaCha20Poly1305Encrypt (const std::vector<std::pair<uint8_t *, size_t> >& bufs,
		const uint8_t * key, const uint8_t * nonce, uint8_t * mac)
	{
		return m_Encryptor.Encrypt (bufs, key, nonce, mac);
	}

	bool NTCP2Server::AEADChaCha20Poly1305Decrypt (const uint8_t * msg, size_t msgLen,
		const uint8_t * ad, size_t adLen, const uint8_t * key, const uint8_t * nonce, uint8_t * buf, size_t len)
	{
		return m_Decryptor.Decrypt (msg, msgLen, ad, adLen, key, nonce, buf, len);
	}

	void NTCP2Server::SetVersion (int version)
	{
#if OPENSSL_MLKEM
        m_Version = version;
#endif
	}
}
}
