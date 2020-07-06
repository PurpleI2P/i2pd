/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <stdlib.h>
#include <future>

#include "I2PEndian.h"
#include "Base.h"
#include "Crypto.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "RouterContext.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "NTCPSession.h"
#include "HTTP.h"
#include "util.h"

using namespace i2p::crypto;

namespace i2p
{
namespace transport
{

	struct NTCPWork
	{
		std::shared_ptr<NTCPSession> session;
	};

	NTCPSession::NTCPSession (NTCPServer& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter):
		TransportSession (in_RemoteRouter, NTCP_ESTABLISH_TIMEOUT),
		m_Server (server), m_Socket (m_Server.GetService ()),
		m_IsEstablished (false), m_IsTerminated (false),
		m_ReceiveBufferOffset (0), m_NextMessage (nullptr), m_IsSending (false)
	{
		m_Establisher = new Establisher;
	}

	NTCPSession::~NTCPSession ()
	{
		delete m_Establisher;
	}

	void NTCPSession::CreateAESKey (uint8_t * pubKey)
	{
		uint8_t sharedKey[256];
		m_DHKeysPair->Agree (pubKey, sharedKey); // time consuming operation

		i2p::crypto::AESKey aesKey;
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
					LogPrint (eLogWarning, "NTCP: First 32 bytes of shared key is all zeros, ignored");
					return;
				}
			}
			memcpy (aesKey, nonZero, 32);
		}

		m_Decryption.SetKey (aesKey);
		m_Encryption.SetKey (aesKey);
	}

	void NTCPSession::Done ()
	{
		m_Server.GetService ().post (std::bind (&NTCPSession::Terminate, shared_from_this ()));
	}

	void NTCPSession::Terminate ()
	{
		if (!m_IsTerminated)
		{
			m_IsTerminated = true;
			m_IsEstablished = false;
			m_Socket.close ();
			transports.PeerDisconnected (shared_from_this ());
			m_Server.RemoveNTCPSession (shared_from_this ());
			m_SendQueue.clear ();
			m_NextMessage = nullptr;
			LogPrint (eLogDebug, "NTCP: session terminated");
		}
	}

	void NTCPSession::Connected ()
	{
		m_IsEstablished = true;

		delete m_Establisher;
		m_Establisher = nullptr;

		m_DHKeysPair = nullptr;

		SetTerminationTimeout (NTCP_TERMINATION_TIMEOUT);
		SendTimeSyncMessage ();
		transports.PeerConnected (shared_from_this ());
	}

	boost::asio::io_service & NTCPSession::GetService()
	{
		return m_Server.GetService();
	}

	void NTCPSession::ClientLogin ()
	{
		if (!m_DHKeysPair)
			m_DHKeysPair = transports.GetNextDHKeysPair ();
		// send Phase1
		const uint8_t * x = m_DHKeysPair->GetPublicKey ();
		memcpy (m_Establisher->phase1.pubKey, x, 256);
		SHA256(x, 256, m_Establisher->phase1.HXxorHI);
		const uint8_t * ident = m_RemoteIdentity->GetIdentHash ();
		for (int i = 0; i < 32; i++)
			m_Establisher->phase1.HXxorHI[i] ^= ident[i];

		boost::asio::async_write (m_Socket, boost::asio::buffer (&m_Establisher->phase1, sizeof (NTCPPhase1)), boost::asio::transfer_all (),
			std::bind(&NTCPSession::HandlePhase1Sent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCPSession::ServerLogin ()
	{
		m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
		// receive Phase1
		boost::asio::async_read (m_Socket, boost::asio::buffer(&m_Establisher->phase1, sizeof (NTCPPhase1)), boost::asio::transfer_all (),
			std::bind(&NTCPSession::HandlePhase1Received, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
	}

	void NTCPSession::HandlePhase1Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: couldn't send Phase 1 message: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			boost::asio::async_read (m_Socket, boost::asio::buffer(&m_Establisher->phase2, sizeof (NTCPPhase2)), boost::asio::transfer_all (),
				std::bind(&NTCPSession::HandlePhase2Received, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2));
		}
	}

	void NTCPSession::HandlePhase1Received (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: phase 1 read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			// verify ident
			uint8_t digest[32];
			SHA256(m_Establisher->phase1.pubKey, 256, digest);
			const uint8_t * ident = i2p::context.GetIdentHash ();
			for (int i = 0; i < 32; i++)
			{
				if ((m_Establisher->phase1.HXxorHI[i] ^ ident[i]) != digest[i])
				{
					LogPrint (eLogError, "NTCP: phase 1 error: ident mismatch");
					Terminate ();
					return;
				}
			}
			// TODO: check for number of pending keys
			auto work = new NTCPWork{shared_from_this()};
			m_Server.Work(work->session, [work, this]() -> std::function<void(void)> {
					if (!work->session->m_DHKeysPair)
						work->session->m_DHKeysPair = transports.GetNextDHKeysPair ();
					work->session->CreateAESKey (work->session->m_Establisher->phase1.pubKey);
					return std::bind(&NTCPSession::SendPhase2, work->session, work);
			});
		}
	}

	void NTCPSession::SendPhase2 (NTCPWork * work)
	{
		if(work)
			delete work;
		const uint8_t * y = m_DHKeysPair->GetPublicKey ();
		memcpy (m_Establisher->phase2.pubKey, y, 256);
		uint8_t xy[512];
		memcpy (xy, m_Establisher->phase1.pubKey, 256);
		memcpy (xy + 256, y, 256);
		SHA256(xy, 512, m_Establisher->phase2.encrypted.hxy);
		uint32_t tsB = htobe32 (i2p::util::GetSecondsSinceEpoch ());
		memcpy (m_Establisher->phase2.encrypted.timestamp, &tsB, 4);
		RAND_bytes (m_Establisher->phase2.encrypted.filler, 12);

		m_Encryption.SetIV (y + 240);
		m_Decryption.SetIV (m_Establisher->phase1.HXxorHI + 16);

		m_Encryption.Encrypt ((uint8_t *)&m_Establisher->phase2.encrypted, sizeof(m_Establisher->phase2.encrypted), (uint8_t *)&m_Establisher->phase2.encrypted);
		boost::asio::async_write(m_Socket, boost::asio::buffer (&m_Establisher->phase2, sizeof (NTCPPhase2)), boost::asio::transfer_all(),
			std::bind(&NTCPSession::HandlePhase2Sent, shared_from_this(), std::placeholders::_1, std::placeholders::_2, tsB));
	}

	void NTCPSession::HandlePhase2Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: Couldn't send Phase 2 message: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_ReceiveBuffer, NTCP_DEFAULT_PHASE3_SIZE), boost::asio::transfer_all (),
				std::bind(&NTCPSession::HandlePhase3Received, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2, tsB));
		}
	}

	void NTCPSession::HandlePhase2Received (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: Phase 2 read error: ", ecode.message (), ". Wrong ident assumed");
			if (ecode != boost::asio::error::operation_aborted)
			{
				// this RI is not valid
				i2p::data::netdb.SetUnreachable (GetRemoteIdentity ()->GetIdentHash (), true);
				transports.ReuseDHKeysPair (m_DHKeysPair);
				m_DHKeysPair = nullptr;
				Terminate ();
			}
		}
		else
		{
			auto work = new NTCPWork{shared_from_this()};
			m_Server.Work(work->session, [work, this]() -> std::function<void(void)> {
				work->session->CreateAESKey (work->session->m_Establisher->phase2.pubKey);
				return std::bind(&NTCPSession::HandlePhase2, work->session, work);
			});
		}
	}

	void NTCPSession::HandlePhase2 (NTCPWork * work)
	{
		if(work) delete work;
		m_Decryption.SetIV (m_Establisher->phase2.pubKey + 240);
		m_Encryption.SetIV (m_Establisher->phase1.HXxorHI + 16);

		m_Decryption.Decrypt((uint8_t *)&m_Establisher->phase2.encrypted, sizeof(m_Establisher->phase2.encrypted), (uint8_t *)&m_Establisher->phase2.encrypted);
		// verify
		uint8_t xy[512];
		memcpy (xy, m_DHKeysPair->GetPublicKey (), 256);
		memcpy (xy + 256, m_Establisher->phase2.pubKey, 256);
		uint8_t digest[32];
		SHA256 (xy, 512, digest);
		if (memcmp(m_Establisher->phase2.encrypted.hxy, digest, 32))
		{
			LogPrint (eLogError, "NTCP: Phase 2 process error: incorrect hash");
			transports.ReuseDHKeysPair (m_DHKeysPair);
			m_DHKeysPair = nullptr;
			Terminate ();
			return ;
		}
		SendPhase3 ();
	}

	void NTCPSession::SendPhase3 ()
	{
		auto& keys = i2p::context.GetPrivateKeys ();
		uint8_t * buf = m_ReceiveBuffer;
		htobe16buf (buf, keys.GetPublic ()->GetFullLen ());
		buf += 2;
		buf += i2p::context.GetIdentity ()->ToBuffer (buf, NTCP_BUFFER_SIZE);
		uint32_t tsA = htobe32 (i2p::util::GetSecondsSinceEpoch ());
		htobuf32(buf,tsA);
		buf += 4;
		size_t signatureLen = keys.GetPublic ()->GetSignatureLen ();
		size_t len = (buf - m_ReceiveBuffer) + signatureLen;
		size_t paddingSize = len & 0x0F; // %16
		if (paddingSize > 0)
		{
			paddingSize = 16 - paddingSize;
			// fill padding with random data
			RAND_bytes(buf, paddingSize);
			buf += paddingSize;
			len += paddingSize;
		}

		SignedData s;
		s.Insert (m_Establisher->phase1.pubKey, 256); // x
		s.Insert (m_Establisher->phase2.pubKey, 256); // y
		s.Insert (m_RemoteIdentity->GetIdentHash (), 32); // ident
		s.Insert (tsA);	// tsA
		s.Insert (m_Establisher->phase2.encrypted.timestamp, 4); // tsB
		s.Sign (keys, buf);

		m_Encryption.Encrypt(m_ReceiveBuffer, len, m_ReceiveBuffer);
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_ReceiveBuffer, len), boost::asio::transfer_all (),
			std::bind(&NTCPSession::HandlePhase3Sent, shared_from_this (), std::placeholders::_1, std::placeholders::_2, tsA));
	}

	void NTCPSession::HandlePhase3Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: Couldn't send Phase 3 message: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			// wait for phase4
			auto signatureLen = m_RemoteIdentity->GetSignatureLen ();
			size_t paddingSize = signatureLen & 0x0F; // %16
			if (paddingSize > 0) signatureLen += (16 - paddingSize);
			boost::asio::async_read (m_Socket, boost::asio::buffer(m_ReceiveBuffer, signatureLen), boost::asio::transfer_all (),
				std::bind(&NTCPSession::HandlePhase4Received, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2, tsA));
		}
	}

	void NTCPSession::HandlePhase3Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB)
	{
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: Phase 3 read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			m_Decryption.Decrypt (m_ReceiveBuffer, bytes_transferred, m_ReceiveBuffer);
			uint8_t * buf = m_ReceiveBuffer;
			uint16_t size = bufbe16toh (buf);
			auto identity = std::make_shared<i2p::data::IdentityEx> (buf + 2, size);
			if (m_Server.FindNTCPSession (identity->GetIdentHash ()))
			{
				LogPrint (eLogInfo, "NTCP: session already exists");
				Terminate ();
			}
			auto existing = i2p::data::netdb.FindRouter (identity->GetIdentHash ()); // check if exists already
			SetRemoteIdentity (existing ? existing->GetRouterIdentity () : identity);

			size_t expectedSize = size + 2/*size*/ + 4/*timestamp*/ + m_RemoteIdentity->GetSignatureLen ();
			size_t paddingLen = expectedSize & 0x0F;
			if (paddingLen) paddingLen = (16 - paddingLen);
			if (expectedSize > NTCP_DEFAULT_PHASE3_SIZE)
			{
				// we need more bytes for Phase3
				expectedSize += paddingLen;
				boost::asio::async_read (m_Socket, boost::asio::buffer(m_ReceiveBuffer + NTCP_DEFAULT_PHASE3_SIZE, expectedSize - NTCP_DEFAULT_PHASE3_SIZE), boost::asio::transfer_all (),
				std::bind(&NTCPSession::HandlePhase3ExtraReceived, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2, tsB, paddingLen));
			}
			else
				HandlePhase3 (tsB, paddingLen);
		}
	}

	void NTCPSession::HandlePhase3ExtraReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB, size_t paddingLen)
	{
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: Phase 3 extra read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			m_Decryption.Decrypt (m_ReceiveBuffer + NTCP_DEFAULT_PHASE3_SIZE, bytes_transferred, m_ReceiveBuffer+ NTCP_DEFAULT_PHASE3_SIZE);
			HandlePhase3 (tsB, paddingLen);
		}
	}

	void NTCPSession::HandlePhase3 (uint32_t tsB, size_t paddingLen)
	{
		uint8_t * buf = m_ReceiveBuffer + m_RemoteIdentity->GetFullLen () + 2 /*size*/;
		uint32_t tsA = buf32toh(buf);
		buf += 4;
		buf += paddingLen;

		// check timestamp
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		uint32_t tsA1 = be32toh (tsA);
		if (tsA1 < ts - NTCP_CLOCK_SKEW || tsA1 > ts + NTCP_CLOCK_SKEW)
		{
			LogPrint (eLogError, "NTCP: Phase3 time difference ", (int)(ts - tsA1), " exceeds clock skew");
			Terminate ();
			return;
		}

		// check signature
		SignedData s;
		s.Insert (m_Establisher->phase1.pubKey, 256); // x
		s.Insert (m_Establisher->phase2.pubKey, 256); // y
		s.Insert (i2p::context.GetRouterInfo ().GetIdentHash (), 32); // ident
		s.Insert (tsA); // tsA
		s.Insert (tsB); // tsB
		if (!s.Verify (m_RemoteIdentity, buf))
		{
			LogPrint (eLogError, "NTCP: signature verification failed");
			Terminate ();
			return;
		}

		SendPhase4 (tsA, tsB);
	}

	void NTCPSession::SendPhase4 (uint32_t tsA, uint32_t tsB)
	{
		SignedData s;
		s.Insert (m_Establisher->phase1.pubKey, 256); // x
		s.Insert (m_Establisher->phase2.pubKey, 256); // y
		s.Insert (m_RemoteIdentity->GetIdentHash (), 32); // ident
		s.Insert (tsA); // tsA
		s.Insert (tsB); // tsB
		auto& keys = i2p::context.GetPrivateKeys ();
		auto signatureLen = keys.GetPublic ()->GetSignatureLen ();
		s.Sign (keys, m_ReceiveBuffer);
		size_t paddingSize = signatureLen & 0x0F; // %16
		if (paddingSize > 0) signatureLen += (16 - paddingSize);
		m_Encryption.Encrypt (m_ReceiveBuffer, signatureLen, m_ReceiveBuffer);

		boost::asio::async_write (m_Socket, boost::asio::buffer (m_ReceiveBuffer, signatureLen), boost::asio::transfer_all (),
			std::bind(&NTCPSession::HandlePhase4Sent, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void NTCPSession::HandlePhase4Sent (const boost::system::error_code& ecode,  std::size_t bytes_transferred)
	{
		(void) bytes_transferred;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP: Couldn't send Phase 4 message: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP: Server session from ", m_Socket.remote_endpoint (), " connected");
			m_Server.AddNTCPSession (shared_from_this ());

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
			LogPrint (eLogError, "NTCP: Phase 4 read error: ", ecode.message (), ". Check your clock");
			if (ecode != boost::asio::error::operation_aborted)
			{
				// this router doesn't like us
				i2p::data::netdb.SetUnreachable (GetRemoteIdentity ()->GetIdentHash (), true);
				Terminate ();
			}
		}
		else
		{
			m_Decryption.Decrypt(m_ReceiveBuffer, bytes_transferred, m_ReceiveBuffer);

			// check timestamp
			uint32_t tsB = bufbe32toh (m_Establisher->phase2.encrypted.timestamp);
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			if (tsB < ts - NTCP_CLOCK_SKEW || tsB > ts + NTCP_CLOCK_SKEW)
			{
				LogPrint (eLogError, "NTCP: Phase4 time difference ", (int)(ts - tsB), " exceeds clock skew");
				Terminate ();
				return;
			}

			// verify signature
			SignedData s;
			s.Insert (m_Establisher->phase1.pubKey, 256); // x
			s.Insert (m_Establisher->phase2.pubKey, 256); // y
			s.Insert (i2p::context.GetIdentHash (), 32); // ident
			s.Insert (tsA); // tsA
			s.Insert (m_Establisher->phase2.encrypted.timestamp, 4); // tsB

			if (!s.Verify (m_RemoteIdentity, m_ReceiveBuffer))
			{
				LogPrint (eLogError, "NTCP: Phase 4 process error: signature verification failed");
				Terminate ();
				return;
			}
			LogPrint (eLogDebug, "NTCP: session to ", m_Socket.remote_endpoint (), " connected");
			Connected ();

			m_ReceiveBufferOffset = 0;
			m_NextMessage = nullptr;
			Receive ();
		}
	}

	void NTCPSession::Receive ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_ReceiveBuffer + m_ReceiveBufferOffset, NTCP_BUFFER_SIZE - m_ReceiveBufferOffset),
			std::bind(&NTCPSession::HandleReceived, shared_from_this (),
			std::placeholders::_1, std::placeholders::_2));
	}

	void NTCPSession::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogDebug, "NTCP: Read error: ", ecode.message ());
			//if (ecode != boost::asio::error::operation_aborted)
			Terminate ();
		}
		else
		{
			m_NumReceivedBytes += bytes_transferred;
			i2p::transport::transports.UpdateReceivedBytes (bytes_transferred);
			m_ReceiveBufferOffset += bytes_transferred;

			if (m_ReceiveBufferOffset >= 16)
			{
				// process received data
				uint8_t * nextBlock = m_ReceiveBuffer;
				while (m_ReceiveBufferOffset >= 16)
				{
					if (!DecryptNextBlock (nextBlock)) // 16 bytes
					{
						Terminate ();
						return;
					}
					nextBlock += 16;
					m_ReceiveBufferOffset -= 16;
				}
				if (m_ReceiveBufferOffset > 0)
					memcpy (m_ReceiveBuffer, nextBlock, m_ReceiveBufferOffset);
			}

			// read and process more is available
			boost::system::error_code ec;
			size_t moreBytes = m_Socket.available(ec);
			if (moreBytes && !ec)
			{
				uint8_t * buf = nullptr, * moreBuf = m_ReceiveBuffer;
				if (moreBytes + m_ReceiveBufferOffset > NTCP_BUFFER_SIZE)
				{
					buf = new uint8_t[moreBytes + m_ReceiveBufferOffset + 16];
					moreBuf = buf;
					uint8_t rem = ((size_t)buf) & 0x0f;
					if (rem) moreBuf += (16 - rem); // align 16
					if (m_ReceiveBufferOffset)
						memcpy (moreBuf, m_ReceiveBuffer, m_ReceiveBufferOffset);
				}
				moreBytes = m_Socket.read_some (boost::asio::buffer (moreBuf + m_ReceiveBufferOffset, moreBytes), ec);
				if (ec)
				{
					LogPrint (eLogInfo, "NTCP: Read more bytes error: ", ec.message ());
					delete[] buf;
					Terminate ();
					return;
				}
				m_ReceiveBufferOffset += moreBytes;
				m_NumReceivedBytes += moreBytes;
				i2p::transport::transports.UpdateReceivedBytes (moreBytes);
				// process more data
				uint8_t * nextBlock = moreBuf;
				while (m_ReceiveBufferOffset >= 16)
				{
					if (!DecryptNextBlock (nextBlock)) // 16 bytes
					{
						delete[] buf;
						Terminate ();
						return;
					}
					nextBlock += 16;
					m_ReceiveBufferOffset -= 16;
				}
				if (m_ReceiveBufferOffset > 0)
					memcpy (m_ReceiveBuffer, nextBlock, m_ReceiveBufferOffset); // nextBlock points to memory inside buf
				delete[] buf;
			}
			m_Handler.Flush ();

			m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
			Receive ();
		}
	}

	bool NTCPSession::DecryptNextBlock (const uint8_t * encrypted) // 16 bytes
	{
		if (!m_NextMessage) // new message, header expected
		{
			// decrypt header and extract length
			uint8_t buf[16];
			m_Decryption.Decrypt (encrypted, buf);
			uint16_t dataSize = bufbe16toh (buf);
			if (dataSize)
			{
				// new message
				if (dataSize + 16U + 15U > NTCP_MAX_MESSAGE_SIZE - 2) // + 6 + padding
				{
					LogPrint (eLogError, "NTCP: data size ", dataSize, " exceeds max size");
					return false;
				}
				m_NextMessage = (dataSize + 16U + 15U) <= I2NP_MAX_SHORT_MESSAGE_SIZE - 2 ? NewI2NPShortMessage () : NewI2NPMessage ();
				m_NextMessage->Align (16);
				m_NextMessage->offset += 2; // size field
				m_NextMessage->len = m_NextMessage->offset + dataSize;
				memcpy (m_NextMessage->GetBuffer () - 2, buf, 16);
				m_NextMessageOffset = 16;
			}
			else
			{
				// timestamp
				int diff = (int)bufbe32toh (buf + 2) - (int)i2p::util::GetSecondsSinceEpoch ();
				LogPrint (eLogInfo, "NTCP: Timestamp. Time difference ", diff, " seconds");
				return true;
			}
		}
		else // message continues
		{
			m_Decryption.Decrypt (encrypted, m_NextMessage->GetBuffer () - 2 + m_NextMessageOffset);
			m_NextMessageOffset += 16;
		}

		if (m_NextMessageOffset >= m_NextMessage->GetLength () + 2 + 4) // +checksum
		{
			// we have a complete I2NP message
			uint8_t checksum[4];
			htobe32buf (checksum, adler32 (adler32 (0, Z_NULL, 0), m_NextMessage->GetBuffer () - 2, m_NextMessageOffset - 4));
			if (!memcmp (m_NextMessage->GetBuffer () - 2 + m_NextMessageOffset - 4, checksum, 4))
			{
				if (!m_NextMessage->IsExpired ())
				{
					m_Handler.PutNextMessage (m_NextMessage);
				}
				else
					LogPrint (eLogInfo, "NTCP: message expired");
			}
			else
				LogPrint (eLogWarning, "NTCP: Incorrect adler checksum of message, dropped");
			m_NextMessage = nullptr;
		}
		return true;
	}

	void NTCPSession::Send (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		m_IsSending = true;
		boost::asio::async_write (m_Socket, CreateMsgBuffer (msg), boost::asio::transfer_all (),
			std::bind(&NTCPSession::HandleSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2, std::vector<std::shared_ptr<I2NPMessage> >{ msg }));
	}

	boost::asio::const_buffers_1 NTCPSession::CreateMsgBuffer (std::shared_ptr<I2NPMessage> msg)
	{
		uint8_t * sendBuffer;
		int len;

		if (msg)
		{
			// regular I2NP
			if (msg->offset < 2)
				LogPrint (eLogError, "NTCP: Malformed I2NP message"); // TODO:
			sendBuffer = msg->GetBuffer () - 2;
			len = msg->GetLength ();
			htobe16buf (sendBuffer, len);
		}
		else
		{
			// prepare timestamp
			sendBuffer = m_TimeSyncBuffer;
			len = 4;
			htobuf16(sendBuffer, 0);
			htobe32buf (sendBuffer + 2, i2p::util::GetSecondsSinceEpoch ());
		}
		int rem = (len + 6) & 0x0F; // %16
		int padding = 0;
		if (rem > 0) {
			padding = 16 - rem;
			// fill with random padding
			RAND_bytes(sendBuffer + len + 2, padding);
		}
		htobe32buf (sendBuffer + len + 2 + padding, adler32 (adler32 (0, Z_NULL, 0), sendBuffer, len + 2+ padding));

		int l = len + padding + 6;
		m_Encryption.Encrypt(sendBuffer, l, sendBuffer);
		return boost::asio::buffer ((const uint8_t *)sendBuffer, l);
	}


	void NTCPSession::Send (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		m_IsSending = true;
		std::vector<boost::asio::const_buffer> bufs;
		for (const auto& it: msgs)
			bufs.push_back (CreateMsgBuffer (it));
		boost::asio::async_write (m_Socket, bufs, boost::asio::transfer_all (),
			std::bind(&NTCPSession::HandleSent, shared_from_this (), std::placeholders::_1, std::placeholders::_2, msgs));
	}

	void NTCPSession::HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		(void) msgs;
		m_IsSending = false;
		if (ecode)
		{
			LogPrint (eLogWarning, "NTCP: Couldn't send msgs: ", ecode.message ());
			// we shouldn't call Terminate () here, because HandleReceive takes care
			// TODO: 'delete this' statement in Terminate () must be eliminated later
			// Terminate ();
		}
		else
		{
			m_LastActivityTimestamp = i2p::util::GetSecondsSinceEpoch ();
			m_NumSentBytes += bytes_transferred;
			i2p::transport::transports.UpdateSentBytes (bytes_transferred);
			if (!m_SendQueue.empty())
			{
				Send (m_SendQueue);
				m_SendQueue.clear ();
			}
		}
	}

	void NTCPSession::SendTimeSyncMessage ()
	{
		Send (nullptr);
	}

	void NTCPSession::SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs)
	{
		m_Server.GetService ().post (std::bind (&NTCPSession::PostI2NPMessages, shared_from_this (), msgs));
	}

	void NTCPSession::PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs)
	{
		if (m_IsTerminated) return;
		if (m_IsSending)
		{
			if (m_SendQueue.size () < NTCP_MAX_OUTGOING_QUEUE_SIZE)
			{
				for (const auto& it: msgs)
					m_SendQueue.push_back (it);
			}
			else
			{
				LogPrint (eLogWarning, "NTCP: outgoing messages queue size exceeds ", NTCP_MAX_OUTGOING_QUEUE_SIZE);
				Terminate ();
			}
		}
		else
			Send (msgs);
	}

//-----------------------------------------
	NTCPServer::NTCPServer (int workers):
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service),
		m_TerminationTimer (m_Service), m_NTCPAcceptor (nullptr), m_NTCPV6Acceptor (nullptr),
		m_ProxyType(eNoProxy), m_Resolver(m_Service), m_ProxyEndpoint(nullptr),
		m_SoftLimit(0), m_HardLimit(0)
	{
		if(workers <= 0) workers = 1;
		m_CryptoPool = std::make_shared<Pool>(workers);
	}

	NTCPServer::~NTCPServer ()
	{
		Stop ();
	}

	void NTCPServer::Start ()
	{
		if (!m_IsRunning)
		{
			m_IsRunning = true;
			m_Thread = new std::thread (std::bind (&NTCPServer::Run, this));
			// we are using a proxy, don't create any acceptors
			if(UsingProxy())
			{
				// TODO: resolve proxy until it is resolved
				boost::asio::ip::tcp::resolver::query q(m_ProxyAddress, std::to_string(m_ProxyPort));
				boost::system::error_code e;
				auto itr = m_Resolver.resolve(q, e);
				if(e)
				{
					LogPrint(eLogError, "NTCP: Failed to resolve proxy ", e.message());
				}
				else
				{
					m_ProxyEndpoint = new boost::asio::ip::tcp::endpoint(*itr);
				}
			}
			else
			{
				// create acceptors
				auto& addresses = context.GetRouterInfo ().GetAddresses ();
				for (const auto& address: addresses)
				{
					if (!address) continue;
					if (address->transportStyle == i2p::data::RouterInfo::eTransportNTCP && !address->IsNTCP2 ())
					{
						if (address->host.is_v4())
						{
							try
							{
								m_NTCPAcceptor = new boost::asio::ip::tcp::acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), address->port));
								LogPrint (eLogInfo, "NTCP: Start listening v6 TCP port ", address->port);
							}
							catch ( std::exception & ex )
							{
								/** fail to bind ip4 */
								LogPrint(eLogError, "NTCP: Failed to bind to v4 port ", address->port, ": ", ex.what());
								ThrowFatal ("Unable to start IPv4 NTCP transport at port ", address->port, ": ", ex.what ());
								continue;
							}

							LogPrint (eLogInfo, "NTCP: Start listening TCP port ", address->port);
							auto conn = std::make_shared<NTCPSession>(*this);
							m_NTCPAcceptor->async_accept(conn->GetSocket (), std::bind (&NTCPServer::HandleAccept, this, conn, std::placeholders::_1));
						}
						else if (address->host.is_v6() && context.SupportsV6 ())
						{
							m_NTCPV6Acceptor = new boost::asio::ip::tcp::acceptor (m_Service);
							try
							{
								m_NTCPV6Acceptor->open (boost::asio::ip::tcp::v6());
								m_NTCPV6Acceptor->set_option (boost::asio::ip::v6_only (true));
								m_NTCPV6Acceptor->set_option (boost::asio::socket_base::reuse_address (true));
								m_NTCPV6Acceptor->bind (boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), address->port));
								m_NTCPV6Acceptor->listen ();

								LogPrint (eLogInfo, "NTCP: Start listening v6 TCP port ", address->port);
								auto conn = std::make_shared<NTCPSession> (*this);
								m_NTCPV6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCPServer::HandleAcceptV6, this, conn, std::placeholders::_1));
							}
							catch ( std::exception & ex )
							{
								LogPrint(eLogError, "NTCP: failed to bind to v6 port ", address->port, ": ", ex.what());
								ThrowFatal (eLogError, "Unable to start IPv6 NTCP transport at port ", address->port, ": ", ex.what ());
								continue;
							}
						}
					}
				}
			}
			ScheduleTermination ();
		}
	}

	void NTCPServer::Stop ()
	{
		{
			// we have to copy it because Terminate changes m_NTCPSessions
			auto ntcpSessions = m_NTCPSessions;
			for (auto& it: ntcpSessions)
				it.second->Terminate ();
			for (auto& it: m_PendingIncomingSessions)
				it->Terminate ();
		}
		m_NTCPSessions.clear ();

		if (m_IsRunning)
		{
			m_IsRunning = false;
			m_TerminationTimer.cancel ();
			if (m_NTCPAcceptor)
			{
					delete m_NTCPAcceptor;
				m_NTCPAcceptor = nullptr;
			}
			if (m_NTCPV6Acceptor)
			{
				delete m_NTCPV6Acceptor;
				m_NTCPV6Acceptor = nullptr;
			}
			m_Service.stop ();
			if (m_Thread)
			{
				m_Thread->join ();
				delete m_Thread;
				m_Thread = nullptr;
			}
			if(m_ProxyEndpoint)
			{
				delete m_ProxyEndpoint;
				m_ProxyEndpoint = nullptr;
			}
		}
	}

	void NTCPServer::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "NTCP: runtime exception: ", ex.what ());
			}
		}
	}

	bool NTCPServer::AddNTCPSession (std::shared_ptr<NTCPSession> session)
	{
		if (!session || !session->GetRemoteIdentity ()) return false;
		auto& ident = session->GetRemoteIdentity ()->GetIdentHash ();
		auto it = m_NTCPSessions.find (ident);
		if (it != m_NTCPSessions.end ())
		{
			LogPrint (eLogWarning, "NTCP: session to ", ident.ToBase64 (), " already exists");
			session->Terminate();
			return false;
		}
		m_NTCPSessions.insert (std::pair<i2p::data::IdentHash, std::shared_ptr<NTCPSession> >(ident, session));
		return true;
	}

	void NTCPServer::RemoveNTCPSession (std::shared_ptr<NTCPSession> session)
	{
		if (session && session->GetRemoteIdentity ())
			m_NTCPSessions.erase (session->GetRemoteIdentity ()->GetIdentHash ());
	}

	std::shared_ptr<NTCPSession> NTCPServer::FindNTCPSession (const i2p::data::IdentHash& ident)
	{
		auto it = m_NTCPSessions.find (ident);
		if (it != m_NTCPSessions.end ())
			return it->second;
		return nullptr;
	}

	void NTCPServer::HandleAccept (std::shared_ptr<NTCPSession> conn, const boost::system::error_code& error)
	{
		if (!error)
		{
			boost::system::error_code ec;
			auto ep = conn->GetSocket ().remote_endpoint(ec);
			if (!ec)
			{
				if(ShouldLimit())
				{
					// hit limit, close premature
					LogPrint(eLogWarning, "NTCP: limiting with backoff session from ", ep);
					conn->Terminate();
					return;
				}
				LogPrint (eLogDebug, "NTCP: Connected from ", ep);
				if (conn)
				{
					conn->ServerLogin ();
					m_PendingIncomingSessions.push_back (conn);
				}
			}
			else
				LogPrint (eLogError, "NTCP: Connected from error ", ec.message ());
		}


		if (error != boost::asio::error::operation_aborted)
		{
			conn = std::make_shared<NTCPSession> (*this);
			m_NTCPAcceptor->async_accept(conn->GetSocket (), std::bind (&NTCPServer::HandleAccept, this,
				conn, std::placeholders::_1));
		}
	}

	void NTCPServer::HandleAcceptV6 (std::shared_ptr<NTCPSession> conn, const boost::system::error_code& error)
	{
		if (!error)
		{
			boost::system::error_code ec;
			auto ep = conn->GetSocket ().remote_endpoint(ec);
			if (!ec)
			{
				if(ShouldLimit())
				{
					// hit limit, close premature
					LogPrint(eLogWarning, "NTCP: limiting with backoff on session from ", ep);
					conn->Terminate();
					return;
				}

				LogPrint (eLogDebug, "NTCP: Connected from ", ep);
				if (conn)
				{
					conn->ServerLogin ();
					m_PendingIncomingSessions.push_back (conn);
				}
			}
			else
				LogPrint (eLogError, "NTCP: Connected from error ", ec.message ());
		}

		if (error != boost::asio::error::operation_aborted)
		{
			conn = std::make_shared<NTCPSession> (*this);
			m_NTCPV6Acceptor->async_accept(conn->GetSocket (), std::bind (&NTCPServer::HandleAcceptV6, this,
				conn, std::placeholders::_1));
		}
	}

	void NTCPServer::Connect(const boost::asio::ip::address & address, uint16_t port, std::shared_ptr<NTCPSession> conn)
	{
		LogPrint (eLogDebug, "NTCP: Connecting to ", address ,":",  port);
		m_Service.post([=]() {
			if (this->AddNTCPSession (conn))
			{

				auto timer = std::make_shared<boost::asio::deadline_timer>(m_Service);
				timer->expires_from_now (boost::posix_time::seconds(NTCP_CONNECT_TIMEOUT));
				timer->async_wait ([conn](const boost::system::error_code& ecode) {
					if (ecode != boost::asio::error::operation_aborted)
					{
						LogPrint (eLogInfo, "NTCP: Not connected in ", NTCP_CONNECT_TIMEOUT, " seconds");
						conn->Terminate ();
					}
				});
				conn->GetSocket ().async_connect (boost::asio::ip::tcp::endpoint (address, port), std::bind (&NTCPServer::HandleConnect, this, std::placeholders::_1, conn, timer));
			}
		});
	}

	void NTCPServer::ConnectWithProxy (const std::string& host, uint16_t port, RemoteAddressType addrtype, std::shared_ptr<NTCPSession> conn)
	{
		if(m_ProxyEndpoint == nullptr)
		{
			return;
		}
		m_Service.post([=]() {
			if (this->AddNTCPSession (conn))
			{

				auto timer = std::make_shared<boost::asio::deadline_timer>(m_Service);
				auto timeout = NTCP_CONNECT_TIMEOUT * 5;
				conn->SetTerminationTimeout(timeout * 2);
				timer->expires_from_now (boost::posix_time::seconds(timeout));
				timer->async_wait ([conn, timeout](const boost::system::error_code& ecode) {
					if (ecode != boost::asio::error::operation_aborted)
					{
						LogPrint (eLogInfo, "NTCP: Not connected in ", timeout, " seconds");
						i2p::data::netdb.SetUnreachable (conn->GetRemoteIdentity ()->GetIdentHash (), true);
						conn->Terminate ();
					}
				});
				conn->GetSocket ().async_connect (*m_ProxyEndpoint, std::bind (&NTCPServer::HandleProxyConnect, this, std::placeholders::_1, conn, timer, host, port, addrtype));
			}
		});
	}

	void NTCPServer::HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCPSession> conn, std::shared_ptr<boost::asio::deadline_timer> timer)
	{
		timer->cancel ();
		if (ecode)
		{
			LogPrint (eLogInfo, "NTCP: Connect error ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				i2p::data::netdb.SetUnreachable (conn->GetRemoteIdentity ()->GetIdentHash (), true);
			conn->Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "NTCP: Connected to ", conn->GetSocket ().remote_endpoint ());
			conn->ClientLogin ();
		}
	}

	void NTCPServer::UseProxy(ProxyType proxytype, const std::string & addr, uint16_t port)
	{
		m_ProxyType = proxytype;
		m_ProxyAddress = addr;
		m_ProxyPort = port;
	}

	void NTCPServer::HandleProxyConnect(const boost::system::error_code& ecode, std::shared_ptr<NTCPSession> conn, std::shared_ptr<boost::asio::deadline_timer> timer, const std::string & host, uint16_t port, RemoteAddressType addrtype)
	{
		if(ecode)
		{
			LogPrint(eLogWarning, "NTCP: failed to connect to proxy ", ecode.message());
			timer->cancel();
			conn->Terminate();
			return;
		}
		if(m_ProxyType == eSocksProxy)
		{
			// TODO: support username/password auth etc
			uint8_t buff[3] = {0x05, 0x01, 0x00};
			boost::asio::async_write(conn->GetSocket(), boost::asio::buffer(buff, 3), boost::asio::transfer_all(), [=] (const boost::system::error_code & ec, std::size_t transferred) {
				(void) transferred;
				if(ec)
				{
					LogPrint(eLogWarning, "NTCP: socks5 write error ", ec.message());
				}
			});
			uint8_t readbuff[2];
			boost::asio::async_read(conn->GetSocket(), boost::asio::buffer(readbuff, 2), [=](const boost::system::error_code & ec, std::size_t transferred) {
				if(ec)
				{
					LogPrint(eLogError, "NTCP: socks5 read error ", ec.message());
					timer->cancel();
					conn->Terminate();
					return;
				}
				else if(transferred == 2)
				{
					if(readbuff[1] == 0x00)
					{
						AfterSocksHandshake(conn, timer, host, port, addrtype);
						return;
					}
					else if (readbuff[1] == 0xff)
					{
						LogPrint(eLogError, "NTCP: socks5 proxy rejected authentication");
						timer->cancel();
						conn->Terminate();
						return;
					}
				}
				LogPrint(eLogError, "NTCP: socks5 server gave invalid response");
				timer->cancel();
				conn->Terminate();
			});
		}
		else if(m_ProxyType == eHTTPProxy)
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

			boost::asio::async_write(conn->GetSocket(), writebuff.data(), boost::asio::transfer_all(), [=](const boost::system::error_code & ec, std::size_t transferred) {
				(void) transferred;
				if(ec)
					LogPrint(eLogError, "NTCP: http proxy write error ", ec.message());
			});

			boost::asio::streambuf * readbuff = new boost::asio::streambuf;
			boost::asio::async_read_until(conn->GetSocket(), *readbuff, "\r\n\r\n", [=] (const boost::system::error_code & ec, std::size_t transferred) {
				if(ec)
				{
					LogPrint(eLogError, "NTCP: http proxy read error ", ec.message());
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
						{
							LogPrint(eLogError, "NTCP: http proxy rejected request ", res.code);
						}
					}
					else
						LogPrint(eLogError, "NTCP: http proxy gave malformed response");
					timer->cancel();
					conn->Terminate();
					delete readbuff;
				}
			});
		}
		else
			LogPrint(eLogError, "NTCP: unknown proxy type, invalid state");
	}

	void NTCPServer::AfterSocksHandshake(std::shared_ptr<NTCPSession> conn, std::shared_ptr<boost::asio::deadline_timer> timer, const std::string & host, uint16_t port, RemoteAddressType addrtype)
	{
		// build request
		size_t sz = 0;
		uint8_t buff[256];
		uint8_t readbuff[256];
		buff[0] = 0x05;
		buff[1] = 0x01;
		buff[2] = 0x00;

		if(addrtype == eIP4Address)
		{
			buff[3] = 0x01;
			auto addr = boost::asio::ip::address::from_string(host).to_v4();
			auto addrbytes = addr.to_bytes();
			auto addrsize = addrbytes.size();
			memcpy(buff+4, addrbytes.data(), addrsize);
		}
		else if (addrtype == eIP6Address)
		{
			buff[3] = 0x04;
			auto addr = boost::asio::ip::address::from_string(host).to_v6();
			auto addrbytes = addr.to_bytes();
			auto addrsize = addrbytes.size();
			memcpy(buff+4, addrbytes.data(), addrsize);
		}
		else if (addrtype == eHostname)
		{
			buff[3] = 0x03;
			size_t addrsize = host.size();
			sz = addrsize + 1 + 4;
			if (2 + sz > sizeof(buff))
			{
				// too big
				return;
			}
			buff[4] = (uint8_t) addrsize;
			memcpy(buff+5, host.c_str(), addrsize);
		}
		htobe16buf(buff+sz, port);
		sz += 2;
		boost::asio::async_write(conn->GetSocket(), boost::asio::buffer(buff, sz), boost::asio::transfer_all(), [=](const boost::system::error_code & ec, std::size_t written) {
			if(ec)
			{
				LogPrint(eLogError, "NTCP: failed to write handshake to socks proxy ", ec.message());
				return;
			}
		});

		boost::asio::async_read(conn->GetSocket(), boost::asio::buffer(readbuff, 10), [=](const boost::system::error_code & e, std::size_t transferred) {
			if(e)
			{
				LogPrint(eLogError, "NTCP: socks proxy read error ", e.message());
			}
			else if(transferred == sz)
			{
				if( readbuff[1] == 0x00)
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

	void NTCPServer::ScheduleTermination ()
	{
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(NTCP_TERMINATION_CHECK_TIMEOUT));
		m_TerminationTimer.async_wait (std::bind (&NTCPServer::HandleTerminationTimer,
			this, std::placeholders::_1));
	}

	void NTCPServer::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			// established
			for (auto& it: m_NTCPSessions)
				if (it.second->IsTerminationTimeoutExpired (ts))
				{
					auto session = it.second;
					// Terminate modifies m_NTCPSession, so we postpone it
					m_Service.post ([session] {
							LogPrint (eLogDebug, "NTCP: No activity for ", session->GetTerminationTimeout (), " seconds");
							session->Terminate ();
					});
				}
			// pending
			for (auto it = m_PendingIncomingSessions.begin (); it != m_PendingIncomingSessions.end ();)
			{
				if ((*it)->IsEstablished () || (*it)->IsTerminated ())
					it = m_PendingIncomingSessions.erase (it); // established or terminated
				else if ((*it)->IsTerminationTimeoutExpired (ts))
				{
					(*it)->Terminate ();
					it = m_PendingIncomingSessions.erase (it); // expired
				}
				else
					it++;
			}

			ScheduleTermination ();
		}
	}
}
}
