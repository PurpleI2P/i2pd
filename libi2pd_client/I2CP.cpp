/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "I2PEndian.h"
#include "Log.h"
#include "Timestamp.h"
#include "LeaseSet.h"
#include "ClientContext.h"
#include "Transports.h"
#include "Signature.h"
#include "I2CP.h"

namespace i2p
{
namespace client
{

	I2CPDestination::I2CPDestination (boost::asio::io_service& service, std::shared_ptr<I2CPSession> owner,
		std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params):
		LeaseSetDestination (service, isPublic, &params),
		m_Owner (owner), m_Identity (identity), m_EncryptionKeyType (m_Identity->GetCryptoKeyType ()),
		m_IsCreatingLeaseSet (false), m_LeaseSetCreationTimer (service)
	{
	}

	void I2CPDestination::Stop ()
	{
		LeaseSetDestination::Stop ();
		m_Owner = nullptr;
		m_LeaseSetCreationTimer.cancel ();
	}

	void I2CPDestination::SetEncryptionPrivateKey (const uint8_t * key)
	{
		m_Decryptor = i2p::data::PrivateKeys::CreateDecryptor (m_Identity->GetCryptoKeyType (), key);
	}

	void I2CPDestination::SetECIESx25519EncryptionPrivateKey (const uint8_t * key)
	{
		if (!m_ECIESx25519Decryptor || memcmp (m_ECIESx25519PrivateKey, key, 32)) // new key?
		{
			m_ECIESx25519Decryptor = std::make_shared<i2p::crypto::ECIESX25519AEADRatchetDecryptor>(key, true); // calculate public
			memcpy (m_ECIESx25519PrivateKey, key, 32);
		}
	}

	bool I2CPDestination::Decrypt (const uint8_t * encrypted, uint8_t * data, i2p::data::CryptoKeyType preferredCrypto) const
	{
		if (preferredCrypto == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD && m_ECIESx25519Decryptor)
			return m_ECIESx25519Decryptor->Decrypt (encrypted, data);
		if (m_Decryptor)
			return m_Decryptor->Decrypt (encrypted, data);
		else
			LogPrint (eLogError, "I2CP: Decryptor is not set");
		return false;
	}

	const uint8_t * I2CPDestination::GetEncryptionPublicKey (i2p::data::CryptoKeyType keyType) const
	{
		if (keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD && m_ECIESx25519Decryptor)
			return m_ECIESx25519Decryptor->GetPubicKey ();
		return nullptr;
	}

	bool I2CPDestination::SupportsEncryptionType (i2p::data::CryptoKeyType keyType) const
	{
		return keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ? (bool)m_ECIESx25519Decryptor : m_EncryptionKeyType == keyType;
	}


	void I2CPDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = bufbe32toh (buf);
		if (length > len - 4) length = len - 4;
		if (m_Owner)
			m_Owner->SendMessagePayloadMessage (buf + 4, length);
	}

	void I2CPDestination::CreateNewLeaseSet (const std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> >& tunnels)
	{
		GetService ().post (std::bind (&I2CPDestination::PostCreateNewLeaseSet, this, tunnels));
	}

	void I2CPDestination::PostCreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels)
	{
		if (m_IsCreatingLeaseSet)
		{
			LogPrint (eLogInfo, "I2CP: LeaseSet is being created");
			return;
		}
		uint8_t priv[256] = {0};
		i2p::data::LocalLeaseSet ls (m_Identity, priv, tunnels); // we don't care about encryption key, we need leases only
		m_LeaseSetExpirationTime = ls.GetExpirationTime ();
		uint8_t * leases = ls.GetLeases ();
		leases[-1] = tunnels.size ();
		if (m_Owner)
		{
			uint16_t sessionID = m_Owner->GetSessionID ();
			if (sessionID != 0xFFFF)
			{
				m_IsCreatingLeaseSet = true;
				htobe16buf (leases - 3, sessionID);
				size_t l = 2/*sessionID*/ + 1/*num leases*/ + i2p::data::LEASE_SIZE*tunnels.size ();
				m_Owner->SendI2CPMessage (I2CP_REQUEST_VARIABLE_LEASESET_MESSAGE, leases - 3, l);
				m_LeaseSetCreationTimer.expires_from_now (boost::posix_time::seconds (I2CP_LEASESET_CREATION_TIMEOUT));
				auto s = GetSharedFromThis ();
				m_LeaseSetCreationTimer.async_wait ([s](const boost::system::error_code& ecode)
				{
					if (ecode != boost::asio::error::operation_aborted)
					{
						LogPrint (eLogInfo, "I2CP: LeaseSet creation timeout expired. Terminate");
						if (s->m_Owner) s->m_Owner->Stop ();
					}
				});
			}
		}
	}

	void I2CPDestination::LeaseSetCreated (const uint8_t * buf, size_t len)
	{
		m_IsCreatingLeaseSet = false;
		m_LeaseSetCreationTimer.cancel ();
		auto ls = std::make_shared<i2p::data::LocalLeaseSet> (m_Identity, buf, len);
		ls->SetExpirationTime (m_LeaseSetExpirationTime);
		SetLeaseSet (ls);
	}

	void I2CPDestination::LeaseSet2Created (uint8_t storeType, const uint8_t * buf, size_t len)
	{
		m_IsCreatingLeaseSet = false;
		m_LeaseSetCreationTimer.cancel ();
		auto ls = (storeType == i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2) ?
			std::make_shared<i2p::data::LocalEncryptedLeaseSet2> (m_Identity, buf, len):
			std::make_shared<i2p::data::LocalLeaseSet2> (storeType, m_Identity, buf, len);
		ls->SetExpirationTime (m_LeaseSetExpirationTime);
		SetLeaseSet (ls);
	}

	void I2CPDestination::SendMsgTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint32_t nonce)
	{
		auto msg = m_I2NPMsgsPool.AcquireSharedMt ();
		uint8_t * buf = msg->GetPayload ();
		htobe32buf (buf, len);
		memcpy (buf + 4, payload, len);
		msg->len += len + 4;
		msg->FillI2NPMessageHeader (eI2NPData);
		auto s = GetSharedFromThis ();
		auto remote = FindLeaseSet (ident);
		if (remote)
		{
			GetService ().post (
				[s, msg, remote, nonce]()
				{
					bool sent = s->SendMsg (msg, remote);
					if (s->m_Owner)
						s->m_Owner->SendMessageStatusMessage (nonce, sent ? eI2CPMessageStatusGuaranteedSuccess : eI2CPMessageStatusGuaranteedFailure);
				});
		}
		else
		{
			RequestDestination (ident,
				[s, msg, nonce](std::shared_ptr<i2p::data::LeaseSet> ls)
				{
					if (ls)
					{
						bool sent = s->SendMsg (msg, ls);
						if (s->m_Owner)
							s->m_Owner->SendMessageStatusMessage (nonce, sent ? eI2CPMessageStatusGuaranteedSuccess : eI2CPMessageStatusGuaranteedFailure);
					}
					else if (s->m_Owner)
						s->m_Owner->SendMessageStatusMessage (nonce, eI2CPMessageStatusNoLeaseSet);
				});
		}
	}

	bool I2CPDestination::SendMsg (std::shared_ptr<I2NPMessage> msg, std::shared_ptr<const i2p::data::LeaseSet> remote)
	{
		auto remoteSession = GetRoutingSession (remote, true);
		if (!remoteSession)
		{
			LogPrint (eLogError, "I2CP: Failed to create remote session");
			return false;
		}
		auto path = remoteSession->GetSharedRoutingPath ();
		std::shared_ptr<i2p::tunnel::OutboundTunnel> outboundTunnel;
		std::shared_ptr<const i2p::data::Lease> remoteLease;
		if (path)
		{
			if (!remoteSession->CleanupUnconfirmedTags ()) // no stuck tags
			{
				outboundTunnel = path->outboundTunnel;
				remoteLease = path->remoteLease;
			}
			else
				remoteSession->SetSharedRoutingPath (nullptr);
		}
		else
		{
			auto leases = remote->GetNonExpiredLeases (false); // without threshold
			if (leases.empty ())
				leases = remote->GetNonExpiredLeases (true); // with threshold
			if (!leases.empty ())
			{
				remoteLease = leases[rand () % leases.size ()];
				auto leaseRouter = i2p::data::netdb.FindRouter (remoteLease->tunnelGateway);
				outboundTunnel = GetTunnelPool ()->GetNextOutboundTunnel (nullptr,
					leaseRouter ? leaseRouter->GetCompatibleTransports (false) : (i2p::data::RouterInfo::CompatibleTransports)i2p::data::RouterInfo::eAllTransports);
			}
			if (remoteLease && outboundTunnel)
				remoteSession->SetSharedRoutingPath (std::make_shared<i2p::garlic::GarlicRoutingPath> (
					i2p::garlic::GarlicRoutingPath{outboundTunnel, remoteLease, 10000, 0, 0})); // 10 secs RTT
			else
				remoteSession->SetSharedRoutingPath (nullptr);
		}
		if (remoteLease && outboundTunnel)
		{
			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
			auto garlic = remoteSession->WrapSingleMessage (msg);
			msgs.push_back (i2p::tunnel::TunnelMessageBlock
				{
					i2p::tunnel::eDeliveryTypeTunnel,
					remoteLease->tunnelGateway, remoteLease->tunnelID,
					garlic
				});
			outboundTunnel->SendTunnelDataMsg (msgs);
			return true;
		}
		else
		{
			if (outboundTunnel)
				LogPrint (eLogWarning, "I2CP: Failed to send message. All leases expired");
			else
				LogPrint (eLogWarning, "I2CP: Failed to send message. No outbound tunnels");
			return false;
		}
	}

	RunnableI2CPDestination::RunnableI2CPDestination (std::shared_ptr<I2CPSession> owner,
		std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params):
		RunnableService ("I2CP"),
		I2CPDestination (GetIOService (), owner, identity, isPublic, params)
	{
	}

	RunnableI2CPDestination::~RunnableI2CPDestination ()
	{
		if (IsRunning ())
			Stop ();
	}

	void RunnableI2CPDestination::Start ()
	{
		if (!IsRunning ())
		{
			I2CPDestination::Start ();
			StartIOService ();
		}
	}

	void RunnableI2CPDestination::Stop ()
	{
		if (IsRunning ())
		{
			I2CPDestination::Stop ();
			StopIOService ();
		}
	}

	I2CPSession::I2CPSession (I2CPServer& owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
		m_Owner (owner), m_Socket (socket), m_SessionID (0xFFFF),
		m_MessageID (0), m_IsSendAccepted (true), m_IsSending (false)
	{
	}

	I2CPSession::~I2CPSession ()
	{
		Terminate ();
	}

	void I2CPSession::Start ()
	{
		ReadProtocolByte ();
	}

	void I2CPSession::Stop ()
	{
		Terminate ();
	}

	void I2CPSession::ReadProtocolByte ()
	{
		if (m_Socket)
		{
			auto s = shared_from_this ();
			m_Socket->async_read_some (boost::asio::buffer (m_Header, 1),
				[s](const boost::system::error_code& ecode, std::size_t bytes_transferred)
					{
						if (!ecode && bytes_transferred > 0 && s->m_Header[0] == I2CP_PROTOCOL_BYTE)
							s->ReceiveHeader ();
						else
							s->Terminate ();
					});
		}
	}

	void I2CPSession::ReceiveHeader ()
	{
		if (!m_Socket)
		{
			LogPrint (eLogError, "I2CP: Can't receive header");
			return;
		}
		boost::asio::async_read (*m_Socket, boost::asio::buffer (m_Header, I2CP_HEADER_SIZE),
			boost::asio::transfer_all (),
			std::bind (&I2CPSession::HandleReceivedHeader, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void I2CPSession::HandleReceivedHeader (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
			Terminate ();
		else
		{
			m_PayloadLen = bufbe32toh (m_Header + I2CP_HEADER_LENGTH_OFFSET);
			if (m_PayloadLen > 0)
			{
				if (m_PayloadLen <= I2CP_MAX_MESSAGE_LENGTH)
					ReceivePayload ();
				else
				{
					LogPrint (eLogError, "I2CP: Unexpected payload length ", m_PayloadLen);
					Terminate ();
				}
			}
			else // no following payload
			{
				HandleMessage ();
				ReceiveHeader (); // next message
			}
		}
	}

	void I2CPSession::ReceivePayload ()
	{
		if (!m_Socket)
		{
			LogPrint (eLogError, "I2CP: Can't receive payload");
			return;
		}
		boost::asio::async_read (*m_Socket, boost::asio::buffer (m_Payload, m_PayloadLen),
			boost::asio::transfer_all (),
			std::bind (&I2CPSession::HandleReceivedPayload, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void I2CPSession::HandleReceivedPayload (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
			Terminate ();
		else
		{
			HandleMessage ();
			m_PayloadLen = 0;
			ReceiveHeader (); // next message
		}
	}

	void I2CPSession::HandleMessage ()
	{
		auto handler = m_Owner.GetMessagesHandlers ()[m_Header[I2CP_HEADER_TYPE_OFFSET]];
		if (handler)
			(this->*handler)(m_Payload, m_PayloadLen);
		else
			LogPrint (eLogError, "I2CP: Unknown I2CP message ", (int)m_Header[I2CP_HEADER_TYPE_OFFSET]);
	}

	void I2CPSession::Terminate ()
	{
		if (m_Destination)
		{
			m_Destination->Stop ();
			m_Destination = nullptr;
		}
		if (m_Socket)
		{
			m_Socket->close ();
			m_Socket = nullptr;
		}
		if (!m_SendQueue.IsEmpty ())
			m_SendQueue.CleanUp ();
		if (m_SessionID != 0xFFFF)
		{
			m_Owner.RemoveSession (GetSessionID ());
			LogPrint (eLogDebug, "I2CP: Session ", m_SessionID, " terminated");
			m_SessionID = 0xFFFF;
		}
	}

	void I2CPSession::SendI2CPMessage (uint8_t type, const uint8_t * payload, size_t len)
	{
		auto l = len + I2CP_HEADER_SIZE;
		if (l > I2CP_MAX_MESSAGE_LENGTH)
		{
			LogPrint (eLogError, "I2CP: Message to send is too long ", l);
			return;
		}
		auto sendBuf = m_IsSending ? std::make_shared<i2p::stream::SendBuffer> (l) : nullptr;
		uint8_t * buf = sendBuf ? sendBuf->buf : m_SendBuffer;
		htobe32buf (buf + I2CP_HEADER_LENGTH_OFFSET, len);
		buf[I2CP_HEADER_TYPE_OFFSET] = type;
		memcpy (buf + I2CP_HEADER_SIZE, payload, len);
		if (sendBuf)
		{
			if (m_SendQueue.GetSize () < I2CP_MAX_SEND_QUEUE_SIZE)
				m_SendQueue.Add (sendBuf);
			else
			{
				LogPrint (eLogWarning, "I2CP: Send queue size exceeds ", I2CP_MAX_SEND_QUEUE_SIZE);
				return;
			}
		}
		else
		{
			auto socket = m_Socket;
			if (socket)
			{
				m_IsSending = true;
				boost::asio::async_write (*socket, boost::asio::buffer (m_SendBuffer, l),
					boost::asio::transfer_all (), std::bind(&I2CPSession::HandleI2CPMessageSent,
					shared_from_this (), std::placeholders::_1, std::placeholders::_2));
			}
		}
	}

	void I2CPSession::HandleI2CPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else if (!m_SendQueue.IsEmpty ())
		{
			auto socket = m_Socket;
			if (socket)
			{
				auto len = m_SendQueue.Get (m_SendBuffer, I2CP_MAX_MESSAGE_LENGTH);
				boost::asio::async_write (*socket, boost::asio::buffer (m_SendBuffer, len),
					boost::asio::transfer_all (),std::bind(&I2CPSession::HandleI2CPMessageSent,
					shared_from_this (), std::placeholders::_1, std::placeholders::_2));
			}
			else
				m_IsSending = false;
		}
		else
			m_IsSending = false;
	}

	std::string I2CPSession::ExtractString (const uint8_t * buf, size_t len)
	{
		uint8_t l = buf[0];
		if (l > len) l = len;
		return std::string ((const char *)(buf + 1), l);
	}

	size_t I2CPSession::PutString (uint8_t * buf, size_t len, const std::string& str)
	{
		auto l = str.length ();
		if (l + 1 >= len) l = len - 1;
		if (l > 255) l = 255; // 1 byte max
		buf[0] = l;
		memcpy (buf + 1, str.c_str (), l);
		return l + 1;
	}

	void I2CPSession::ExtractMapping (const uint8_t * buf, size_t len, std::map<std::string, std::string>& mapping)
	// TODO: move to Base.cpp
	{
		size_t offset = 0;
		while (offset < len)
		{
			std::string param = ExtractString (buf + offset, len - offset);
			offset += param.length () + 1;
			if (buf[offset] != '=')
			{
				LogPrint (eLogWarning, "I2CP: Unexpected character ", buf[offset], " instead '=' after ", param);
				break;
			}
			offset++;

			std::string value = ExtractString (buf + offset, len - offset);
			offset += value.length () + 1;
			if (buf[offset] != ';')
			{
				LogPrint (eLogWarning, "I2CP: Unexpected character ", buf[offset], " instead ';' after ", value);
				break;
			}
			offset++;
			mapping.insert (std::make_pair (param, value));
		}
	}

	void I2CPSession::GetDateMessageHandler (const uint8_t * buf, size_t len)
	{
		// get version
		auto version = ExtractString (buf, len);
		auto l = version.length () + 1 + 8;
		uint8_t * payload = new uint8_t[l];
		// set date
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		htobe64buf (payload, ts);
		// echo vesrion back
		PutString (payload + 8, l - 8, version);
		SendI2CPMessage (I2CP_SET_DATE_MESSAGE, payload, l);
		delete[] payload;
	}

	void I2CPSession::CreateSessionMessageHandler (const uint8_t * buf, size_t len)
	{
		RAND_bytes ((uint8_t *)&m_SessionID, 2);
		auto identity = std::make_shared<i2p::data::IdentityEx>();
		size_t offset = identity->FromBuffer (buf, len);
		if (!offset)
		{
			LogPrint (eLogError, "I2CP: Create session malformed identity");
			SendSessionStatusMessage (eI2CPSessionStatusInvalid); // invalid
			return;
		}
		if (m_Owner.FindSessionByIdentHash (identity->GetIdentHash ()))
		{
			LogPrint (eLogError, "I2CP: Create session duplicate address ", identity->GetIdentHash ().ToBase32 ());
			SendSessionStatusMessage (eI2CPSessionStatusInvalid); // invalid
			return;
		}
		uint16_t optionsSize = bufbe16toh (buf + offset);
		offset += 2;
		if (optionsSize > len - offset)
		{
			LogPrint (eLogError, "I2CP: Options size ", optionsSize, "exceeds message size");
			SendSessionStatusMessage (eI2CPSessionStatusInvalid); // invalid
			return;
		}
		std::map<std::string, std::string> params;
		ExtractMapping (buf + offset, optionsSize, params);
		offset += optionsSize; // options
		if (params[I2CP_PARAM_MESSAGE_RELIABILITY] == "none") m_IsSendAccepted = false;

		offset += 8; // date
		if (identity->Verify (buf, offset, buf + offset)) // signature
		{
			if (!m_Destination)
			{
				m_Destination = m_Owner.IsSingleThread () ?
					std::make_shared<I2CPDestination>(m_Owner.GetService (), shared_from_this (), identity, true, params):
					std::make_shared<RunnableI2CPDestination>(shared_from_this (), identity, true, params);
				if (m_Owner.InsertSession (shared_from_this ()))
				{
					SendSessionStatusMessage (eI2CPSessionStatusCreated); // created
					LogPrint (eLogDebug, "I2CP: Session ", m_SessionID, " created");
					m_Destination->Start ();
				}
				else
				{
					LogPrint (eLogError, "I2CP: Session already exists");
					SendSessionStatusMessage (eI2CPSessionStatusRefused);
				}
			}
			else
			{
				LogPrint (eLogError, "I2CP: Session already exists");
				SendSessionStatusMessage (eI2CPSessionStatusRefused); // refused
			}
		}
		else
		{
			LogPrint (eLogError, "I2CP: Create session signature verification failed");
			SendSessionStatusMessage (eI2CPSessionStatusInvalid); // invalid
		}
	}

	void I2CPSession::DestroySessionMessageHandler (const uint8_t * buf, size_t len)
	{
		SendSessionStatusMessage (eI2CPSessionStatusDestroyed); // destroy
		LogPrint (eLogDebug, "I2CP: Session ", m_SessionID, " destroyed");
		Terminate ();
	}

	void I2CPSession::ReconfigureSessionMessageHandler (const uint8_t * buf, size_t len)
	{
		I2CPSessionStatus status = eI2CPSessionStatusInvalid; // rejected
		if(len > sizeof(uint16_t))
		{
			uint16_t sessionID = bufbe16toh(buf);
			if(sessionID == m_SessionID)
			{
				buf += sizeof(uint16_t);
				const uint8_t * body = buf;
				i2p::data::IdentityEx ident;
				if(ident.FromBuffer(buf, len - sizeof(uint16_t)))
				{
					if (ident == *m_Destination->GetIdentity())
					{
						size_t identsz = ident.GetFullLen();
						buf += identsz;
						uint16_t optssize = bufbe16toh(buf);
						if (optssize <= len - sizeof(uint16_t) - sizeof(uint64_t) - identsz - ident.GetSignatureLen() - sizeof(uint16_t))
						{
							buf += sizeof(uint16_t);
							std::map<std::string, std::string> opts;
							ExtractMapping(buf, optssize, opts);
							buf += optssize;
							//uint64_t date = bufbe64toh(buf);
							buf += sizeof(uint64_t);
							const uint8_t * sig = buf;
							if(ident.Verify(body, len - sizeof(uint16_t) - ident.GetSignatureLen(), sig))
							{
								if(m_Destination->Reconfigure(opts))
								{
									LogPrint(eLogInfo, "I2CP: Reconfigured destination");
									status = eI2CPSessionStatusUpdated; // updated
								}
								else
									LogPrint(eLogWarning, "I2CP: Failed to reconfigure destination");
							}
							else
								LogPrint(eLogError, "I2CP: Invalid reconfigure message signature");
						}
						else
							LogPrint(eLogError, "I2CP: Mapping size mismatch");
					}
					else
						LogPrint(eLogError, "I2CP: Destination mismatch");
				}
				else
					LogPrint(eLogError, "I2CP: Malfromed destination");
			}
			else
				LogPrint(eLogError, "I2CP: Session mismatch");
		}
		else
			LogPrint(eLogError, "I2CP: Short message");
		SendSessionStatusMessage (status);
	}

	void I2CPSession::SendSessionStatusMessage (I2CPSessionStatus status)
	{
		uint8_t buf[3];
		htobe16buf (buf, m_SessionID);
		buf[2] = (uint8_t)status;
		SendI2CPMessage (I2CP_SESSION_STATUS_MESSAGE, buf, 3);
	}

	void I2CPSession::SendMessageStatusMessage (uint32_t nonce, I2CPMessageStatus status)
	{
		if (!nonce) return; // don't send status with zero nonce
		uint8_t buf[15];
		htobe16buf (buf, m_SessionID);
		htobe32buf (buf + 2, m_MessageID++);
		buf[6] = (uint8_t)status;
		memset (buf + 7, 0, 4); // size
		htobe32buf (buf + 11, nonce);
		SendI2CPMessage (I2CP_MESSAGE_STATUS_MESSAGE, buf, 15);
	}

	void I2CPSession::CreateLeaseSetMessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID)
		{
			size_t offset = 2;
			if (m_Destination)
			{
				offset += i2p::crypto::DSA_PRIVATE_KEY_LENGTH; // skip signing private key
				// we always assume this field as 20 bytes (DSA) regardless actual size
				// instead of
				//offset += m_Destination->GetIdentity ()->GetSigningPrivateKeyLen ();
				m_Destination->SetEncryptionPrivateKey (buf + offset);
				offset += 256;
				m_Destination->LeaseSetCreated (buf + offset, len - offset);
			}
		}
		else
			LogPrint (eLogError, "I2CP: Unexpected sessionID ", sessionID);
	}

	void I2CPSession::CreateLeaseSet2MessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID)
		{
			size_t offset = 2;
			if (m_Destination)
			{
				uint8_t storeType = buf[offset]; offset++; // store type
				i2p::data::LeaseSet2 ls (storeType, buf + offset, len - offset); // outer layer only for encrypted
				if (!ls.IsValid ())
				{
					LogPrint (eLogError, "I2CP: Invalid LeaseSet2 of type ", storeType);
					return;
				}
				offset += ls.GetBufferLen ();
				// private keys
				int numPrivateKeys = buf[offset]; offset++;
				for (int i = 0; i < numPrivateKeys; i++)
				{
					if (offset + 4 > len) return;
					uint16_t keyType = bufbe16toh (buf + offset); offset += 2; // encryption type
					uint16_t keyLen = bufbe16toh (buf + offset); offset += 2; // private key length
					if (offset + keyLen > len) return;
					if (keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
						m_Destination->SetECIESx25519EncryptionPrivateKey (buf + offset);
					else
					{
						m_Destination->SetEncryptionType (keyType);
						m_Destination->SetEncryptionPrivateKey (buf + offset);
					}
					offset += keyLen;
				}

				m_Destination->LeaseSet2Created (storeType, ls.GetBuffer (), ls.GetBufferLen ());
			}
		}
		else
			LogPrint (eLogError, "I2CP: Unexpected sessionID ", sessionID);
	}

	void I2CPSession::SendMessageMessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID)
		{
			size_t offset = 2;
			if (m_Destination)
			{
				i2p::data::IdentityEx identity;
				size_t identsize = identity.FromBuffer (buf + offset, len - offset);
				if (identsize)
				{
					offset += identsize;
					uint32_t payloadLen = bufbe32toh (buf + offset);
					if (payloadLen + offset <= len)
					{
						offset += 4;
						uint32_t nonce = bufbe32toh (buf + offset + payloadLen);
						if (m_IsSendAccepted)
							SendMessageStatusMessage (nonce, eI2CPMessageStatusAccepted); // accepted
						m_Destination->SendMsgTo (buf + offset, payloadLen, identity.GetIdentHash (), nonce);
					}
					else
						LogPrint(eLogError, "I2CP: Cannot send message, too big");
				}
				else
					LogPrint(eLogError, "I2CP: Invalid identity");
			}
		}
		else
			LogPrint (eLogError, "I2CP: Unexpected sessionID ", sessionID);
	}

	void I2CPSession::SendMessageExpiresMessageHandler (const uint8_t * buf, size_t len)
	{
		SendMessageMessageHandler (buf, len - 8); // ignore flags(2) and expiration(6)
	}

	void I2CPSession::HostLookupMessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID || sessionID == 0xFFFF) // -1 means without session
		{
			uint32_t requestID = bufbe32toh (buf + 2);
			//uint32_t timeout = bufbe32toh (buf + 6);
			i2p::data::IdentHash ident;
			switch (buf[10])
			{
				case 0: // hash
					ident = i2p::data::IdentHash (buf + 11);
				break;
				case 1: // address
				{
					auto name = ExtractString (buf + 11, len - 11);
					auto addr = i2p::client::context.GetAddressBook ().GetAddress (name);
					if (!addr || !addr->IsIdentHash ())
					{
						// TODO: handle blinded addresses
						LogPrint (eLogError, "I2CP: Address ", name, " not found");
						SendHostReplyMessage (requestID, nullptr);
						return;
					}
					else
						ident = addr->identHash;
					break;
				}
				default:
					LogPrint (eLogError, "I2CP: Request type ", (int)buf[10], " is not supported");
					SendHostReplyMessage (requestID, nullptr);
					return;
			}

			std::shared_ptr<LeaseSetDestination> destination = m_Destination;
			if(!destination) destination = i2p::client::context.GetSharedLocalDestination ();
			if (destination)
			{
				auto ls = destination->FindLeaseSet (ident);
				if (ls)
					SendHostReplyMessage (requestID, ls->GetIdentity ());
				else
				{
					auto s = shared_from_this ();
					destination->RequestDestination (ident,
						[s, requestID](std::shared_ptr<i2p::data::LeaseSet> leaseSet)
						{
							s->SendHostReplyMessage (requestID, leaseSet ? leaseSet->GetIdentity () : nullptr);
						});
				}
			}
			else
				SendHostReplyMessage (requestID, nullptr);
		}
		else
			LogPrint (eLogError, "I2CP: Unexpected sessionID ", sessionID);
	}

	void I2CPSession::SendHostReplyMessage (uint32_t requestID, std::shared_ptr<const i2p::data::IdentityEx> identity)
	{
		if (identity)
		{
			size_t l = identity->GetFullLen () + 7;
			uint8_t * buf = new uint8_t[l];
			htobe16buf (buf, m_SessionID);
			htobe32buf (buf + 2, requestID);
			buf[6] = 0; // result code
			identity->ToBuffer (buf + 7, l - 7);
			SendI2CPMessage (I2CP_HOST_REPLY_MESSAGE, buf, l);
			delete[] buf;
		}
		else
		{
			uint8_t buf[7];
			htobe16buf (buf, m_SessionID);
			htobe32buf (buf + 2, requestID);
			buf[6] = 1; // result code
			SendI2CPMessage (I2CP_HOST_REPLY_MESSAGE, buf, 7);
		}
	}

	void I2CPSession::DestLookupMessageHandler (const uint8_t * buf, size_t len)
	{
		if (m_Destination)
		{
			auto ls = m_Destination->FindLeaseSet (buf);
			if (ls)
			{
				auto l = ls->GetIdentity ()->GetFullLen ();
				uint8_t * identBuf = new uint8_t[l];
				ls->GetIdentity ()->ToBuffer (identBuf, l);
				SendI2CPMessage (I2CP_DEST_REPLY_MESSAGE, identBuf, l);
				delete[] identBuf;
			}
			else
			{
				auto s = shared_from_this ();
				i2p::data::IdentHash ident (buf);
				m_Destination->RequestDestination (ident,
					[s, ident](std::shared_ptr<i2p::data::LeaseSet> leaseSet)
					{
						if (leaseSet) // found
						{
							auto l = leaseSet->GetIdentity ()->GetFullLen ();
							uint8_t * identBuf = new uint8_t[l];
							leaseSet->GetIdentity ()->ToBuffer (identBuf, l);
							s->SendI2CPMessage (I2CP_DEST_REPLY_MESSAGE, identBuf, l);
							delete[] identBuf;
						}
						else
							s->SendI2CPMessage (I2CP_DEST_REPLY_MESSAGE, ident, 32); // not found
					});
			}
		}
		else
			SendI2CPMessage (I2CP_DEST_REPLY_MESSAGE, buf, 32);
	}

	void I2CPSession::GetBandwidthLimitsMessageHandler (const uint8_t * buf, size_t len)
	{
		uint8_t limits[64];
		memset (limits, 0, 64);
		htobe32buf (limits, i2p::transport::transports.GetInBandwidth ()); // inbound
		htobe32buf (limits + 4, i2p::transport::transports.GetOutBandwidth ()); // outbound
		SendI2CPMessage (I2CP_BANDWIDTH_LIMITS_MESSAGE, limits, 64);
	}

	void I2CPSession::SendMessagePayloadMessage (const uint8_t * payload, size_t len)
	{
		// we don't use SendI2CPMessage to eliminate additional copy
		auto l = len + 10 + I2CP_HEADER_SIZE;
		if (l > I2CP_MAX_MESSAGE_LENGTH)
		{
			LogPrint (eLogError, "I2CP: Message to send is too long ", l);
			return;
		}
		auto sendBuf = m_IsSending ? std::make_shared<i2p::stream::SendBuffer> (l) : nullptr;
		uint8_t * buf = sendBuf ? sendBuf->buf : m_SendBuffer;
		htobe32buf (buf + I2CP_HEADER_LENGTH_OFFSET, len + 10);
		buf[I2CP_HEADER_TYPE_OFFSET] = I2CP_MESSAGE_PAYLOAD_MESSAGE;
		htobe16buf (buf + I2CP_HEADER_SIZE, m_SessionID);
		htobe32buf (buf + I2CP_HEADER_SIZE + 2, m_MessageID++);
		htobe32buf (buf + I2CP_HEADER_SIZE + 6, len);
		memcpy (buf + I2CP_HEADER_SIZE + 10, payload, len);
		if (sendBuf)
		{
			if (m_SendQueue.GetSize () < I2CP_MAX_SEND_QUEUE_SIZE)
				m_SendQueue.Add (sendBuf);
			else
			{
				LogPrint (eLogWarning, "I2CP: Send queue size exceeds ", I2CP_MAX_SEND_QUEUE_SIZE);
				return;
			}
		}
		else
		{
			auto socket = m_Socket;
			if (socket)
			{
				m_IsSending = true;
				boost::asio::async_write (*socket, boost::asio::buffer (m_SendBuffer, l),
					boost::asio::transfer_all (), std::bind(&I2CPSession::HandleI2CPMessageSent,
					shared_from_this (), std::placeholders::_1, std::placeholders::_2));
			}
		}
	}

	I2CPServer::I2CPServer (const std::string& interface, int port, bool isSingleThread):
		RunnableService ("I2CP"), m_IsSingleThread (isSingleThread),
		m_Acceptor (GetIOService (),
		boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(interface), port))
	{
		memset (m_MessagesHandlers, 0, sizeof (m_MessagesHandlers));
		m_MessagesHandlers[I2CP_GET_DATE_MESSAGE] = &I2CPSession::GetDateMessageHandler;
		m_MessagesHandlers[I2CP_CREATE_SESSION_MESSAGE] = &I2CPSession::CreateSessionMessageHandler;
		m_MessagesHandlers[I2CP_DESTROY_SESSION_MESSAGE] = &I2CPSession::DestroySessionMessageHandler;
		m_MessagesHandlers[I2CP_RECONFIGURE_SESSION_MESSAGE] = &I2CPSession::ReconfigureSessionMessageHandler;
		m_MessagesHandlers[I2CP_CREATE_LEASESET_MESSAGE] = &I2CPSession::CreateLeaseSetMessageHandler;
		m_MessagesHandlers[I2CP_CREATE_LEASESET2_MESSAGE] = &I2CPSession::CreateLeaseSet2MessageHandler;
		m_MessagesHandlers[I2CP_SEND_MESSAGE_MESSAGE] = &I2CPSession::SendMessageMessageHandler;
		m_MessagesHandlers[I2CP_SEND_MESSAGE_EXPIRES_MESSAGE] = &I2CPSession::SendMessageExpiresMessageHandler;
		m_MessagesHandlers[I2CP_HOST_LOOKUP_MESSAGE] = &I2CPSession::HostLookupMessageHandler;
		m_MessagesHandlers[I2CP_DEST_LOOKUP_MESSAGE] = &I2CPSession::DestLookupMessageHandler;
		m_MessagesHandlers[I2CP_GET_BANDWIDTH_LIMITS_MESSAGE] = &I2CPSession::GetBandwidthLimitsMessageHandler;
	}

	I2CPServer::~I2CPServer ()
	{
		if (IsRunning ())
			Stop ();
	}

	void I2CPServer::Start ()
	{
		Accept ();
		StartIOService ();
	}

	void I2CPServer::Stop ()
	{
		m_Acceptor.cancel ();
		{
			auto sessions = m_Sessions;
			for (auto& it: sessions)
				it.second->Stop ();
		}
		m_Sessions.clear ();
		StopIOService ();
	}

	void I2CPServer::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (GetIOService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&I2CPServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void I2CPServer::HandleAccept(const boost::system::error_code& ecode,
		std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (!ecode && socket)
		{
			boost::system::error_code ec;
			auto ep = socket->remote_endpoint (ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "I2CP: New connection from ", ep);
				auto session = std::make_shared<I2CPSession>(*this, socket);
				session->Start ();
			}
			else
				LogPrint (eLogError, "I2CP: Incoming connection error ", ec.message ());
		}
		else
			LogPrint (eLogError, "I2CP: Accept error: ", ecode.message ());

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}

	bool I2CPServer::InsertSession (std::shared_ptr<I2CPSession> session)
	{
		if (!session) return false;
		if (!m_Sessions.insert({session->GetSessionID (), session}).second)
		{
			LogPrint (eLogError, "I2CP: Duplicate session id ", session->GetSessionID ());
			return false;
		}
		return true;
	}

	void I2CPServer::RemoveSession (uint16_t sessionID)
	{
		m_Sessions.erase (sessionID);
	}

	std::shared_ptr<I2CPSession> I2CPServer::FindSessionByIdentHash (const i2p::data::IdentHash& ident) const
	{
		for (const auto& it: m_Sessions)
		{
			if (it.second)
			{
				auto dest = it.second->GetDestination ();
				if (dest && dest->GetIdentHash () == ident)
					return it.second;
			}
		}
		return nullptr;
	}
}
}
