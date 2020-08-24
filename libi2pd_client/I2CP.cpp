/*
* Copyright (c) 2013-2020, The PurpleI2P Project
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

	I2CPDestination::I2CPDestination (std::shared_ptr<I2CPSession> owner, std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params):
		RunnableService ("I2CP"), LeaseSetDestination (GetIOService (), isPublic, &params),
		m_Owner (owner), m_Identity (identity), m_EncryptionKeyType (m_Identity->GetCryptoKeyType ())
	{
	}

	I2CPDestination::~I2CPDestination ()
	{
		if (IsRunning ())
			Stop ();
	}

	void I2CPDestination::Start ()
	{
		if (!IsRunning ())
		{
			LeaseSetDestination::Start ();
			StartIOService ();
		}
	}

	void I2CPDestination::Stop ()
	{
		if (IsRunning ())
		{
			LeaseSetDestination::Stop ();
			StopIOService ();
		}
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
		
	bool I2CPDestination::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, i2p::data::CryptoKeyType preferredCrypto) const
	{
		if (preferredCrypto == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET && m_ECIESx25519Decryptor)
			return m_ECIESx25519Decryptor->Decrypt (encrypted, data, ctx, true);
		if (m_Decryptor)
			return m_Decryptor->Decrypt (encrypted, data, ctx, true);
		else
			LogPrint (eLogError, "I2CP: decryptor is not set");
		return false;
	}

	const uint8_t * I2CPDestination::GetEncryptionPublicKey (i2p::data::CryptoKeyType keyType) const
	{
		if (keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET && m_ECIESx25519Decryptor)
			return m_ECIESx25519Decryptor->GetPubicKey ();
		return nullptr;
	}	

	bool I2CPDestination::SupportsEncryptionType (i2p::data::CryptoKeyType keyType) const 
	{ 
		return keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET ? (bool)m_ECIESx25519Decryptor : m_EncryptionKeyType == keyType; 
	}
	
		
	void I2CPDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = bufbe32toh (buf);
		if (length > len - 4) length = len - 4;
		m_Owner->SendMessagePayloadMessage (buf + 4, length);
	}

	void I2CPDestination::CreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels)
	{
		uint8_t priv[256] = {0};
		i2p::data::LocalLeaseSet ls (m_Identity, priv, tunnels); // we don't care about encryption key, we need leases only
		m_LeaseSetExpirationTime = ls.GetExpirationTime ();
		uint8_t * leases = ls.GetLeases ();
		leases[-1] = tunnels.size ();
		htobe16buf (leases - 3, m_Owner->GetSessionID ());
		size_t l = 2/*sessionID*/ + 1/*num leases*/ + i2p::data::LEASE_SIZE*tunnels.size ();
		m_Owner->SendI2CPMessage (I2CP_REQUEST_VARIABLE_LEASESET_MESSAGE, leases - 3, l);
	}

	void I2CPDestination::LeaseSetCreated (const uint8_t * buf, size_t len)
	{
		auto ls = std::make_shared<i2p::data::LocalLeaseSet> (m_Identity, buf, len);
		ls->SetExpirationTime (m_LeaseSetExpirationTime);
		SetLeaseSet (ls);
	}

	void I2CPDestination::LeaseSet2Created (uint8_t storeType, const uint8_t * buf, size_t len)
	{
		auto ls = (storeType == i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2) ?
			std::make_shared<i2p::data::LocalEncryptedLeaseSet2> (m_Identity, buf, len):
			std::make_shared<i2p::data::LocalLeaseSet2> (storeType, m_Identity, buf, len);
		ls->SetExpirationTime (m_LeaseSetExpirationTime);
		SetLeaseSet (ls);
	}

	void I2CPDestination::SendMsgTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint32_t nonce)
	{
		auto msg = NewI2NPMessage ();
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
						s->m_Owner->SendMessageStatusMessage (nonce, sent ? eI2CPMessageStatusGuaranteedSuccess : eI2CPMessageStatusGuaranteedFailure);
					}
					else
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
			outboundTunnel = GetTunnelPool ()->GetNextOutboundTunnel ();
			auto leases = remote->GetNonExpiredLeases ();
			if (!leases.empty ())
				remoteLease = leases[rand () % leases.size ()];
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

	I2CPSession::I2CPSession (I2CPServer& owner, std::shared_ptr<proto::socket> socket):
		m_Owner (owner), m_Socket (socket), m_Payload (nullptr),
		m_SessionID (0xFFFF), m_MessageID (0), m_IsSendAccepted (true)
	{
	}

	I2CPSession::~I2CPSession ()
	{
		delete[] m_Payload;
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
				{
					m_Payload = new uint8_t[m_PayloadLen];
					ReceivePayload ();
				}
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
			delete[] m_Payload;
			m_Payload = nullptr;
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
		m_Owner.RemoveSession (GetSessionID ());
		LogPrint (eLogDebug, "I2CP: session ", m_SessionID, " terminated");
	}

	void I2CPSession::SendI2CPMessage (uint8_t type, const uint8_t * payload, size_t len)
	{
		auto socket = m_Socket;
		if (socket)
		{
			auto l = len + I2CP_HEADER_SIZE;
			uint8_t * buf = new uint8_t[l];
			htobe32buf (buf + I2CP_HEADER_LENGTH_OFFSET, len);
			buf[I2CP_HEADER_TYPE_OFFSET] = type;
			memcpy (buf + I2CP_HEADER_SIZE, payload, len);
			boost::asio::async_write (*socket, boost::asio::buffer (buf, l), boost::asio::transfer_all (),
			std::bind(&I2CPSession::HandleI2CPMessageSent, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2, buf));
		}
		else
			LogPrint (eLogError, "I2CP: Can't write to the socket");
	}

	void I2CPSession::HandleI2CPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, const uint8_t * buf)
	{
		delete[] buf;
		if (ecode && ecode != boost::asio::error::operation_aborted)
			Terminate ();
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
		m_Owner.InsertSession (shared_from_this ());
		auto identity = std::make_shared<i2p::data::IdentityEx>();
		size_t offset = identity->FromBuffer (buf, len);
		if (!offset)
		{
			LogPrint (eLogError, "I2CP: create session malformed identity");
			SendSessionStatusMessage (3); // invalid
			return;
		}
		uint16_t optionsSize = bufbe16toh (buf + offset);
		offset += 2;
		if (optionsSize > len - offset)
		{
			LogPrint (eLogError, "I2CP: options size ", optionsSize, "exceeds message size");
			SendSessionStatusMessage (3); // invalid
			return;
		}
		std::map<std::string, std::string> params;
		ExtractMapping (buf + offset, optionsSize, params);
		offset += optionsSize; // options
		if (params[I2CP_PARAM_MESSAGE_RELIABILITY] == "none") m_IsSendAccepted = false;

		offset += 8; // date
		if (identity->Verify (buf, offset, buf + offset)) // signature
		{
			bool isPublic = true;
			if (params[I2CP_PARAM_DONT_PUBLISH_LEASESET] == "true") isPublic = false;
			if (!m_Destination)
			{
				m_Destination = std::make_shared<I2CPDestination>(shared_from_this (), identity, isPublic, params);
				SendSessionStatusMessage (1); // created
				LogPrint (eLogDebug, "I2CP: session ", m_SessionID, " created");
				m_Destination->Start ();
			}
			else
			{
				LogPrint (eLogError, "I2CP: session already exists");
				SendSessionStatusMessage (4); // refused
			}
		}
		else
		{
			LogPrint (eLogError, "I2CP: create session signature verification failed");
			SendSessionStatusMessage (3); // invalid
		}
	}

	void I2CPSession::DestroySessionMessageHandler (const uint8_t * buf, size_t len)
	{
		SendSessionStatusMessage (0); // destroy
		LogPrint (eLogDebug, "I2CP: session ", m_SessionID, " destroyed");
		if (m_Destination)
		{
			m_Destination->Stop ();
			m_Destination = 0;
		}
	}

	void I2CPSession::ReconfigureSessionMessageHandler (const uint8_t * buf, size_t len)
	{
		uint8_t status = 3; // rejected
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
									LogPrint(eLogInfo, "I2CP: reconfigured destination");
									status = 2; // updated
								}
								else
									LogPrint(eLogWarning, "I2CP: failed to reconfigure destination");
							}
							else
								LogPrint(eLogError, "I2CP: invalid reconfigure message signature");
						}
						else
							LogPrint(eLogError, "I2CP: mapping size mismatch");
					}
					else
						LogPrint(eLogError, "I2CP: destination mismatch");
				}
				else
					LogPrint(eLogError, "I2CP: malfromed destination");
			}
			else
				LogPrint(eLogError, "I2CP: session mismatch");
		}
		else
			LogPrint(eLogError, "I2CP: short message");
		SendSessionStatusMessage (status);
	}

	void I2CPSession::SendSessionStatusMessage (uint8_t status)
	{
		uint8_t buf[3];
		htobe16buf (buf, m_SessionID);
		buf[2] = status;
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
			LogPrint (eLogError, "I2CP: unexpected sessionID ", sessionID);
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
					LogPrint (eLogError, "I2CP: invalid LeaseSet2 of type ", storeType);
					return;
				}
				offset += ls.GetBufferLen ();
				// private keys
				int numPrivateKeys = buf[offset]; offset++;
				for (int i = 0; i < numPrivateKeys; i++)
				{
					if (offset + 4 > len) return;
					uint16_t keyType = bufbe16toh (buf + offset); offset += 2; // encryption type
					uint16_t keyLen = bufbe16toh (buf + offset); offset += 2;  // private key length
					if (offset + keyLen > len) return;
					if (keyType == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET)
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
			LogPrint (eLogError, "I2CP: unexpected sessionID ", sessionID);
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
						LogPrint(eLogError, "I2CP: cannot send message, too big");
				}
				else
					LogPrint(eLogError, "I2CP: invalid identity");
			}
		}
		else
			LogPrint (eLogError, "I2CP: unexpected sessionID ", sessionID);
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
						LogPrint (eLogError, "I2CP: address ", name, " not found");
						SendHostReplyMessage (requestID, nullptr);
						return;
					}
					else
						ident = addr->identHash;
					break;
				}
				default:
					LogPrint (eLogError, "I2CP: request type ", (int)buf[10], " is not supported");
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
			LogPrint (eLogError, "I2CP: unexpected sessionID ", sessionID);
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
		uint8_t * buf = new uint8_t[l];
		htobe32buf (buf + I2CP_HEADER_LENGTH_OFFSET, len + 10);
		buf[I2CP_HEADER_TYPE_OFFSET] = I2CP_MESSAGE_PAYLOAD_MESSAGE;
		htobe16buf (buf + I2CP_HEADER_SIZE, m_SessionID);
		htobe32buf (buf + I2CP_HEADER_SIZE + 2, m_MessageID++);
		htobe32buf (buf + I2CP_HEADER_SIZE + 6, len);
		memcpy (buf + I2CP_HEADER_SIZE + 10, payload, len);
		boost::asio::async_write (*m_Socket, boost::asio::buffer (buf, l), boost::asio::transfer_all (),
		std::bind(&I2CPSession::HandleI2CPMessageSent, shared_from_this (),
			std::placeholders::_1, std::placeholders::_2, buf));
	}

	I2CPServer::I2CPServer (const std::string& interface, int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service,
#ifdef ANDROID
			I2CPSession::proto::endpoint(std::string (1, '\0') + interface)) // leading 0 for abstract address
#else
			I2CPSession::proto::endpoint(boost::asio::ip::address::from_string(interface), port))
#endif
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
		if (m_IsRunning)
			Stop ();
	}

	void I2CPServer::Start ()
	{
		Accept ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&I2CPServer::Run, this));
	}

	void I2CPServer::Stop ()
	{
		m_IsRunning = false;
		m_Acceptor.cancel ();
		{
			auto sessions = m_Sessions;
			for (auto& it: sessions)
				it.second->Stop ();
		}
		m_Sessions.clear ();
		m_Service.stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = nullptr;
		}
	}

	void I2CPServer::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "I2CP: runtime exception: ", ex.what ());
			}
		}
	}

	void I2CPServer::Accept ()
	{
		auto newSocket = std::make_shared<I2CPSession::proto::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&I2CPServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void I2CPServer::HandleAccept(const boost::system::error_code& ecode,
		std::shared_ptr<I2CPSession::proto::socket> socket)
	{
		if (!ecode && socket)
		{
			boost::system::error_code ec;
			auto ep = socket->remote_endpoint (ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "I2CP: new connection from ", ep);
				auto session = std::make_shared<I2CPSession>(*this, socket);
				session->Start ();
			}
			else
				LogPrint (eLogError, "I2CP: incoming connection error ", ec.message ());
		}
		else
			LogPrint (eLogError, "I2CP: accept error: ", ecode.message ());

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}

	bool I2CPServer::InsertSession (std::shared_ptr<I2CPSession> session)
	{
		if (!session) return false;
		if (!m_Sessions.insert({session->GetSessionID (), session}).second)
		{
			LogPrint (eLogError, "I2CP: duplicate session id ", session->GetSessionID ());
			return false;
		}
		return true;
	}

	void I2CPServer::RemoveSession (uint16_t sessionID)
	{
		m_Sessions.erase (sessionID);
	}
}
}
