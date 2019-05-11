/*
* Copyright (c) 2013-2019, The PurpleI2P Project
*
* This file is part of Purple dotnet project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "DotNetEndian.h"
#include "Log.h"
#include "Timestamp.h"
#include "LeaseSet.h"
#include "ClientContext.h"
#include "Transports.h"
#include "Signature.h"
#include "DNCP.h"

namespace dotnet
{
namespace client
{

	DNCPDestination::DNCPDestination (std::shared_ptr<DNCPSession> owner, std::shared_ptr<const dotnet::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params):
		LeaseSetDestination (isPublic, &params), m_Owner (owner), m_Identity (identity)
	{
	}

	void DNCPDestination::SetEncryptionPrivateKey (const uint8_t * key)
	{
		memcpy (m_EncryptionPrivateKey, key, 256);
		m_Decryptor = dotnet::data::PrivateKeys::CreateDecryptor (m_Identity->GetCryptoKeyType (), m_EncryptionPrivateKey);
	}

	bool DNCPDestination::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx) const
	{
		if (m_Decryptor)
			return m_Decryptor->Decrypt (encrypted, data, ctx, true);
		else
			LogPrint (eLogError, "DNCP: decryptor is not set");
		return false;
	}

	void DNCPDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = bufbe32toh (buf);
		if (length > len - 4) length = len - 4;
		m_Owner->SendMessagePayloadMessage (buf + 4, length);
	}

	void DNCPDestination::CreateNewLeaseSet (std::vector<std::shared_ptr<dotnet::tunnel::InboundTunnel> > tunnels)
	{
		dotnet::data::LocalLeaseSet ls (m_Identity, m_EncryptionPrivateKey, tunnels); // we don't care about encryption key
		m_LeaseSetExpirationTime = ls.GetExpirationTime ();
		uint8_t * leases = ls.GetLeases ();
		leases[-1] = tunnels.size ();
		htobe16buf (leases - 3, m_Owner->GetSessionID ());
		size_t l = 2/*sessionID*/ + 1/*num leases*/ + dotnet::data::LEASE_SIZE*tunnels.size ();
		m_Owner->SendDNCPMessage (DNCP_REQUEST_VARIABLE_LEASESET_MESSAGE, leases - 3, l);
	}

	void DNCPDestination::LeaseSetCreated (const uint8_t * buf, size_t len)
	{
		auto ls = std::make_shared<dotnet::data::LocalLeaseSet> (m_Identity, buf, len);
		ls->SetExpirationTime (m_LeaseSetExpirationTime);
		SetLeaseSet (ls);
	}

	void DNCPDestination::LeaseSet2Created (uint8_t storeType, const uint8_t * buf, size_t len)
	{
		auto ls = (storeType == dotnet::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2) ?
			std::make_shared<dotnet::data::LocalEncryptedLeaseSet2> (m_Identity, buf, len):
			std::make_shared<dotnet::data::LocalLeaseSet2> (storeType, m_Identity, buf, len);
		ls->SetExpirationTime (m_LeaseSetExpirationTime);	
		SetLeaseSet (ls);
	}

	void DNCPDestination::SendMsgTo (const uint8_t * payload, size_t len, const dotnet::data::IdentHash& ident, uint32_t nonce)
	{
		auto msg = NewDNNPMessage ();
		uint8_t * buf = msg->GetPayload ();
		htobe32buf (buf, len);
		memcpy (buf + 4, payload, len);
		msg->len += len + 4;
		msg->FillDNNPMessageHeader (eDNNPData);
		auto s = GetSharedFromThis ();
		auto remote = FindLeaseSet (ident);
		if (remote)
		{
			GetService ().post (
				[s, msg, remote, nonce]()
				{
					bool sent = s->SendMsg (msg, remote);
					s->m_Owner->SendMessageStatusMessage (nonce, sent ? eDNCPMessageStatusGuaranteedSuccess : eDNCPMessageStatusGuaranteedFailure);
				});
		}
		else
		{
			RequestDestination (ident,
				[s, msg, nonce](std::shared_ptr<dotnet::data::LeaseSet> ls)
				{
					if (ls)
					{
						bool sent = s->SendMsg (msg, ls);
						s->m_Owner->SendMessageStatusMessage (nonce, sent ? eDNCPMessageStatusGuaranteedSuccess : eDNCPMessageStatusGuaranteedFailure);
					}
					else
						s->m_Owner->SendMessageStatusMessage (nonce, eDNCPMessageStatusNoLeaseSet);
				});
		}
	}

	bool DNCPDestination::SendMsg (std::shared_ptr<DNNPMessage> msg, std::shared_ptr<const dotnet::data::LeaseSet> remote)
	{
		auto remoteSession = GetRoutingSession (remote, true);
		if (!remoteSession)
		{
			LogPrint (eLogError, "DNCP: Failed to create remote session");
			return false;
		}
		auto path = remoteSession->GetSharedRoutingPath ();
		std::shared_ptr<dotnet::tunnel::OutboundTunnel> outboundTunnel;
		std::shared_ptr<const dotnet::data::Lease> remoteLease;
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
				remoteSession->SetSharedRoutingPath (std::make_shared<dotnet::garlic::GarlicRoutingPath> (
					dotnet::garlic::GarlicRoutingPath{outboundTunnel, remoteLease, 10000, 0, 0})); // 10 secs RTT
			else
				remoteSession->SetSharedRoutingPath (nullptr);
		}
		if (remoteLease && outboundTunnel)
		{
			std::vector<dotnet::tunnel::TunnelMessageBlock> msgs;
			auto garlic = remoteSession->WrapSingleMessage (msg);
			msgs.push_back (dotnet::tunnel::TunnelMessageBlock
				{
					dotnet::tunnel::eDeliveryTypeTunnel,
					remoteLease->tunnelGateway, remoteLease->tunnelID,
					garlic
				});
			outboundTunnel->SendTunnelDataMsg (msgs);
			return true;
		}
		else
		{
			if (outboundTunnel)
				LogPrint (eLogWarning, "DNCP: Failed to send message. All leases expired");
			else
				LogPrint (eLogWarning, "DNCP: Failed to send message. No outbound tunnels");
			return false;
		}
	}

	DNCPSession::DNCPSession (DNCPServer& owner, std::shared_ptr<proto::socket> socket):
		m_Owner (owner), m_Socket (socket), m_Payload (nullptr),
		m_SessionID (0xFFFF), m_MessageID (0), m_IsSendAccepted (true)
	{
	}

	DNCPSession::~DNCPSession ()
	{
		delete[] m_Payload;
	}

	void DNCPSession::Start ()
	{
		ReadProtocolByte ();
	}

	void DNCPSession::Stop ()
	{
		Terminate ();
	}

	void DNCPSession::ReadProtocolByte ()
	{
		if (m_Socket)
		{
			auto s = shared_from_this ();
			m_Socket->async_read_some (boost::asio::buffer (m_Header, 1),
				[s](const boost::system::error_code& ecode, std::size_t bytes_transferred)
				    {
						if (!ecode && bytes_transferred > 0 && s->m_Header[0] == DNCP_PROTOCOL_BYTE)
							s->ReceiveHeader ();
						else
							s->Terminate ();
					});
		}
	}

	void DNCPSession::ReceiveHeader ()
	{
		boost::asio::async_read (*m_Socket, boost::asio::buffer (m_Header, DNCP_HEADER_SIZE),
			boost::asio::transfer_all (),
			std::bind (&DNCPSession::HandleReceivedHeader, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void DNCPSession::HandleReceivedHeader (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
			Terminate ();
		else
		{
			m_PayloadLen = bufbe32toh (m_Header + DNCP_HEADER_LENGTH_OFFSET);
			if (m_PayloadLen > 0)
			{
				m_Payload = new uint8_t[m_PayloadLen];
				ReceivePayload ();
			}
			else // no following payload
			{
				HandleMessage ();
				ReceiveHeader (); // next message
			}
		}
	}

	void DNCPSession::ReceivePayload ()
	{
		boost::asio::async_read (*m_Socket, boost::asio::buffer (m_Payload, m_PayloadLen),
			boost::asio::transfer_all (),
			std::bind (&DNCPSession::HandleReceivedPayload, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void DNCPSession::HandleReceivedPayload (const boost::system::error_code& ecode, std::size_t bytes_transferred)
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

	void DNCPSession::HandleMessage ()
	{
		auto handler = m_Owner.GetMessagesHandlers ()[m_Header[DNCP_HEADER_TYPE_OFFSET]];
		if (handler)
			(this->*handler)(m_Payload, m_PayloadLen);
		else
			LogPrint (eLogError, "DNCP: Unknown DNCP message ", (int)m_Header[DNCP_HEADER_TYPE_OFFSET]);
	}

	void DNCPSession::Terminate ()
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
		LogPrint (eLogDebug, "DNCP: session ", m_SessionID, " terminated");
	}

	void DNCPSession::SendDNCPMessage (uint8_t type, const uint8_t * payload, size_t len)
	{
		auto socket = m_Socket;
		if (socket)
		{
			auto l = len + DNCP_HEADER_SIZE;
			uint8_t * buf = new uint8_t[l];
			htobe32buf (buf + DNCP_HEADER_LENGTH_OFFSET, len);
			buf[DNCP_HEADER_TYPE_OFFSET] = type;
			memcpy (buf + DNCP_HEADER_SIZE, payload, len);
			boost::asio::async_write (*socket, boost::asio::buffer (buf, l), boost::asio::transfer_all (),
			std::bind(&DNCPSession::HandleDNCPMessageSent, shared_from_this (),
							std::placeholders::_1, std::placeholders::_2, buf));
		}
		else
			LogPrint (eLogError, "DNCP: Can't write to the socket");
	}

	void DNCPSession::HandleDNCPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, const uint8_t * buf)
	{
		delete[] buf;
		if (ecode && ecode != boost::asio::error::operation_aborted)
			Terminate ();
	}

	std::string DNCPSession::ExtractString (const uint8_t * buf, size_t len)
	{
		uint8_t l = buf[0];
		if (l > len) l = len;
		return std::string ((const char *)(buf + 1), l);
	}

	size_t DNCPSession::PutString (uint8_t * buf, size_t len, const std::string& str)
	{
		auto l = str.length ();
		if (l + 1 >= len) l = len - 1;
		if (l > 255) l = 255; // 1 byte max
		buf[0] = l;
		memcpy (buf + 1, str.c_str (), l);
		return l + 1;
	}

	void DNCPSession::ExtractMapping (const uint8_t * buf, size_t len, std::map<std::string, std::string>& mapping)
	// TODO: move to Base.cpp
	{
		size_t offset = 0;
		while (offset < len)
		{
			std::string param = ExtractString (buf + offset, len - offset);
			offset += param.length () + 1;
			if (buf[offset] != '=')
			{
				LogPrint (eLogWarning, "DNCP: Unexpected character ", buf[offset], " instead '=' after ", param);
				break;
			}
			offset++;

			std::string value = ExtractString (buf + offset, len - offset);
			offset += value.length () + 1;
			if (buf[offset] != ';')
			{
				LogPrint (eLogWarning, "DNCP: Unexpected character ", buf[offset], " instead ';' after ", value);
				break;
			}
			offset++;
			mapping.insert (std::make_pair (param, value));
		}
	}

	void DNCPSession::GetDateMessageHandler (const uint8_t * buf, size_t len)
	{
		// get version
		auto version = ExtractString (buf, len);
		auto l = version.length () + 1 + 8;
		uint8_t * payload = new uint8_t[l];
		// set date
		auto ts = dotnet::util::GetMillisecondsSinceEpoch ();
		htobe64buf (payload, ts);
		// echo vesrion back
		PutString (payload + 8, l - 8, version);
		SendDNCPMessage (DNCP_SET_DATE_MESSAGE, payload, l);
		delete[] payload;
	}

	void DNCPSession::CreateSessionMessageHandler (const uint8_t * buf, size_t len)
	{
		RAND_bytes ((uint8_t *)&m_SessionID, 2);
		m_Owner.InsertSession (shared_from_this ());
		auto identity = std::make_shared<dotnet::data::IdentityEx>();
		size_t offset = identity->FromBuffer (buf, len);
		if (!offset)
		{
			LogPrint (eLogError, "DNCP: create session malformed identity");
			SendSessionStatusMessage (3); // invalid
			return;
		}
		uint16_t optionsSize = bufbe16toh (buf + offset);
		offset += 2;
		if (optionsSize > len - offset)
		{
			LogPrint (eLogError, "DNCP: options size ", optionsSize, "exceeds message size");
			SendSessionStatusMessage (3); // invalid
			return;
		}
		std::map<std::string, std::string> params;
		ExtractMapping (buf + offset, optionsSize, params);
		offset += optionsSize; // options
		if (params[DNCP_PARAM_MESSAGE_RELIABILITY] == "none") m_IsSendAccepted = false;

		offset += 8; // date
		if (identity->Verify (buf, offset, buf + offset)) // signature
		{
			bool isPublic = true;
			if (params[DNCP_PARAM_DONT_PUBLISH_LEASESET] == "true") isPublic = false;
			if (!m_Destination)
			{
				m_Destination = std::make_shared<DNCPDestination>(shared_from_this (), identity, isPublic, params);
				SendSessionStatusMessage (1); // created
				LogPrint (eLogDebug, "DNCP: session ", m_SessionID, " created");
				m_Destination->Start ();
			}
			else
			{
				LogPrint (eLogError, "DNCP: session already exists");
				SendSessionStatusMessage (4); // refused
			}
		}
		else
		{
			LogPrint (eLogError, "DNCP: create session signature verification failed");
			SendSessionStatusMessage (3); // invalid
		}
	}

	void DNCPSession::DestroySessionMessageHandler (const uint8_t * buf, size_t len)
	{
		SendSessionStatusMessage (0); // destroy
		LogPrint (eLogDebug, "DNCP: session ", m_SessionID, " destroyed");
		if (m_Destination)
		{
			m_Destination->Stop ();
			m_Destination = 0;
		}
	}

	void DNCPSession::ReconfigureSessionMessageHandler (const uint8_t * buf, size_t len)
	{
		uint8_t status = 3; // rejected
		if(len > sizeof(uint16_t))
		{
			uint16_t sessionID = bufbe16toh(buf);
			if(sessionID == m_SessionID)
			{
				buf += sizeof(uint16_t);
				const uint8_t * body = buf;
				dotnet::data::IdentityEx ident;
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
									LogPrint(eLogInfo, "DNCP: reconfigured destination");
									status = 2; // updated
								}
								else
									LogPrint(eLogWarning, "DNCP: failed to reconfigure destination");
							}
							else
								LogPrint(eLogError, "DNCP: invalid reconfigure message signature");
						}
						else
							LogPrint(eLogError, "DNCP: mapping size mismatch");
					}
					else
						LogPrint(eLogError, "DNCP: destination mismatch");
				}
				else
					LogPrint(eLogError, "DNCP: malfromed destination");
			}
			else
				LogPrint(eLogError, "DNCP: session mismatch");
		}
		else
			LogPrint(eLogError, "DNCP: short message");
		SendSessionStatusMessage (status); 
	}	

	void DNCPSession::SendSessionStatusMessage (uint8_t status)
	{
		uint8_t buf[3];
		htobe16buf (buf, m_SessionID);
		buf[2] = status;
		SendDNCPMessage (DNCP_SESSION_STATUS_MESSAGE, buf, 3);
	}

	void DNCPSession::SendMessageStatusMessage (uint32_t nonce, DNCPMessageStatus status)
	{
		if (!nonce) return; // don't send status with zero nonce
		uint8_t buf[15];
		htobe16buf (buf, m_SessionID);
		htobe32buf (buf + 2, m_MessageID++);
		buf[6] = (uint8_t)status;
		memset (buf + 7, 0, 4); // size
		htobe32buf (buf + 11, nonce);
		SendDNCPMessage (DNCP_MESSAGE_STATUS_MESSAGE, buf, 15);
	}

	void DNCPSession::CreateLeaseSetMessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID)
		{
			size_t offset = 2;
			if (m_Destination)
			{
				offset += dotnet::crypto::DSA_PRIVATE_KEY_LENGTH; // skip signing private key
				// we always assume this field as 20 bytes (DSA) regardless actual size
				// instead of
				//offset += m_Destination->GetIdentity ()->GetSigningPrivateKeyLen ();
				m_Destination->SetEncryptionPrivateKey (buf + offset);
				offset += 256;
				m_Destination->LeaseSetCreated (buf + offset, len - offset);
			}
		}
		else
			LogPrint (eLogError, "DNCP: unexpected sessionID ", sessionID);
	}

	void DNCPSession::CreateLeaseSet2MessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID)
		{
			size_t offset = 2;
			if (m_Destination)
			{
				uint8_t storeType = buf[offset]; offset++; // store type
				dotnet::data::LeaseSet2 ls (storeType, buf + offset, len - offset); // outer layer only for encrypted
				if (!ls.IsValid ())
				{
					LogPrint (eLogError, "DNCP: invalid LeaseSet2 of type ", storeType);
					return;
				}	
				offset += ls.GetBufferLen ();
				// private keys
				int numPrivateKeys = buf[offset]; offset++;
				uint16_t currentKeyType = 0;
				const uint8_t * currentKey = nullptr;	
				for (int i = 0; i < numPrivateKeys; i++)
				{
					if (offset + 4 > len) return;
					uint16_t keyType = bufbe16toh (buf + offset); offset += 2; // encryption type
					uint16_t keyLen = bufbe16toh (buf + offset); offset += 2;  // private key length
					if (offset + keyLen > len) return;
					if (keyType > currentKeyType)
					{
						currentKeyType = keyType;
						currentKey = buf + offset;
					}
					offset += keyLen;
				}				
				// TODO: support multiple keys
				if (currentKey)
					m_Destination->SetEncryptionPrivateKey (currentKey);

				m_Destination->LeaseSet2Created (storeType, ls.GetBuffer (), ls.GetBufferLen ()); 
			}
		}
		else
			LogPrint (eLogError, "DNCP: unexpected sessionID ", sessionID);
	}

	void DNCPSession::SendMessageMessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID)
		{
			size_t offset = 2;
			if (m_Destination)
			{
				dotnet::data::IdentityEx identity;
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
							SendMessageStatusMessage (nonce, eDNCPMessageStatusAccepted); // accepted
						m_Destination->SendMsgTo (buf + offset, payloadLen, identity.GetIdentHash (), nonce);
					}
					else
						LogPrint(eLogError, "DNCP: cannot send message, too big");
				}
				else
					LogPrint(eLogError, "DNCP: invalid identity");
			}
		}
		else
			LogPrint (eLogError, "DNCP: unexpected sessionID ", sessionID);
	}

	void DNCPSession::SendMessageExpiresMessageHandler (const uint8_t * buf, size_t len)
	{
		SendMessageMessageHandler (buf, len - 8); // ignore flags(2) and expiration(6)
	}

	void DNCPSession::HostLookupMessageHandler (const uint8_t * buf, size_t len)
	{
		uint16_t sessionID = bufbe16toh (buf);
		if (sessionID == m_SessionID || sessionID == 0xFFFF) // -1 means without session
		{
			uint32_t requestID = bufbe32toh (buf + 2);
			//uint32_t timeout = bufbe32toh (buf + 6);
			dotnet::data::IdentHash ident;
			switch (buf[10])
			{
				case 0: // hash
					ident = dotnet::data::IdentHash (buf + 11);
				break;
				case 1: // address
				{
					auto name = ExtractString (buf + 11, len - 11);
					auto addr = dotnet::client::context.GetAddressBook ().GetAddress (name);
					if (!addr || !addr->IsIdentHash ())
					{
						// TODO: handle blinded addresses
						LogPrint (eLogError, "DNCP: address ", name, " not found");
						SendHostReplyMessage (requestID, nullptr);
						return;
					}
					else
						ident = addr->identHash;
					break;
				}
				default:
					LogPrint (eLogError, "DNCP: request type ", (int)buf[10], " is not supported");
					SendHostReplyMessage (requestID, nullptr);
					return;
			}

			std::shared_ptr<LeaseSetDestination> destination = m_Destination;
			if(!destination) destination = dotnet::client::context.GetSharedLocalDestination ();
			if (destination)
			{
				auto ls = destination->FindLeaseSet (ident);
				if (ls)
					SendHostReplyMessage (requestID, ls->GetIdentity ());
				else
				{
					auto s = shared_from_this ();
					destination->RequestDestination (ident,
						[s, requestID](std::shared_ptr<dotnet::data::LeaseSet> leaseSet)
						{
							s->SendHostReplyMessage (requestID, leaseSet ? leaseSet->GetIdentity () : nullptr);
						});
				}
			}
			else
				SendHostReplyMessage (requestID, nullptr);
		}
		else
			LogPrint (eLogError, "DNCP: unexpected sessionID ", sessionID);
	}

	void DNCPSession::SendHostReplyMessage (uint32_t requestID, std::shared_ptr<const dotnet::data::IdentityEx> identity)
	{
		if (identity)
		{
			size_t l = identity->GetFullLen () + 7;
			uint8_t * buf = new uint8_t[l];
			htobe16buf (buf, m_SessionID);
			htobe32buf (buf + 2, requestID);
			buf[6] = 0; // result code
			identity->ToBuffer (buf + 7, l - 7);
			SendDNCPMessage (DNCP_HOST_REPLY_MESSAGE, buf, l);
			delete[] buf;
		}
		else
		{
			uint8_t buf[7];
			htobe16buf (buf, m_SessionID);
			htobe32buf (buf + 2, requestID);
			buf[6] = 1; // result code
			SendDNCPMessage (DNCP_HOST_REPLY_MESSAGE, buf, 7);
		}
	}

	void DNCPSession::DestLookupMessageHandler (const uint8_t * buf, size_t len)
	{
		if (m_Destination)
		{
			auto ls = m_Destination->FindLeaseSet (buf);
			if (ls)
			{
				auto l = ls->GetIdentity ()->GetFullLen ();
				uint8_t * identBuf = new uint8_t[l];
				ls->GetIdentity ()->ToBuffer (identBuf, l);
				SendDNCPMessage (DNCP_DEST_REPLY_MESSAGE, identBuf, l);
				delete[] identBuf;
			}
			else
			{
				auto s = shared_from_this ();
				dotnet::data::IdentHash ident (buf);
				m_Destination->RequestDestination (ident,
					[s, ident](std::shared_ptr<dotnet::data::LeaseSet> leaseSet)
					{
						if (leaseSet) // found
						{
							auto l = leaseSet->GetIdentity ()->GetFullLen ();
							uint8_t * identBuf = new uint8_t[l];
							leaseSet->GetIdentity ()->ToBuffer (identBuf, l);
							s->SendDNCPMessage (DNCP_DEST_REPLY_MESSAGE, identBuf, l);
							delete[] identBuf;
						}
						else
							s->SendDNCPMessage (DNCP_DEST_REPLY_MESSAGE, ident, 32); // not found
					});
			}
		}
		else
			SendDNCPMessage (DNCP_DEST_REPLY_MESSAGE, buf, 32);
	}

	void DNCPSession::GetBandwidthLimitsMessageHandler (const uint8_t * buf, size_t len)
	{
		uint8_t limits[64];
		memset (limits, 0, 64);
		htobe32buf (limits, dotnet::transport::transports.GetInBandwidth ()); // inbound
		htobe32buf (limits + 4, dotnet::transport::transports.GetOutBandwidth ()); // outbound
		SendDNCPMessage (DNCP_BANDWIDTH_LIMITS_MESSAGE, limits, 64);
	}

	void DNCPSession::SendMessagePayloadMessage (const uint8_t * payload, size_t len)
	{
		// we don't use SendDNCPMessage to eliminate additional copy
		auto l = len + 10 + DNCP_HEADER_SIZE;
		uint8_t * buf = new uint8_t[l];
		htobe32buf (buf + DNCP_HEADER_LENGTH_OFFSET, len + 10);
		buf[DNCP_HEADER_TYPE_OFFSET] = DNCP_MESSAGE_PAYLOAD_MESSAGE;
		htobe16buf (buf + DNCP_HEADER_SIZE, m_SessionID);
		htobe32buf (buf + DNCP_HEADER_SIZE + 2, m_MessageID++);
		htobe32buf (buf + DNCP_HEADER_SIZE + 6, len);
		memcpy (buf + DNCP_HEADER_SIZE + 10, payload, len);
		boost::asio::async_write (*m_Socket, boost::asio::buffer (buf, l), boost::asio::transfer_all (),
		std::bind(&DNCPSession::HandleDNCPMessageSent, shared_from_this (),
						std::placeholders::_1, std::placeholders::_2, buf));
	}

	DNCPServer::DNCPServer (const std::string& interface, int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service,
#ifdef ANDROID
            DNCPSession::proto::endpoint(std::string (1, '\0') + interface)) // leading 0 for abstract address
#else
			DNCPSession::proto::endpoint(boost::asio::ip::address::from_string(interface), port))
#endif
	{
		memset (m_MessagesHandlers, 0, sizeof (m_MessagesHandlers));
		m_MessagesHandlers[DNCP_GET_DATE_MESSAGE] = &DNCPSession::GetDateMessageHandler;
		m_MessagesHandlers[DNCP_CREATE_SESSION_MESSAGE] = &DNCPSession::CreateSessionMessageHandler;
		m_MessagesHandlers[DNCP_DESTROY_SESSION_MESSAGE] = &DNCPSession::DestroySessionMessageHandler;
		m_MessagesHandlers[DNCP_RECONFIGURE_SESSION_MESSAGE] = &DNCPSession::ReconfigureSessionMessageHandler;
		m_MessagesHandlers[DNCP_CREATE_LEASESET_MESSAGE] = &DNCPSession::CreateLeaseSetMessageHandler;
		m_MessagesHandlers[DNCP_CREATE_LEASESET2_MESSAGE] = &DNCPSession::CreateLeaseSet2MessageHandler;
		m_MessagesHandlers[DNCP_SEND_MESSAGE_MESSAGE] = &DNCPSession::SendMessageMessageHandler;
		m_MessagesHandlers[DNCP_SEND_MESSAGE_EXPIRES_MESSAGE] = &DNCPSession::SendMessageExpiresMessageHandler;
		m_MessagesHandlers[DNCP_HOST_LOOKUP_MESSAGE] = &DNCPSession::HostLookupMessageHandler;
		m_MessagesHandlers[DNCP_DEST_LOOKUP_MESSAGE] = &DNCPSession::DestLookupMessageHandler;
		m_MessagesHandlers[DNCP_GET_BANDWIDTH_LIMITS_MESSAGE] = &DNCPSession::GetBandwidthLimitsMessageHandler;
	}

	DNCPServer::~DNCPServer ()
	{
		if (m_IsRunning)
			Stop ();
	}

	void DNCPServer::Start ()
	{
		Accept ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&DNCPServer::Run, this));
	}

	void DNCPServer::Stop ()
	{
		m_IsRunning = false;
		m_Acceptor.cancel ();
		for (auto& it: m_Sessions)
			it.second->Stop ();
		m_Sessions.clear ();
		m_Service.stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = nullptr;
		}
	}

	void DNCPServer::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "DNCP: runtime exception: ", ex.what ());
			}
		}
	}

	void DNCPServer::Accept ()
	{
		auto newSocket = std::make_shared<DNCPSession::proto::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&DNCPServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void DNCPServer::HandleAccept(const boost::system::error_code& ecode,
		std::shared_ptr<DNCPSession::proto::socket> socket)
	{
		if (!ecode && socket)
		{
			boost::system::error_code ec;
			auto ep = socket->remote_endpoint (ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "DNCP: new connection from ", ep);
				auto session = std::make_shared<DNCPSession>(*this, socket);
				session->Start ();
			}
			else
				LogPrint (eLogError, "DNCP: incoming connection error ", ec.message ());
		}
		else
			LogPrint (eLogError, "DNCP: accept error: ", ecode.message ());

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}

	bool DNCPServer::InsertSession (std::shared_ptr<DNCPSession> session)
	{
		if (!session) return false;
		if (!m_Sessions.insert({session->GetSessionID (), session}).second)
		{
			LogPrint (eLogError, "DNCP: duplicate session id ", session->GetSessionID ());
			return false;
		}
		return true;
	}

	void DNCPServer::RemoveSession (uint16_t sessionID)
	{
		m_Sessions.erase (sessionID);
	}
}
}

