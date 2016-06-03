/*
* Copyright (c) 2013-2016, The PurpleI2P Project
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
#include "I2CP.h"

namespace i2p
{
namespace client
{

	I2CPDestination::I2CPDestination (I2CPSession& owner, std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic, const std::map<std::string, std::string>& params): 
		LeaseSetDestination (isPublic, &params), m_Owner (owner), m_Identity (identity) 
	{
	}

	void I2CPDestination::SetEncryptionPrivateKey (const uint8_t * key)
	{
		memcpy (m_EncryptionPrivateKey, key, 256);
	}

	void I2CPDestination::HandleDataMessage (const uint8_t * buf, size_t len)
	{
		uint32_t length = bufbe32toh (buf);
		if (length > len - 4) length = len - 4;
		m_Owner.SendMessagePayloadMessage (buf + 4, length);
	}

	void I2CPDestination::CreateNewLeaseSet (std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels) 
	{
		i2p::data::LocalLeaseSet ls (m_Identity, m_EncryptionPrivateKey, tunnels); // we don't care about encryption key
		m_LeaseSetExpirationTime = ls.GetExpirationTime ();
		uint8_t * leases = ls.GetLeases ();
		leases[-1] = tunnels.size ();
		htobe16buf (leases - 3, m_Owner.GetSessionID ());
		size_t l = 2/*sessionID*/ + 1/*num leases*/ + i2p::data::LEASE_SIZE*tunnels.size ();
		m_Owner.SendI2CPMessage (I2CP_REQUEST_VARIABLE_LEASESET_MESSAGE, leases - 3, l); 
	}
	
	void I2CPDestination::LeaseSetCreated (const uint8_t * buf, size_t len)
	{
		auto ls = new i2p::data::LocalLeaseSet (m_Identity, buf, len);
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
		auto remote = FindLeaseSet (ident);
		if (remote)
			GetService ().post (std::bind (&I2CPDestination::SendMsg, GetSharedFromThis (), msg, remote));
		else
		{
			auto s = GetSharedFromThis ();
			RequestDestination (ident,
				[s, msg, nonce](std::shared_ptr<i2p::data::LeaseSet> ls)
				{
					if (ls)
					{ 
						bool sent = s->SendMsg (msg, ls);
						s->m_Owner.SendMessageStatusMessage (nonce, sent ? eI2CPMessageStatusGuaranteedSuccess : eI2CPMessageStatusGuaranteedFailure);
					}
					else
						s->m_Owner.SendMessageStatusMessage (nonce, eI2CPMessageStatusNoLeaseSet);
				});
		}
	}

	bool I2CPDestination::SendMsg (std::shared_ptr<I2NPMessage> msg, std::shared_ptr<const i2p::data::LeaseSet> remote)
	{
		auto outboundTunnel = GetTunnelPool ()->GetNextOutboundTunnel ();
		auto leases = remote->GetNonExpiredLeases ();
		if (!leases.empty () && outboundTunnel)
		{
			std::vector<i2p::tunnel::TunnelMessageBlock> msgs;			
			uint32_t i = rand () % leases.size ();
			auto garlic = WrapMessage (remote, msg, true);
			msgs.push_back (i2p::tunnel::TunnelMessageBlock 
				{ 
					i2p::tunnel::eDeliveryTypeTunnel,
					leases[i]->tunnelGateway, leases[i]->tunnelID,
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

	I2CPSession::I2CPSession (I2CPServer& owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
		m_Owner (owner), m_Socket (socket), 
		m_NextMessage (nullptr), m_NextMessageLen (0), m_NextMessageOffset (0),
		m_MessageID (0)
	{
		RAND_bytes ((uint8_t *)&m_SessionID, 2);
	}
		
	I2CPSession::~I2CPSession ()
	{
		delete[] m_NextMessage;
	}

	void I2CPSession::Start ()
	{
		ReadProtocolByte ();
	}

	void I2CPSession::Stop ()
	{
	}

	void I2CPSession::ReadProtocolByte ()
	{
		if (m_Socket)
		{
			auto s = shared_from_this ();	
			m_Socket->async_read_some (boost::asio::buffer (m_Buffer, 1), 
				[s](const boost::system::error_code& ecode, std::size_t bytes_transferred)
				    {
						if (!ecode && bytes_transferred > 0 && s->m_Buffer[0] == I2CP_PROTOCOL_BYTE)
							s->Receive ();
						else
							s->Terminate ();
					});
		}
	}

	void I2CPSession::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, I2CP_SESSION_BUFFER_SIZE),
			std::bind (&I2CPSession::HandleReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void I2CPSession::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
			Terminate ();
		else
		{
			size_t offset = 0;
			if (m_NextMessage)
			{
				if (m_NextMessageOffset + bytes_transferred <= m_NextMessageLen)
				{
					memcpy (m_NextMessage + m_NextMessageOffset, m_Buffer, bytes_transferred);
					m_NextMessageOffset += bytes_transferred;
				}	
				else
				{
					offset = m_NextMessageLen - m_NextMessageOffset;
					memcpy (m_NextMessage + m_NextMessageOffset, m_Buffer, offset);
					HandleNextMessage (m_NextMessage);
					delete[] m_NextMessage;
				}
			}	
			while (offset < bytes_transferred)
			{
				auto msgLen = bufbe32toh (m_Buffer + offset + I2CP_HEADER_LENGTH_OFFSET) + I2CP_HEADER_SIZE;
				if (msgLen <= bytes_transferred - offset)
				{
					HandleNextMessage (m_Buffer + offset);
					offset += msgLen;	
				}
				else
				{
					m_NextMessageLen = msgLen;
					m_NextMessageOffset = bytes_transferred - offset;
					m_NextMessage = new uint8_t[m_NextMessageLen];
					memcpy (m_NextMessage, m_Buffer + offset, m_NextMessageOffset);
					offset = bytes_transferred;
				}	
			}	
			Receive ();
		}
	}

	void I2CPSession::HandleNextMessage (const uint8_t * buf)
	{
		auto handler = m_Owner.GetMessagesHandlers ()[buf[I2CP_HEADER_TYPE_OFFSET]];
		if (handler)
			(this->*handler)(buf + I2CP_HEADER_SIZE, bufbe32toh (buf + I2CP_HEADER_LENGTH_OFFSET));
		else
			LogPrint (eLogError, "I2CP: Unknown I2CP messsage ", (int)buf[I2CP_HEADER_TYPE_OFFSET]);
	}

	void I2CPSession::Terminate ()
	{
		if (m_Destination)
		{
			m_Destination->Stop ();
			m_Destination = nullptr;
		}
		m_Owner.RemoveSession (GetSessionID ());
	}

	void I2CPSession::SendI2CPMessage (uint8_t type, const uint8_t * payload, size_t len)
	{
		auto l = len + I2CP_HEADER_SIZE;
		uint8_t * buf = new uint8_t[l];
		htobe32buf (buf + I2CP_HEADER_LENGTH_OFFSET, len);
		buf[I2CP_HEADER_TYPE_OFFSET] = type;
		memcpy (buf + I2CP_HEADER_SIZE, payload, len);
		boost::asio::async_write (*m_Socket, boost::asio::buffer (buf, l), boost::asio::transfer_all (),
        	std::bind(&I2CPSession::HandleI2CPMessageSent, shared_from_this (), 
						std::placeholders::_1, std::placeholders::_2, buf));			
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
		return std::string ((const char *)buf, l);
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
			auto semicolon = (const uint8_t *)memchr (buf + offset, ';', len - offset);
			if (semicolon)
			{
				auto l = semicolon - buf - offset + 1; 
				auto equal = (const uint8_t *)memchr (buf + offset, '=', l);
				if (equal)
				{
					auto l1 = equal - buf - offset + 1;
					mapping.insert (std::make_pair (std::string ((const char *)(buf + offset), l1 -1), 
						std::string ((const char *)(buf + offset + l1), l - l1 - 2)));
				}
				offset += l;
			}
			else
				break;
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
		auto identity = std::make_shared<i2p::data::IdentityEx>();
		size_t offset = identity->FromBuffer (buf, len);
		uint16_t optionsSize = bufbe16toh (buf + offset);
		offset += 2;
		
		std::map<std::string, std::string> params;
		ExtractMapping (buf + offset, optionsSize, params);		
		offset += optionsSize;
		offset += 8; // date
		if (identity->Verify (buf, offset, buf + offset)) // signature
		{	
			bool isPublic = true;
			if (params[I2CP_PARAM_DONT_PUBLISH_LEASESET] == "true") isPublic = false;
			m_Destination = std::make_shared<I2CPDestination>(*this, identity, isPublic, params);
			m_Destination->Start ();
			SendSessionStatusMessage (1); // created
			LogPrint (eLogDebug, "I2CP: session ", m_SessionID, " created");	
		}
		else
		{
			LogPrint (eLogError, "I2CP: create session signature verification falied");	
			SendSessionStatusMessage (3); // invalid
		}
	}

	void I2CPSession::DestroySessionMessageHandler (const uint8_t * buf, size_t len)
	{
		SendSessionStatusMessage (0); // destroy
		LogPrint (eLogDebug, "I2CP: session ", m_SessionID, " destroyed");
		Terminate ();
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
				m_Destination->SetEncryptionPrivateKey (buf + offset);
				offset += 256;
				m_Destination->LeaseSetCreated (buf + offset, len - offset);
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
				offset += identity.FromBuffer (buf + offset, len - offset);
				uint32_t payloadLen = bufbe32toh (buf + offset);
				offset += 4;
				uint32_t nonce = bufbe32toh (buf + offset + payloadLen);
				SendMessageStatusMessage (nonce, eI2CPMessageStatusAccepted); // accepted
				m_Destination->SendMsgTo (buf + offset, payloadLen, identity.GetIdentHash (), nonce);
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
		if (sessionID == m_SessionID)
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
					if (!i2p::client::context.GetAddressBook ().GetIdentHash (name, ident))
					{
						LogPrint (eLogError, "I2CP: address ", name, " not found");
						SendHostReplyMessage (requestID, nullptr);
						return;
					}
					break;	
				}
				default:
					LogPrint (eLogError, "I2CP: request type ", (int)buf[10], " is not supported");
					SendHostReplyMessage (requestID, nullptr);
					return;
			}

			if (m_Destination)
			{
				auto ls = m_Destination->FindLeaseSet (ident);
				if (ls)
					SendHostReplyMessage (requestID, ls->GetIdentity ());
				else
				{
					auto s = shared_from_this ();
					m_Destination->RequestDestination (ident,
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
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(interface), port))
	{
		memset (m_MessagesHandlers, 0, sizeof (m_MessagesHandlers));
		m_MessagesHandlers[I2CP_GET_DATE_MESSAGE] = &I2CPSession::GetDateMessageHandler;
		m_MessagesHandlers[I2CP_CREATE_SESSION_MESSAGE] = &I2CPSession::CreateSessionMessageHandler;
		m_MessagesHandlers[I2CP_DESTROY_SESSION_MESSAGE] = &I2CPSession::DestroySessionMessageHandler;
		m_MessagesHandlers[I2CP_CREATE_LEASESET_MESSAGE] = &I2CPSession::CreateLeaseSetMessageHandler;
		m_MessagesHandlers[I2CP_SEND_MESSAGE_MESSAGE] = &I2CPSession::SendMessageMessageHandler;
		m_MessagesHandlers[I2CP_SEND_MESSAGE_EXPIRES_MESSAGE] = &I2CPSession::SendMessageExpiresMessageHandler;	
		m_MessagesHandlers[I2CP_HOST_LOOKUP_MESSAGE] = &I2CPSession::HostLookupMessageHandler;
		m_MessagesHandlers[I2CP_DEST_LOOKUP_MESSAGE] = &I2CPSession::DestLookupMessageHandler;	
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
		for (auto it: m_Sessions)
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
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&I2CPServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void I2CPServer::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (!ecode && socket)
		{
			boost::system::error_code ec;
			auto ep = socket->remote_endpoint (ec);
			if (!ec)
			{	
				LogPrint (eLogDebug, "I2CP: new connection from ", ep);
				auto session = std::make_shared<I2CPSession>(*this, socket);
				m_Sessions[session->GetSessionID ()] = session;
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

	void I2CPServer::RemoveSession (uint16_t sessionID)
	{
		m_Sessions.erase (sessionID);
	}	
}
}

