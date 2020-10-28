/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <stdio.h>
#ifdef _MSC_VER
#include <stdlib.h>
#endif
#include "Base.h"
#include "Identity.h"
#include "Log.h"
#include "Destination.h"
#include "ClientContext.h"
#include "util.h"
#include "SAM.h"

namespace i2p
{
namespace client
{
	SAMSocket::SAMSocket (SAMBridge& owner):
		m_Owner (owner), m_Socket(owner.GetService()), m_Timer (m_Owner.GetService ()),
		m_BufferOffset (0),
		m_SocketType (eSAMSocketTypeUnknown), m_IsSilent (false),
		m_IsAccepting (false), m_Stream (nullptr)
	{
	}

	SAMSocket::~SAMSocket ()
	{
		m_Stream = nullptr;
	}

	void SAMSocket::Terminate (const char* reason)
	{
		if(m_Stream)
		{
			m_Stream->AsyncClose ();
			m_Stream = nullptr;
		}
		auto Session = m_Owner.FindSession(m_ID);
		switch (m_SocketType)
		{
			case eSAMSocketTypeSession:
				m_Owner.CloseSession (m_ID);
			break;
			case eSAMSocketTypeStream:
			{
				break;
			}
			case eSAMSocketTypeAcceptor:
			case eSAMSocketTypeForward:	
			{
				if (Session)
				{
					if (m_IsAccepting && Session->localDestination)
						Session->localDestination->StopAcceptingStreams ();
				}
				break;
			}
			default: ;
		}
		m_SocketType = eSAMSocketTypeTerminated;
		if (m_Socket.is_open ())
		{
			boost::system::error_code ec;
			m_Socket.shutdown (boost::asio::ip::tcp::socket::shutdown_both, ec);
			m_Socket.close ();
		}
		m_Owner.RemoveSocket(shared_from_this());
	}

	void SAMSocket::ReceiveHandshake ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_Buffer, SAM_SOCKET_BUFFER_SIZE),
			std::bind(&SAMSocket::HandleHandshakeReceived, shared_from_this (),
			std::placeholders::_1, std::placeholders::_2));
	}

	static bool SAMVersionAcceptable(const std::string & ver)
	{
		return ver == "3.0" || ver == "3.1";
	}

	static bool SAMVersionTooLow(const std::string & ver)
	{
		return ver.size() && ver[0] < '3';
	}

	static bool SAMVersionTooHigh(const std::string & ver)
	{
		return ver.size() && ver > "3.1";
	}

	void SAMSocket::HandleHandshakeReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: handshake read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("SAM: handshake read error");
		}
		else
		{
			m_Buffer[bytes_transferred] = 0;
			char * eol = (char *)memchr (m_Buffer, '\n', bytes_transferred);
			if (eol)
				*eol = 0;
			LogPrint (eLogDebug, "SAM: handshake ", m_Buffer);
			char * separator = strchr (m_Buffer, ' ');
			if (separator)
			{
				separator = strchr (separator + 1, ' ');
				if (separator)
					*separator = 0;
			}

			if (!strcmp (m_Buffer, SAM_HANDSHAKE))
			{
				std::string maxver("3.1");
				std::string minver("3.0");
				// try to find MIN and MAX, 3.0 if not found
				if (separator)
				{
					separator++;
					std::map<std::string, std::string> params;
					ExtractParams (separator, params);
					auto it = params.find (SAM_PARAM_MAX);
					if (it != params.end ())
						maxver = it->second;
					it = params.find(SAM_PARAM_MIN);
					if (it != params.end ())
						minver = it->second;
				}
				// version negotiation
				std::string version;
				if (SAMVersionAcceptable(maxver))
				{
					version = maxver;
				}
				else if (SAMVersionAcceptable(minver))
				{
					version = minver;
				}
				else if (SAMVersionTooLow(minver) && SAMVersionTooHigh(maxver))
				{
					version = "3.0";
				}

				if (SAMVersionAcceptable(version))
				{
#ifdef _MSC_VER
					size_t l = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_HANDSHAKE_REPLY, version.c_str ());
#else
					size_t l = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_HANDSHAKE_REPLY, version.c_str ());
#endif
					boost::asio::async_write (m_Socket, boost::asio::buffer (m_Buffer, l), boost::asio::transfer_all (),
						std::bind(&SAMSocket::HandleHandshakeReplySent, shared_from_this (),
						std::placeholders::_1, std::placeholders::_2));
				}
				else
					SendMessageReply (SAM_HANDSHAKE_NOVERSION, strlen (SAM_HANDSHAKE_NOVERSION), true);
			}
			else
			{
				LogPrint (eLogError, "SAM: handshake mismatch");
				Terminate ("SAM: handshake mismatch");
			}
		}
	}

	bool SAMSocket::IsSession(const std::string & id) const
	{
		return id == m_ID;
	}

	void SAMSocket::HandleHandshakeReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: handshake reply send error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("SAM: handshake reply send error");
		}
		else
		{
			m_Socket.async_read_some (boost::asio::buffer(m_Buffer, SAM_SOCKET_BUFFER_SIZE),
				std::bind(&SAMSocket::HandleMessage, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
		}
	}

	void SAMSocket::SendMessageReply (const char * msg, size_t len, bool close)
	{
		LogPrint (eLogDebug, "SAMSocket::SendMessageReply, close=",close?"true":"false", " reason: ", msg);

		if (!m_IsSilent || m_SocketType == eSAMSocketTypeForward)
			boost::asio::async_write (m_Socket, boost::asio::buffer (msg, len), boost::asio::transfer_all (),
				std::bind(&SAMSocket::HandleMessageReplySent, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2, close));
		else
		{
			if (close)
				Terminate ("SAMSocket::SendMessageReply(close=true)");
			else
				Receive ();
		}
	}

	void SAMSocket::HandleMessageReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred, bool close)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: reply send error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("SAM: reply send error");
		}
		else
		{
			if (close)
				Terminate ("SAMSocket::HandleMessageReplySent(close=true)");
			else
				Receive ();
		}
	}

	void SAMSocket::HandleMessage (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("SAM: read error");
		}
		else if (m_SocketType == eSAMSocketTypeStream)
			HandleReceived (ecode, bytes_transferred);
		else
		{
			bytes_transferred += m_BufferOffset;
			m_BufferOffset = 0;
			m_Buffer[bytes_transferred] = 0;
			char * eol = (char *)memchr (m_Buffer, '\n', bytes_transferred);
			if (eol)
			{
				if (eol > m_Buffer && eol[-1] == '\r') eol--;
				*eol = 0;
				char * separator = strchr (m_Buffer, ' ');
				if (separator)
				{
					separator = strchr (separator + 1, ' ');
					if (separator)
						*separator = 0;
					else
						separator = eol;

					if (!strcmp (m_Buffer, SAM_SESSION_CREATE))
						ProcessSessionCreate (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_STREAM_CONNECT))
						ProcessStreamConnect (separator + 1, bytes_transferred - (separator - m_Buffer) - 1, bytes_transferred - (eol - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_STREAM_ACCEPT))
						ProcessStreamAccept (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_STREAM_FORWARD))
						ProcessStreamForward (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_DEST_GENERATE))
						ProcessDestGenerate (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_NAMING_LOOKUP))
						ProcessNamingLookup (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_DATAGRAM_SEND) || !strcmp (m_Buffer, SAM_RAW_SEND))
					{
						size_t len = bytes_transferred - (separator - m_Buffer) - 1;
						size_t processed = ProcessDatagramSend (separator + 1, len, eol + 1);
						if (processed < len)
						{
							m_BufferOffset = len - processed;
							if (processed > 0)
								memmove (m_Buffer, separator + 1 + processed, m_BufferOffset);
							else
							{
								// restore string back
								*separator = ' ';
								*eol = '\n';
							}
						}
						// since it's SAM v1 reply is not expected
						Receive ();
					}
					else
					{
						LogPrint (eLogError, "SAM: unexpected message ", m_Buffer);
						Terminate ("SAM: unexpected message");
					}
				}
				else
				{
					LogPrint (eLogError, "SAM: malformed message ", m_Buffer);
					Terminate ("malformed message");
				}
			}

			else
			{
				LogPrint (eLogWarning, "SAM: incomplete message ", bytes_transferred);
				m_BufferOffset = bytes_transferred;
				// try to receive remaining message
				Receive ();
			}
		}
	}

	static bool IsAcceptableSessionName(const std::string & str)
	{
		auto itr = str.begin();
		while(itr != str.end())
		{
			char ch = *itr;
			++itr;
			if (ch == '<' || ch == '>' || ch == '"' || ch == '\'' || ch == '/')
				return false;
		}
		return true;
	}

	void SAMSocket::ProcessSessionCreate (char * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: session create: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& style = params[SAM_PARAM_STYLE];
		std::string& id = params[SAM_PARAM_ID];
		std::string& destination = params[SAM_PARAM_DESTINATION];

		if(!IsAcceptableSessionName(id))
		{
			// invalid session id
			SendMessageReply (SAM_SESSION_CREATE_INVALID_ID, strlen(SAM_SESSION_CREATE_INVALID_ID), true);
			return;
		}
		m_ID = id;
		if (m_Owner.FindSession (id))
		{
			// session exists
			SendMessageReply (SAM_SESSION_CREATE_DUPLICATED_ID, strlen(SAM_SESSION_CREATE_DUPLICATED_ID), true);
			return;
		}

		SAMSessionType type = eSAMSessionTypeUnknown;
		if (style == SAM_VALUE_STREAM) type = eSAMSessionTypeStream;
		else if (style == SAM_VALUE_DATAGRAM) type = eSAMSessionTypeDatagram;
		else if (style == SAM_VALUE_RAW) type = eSAMSessionTypeRaw;
		if (type == eSAMSessionTypeUnknown)
		{
			// unknown style
			SendI2PError("Unknown STYLE");
			return;
		}

		std::shared_ptr<boost::asio::ip::udp::endpoint> forward = nullptr;
		if ((type == eSAMSessionTypeDatagram || type == eSAMSessionTypeRaw) &&
			params.find(SAM_PARAM_HOST) != params.end() && params.find(SAM_PARAM_PORT) != params.end())
		{
			// udp forward selected
			boost::system::error_code e;
			// TODO: support hostnames in udp forward
			auto addr = boost::asio::ip::address::from_string(params[SAM_PARAM_HOST], e);
			if (e)
			{
				// not an ip address
				SendI2PError("Invalid IP Address in HOST");
				return;
			}

			auto port = std::stoi(params[SAM_PARAM_PORT]);
			if (port == -1)
			{
				SendI2PError("Invalid port");
				return;
			}
			forward = std::make_shared<boost::asio::ip::udp::endpoint>(addr, port);
		}

		//ensure we actually received a destination
		if (destination.empty())
		{
			SendMessageReply (SAM_SESSION_STATUS_INVALID_KEY, strlen(SAM_SESSION_STATUS_INVALID_KEY), true);
			return;
		}

		if (destination != SAM_VALUE_TRANSIENT)
		{
			//ensure it's a base64 string
			i2p::data::PrivateKeys keys;
			if (!keys.FromBase64(destination))
			{
				SendMessageReply(SAM_SESSION_STATUS_INVALID_KEY, strlen(SAM_SESSION_STATUS_INVALID_KEY), true);
				return;
			}
		}

		// create destination
		auto session = m_Owner.CreateSession (id, type, destination == SAM_VALUE_TRANSIENT ? "" : destination, &params);
		if (session)
		{
			m_SocketType = eSAMSocketTypeSession;
			if (type == eSAMSessionTypeDatagram || type == eSAMSessionTypeRaw)
			{
				session->UDPEndpoint = forward;
				auto dest = session->localDestination->CreateDatagramDestination ();
				if (type == eSAMSessionTypeDatagram)
					dest->SetReceiver (std::bind (&SAMSocket::HandleI2PDatagramReceive, shared_from_this (),
						std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
				else // raw
					dest->SetRawReceiver (std::bind (&SAMSocket::HandleI2PRawDatagramReceive, shared_from_this (),
						std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
			}

			if (session->localDestination->IsReady ())
				SendSessionCreateReplyOk ();
			else
			{
				m_Timer.expires_from_now (boost::posix_time::seconds(SAM_SESSION_READINESS_CHECK_INTERVAL));
				m_Timer.async_wait (std::bind (&SAMSocket::HandleSessionReadinessCheckTimer,
					shared_from_this (), std::placeholders::_1));
			}
		}
		else
			SendMessageReply (SAM_SESSION_CREATE_DUPLICATED_DEST, strlen(SAM_SESSION_CREATE_DUPLICATED_DEST), true);
	}

	void SAMSocket::HandleSessionReadinessCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto session = m_Owner.FindSession(m_ID);
			if(session)
			{
				if (session->localDestination->IsReady ())
					SendSessionCreateReplyOk ();
				else
				{
					m_Timer.expires_from_now (boost::posix_time::seconds(SAM_SESSION_READINESS_CHECK_INTERVAL));
					m_Timer.async_wait (std::bind (&SAMSocket::HandleSessionReadinessCheckTimer,
						shared_from_this (), std::placeholders::_1));
				}
			}
		}
	}

	void SAMSocket::SendSessionCreateReplyOk ()
	{
		auto session = m_Owner.FindSession(m_ID);
		if (session)
		{
			uint8_t buf[1024];
			char priv[1024];
			size_t l = session->localDestination->GetPrivateKeys ().ToBuffer (buf, 1024);
			size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, priv, 1024);
			priv[l1] = 0;
#ifdef _MSC_VER
			size_t l2 = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_CREATE_REPLY_OK, priv);
#else
			size_t l2 = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_CREATE_REPLY_OK, priv);
#endif
			SendMessageReply (m_Buffer, l2, false);
		}
	}

	void SAMSocket::ProcessStreamConnect (char * buf, size_t len, size_t rem)
	{
		LogPrint (eLogDebug, "SAM: stream connect: ", buf);
		if ( m_SocketType != eSAMSocketTypeUnknown)
		{
			SendI2PError ("Socket already in use");
			return;
		}	
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& destination = params[SAM_PARAM_DESTINATION];
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;
		m_ID = id;
		auto session = m_Owner.FindSession (id);
		if (session)
		{
			if (rem > 0) // handle follow on data
			{
				memmove (m_Buffer, buf + len + 1, rem); // buf is a pointer to m_Buffer's content
				m_BufferOffset = rem;
			}
			else
				m_BufferOffset = 0;

			auto dest = std::make_shared<i2p::data::IdentityEx> ();
			size_t l = dest->FromBase64(destination);
			if (l > 0)
			{
				context.GetAddressBook().InsertFullAddress(dest);
				auto leaseSet = session->localDestination->FindLeaseSet(dest->GetIdentHash());
				if (leaseSet)
					Connect(leaseSet, session);
				else
				{
					session->localDestination->RequestDestination(dest->GetIdentHash(),
						std::bind(&SAMSocket::HandleConnectLeaseSetRequestComplete,
						shared_from_this(), std::placeholders::_1));
				}
			}
			else
				SendMessageReply (SAM_STREAM_STATUS_INVALID_KEY, strlen(SAM_STREAM_STATUS_INVALID_KEY), true);
		}
		else
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
	}

	void SAMSocket::Connect (std::shared_ptr<const i2p::data::LeaseSet> remote, std::shared_ptr<SAMSession> session)
	{
		if (!session) session = m_Owner.FindSession(m_ID);
		if (session)
		{
			m_SocketType = eSAMSocketTypeStream;
			m_Stream = session->localDestination->CreateStream (remote);
			if (m_Stream)
			{	
				m_Stream->Send ((uint8_t *)m_Buffer, m_BufferOffset); // connect and send
				m_BufferOffset = 0;
				I2PReceive ();
				SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
			}	
			else
				SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
		}
		else
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
	}

	void SAMSocket::HandleConnectLeaseSetRequestComplete (std::shared_ptr<i2p::data::LeaseSet> leaseSet)
	{
		if (leaseSet)
			Connect (leaseSet);
		else
		{
			LogPrint (eLogError, "SAM: destination to connect not found");
			SendMessageReply (SAM_STREAM_STATUS_CANT_REACH_PEER, strlen(SAM_STREAM_STATUS_CANT_REACH_PEER), true);
		}
	}

	void SAMSocket::ProcessStreamAccept (char * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: stream accept: ", buf);
		if ( m_SocketType != eSAMSocketTypeUnknown)
		{
			SendI2PError ("Socket already in use");
			return;
		}	
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;
		m_ID = id;
		auto session = m_Owner.FindSession (id);
		if (session)
		{
			m_SocketType = eSAMSocketTypeAcceptor;
			if (!session->localDestination->IsAcceptingStreams ())
			{
				m_IsAccepting = true;
				session->localDestination->AcceptOnce (std::bind (&SAMSocket::HandleI2PAccept, shared_from_this (), std::placeholders::_1));
			}
			SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
		}
		else
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
	}

	void SAMSocket::ProcessStreamForward (char * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: stream forward: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& id = params[SAM_PARAM_ID];
		auto session = m_Owner.FindSession (id);
		if (!session)
		{
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
			return;
		}	
		if (session->localDestination->IsAcceptingStreams ())
		{	
			SendI2PError ("Already accepting");
			return;
		}	
		auto it = params.find (SAM_PARAM_PORT);
		if (it == params.end ())
		{
			SendI2PError ("PORT is missing");
			return;
		}	
		auto port = std::stoi (it->second);
		if (port <= 0 || port >= 0xFFFF)
		{
			SendI2PError ("Invalid PORT");
			return;
		}	
		boost::system::error_code ec;
		auto ep = m_Socket.remote_endpoint (ec);
		if (ec)
		{
			SendI2PError ("Socket error");
			return;
		}	
		ep.port (port);
		m_SocketType = eSAMSocketTypeForward;
		m_ID = id;
		m_IsAccepting = true;
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;
		session->localDestination->AcceptStreams (std::bind (&SAMSocket::HandleI2PForward, 
			shared_from_this (), std::placeholders::_1, ep));
		SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);			
	}	
		
	size_t SAMSocket::ProcessDatagramSend (char * buf, size_t len, const char * data)
	{
		LogPrint (eLogDebug, "SAM: datagram send: ", buf, " ", len);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		size_t size = std::stoi(params[SAM_PARAM_SIZE]), offset = data - buf;
		if (offset + size <= len)
		{
			auto session = m_Owner.FindSession(m_ID);
			if (session)
			{
				auto d = session->localDestination->GetDatagramDestination ();
				if (d)
				{
					i2p::data::IdentityEx dest;
					dest.FromBase64 (params[SAM_PARAM_DESTINATION]);
					if (session->Type == eSAMSessionTypeDatagram)
						d->SendDatagramTo ((const uint8_t *)data, size, dest.GetIdentHash ());
					else // raw
						d->SendRawDatagramTo ((const uint8_t *)data, size, dest.GetIdentHash ());
				}
				else
					LogPrint (eLogError, "SAM: missing datagram destination");
			}
			else
				LogPrint (eLogError, "SAM: session is not created from DATAGRAM SEND");
		}
		else
		{
			LogPrint (eLogWarning, "SAM: sent datagram size ", size, " exceeds buffer ", len - offset);
			return 0; // try to receive more
		}
		return offset + size;
	}

	void SAMSocket::ProcessDestGenerate (char * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: dest generate");
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		// extract signature type
		i2p::data::SigningKeyType signatureType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1;
		i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL;
		auto it = params.find (SAM_PARAM_SIGNATURE_TYPE);
		if (it != params.end ())
		{
			if (!m_Owner.ResolveSignatureType (it->second, signatureType))
				LogPrint (eLogWarning, "SAM: ", SAM_PARAM_SIGNATURE_TYPE, " is invalid ", it->second);
		}
		it = params.find (SAM_PARAM_CRYPTO_TYPE);
		if (it != params.end ())
		{
			try
			{
				cryptoType = std::stoi(it->second);
			}
			catch (const std::exception& ex)
			{
				LogPrint (eLogWarning, "SAM: ", SAM_PARAM_CRYPTO_TYPE, "error: ", ex.what ());
			}
		}
		auto keys = i2p::data::PrivateKeys::CreateRandomKeys (signatureType, cryptoType);
#ifdef _MSC_VER
		size_t l = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_DEST_REPLY,
			keys.GetPublic ()->ToBase64 ().c_str (), keys.ToBase64 ().c_str ());
#else
		size_t l = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_DEST_REPLY,
			keys.GetPublic ()->ToBase64 ().c_str (), keys.ToBase64 ().c_str ());
#endif
		SendMessageReply (m_Buffer, l, false);
	}

	void SAMSocket::ProcessNamingLookup (char * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: naming lookup: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& name = params[SAM_PARAM_NAME];
		std::shared_ptr<const i2p::data::IdentityEx> identity;
		std::shared_ptr<const Address> addr;
		auto session = m_Owner.FindSession(m_ID);
		auto dest = session == nullptr ? context.GetSharedLocalDestination() : session->localDestination;
		if (name == "ME")
			SendNamingLookupReply (dest->GetIdentity ());
		else if ((identity = context.GetAddressBook ().GetFullAddress (name)) != nullptr)
			SendNamingLookupReply (identity);
		else if ((addr = context.GetAddressBook ().GetAddress (name)))
		{
			if (addr->IsIdentHash ())
			{
				auto leaseSet = dest->FindLeaseSet (addr->identHash);
				if (leaseSet)
					SendNamingLookupReply (leaseSet->GetIdentity ());
				else
					dest->RequestDestination (addr->identHash,
						std::bind (&SAMSocket::HandleNamingLookupLeaseSetRequestComplete,
						shared_from_this (), std::placeholders::_1, name));
			}
			else
				dest->RequestDestinationWithEncryptedLeaseSet (addr->blindedPublicKey,
					std::bind (&SAMSocket::HandleNamingLookupLeaseSetRequestComplete,
					shared_from_this (), std::placeholders::_1, name));
		}
		else
		{
			LogPrint (eLogError, "SAM: naming failed, unknown address ", name);
#ifdef _MSC_VER
			size_t len = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
#else
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
#endif
			SendMessageReply (m_Buffer, len, false);
		}
	}

	void SAMSocket::SendI2PError(const std::string & msg)
	{
		LogPrint (eLogError, "SAM: i2p error ", msg);
#ifdef _MSC_VER
		size_t len = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_STATUS_I2P_ERROR, msg.c_str());
#else
		size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_STATUS_I2P_ERROR, msg.c_str());
#endif
		SendMessageReply (m_Buffer, len, true);
	}

	void SAMSocket::HandleNamingLookupLeaseSetRequestComplete (std::shared_ptr<i2p::data::LeaseSet> leaseSet, std::string name)
	{
		if (leaseSet)
		{
			context.GetAddressBook ().InsertFullAddress (leaseSet->GetIdentity ());
			SendNamingLookupReply (leaseSet->GetIdentity ());
		}
		else
		{
			LogPrint (eLogError, "SAM: naming lookup failed. LeaseSet for ", name, " not found");
#ifdef _MSC_VER
			size_t len = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
#else
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
#endif
			SendMessageReply (m_Buffer, len, false);
		}
	}

	void SAMSocket::SendNamingLookupReply (std::shared_ptr<const i2p::data::IdentityEx> identity)
	{
		auto base64 = identity->ToBase64 ();
#ifdef _MSC_VER
		size_t l = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY, base64.c_str ());
#else
		size_t l = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY, base64.c_str ());
#endif
		SendMessageReply (m_Buffer, l, false);
	}

	void SAMSocket::ExtractParams (char * buf, std::map<std::string, std::string>& params)
	{
		char * separator;
		do
		{
			separator = strchr (buf, ' ');
			if (separator) *separator = 0;
			char * value = strchr (buf, '=');
			if (value)
			{
				*value = 0;
				value++;
				params[buf] = value;
			}
			buf = separator + 1;
		}
		while (separator);
	}

	void SAMSocket::Receive ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_Buffer + m_BufferOffset, SAM_SOCKET_BUFFER_SIZE - m_BufferOffset),
			std::bind((m_SocketType == eSAMSocketTypeStream) ? &SAMSocket::HandleReceived : &SAMSocket::HandleMessage,
			shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void SAMSocket::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("read error");
		}
		else
		{
			if (m_Stream)
			{
				bytes_transferred += m_BufferOffset;
				m_BufferOffset = 0;
				m_Stream->AsyncSend ((uint8_t *)m_Buffer, bytes_transferred,
					std::bind(&SAMSocket::HandleStreamSend, shared_from_this(), std::placeholders::_1));
			}
			else
			{
				Terminate("No Stream Remaining");
			}
		}
	}

	void SAMSocket::I2PReceive ()
	{
		if (m_Stream)
		{
			if (m_Stream->GetStatus () == i2p::stream::eStreamStatusNew ||
				m_Stream->GetStatus () == i2p::stream::eStreamStatusOpen) // regular
			{
				m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE),
						std::bind (&SAMSocket::HandleI2PReceive, shared_from_this(),
						std::placeholders::_1, std::placeholders::_2),
							SAM_SOCKET_CONNECTION_MAX_IDLE);
			}
			else // closed by peer
			{
				uint8_t * buff = new uint8_t[SAM_SOCKET_BUFFER_SIZE];
				// get remaning data
				auto len = m_Stream->ReadSome (buff, SAM_SOCKET_BUFFER_SIZE);
				if (len > 0) // still some data
				{
					WriteI2PDataImmediate(buff, len);
				}
				else // no more data
				{
					delete [] buff;
					Terminate ("no more data");
				}
			}
		}
	}

	void SAMSocket::WriteI2PDataImmediate(uint8_t * buff, size_t sz)
	{
		boost::asio::async_write (
			m_Socket,
			boost::asio::buffer (buff, sz),
			boost::asio::transfer_all(),
			std::bind (&SAMSocket::HandleWriteI2PDataImmediate, shared_from_this (), std::placeholders::_1, buff)); // postpone termination
	}

	void SAMSocket::HandleWriteI2PDataImmediate(const boost::system::error_code & ec, uint8_t * buff)
	{
		delete [] buff;
	}

	void SAMSocket::WriteI2PData(size_t sz)
	{
		boost::asio::async_write (
			m_Socket,
			boost::asio::buffer (m_StreamBuffer, sz),
			boost::asio::transfer_all(),
			std::bind(&SAMSocket::HandleWriteI2PData, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

	void SAMSocket::HandleI2PReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: stream read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
			{
				if (bytes_transferred > 0)
				{
					WriteI2PData(bytes_transferred);
				}
				else
				{
					auto s = shared_from_this ();
					m_Owner.GetService ().post ([s] { s->Terminate ("stream read error"); });
				}
			}
			else
			{
				auto s = shared_from_this ();
				m_Owner.GetService ().post ([s] { s->Terminate ("stream read error (op aborted)"); });
			}
		}
		else
		{
			if (m_SocketType != eSAMSocketTypeTerminated)
			{
				if (bytes_transferred > 0)
				{
					WriteI2PData(bytes_transferred);
				}
				else
					I2PReceive();
			}
		}
	}

	void SAMSocket::HandleWriteI2PData (const boost::system::error_code& ecode, size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: socket write error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("socket write error at HandleWriteI2PData");
		}
		else
		{
			I2PReceive ();
		}
	}

	void SAMSocket::HandleI2PAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			LogPrint (eLogDebug, "SAM: incoming I2P connection for session ", m_ID);
			m_SocketType = eSAMSocketTypeStream;
			m_IsAccepting = false;
			m_Stream = stream;
			context.GetAddressBook ().InsertFullAddress (stream->GetRemoteIdentity ());
			auto session = m_Owner.FindSession (m_ID);
			if (session)
			{
				// find more pending acceptors
				for (auto & it: m_Owner.ListSockets (m_ID))
					if (it->m_SocketType == eSAMSocketTypeAcceptor)
					{
						it->m_IsAccepting = true;
						session->localDestination->AcceptOnce (std::bind (&SAMSocket::HandleI2PAccept, it, std::placeholders::_1));
						break;
					}
			}
			if (!m_IsSilent)
			{
				// get remote peer address
				auto ident_ptr = stream->GetRemoteIdentity();
				const size_t ident_len = ident_ptr->GetFullLen();
				uint8_t* ident = new uint8_t[ident_len];

				// send remote peer address as base64
				const size_t l = ident_ptr->ToBuffer (ident, ident_len);
				const size_t l1 = i2p::data::ByteStreamToBase64 (ident, l, (char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE);
				delete[] ident;
				m_StreamBuffer[l1] = '\n';
				HandleI2PReceive (boost::system::error_code (), l1 +1); // we send identity like it has been received from stream
			}
			else
				I2PReceive ();
		}
		else
			LogPrint (eLogWarning, "SAM: I2P acceptor has been reset");
	}

	void SAMSocket::HandleI2PForward (std::shared_ptr<i2p::stream::Stream> stream, 
		boost::asio::ip::tcp::endpoint ep)
	{
		if (stream)
		{
			LogPrint (eLogDebug, "SAM: incoming forward I2P connection for session ", m_ID);
			auto newSocket = std::make_shared<SAMSocket>(m_Owner);
			newSocket->SetSocketType (eSAMSocketTypeStream);
			auto s = shared_from_this ();
			newSocket->GetSocket ().async_connect (ep, 
				[s, newSocket, stream](const boost::system::error_code& ecode)
			    {
					if (!ecode)
					{
						s->m_Owner.AddSocket (newSocket);
						newSocket->Receive ();
						newSocket->m_Stream = stream;
						newSocket->m_ID = s->m_ID;
						if (!s->m_IsSilent)
						{
							// get remote peer address
							auto dest = stream->GetRemoteIdentity()->ToBase64 ();
							memcpy (newSocket->m_StreamBuffer, dest.c_str (), dest.length ());
							newSocket->m_StreamBuffer[dest.length ()] = '\n';
							newSocket->HandleI2PReceive (boost::system::error_code (),dest.length () + 1); // we send identity like it has been received from stream
						}
						else
							newSocket->I2PReceive ();
					}
					else
						stream->AsyncClose ();
				});			
		}
		else
			LogPrint (eLogWarning, "SAM: I2P forward acceptor has been reset");
	}	
		
	void SAMSocket::HandleI2PDatagramReceive (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: datagram received ", len);
		auto base64 = from.ToBase64 ();
		auto session = m_Owner.FindSession(m_ID);
		if(session)
		{
			auto ep = session->UDPEndpoint;
			if (ep)
			{
				// udp forward enabled
				size_t bsz = base64.size();
				size_t sz = bsz + 1 + len;
				// build datagram body
				uint8_t * data = new uint8_t[sz];
				// Destination
				memcpy(data, base64.c_str(), bsz);
				// linefeed
				data[bsz] = '\n';
				// Payload
				memcpy(data+bsz+1, buf, len);
				// send to remote endpoint
				m_Owner.SendTo(data, sz, ep);
				delete [] data;
			}
			else
			{
#ifdef _MSC_VER
				size_t l = sprintf_s ((char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE, SAM_DATAGRAM_RECEIVED, base64.c_str (), (long unsigned int)len);
#else
				size_t l = snprintf ((char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE, SAM_DATAGRAM_RECEIVED, base64.c_str (), (long unsigned int)len);
#endif
				if (len < SAM_SOCKET_BUFFER_SIZE - l)
				{
					memcpy (m_StreamBuffer + l, buf, len);
					WriteI2PData(len + l);
				}
				else
					LogPrint (eLogWarning, "SAM: received datagram size ", len," exceeds buffer");
			}
		}
	}

	void SAMSocket::HandleI2PRawDatagramReceive (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: raw datagram received ", len);
		auto session = m_Owner.FindSession(m_ID);
		if(session)
		{
			auto ep = session->UDPEndpoint;
			if (ep)
				// udp forward enabled
				m_Owner.SendTo(buf, len, ep);
			else
			{
#ifdef _MSC_VER
				size_t l = sprintf_s ((char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE, SAM_RAW_RECEIVED, (long unsigned int)len);
#else
				size_t l = snprintf ((char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE, SAM_RAW_RECEIVED, (long unsigned int)len);
#endif
				if (len < SAM_SOCKET_BUFFER_SIZE - l)
				{
					memcpy (m_StreamBuffer + l, buf, len);
					WriteI2PData(len + l);
				}
				else
					LogPrint (eLogWarning, "SAM: received raw datagram size ", len," exceeds buffer");
			}
		}
	}

	void SAMSocket::HandleStreamSend(const boost::system::error_code & ec)
	{
		m_Owner.GetService ().post (std::bind( !ec ? &SAMSocket::Receive : &SAMSocket::TerminateClose, shared_from_this()));
	}

	SAMSession::SAMSession (SAMBridge & parent, const std::string & id, SAMSessionType type, std::shared_ptr<ClientDestination> dest):
		m_Bridge(parent),
		localDestination (dest),
		UDPEndpoint(nullptr),
		Name(id), Type (type)
	{
	}

	SAMSession::~SAMSession ()
	{
		i2p::client::context.DeleteLocalDestination (localDestination);
	}

	void SAMSession::CloseStreams ()
	{
		for(const auto & itr : m_Bridge.ListSockets(Name))
		{
			itr->Terminate(nullptr);
		}
	}

	SAMBridge::SAMBridge (const std::string& address, int port, bool singleThread):
		RunnableService ("SAM"), m_IsSingleThread (singleThread),
		m_Acceptor (GetIOService (), boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(address), port)),
		m_DatagramEndpoint (boost::asio::ip::address::from_string(address), port-1), m_DatagramSocket (GetIOService (), m_DatagramEndpoint),
		m_SignatureTypes
		{
			{"DSA_SHA1", i2p::data::SIGNING_KEY_TYPE_DSA_SHA1},
			{"ECDSA_SHA256_P256", i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256},
			{"ECDSA_SHA384_P384", i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA384_P384},
			{"ECDSA_SHA512_P521", i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA512_P521},
			{"EdDSA_SHA512_Ed25519", i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519},
			{"GOST_GOSTR3411256_GOSTR3410CRYPTOPROA", i2p::data::SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256},
			{"GOST_GOSTR3411512_GOSTR3410TC26A512", i2p::data::SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512},
			{"RedDSA_SHA512_Ed25519", i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519},
		}
	{
	}

	SAMBridge::~SAMBridge ()
	{
		if (IsRunning ())
			Stop ();
	}

	void SAMBridge::Start ()
	{
		Accept ();
		ReceiveDatagram ();
		StartIOService ();
	}

	void SAMBridge::Stop ()
	{
		try
		{
			m_Acceptor.cancel ();
		}
		catch (const std::exception& ex)
		{
			LogPrint (eLogError, "SAM: runtime exception: ", ex.what ());
		}

		{
			std::unique_lock<std::mutex> l(m_SessionsMutex);
			for (auto& it: m_Sessions)
				it.second->CloseStreams ();
			m_Sessions.clear ();
		}
		StopIOService ();
	}

	void SAMBridge::Accept ()
	{
		auto newSocket = std::make_shared<SAMSocket>(*this);
		m_Acceptor.async_accept (newSocket->GetSocket(), std::bind (&SAMBridge::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void SAMBridge::AddSocket(std::shared_ptr<SAMSocket> socket)
	{
		std::unique_lock<std::mutex> lock(m_OpenSocketsMutex);
		m_OpenSockets.push_back(socket);
	}		
		
	void SAMBridge::RemoveSocket(const std::shared_ptr<SAMSocket> & socket)
	{
		std::unique_lock<std::mutex> lock(m_OpenSocketsMutex);
		m_OpenSockets.remove_if([socket](const std::shared_ptr<SAMSocket> & item) -> bool { return item == socket; });
	}

	void SAMBridge::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<SAMSocket> socket)
	{
		if (!ecode)
		{
			boost::system::error_code ec;
			auto ep = socket->GetSocket ().remote_endpoint (ec);
			if (!ec)
			{
				LogPrint (eLogDebug, "SAM: new connection from ", ep);
				AddSocket (socket);
				socket->ReceiveHandshake ();
			}
			else
				LogPrint (eLogError, "SAM: incoming connection error ", ec.message ());
		}
		else
			LogPrint (eLogError, "SAM: accept error: ", ecode.message ());

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}

	std::shared_ptr<SAMSession> SAMBridge::CreateSession (const std::string& id, SAMSessionType type,
		const std::string& destination, const std::map<std::string, std::string> * params)
	{
		std::shared_ptr<ClientDestination> localDestination = nullptr;
		if (destination != "")
		{
			i2p::data::PrivateKeys keys;
			if (!keys.FromBase64 (destination)) return nullptr;
			localDestination = m_IsSingleThread ?
				i2p::client::context.CreateNewLocalDestination (GetIOService (), keys, true, params) :
				i2p::client::context.CreateNewLocalDestination (keys, true, params);
		}
		else // transient
		{
			// extract signature type
			i2p::data::SigningKeyType signatureType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1;
			i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL;
			if (params)
			{
				auto it = params->find (SAM_PARAM_SIGNATURE_TYPE);
				if (it != params->end ())
				{
					if (!ResolveSignatureType (it->second, signatureType))
						LogPrint (eLogWarning, "SAM: ", SAM_PARAM_SIGNATURE_TYPE, " is invalid ", it->second);
				}
				it = params->find (SAM_PARAM_CRYPTO_TYPE);
				if (it != params->end ())
				{
					try
					{
						cryptoType = std::stoi(it->second);
					}
					catch (const std::exception& ex)
					{
						LogPrint (eLogWarning, "SAM: ", SAM_PARAM_CRYPTO_TYPE, "error: ", ex.what ());
					}
				}
			}
			localDestination = m_IsSingleThread ?
				i2p::client::context.CreateNewLocalDestination (GetIOService (), true, signatureType, cryptoType, params) :
				i2p::client::context.CreateNewLocalDestination (true, signatureType, cryptoType, params);
		}
		if (localDestination)
		{
			localDestination->Acquire ();
			auto session = std::make_shared<SAMSession>(*this, id, type, localDestination);
			std::unique_lock<std::mutex> l(m_SessionsMutex);
			auto ret = m_Sessions.insert (std::make_pair(id, session));
			if (!ret.second)
				LogPrint (eLogWarning, "SAM: Session ", id, " already exists");
			return ret.first->second;
		}
		return nullptr;
	}

	void SAMBridge::CloseSession (const std::string& id)
	{
		std::shared_ptr<SAMSession> session;
		{
			std::unique_lock<std::mutex> l(m_SessionsMutex);
			auto it = m_Sessions.find (id);
			if (it != m_Sessions.end ())
			{
				session = it->second;
				m_Sessions.erase (it);
			}
		}
		if (session)
		{
			session->localDestination->Release ();
			session->localDestination->StopAcceptingStreams ();
			session->CloseStreams ();
			if (m_IsSingleThread)
			{
				auto timer = std::make_shared<boost::asio::deadline_timer>(GetService ());
				timer->expires_from_now (boost::posix_time::seconds(5)); // postpone destination clean for 5 seconds
				timer->async_wait ([timer, session](const boost::system::error_code& ecode)
				{
					// session's destructor is called here
				});
			}
		}
	}

	std::shared_ptr<SAMSession> SAMBridge::FindSession (const std::string& id) const
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
			return it->second;
		return nullptr;
	}

	std::list<std::shared_ptr<SAMSocket> > SAMBridge::ListSockets(const std::string & id) const
	{
		std::list<std::shared_ptr<SAMSocket > > list;
		{
			std::unique_lock<std::mutex> l(m_OpenSocketsMutex);
			for (const auto & itr : m_OpenSockets)
				if (itr->IsSession(id))
					list.push_back(itr);
		}
		return list;
	}

	void SAMBridge::SendTo(const uint8_t * buf, size_t len, std::shared_ptr<boost::asio::ip::udp::endpoint> remote)
	{
		if(remote)
		{
			m_DatagramSocket.send_to(boost::asio::buffer(buf, len), *remote);
		}
	}

	void SAMBridge::ReceiveDatagram ()
	{
		m_DatagramSocket.async_receive_from (
			boost::asio::buffer (m_DatagramReceiveBuffer, i2p::datagram::MAX_DATAGRAM_SIZE),
			m_SenderEndpoint,
			std::bind (&SAMBridge::HandleReceivedDatagram, this, std::placeholders::_1, std::placeholders::_2));
	}

	void SAMBridge::HandleReceivedDatagram (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			m_DatagramReceiveBuffer[bytes_transferred] = 0;
			char * eol = strchr ((char *)m_DatagramReceiveBuffer, '\n');
			if(eol)
			{
				*eol = 0; eol++;
				size_t payloadLen = bytes_transferred - ((uint8_t *)eol - m_DatagramReceiveBuffer);
				LogPrint (eLogDebug, "SAM: datagram received ", m_DatagramReceiveBuffer," size=", payloadLen);
				char * sessionID = strchr ((char *)m_DatagramReceiveBuffer, ' ');
				if (sessionID)
				{
					sessionID++;
					char * destination = strchr (sessionID, ' ');
					if (destination)
					{
						*destination = 0; destination++;
						auto session = FindSession (sessionID);
						if (session)
						{
							i2p::data::IdentityEx dest;
							dest.FromBase64 (destination);
							if (session->Type == eSAMSessionTypeDatagram)
								session->localDestination->GetDatagramDestination ()->
									SendDatagramTo ((uint8_t *)eol, payloadLen, dest.GetIdentHash ());
							else // raw
								session->localDestination->GetDatagramDestination ()->
									SendRawDatagramTo ((uint8_t *)eol, payloadLen, dest.GetIdentHash ());
						}
						else
							LogPrint (eLogError, "SAM: Session ", sessionID, " not found");
					}
					else
						LogPrint (eLogError, "SAM: Missing destination key");
				}
				else
					LogPrint (eLogError, "SAM: Missing sessionID");
			}
			else
				LogPrint(eLogError, "SAM: invalid datagram");
			ReceiveDatagram ();
		}
		else
			LogPrint (eLogError, "SAM: datagram receive error: ", ecode.message ());
	}

	bool SAMBridge::ResolveSignatureType (const std::string& name, i2p::data::SigningKeyType& type) const
	{
		try
		{
			type = std::stoi (name);
		}
		catch (const std::invalid_argument& ex)
		{
			// name is not numeric, resolving
			auto it = m_SignatureTypes.find (name);
			if (it != m_SignatureTypes.end ())
				type = it->second;
			else
				return false;
		}
		catch (const std::exception& ex)
		{
			return false;
		}
		// name has been resolved
		return true;
	}
}
}
