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
		m_Owner (owner), m_Socket (m_Owner.GetService ()), m_Timer (m_Owner.GetService ()),
		m_BufferOffset (0), m_SocketType (eSAMSocketTypeUnknown), m_IsSilent (false),
		m_IsAccepting (false), m_Stream (nullptr), m_Session (nullptr)
	{
	}

	SAMSocket::~SAMSocket ()
	{
		Terminate ("~SAMSocket()");
	}	

	void SAMSocket::CloseStream (const char* reason)
	{
		LogPrint (eLogDebug, "SAMSocket::CloseStream, reason: ", reason);
		if (m_Stream)
		{
			m_Stream->Close ();
			m_Stream.reset ();
		}	
	}	
		
	void SAMSocket::Terminate (const char* reason)
	{
		CloseStream (reason);
		
		switch (m_SocketType)
		{
			case eSAMSocketTypeSession:
				m_Owner.CloseSession (m_ID);
			break;
			case eSAMSocketTypeStream:
			{
				if (m_Session)
					m_Session->DelSocket (shared_from_this ());
				break;
			}
			case eSAMSocketTypeAcceptor:
			{
				if (m_Session)
				{
					m_Session->DelSocket (shared_from_this ());
					if (m_IsAccepting && m_Session->localDestination)
						m_Session->localDestination->StopAcceptingStreams ();
				}
				break;
			}
			default:
				;
		}
		m_SocketType = eSAMSocketTypeTerminated;
		if (m_Socket.is_open()) m_Socket.close ();
		m_Session = nullptr;
	}

	void SAMSocket::ReceiveHandshake ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_Buffer, SAM_SOCKET_BUFFER_SIZE),
			std::bind(&SAMSocket::HandleHandshakeReceived, shared_from_this (),
			std::placeholders::_1, std::placeholders::_2));
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
				std::string version("3.0");
				// try to find MIN and MAX, 3.0 if not found
				if (separator)
				{
					separator++;
					std::map<std::string, std::string> params;
					ExtractParams (separator, params);
					//auto it = params.find (SAM_PARAM_MAX);
					// TODO: check MIN as well
					//if (it != params.end ())
					//	version = it->second;
				}
				if (version[0] == '3') // we support v3 (3.0 and 3.1) only
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
					SendMessageReply (SAM_HANDSHAKE_I2P_ERROR, strlen (SAM_HANDSHAKE_I2P_ERROR), true);
			}
			else
			{
				LogPrint (eLogError, "SAM: handshake mismatch");
				Terminate ("SAM: handshake mismatch");
			}
		}
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

		if (!m_IsSilent)
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
					else if (!strcmp (m_Buffer, SAM_DEST_GENERATE))
						ProcessDestGenerate (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_NAMING_LOOKUP))
						ProcessNamingLookup (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_DATAGRAM_SEND))
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

	void SAMSocket::ProcessSessionCreate (char * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: session create: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& style = params[SAM_PARAM_STYLE];
		std::string& id = params[SAM_PARAM_ID];
		std::string& destination = params[SAM_PARAM_DESTINATION];
		m_ID = id;
		if (m_Owner.FindSession (id))
		{
			// session exists
			SendMessageReply (SAM_SESSION_CREATE_DUPLICATED_ID, strlen(SAM_SESSION_CREATE_DUPLICATED_ID), true);
			return;
		}

		std::shared_ptr<boost::asio::ip::udp::endpoint> forward = nullptr;
		if (style == SAM_VALUE_DATAGRAM && params.find(SAM_VALUE_HOST) != params.end() && params.find(SAM_VALUE_PORT) != params.end())
		{
			// udp forward selected
			boost::system::error_code e;
			// TODO: support hostnames in udp forward
			auto addr = boost::asio::ip::address::from_string(params[SAM_VALUE_HOST], e);
			if (e)
			{
				// not an ip address
				SendI2PError("Invalid IP Address in HOST");
				return;
			}

			auto port = std::stoi(params[SAM_VALUE_PORT]);
			if (port == -1)
			{
				SendI2PError("Invalid port");
				return;
			}
			forward = std::make_shared<boost::asio::ip::udp::endpoint>(addr, port);
		}

		// create destination
		m_Session = m_Owner.CreateSession (id, destination == SAM_VALUE_TRANSIENT ? "" : destination, &params);
		if (m_Session)
		{
			m_SocketType = eSAMSocketTypeSession;
			if (style == SAM_VALUE_DATAGRAM)
			{
				m_Session->UDPEndpoint = forward;
				auto dest = m_Session->localDestination->CreateDatagramDestination ();
				dest->SetReceiver (std::bind (&SAMSocket::HandleI2PDatagramReceive, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
			}

			if (m_Session->localDestination->IsReady ())
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
			if (m_Session->localDestination->IsReady ())
				SendSessionCreateReplyOk ();
			else
			{
				m_Timer.expires_from_now (boost::posix_time::seconds(SAM_SESSION_READINESS_CHECK_INTERVAL));
				m_Timer.async_wait (std::bind (&SAMSocket::HandleSessionReadinessCheckTimer,
					shared_from_this (), std::placeholders::_1));
			}
		}
	}

	void SAMSocket::SendSessionCreateReplyOk ()
	{
		uint8_t buf[1024];
		char priv[1024];
		size_t l = m_Session->localDestination->GetPrivateKeys ().ToBuffer (buf, 1024);
		size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, priv, 1024);
		priv[l1] = 0;
#ifdef _MSC_VER
		size_t l2 = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_CREATE_REPLY_OK, priv);
#else
		size_t l2 = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_CREATE_REPLY_OK, priv);
#endif
		SendMessageReply (m_Buffer, l2, false);
	}

	void SAMSocket::ProcessStreamConnect (char * buf, size_t len, size_t rem)
	{
		LogPrint (eLogDebug, "SAM: stream connect: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& destination = params[SAM_PARAM_DESTINATION];
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;
		m_ID = id;
		m_Session = m_Owner.FindSession (id);
		if (m_Session)
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
				context.GetAddressBook().InsertAddress(dest);
				auto leaseSet = m_Session->localDestination->FindLeaseSet(dest->GetIdentHash());
				if (leaseSet)
					Connect(leaseSet);
				else
				{
					m_Session->localDestination->RequestDestination(dest->GetIdentHash(),
						std::bind(&SAMSocket::HandleConnectLeaseSetRequestComplete,
						shared_from_this(), std::placeholders::_1));
				}
			}
			else
				SendMessageReply(SAM_SESSION_STATUS_INVALID_KEY, strlen(SAM_SESSION_STATUS_INVALID_KEY), true);
		}
		else
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
	}

	void SAMSocket::Connect (std::shared_ptr<const i2p::data::LeaseSet> remote)
	{
		m_SocketType = eSAMSocketTypeStream;
		m_Session->AddSocket (shared_from_this ());
		m_Stream = m_Session->localDestination->CreateStream (remote);
		m_Stream->Send ((uint8_t *)m_Buffer, m_BufferOffset); // connect and send
		m_BufferOffset = 0;
		I2PReceive ();
		SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
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
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;
		m_ID = id;
		m_Session = m_Owner.FindSession (id);
		if (m_Session)
		{
			m_SocketType = eSAMSocketTypeAcceptor;
			m_Session->AddSocket (shared_from_this ());
			if (!m_Session->localDestination->IsAcceptingStreams ())
			{
				m_IsAccepting = true;	
				m_Session->localDestination->AcceptOnce (std::bind (&SAMSocket::HandleI2PAccept, shared_from_this (), std::placeholders::_1));
			}
			SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
		}
		else
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
	}

	size_t SAMSocket::ProcessDatagramSend (char * buf, size_t len, const char * data)
	{
		LogPrint (eLogDebug, "SAM: datagram send: ", buf, " ", len);
		std::map<std::string, std::string> params;
		ExtractParams (buf, params);
		size_t size = std::stoi(params[SAM_PARAM_SIZE]), offset = data - buf;
		if (offset + size <= len)
		{
			if (m_Session)
			{
				auto d = m_Session->localDestination->GetDatagramDestination ();
				if (d)
				{
					i2p::data::IdentityEx dest;
					dest.FromBase64 (params[SAM_PARAM_DESTINATION]);
					d->SendDatagramTo ((const uint8_t *)data, size, dest.GetIdentHash ());
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
		auto it = params.find (SAM_PARAM_SIGNATURE_TYPE);
		if (it != params.end ())
				// TODO: extract string values
			signatureType = std::stoi(it->second);
		auto keys = i2p::data::PrivateKeys::CreateRandomKeys (signatureType);
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
		i2p::data::IdentHash ident;
		auto dest = m_Session == nullptr ? context.GetSharedLocalDestination() : m_Session->localDestination;
		if (name == "ME")
			SendNamingLookupReply (dest->GetIdentity ());
		else if ((identity = context.GetAddressBook ().GetAddress (name)) != nullptr)
			SendNamingLookupReply (identity);
		else if (context.GetAddressBook ().GetIdentHash (name, ident))
		{
			auto leaseSet = dest->FindLeaseSet (ident);
			if (leaseSet)
				SendNamingLookupReply (leaseSet->GetIdentity ());
			else
				dest->RequestDestination (ident,
					std::bind (&SAMSocket::HandleNamingLookupLeaseSetRequestComplete,
					shared_from_this (), std::placeholders::_1, ident));
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

	void SAMSocket::HandleNamingLookupLeaseSetRequestComplete (std::shared_ptr<i2p::data::LeaseSet> leaseSet, i2p::data::IdentHash ident)
	{
		if (leaseSet)
		{
			context.GetAddressBook ().InsertAddress (leaseSet->GetIdentity ());
			SendNamingLookupReply (leaseSet->GetIdentity ());
		}
		else
		{
			LogPrint (eLogError, "SAM: naming lookup failed. LeaseSet for ", ident.ToBase32 (), " not found");
#ifdef _MSC_VER
			size_t len = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY,
				context.GetAddressBook ().ToAddress (ident).c_str());
#else
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY,
				context.GetAddressBook ().ToAddress (ident).c_str());
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
		if (m_BufferOffset >= SAM_SOCKET_BUFFER_SIZE)
		{
			LogPrint (eLogError, "SAM: Buffer is full, terminate");
			Terminate ("Buffer is full");
			return;
		}
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
				auto s = shared_from_this ();
				m_Stream->AsyncSend ((uint8_t *)m_Buffer, bytes_transferred,
					[s](const boost::system::error_code& ecode)
				    {
						if (!ecode)
							s->Receive ();
						else	
							s->m_Owner.GetService ().post ([s] { s->Terminate ("AsyncSend failed"); });
					});
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
					std::bind (&SAMSocket::HandleI2PReceive, shared_from_this (),
						std::placeholders::_1, std::placeholders::_2),
					SAM_SOCKET_CONNECTION_MAX_IDLE);
			}
			else // closed by peer
			{
				// get remaning data
				auto len = m_Stream->ReadSome (m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE);
				if (len > 0) // still some data
				{
					boost::asio::async_write (m_Socket, boost::asio::buffer (m_StreamBuffer, len),
        				std::bind (&SAMSocket::HandleWriteI2PData, shared_from_this (), std::placeholders::_1));
				}
				else // no more data
					Terminate ("no more data");
			}		
		}
	}

	void SAMSocket::HandleI2PReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: stream read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
			{
				if (bytes_transferred > 0)
					boost::asio::async_write (m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		std::bind (&SAMSocket::HandleWriteI2PData, shared_from_this (), std::placeholders::_1)); // postpone termination
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
			boost::asio::async_write (m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		std::bind (&SAMSocket::HandleWriteI2PData, shared_from_this (), std::placeholders::_1));
		}
	}

	void SAMSocket::HandleWriteI2PData (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SAM: socket write error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ("socket write error at HandleWriteI2PData");
		}
		else
			I2PReceive ();
	}

	void SAMSocket::HandleI2PAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			LogPrint (eLogDebug, "SAM: incoming I2P connection for session ", m_ID);
			m_SocketType = eSAMSocketTypeStream;
			m_IsAccepting = false;
			m_Stream = stream;
			context.GetAddressBook ().InsertAddress (stream->GetRemoteIdentity ());
			auto session = m_Owner.FindSession (m_ID);
			if (session)
			{
				// find more pending acceptors
				for (auto it: session->ListSockets ())
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

	void SAMSocket::HandleI2PDatagramReceive (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		LogPrint (eLogDebug, "SAM: datagram received ", len);
		auto base64 = from.ToBase64 ();
		auto ep = m_Session->UDPEndpoint;
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
				boost::asio::async_write (m_Socket, boost::asio::buffer (m_StreamBuffer, len + l),
																	std::bind (&SAMSocket::HandleWriteI2PData, shared_from_this (), std::placeholders::_1));
			}
			else
				LogPrint (eLogWarning, "SAM: received datagram size ", len," exceeds buffer");
		}
	}

	SAMSession::SAMSession (std::shared_ptr<ClientDestination> dest):
		localDestination (dest),
		UDPEndpoint(nullptr)
	{
	}

	SAMSession::~SAMSession ()
	{
		CloseStreams();
		i2p::client::context.DeleteLocalDestination (localDestination);
	}

	void SAMSession::CloseStreams ()
	{
		std::vector<std::shared_ptr<SAMSocket> > socks;
		{
			std::lock_guard<std::mutex> lock(m_SocketsMutex);
			for (const auto& sock : m_Sockets) {
				socks.push_back(sock);
			}
		}
                for (auto & sock : socks ) sock->Terminate("SAMSession::CloseStreams()");
		m_Sockets.clear();
	}

	SAMBridge::SAMBridge (const std::string& address, int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(address), port)),
		m_DatagramEndpoint (boost::asio::ip::address::from_string(address), port-1), m_DatagramSocket (m_Service, m_DatagramEndpoint)
	{
	}

	SAMBridge::~SAMBridge ()
	{
		if (m_IsRunning)
			Stop ();
	}

	void SAMBridge::Start ()
	{
		Accept ();
		ReceiveDatagram ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&SAMBridge::Run, this));
	}

	void SAMBridge::Stop ()
	{
		m_IsRunning = false;
		m_Acceptor.cancel ();
		for (auto& it: m_Sessions)
			it.second->CloseStreams ();
		m_Sessions.clear ();
		m_Service.stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = nullptr;
		}
	}

	void SAMBridge::Run ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SAM: runtime exception: ", ex.what ());
			}
		}
	}

	void SAMBridge::Accept ()
	{
		auto newSocket = std::make_shared<SAMSocket> (*this);
		m_Acceptor.async_accept (newSocket->GetSocket (), std::bind (&SAMBridge::HandleAccept, this,
			std::placeholders::_1, newSocket));
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

	std::shared_ptr<SAMSession> SAMBridge::CreateSession (const std::string& id, const std::string& destination,
		const std::map<std::string, std::string> * params)
	{
		std::shared_ptr<ClientDestination> localDestination = nullptr;
		if (destination != "")
		{
			i2p::data::PrivateKeys keys;
			if (!keys.FromBase64 (destination)) return nullptr;
			localDestination = i2p::client::context.CreateNewLocalDestination (keys, true, params);
		}
		else // transient
		{
			// extract signature type
			i2p::data::SigningKeyType signatureType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1;
			if (params)
			{
				auto it = params->find (SAM_PARAM_SIGNATURE_TYPE);
				if (it != params->end ())
					// TODO: extract string values
					signatureType = std::stoi(it->second);
			}
			localDestination = i2p::client::context.CreateNewLocalDestination (true, signatureType, params);
		}
		if (localDestination)
		{
			localDestination->Acquire ();
			auto session = std::make_shared<SAMSession>(localDestination);
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
						session->localDestination->GetDatagramDestination ()->
							SendDatagramTo ((uint8_t *)eol, payloadLen, dest.GetIdentHash ());
					}
					else
						LogPrint (eLogError, "SAM: Session ", sessionID, " not found");
				}
				else
					LogPrint (eLogError, "SAM: Missing destination key");
			}
			else
				LogPrint (eLogError, "SAM: Missing sessionID");
			ReceiveDatagram ();
		}
		else
			LogPrint (eLogError, "SAM: datagram receive error: ", ecode.message ());
	}
}
}
