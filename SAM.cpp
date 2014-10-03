#include <string.h>
#include <stdio.h>
#include <boost/bind.hpp>
#include "base64.h"
#include "Identity.h"
#include "Log.h"
#include "NetDb.h"
#include "SAM.h"

namespace i2p
{
namespace stream
{
	SAMSocket::SAMSocket (SAMBridge& owner): 
		m_Owner (owner), m_Socket (m_Owner.GetService ()), m_Timer (m_Owner.GetService ()),
		m_SocketType (eSAMSocketTypeUnknown), m_IsSilent (false), m_Stream (nullptr),
		m_Session (nullptr)
	{
	}

	SAMSocket::~SAMSocket ()
	{
		if (m_Stream)
		{
			m_Stream->Close ();
			DeleteStream (m_Stream);
		}
	}	

	void SAMSocket::Terminate ()
	{
		if (m_Stream)
		{
			m_Stream->Close ();
			DeleteStream (m_Stream);
			m_Stream = nullptr;
		}
		switch (m_SocketType)
		{
			case eSAMSocketTypeSession:
				m_Owner.CloseSession (m_ID);
			break;
			case eSAMSocketTypeStream:
			{
				auto session = m_Owner.FindSession (m_ID);
				if (session)
					session->sockets.remove (this);
				break;
			}
			case eSAMSocketTypeAcceptor:
			{
				auto session = m_Owner.FindSession (m_ID);
				if (session)
				{
					session->sockets.remove (this);
					session->localDestination->ResetAcceptor ();
				}
				break;
			}
			default:
				;
		}
		delete this;
	}

	void SAMSocket::ReceiveHandshake ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_Buffer, SAM_SOCKET_BUFFER_SIZE),                
			boost::bind(&SAMSocket::HandleHandshakeReceived, this, 
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void SAMSocket::HandleHandshakeReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("SAM handshake read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{	
			m_Buffer[bytes_transferred] = 0;
			LogPrint ("SAM handshake ", m_Buffer);
			if (!memcmp (m_Buffer, SAM_HANDSHAKE, strlen (SAM_HANDSHAKE)))
			{
				// TODO: check version
				boost::asio::async_write (m_Socket, boost::asio::buffer (SAM_HANDSHAKE_REPLY, strlen (SAM_HANDSHAKE_REPLY)), boost::asio::transfer_all (),
        			boost::bind(&SAMSocket::HandleHandshakeReplySent, this, 
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
			}
			else
			{
				LogPrint ("SAM handshake mismatch");
				Terminate ();
			}
		}
	}

	void SAMSocket::HandleHandshakeReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("SAM handshake reply send error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			m_Socket.async_read_some (boost::asio::buffer(m_Buffer, SAM_SOCKET_BUFFER_SIZE),                
				boost::bind(&SAMSocket::HandleMessage, this, 
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));	
		}	
	}

	void SAMSocket::SendMessageReply (const char * msg, size_t len, bool close)
	{
		if (!m_IsSilent || m_SocketType == eSAMSocketTypeAcceptor) 
			boost::asio::async_write (m_Socket, boost::asio::buffer (msg, len), boost::asio::transfer_all (),
				boost::bind(&SAMSocket::HandleMessageReplySent, this, 
				boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, close));
		else
		{
			if (close)
				Terminate ();
			else
				Receive ();	
		}		
	}

	void SAMSocket::HandleMessageReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred, bool close)
	{
		if (ecode)
        {
			LogPrint ("SAM reply send error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			if (close)
				Terminate ();
			else
				Receive ();	
		}	
	}

	void SAMSocket::HandleMessage (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("SAM read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			m_Buffer[bytes_transferred] = 0;
			char * eol = strchr (m_Buffer, '\n');
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
						ProcessStreamConnect (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_STREAM_ACCEPT))
						ProcessStreamAccept (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else if (!strcmp (m_Buffer, SAM_DEST_GENERATE))
						ProcessDestGenerate ();
					else if (!strcmp (m_Buffer, SAM_NAMING_LOOKUP))
						ProcessNamingLookup (separator + 1, bytes_transferred - (separator - m_Buffer) - 1);
					else		
					{	
						LogPrint ("SAM unexpected message ", m_Buffer);		
						Terminate ();
					}
				}
				else
				{
					LogPrint ("SAM malformed message ", m_Buffer);
					Terminate ();
				}
			}
			else
			{	
				LogPrint ("SAM malformed message ", m_Buffer);
				Terminate ();
			}
		}
	}

	void SAMSocket::ProcessSessionCreate (char * buf, size_t len)
	{
		LogPrint ("SAM session create: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, len, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& destination = params[SAM_PARAM_DESTINATION];
		m_ID = id;
		if (m_Owner.FindSession (id))
		{
			// session exists
			SendMessageReply (SAM_SESSION_CREATE_DUPLICATED_ID, strlen(SAM_SESSION_CREATE_DUPLICATED_ID), true);
			return;
		}
		m_Session = m_Owner.CreateSession (id, destination == SAM_VALUE_TRANSIENT ? "" : destination); 
		if (m_Session)
		{
			m_SocketType = eSAMSocketTypeSession;
			uint8_t buf[1024];
			char priv[1024];
			size_t l = m_Session->localDestination->GetPrivateKeys ().ToBuffer (buf, 1024);
			size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, priv, 1024);
			priv[l1] = 0;
			size_t l2 = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_CREATE_REPLY_OK, priv);
			SendMessageReply (m_Buffer, l2, false);
		}
		else
			SendMessageReply (SAM_SESSION_CREATE_DUPLICATED_DEST, strlen(SAM_SESSION_CREATE_DUPLICATED_DEST), true);
	}

	void SAMSocket::ProcessStreamConnect (char * buf, size_t len)
	{
		LogPrint ("SAM stream connect: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, len, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& destination = params[SAM_PARAM_DESTINATION];
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;	
		m_ID = id;
		auto session = m_Owner.FindSession (id);
		if (session)
		{
			uint8_t ident[1024];
			size_t l = i2p::data::Base64ToByteStream (destination.c_str (), destination.length (), ident, 1024);
			i2p::data::IdentityEx dest;
			dest.FromBuffer (ident, l);
			auto leaseSet = i2p::data::netdb.FindLeaseSet (dest.GetIdentHash ());
			if (leaseSet)
				Connect (*leaseSet, session);
			else
			{
				i2p::data::netdb.Subscribe (dest.GetIdentHash (), session->localDestination->GetTunnelPool ());
				m_Timer.expires_from_now (boost::posix_time::seconds(SAM_CONNECT_TIMEOUT));
				m_Timer.async_wait (boost::bind (&SAMSocket::HandleDestinationRequestTimer,
					this, boost::asio::placeholders::error, dest.GetIdentHash (), session));	
			}
		}
		else	
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);		
	}

	void SAMSocket::Connect (const i2p::data::LeaseSet& remote, SAMSession * session)
	{
		m_SocketType = eSAMSocketTypeStream;
		session->sockets.push_back (this);
		m_Stream = session->localDestination->CreateNewOutgoingStream (remote);
		m_Stream->Send ((uint8_t *)m_Buffer, 0); // connect
		I2PReceive ();			
		SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
	}

	void SAMSocket::HandleDestinationRequestTimer (const boost::system::error_code& ecode, i2p::data::IdentHash ident, SAMSession * session)
	{
		if (!ecode) // timeout expired
		{
			auto leaseSet = i2p::data::netdb.FindLeaseSet (ident);
			if (leaseSet)
				Connect (*leaseSet, session);
			else
			{
				LogPrint ("SAM destination to connect not found");
				SendMessageReply (SAM_STREAM_STATUS_CANT_REACH_PEER, strlen(SAM_STREAM_STATUS_CANT_REACH_PEER), true);
			}
		}
	}

	void SAMSocket::ProcessStreamAccept (char * buf, size_t len)
	{
		LogPrint ("SAM stream accept: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, len, params);
		std::string& id = params[SAM_PARAM_ID];
		std::string& silent = params[SAM_PARAM_SILENT];
		if (silent == SAM_VALUE_TRUE) m_IsSilent = true;	
		m_ID = id;
		auto session = m_Owner.FindSession (id);
		if (session)
		{
			if (!session->localDestination->IsAcceptorSet ())
			{
				m_SocketType = eSAMSocketTypeAcceptor;
				session->sockets.push_back (this);
				session->localDestination->SetAcceptor (std::bind (&SAMSocket::HandleI2PAccept, this, std::placeholders::_1));
				SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
			}
			else
				SendMessageReply (SAM_STREAM_STATUS_I2P_ERROR, strlen(SAM_STREAM_STATUS_I2P_ERROR), true);
		}	
		else
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);
	}

	void SAMSocket::ProcessDestGenerate ()
	{
		LogPrint ("SAM dest generate");
		auto localDestination = CreateNewLocalDestination ();
		if (localDestination)
		{
			uint8_t buf[1024];
			char priv[1024], pub[1024];
			size_t l = localDestination->GetPrivateKeys ().ToBuffer (buf, 1024);
			size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, priv, 1024);
			priv[l1] = 0;

			l = localDestination->GetIdentity ().ToBuffer (buf, 1024);
			l1 = i2p::data::ByteStreamToBase64 (buf, l, pub, 1024);
			pub[l1] = 0;
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_DEST_REPLY, pub, priv);
			SendMessageReply (m_Buffer, len, true);
		}
		else
			SendMessageReply (SAM_DEST_REPLY_I2P_ERROR, strlen(SAM_DEST_REPLY_I2P_ERROR), true);
	}

	void SAMSocket::ProcessNamingLookup (char * buf, size_t len)
	{
		LogPrint ("SAM naming lookup: ", buf);
		std::map<std::string, std::string> params;
		ExtractParams (buf, len, params);
		std::string& name = params[SAM_PARAM_NAME];
		if (name == "ME" && m_Session)
		{
			uint8_t buf[1024];
			char pub[1024];
			size_t l = m_Session->localDestination->GetIdentity ().ToBuffer (buf, 1024);
			size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, pub, 1024);
			pub[l1] = 0;
			size_t l2 = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY, pub);
			SendMessageReply (m_Buffer, l2, false);
		}
		else
		{
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
			SendMessageReply (m_Buffer, len, true);
		}
	}	

	void SAMSocket::ExtractParams (char * buf, size_t len, std::map<std::string, std::string>& params)
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
		m_Socket.async_read_some (boost::asio::buffer(m_Buffer, SAM_SOCKET_BUFFER_SIZE),                
			boost::bind((m_SocketType == eSAMSocketTypeSession) ? &SAMSocket::HandleMessage : &SAMSocket::HandleReceived,
			this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void SAMSocket::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("SAM read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			if (m_Stream)
				m_Stream->Send ((uint8_t *)m_Buffer, bytes_transferred);
			Receive ();
		}
	}

	void SAMSocket::I2PReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE),
				boost::bind (&SAMSocket::HandleI2PReceive, this,
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred),
				SAM_SOCKET_CONNECTION_MAX_IDLE);
	}	

	void SAMSocket::HandleI2PReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint ("SAM stream read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			boost::asio::async_write (m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		boost::bind (&SAMSocket::HandleWriteI2PData, this, boost::asio::placeholders::error));
		}
	}

	void SAMSocket::HandleWriteI2PData (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint ("SAM socket write error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
			I2PReceive ();
	}

	void SAMSocket::HandleI2PAccept (i2p::stream::Stream * stream)
	{
		if (stream)
		{
			m_Stream = stream;
			auto session = m_Owner.FindSession (m_ID);
			if (session)	
				session->localDestination->ResetAcceptor ();	
			if (!m_IsSilent)
			{
				// send remote peer address
				uint8_t ident[1024];
				size_t l = stream->GetRemoteIdentity ().ToBuffer (ident, 1024);
				size_t l1 = i2p::data::ByteStreamToBase64 (ident, l, m_Buffer, SAM_SOCKET_BUFFER_SIZE);
				m_Buffer[l1] = '\n';
				SendMessageReply (m_Buffer, l1 + 1, false);
			}	
			I2PReceive ();
		}
	}	

	SAMBridge::SAMBridge (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		m_NewSocket	(nullptr)
	{
	}

	SAMBridge::~SAMBridge ()
	{
		Stop ();
		delete m_NewSocket;
	}	

	void SAMBridge::Start ()
	{
		Accept ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&SAMBridge::Run, this));
	}

	void SAMBridge::Stop ()
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
				LogPrint ("SAM: ", ex.what ());
			}	
		}	
	}

	void SAMBridge::Accept ()
	{
		m_NewSocket = new SAMSocket (*this);
		m_Acceptor.async_accept (m_NewSocket->GetSocket (), boost::bind (&SAMBridge::HandleAccept, this,
			boost::asio::placeholders::error));
	}

	void SAMBridge::HandleAccept(const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			LogPrint ("New SAM connection from ", m_NewSocket->GetSocket ().remote_endpoint ());
			m_NewSocket->ReceiveHandshake ();		
		}
		else
		{
			LogPrint ("SAM accept error: ",  ecode.message ());
			delete m_NewSocket;
			m_NewSocket = nullptr;	
		}

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}

	SAMSession * SAMBridge::CreateSession (const std::string& id, const std::string& destination)
	{
		StreamingDestination * localDestination = nullptr; 
		if (destination != "")
		{
			uint8_t * buf = new uint8_t[destination.length ()];
			size_t l = i2p::data::Base64ToByteStream (destination.c_str (), destination.length (), buf, destination.length ());
			i2p::data::PrivateKeys keys;
			keys.FromBuffer (buf, l);
			delete[] buf;
			localDestination = CreateNewLocalDestination (keys);
		}
		else // transient
			localDestination = CreateNewLocalDestination (); 
		if (localDestination)
		{
			SAMSession session;
			session.localDestination = localDestination;
			auto ret = m_Sessions.insert (std::pair<std::string, SAMSession>(id, session));
			if (!ret.second)
				LogPrint ("Session ", id, " already exists");
			return &(ret.first->second);
		}
		return nullptr;
	}

	void SAMBridge::CloseSession (const std::string& id)
	{
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
		{
			for (auto it1 : it->second.sockets)
				delete it1;
			it->second.sockets.clear ();
			DeleteLocalDestination (it->second.localDestination);
			m_Sessions.erase (it);
		}
	}

	SAMSession * SAMBridge::FindSession (const std::string& id)
	{
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
			return &it->second;
		return nullptr;
	}
}
}
