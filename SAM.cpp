#include <string.h>
#include <stdio.h>
#include <boost/bind.hpp>
#include "base64.h"
#include "Identity.h"
#include "Log.h"
#include "NetDb.h"
#include "Destination.h"
#include "ClientContext.h"
#include "SAM.h"

namespace i2p
{
namespace client
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
			i2p::stream::DeleteStream (m_Stream);
			m_Stream = nullptr;
		}
	}	

	void SAMSocket::Terminate ()
	{
		if (m_Stream)
		{
			m_Stream->Close ();
			i2p::stream::DeleteStream (m_Stream);
			m_Stream = nullptr;
		}
		switch (m_SocketType)
		{
			case eSAMSocketTypeSession:
				m_Owner.CloseSession (m_ID);
			break;
			case eSAMSocketTypeStream:
			{
				if (m_Session)
					m_Session->sockets.remove (this);
				break;
			}
			case eSAMSocketTypeAcceptor:
			{
				if (m_Session)
				{
					m_Session->sockets.remove (this);
					m_Session->localDestination->StopAcceptingStreams ();
				}
				break;
			}
			default:
				;
		}
		m_Socket.close ();
	//	delete this;
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
		m_Session = m_Owner.CreateSession (id, destination == SAM_VALUE_TRANSIENT ? "" : destination); 
		if (m_Session)
		{
			m_SocketType = eSAMSocketTypeSession;
			if (m_Session->localDestination->IsReady ())
			{
				if (style == SAM_VALUE_DATAGRAM)
					m_Session->localDestination->CreateDatagramDestination ();
				SendSessionCreateReplyOk ();
			}
			else
			{
				m_Timer.expires_from_now (boost::posix_time::seconds(SAM_SESSION_READINESS_CHECK_INTERVAL));
				m_Timer.async_wait (boost::bind (&SAMSocket::HandleSessionReadinessCheckTimer,
					this, boost::asio::placeholders::error));	
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
				m_Timer.async_wait (boost::bind (&SAMSocket::HandleSessionReadinessCheckTimer,
					this, boost::asio::placeholders::error));
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
		size_t l2 = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_SESSION_CREATE_REPLY_OK, priv);
		SendMessageReply (m_Buffer, l2, false);
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
		m_Session = m_Owner.FindSession (id);
		if (m_Session)
		{
			uint8_t ident[1024];
			size_t l = i2p::data::Base64ToByteStream (destination.c_str (), destination.length (), ident, 1024);
			i2p::data::IdentityEx dest;
			dest.FromBuffer (ident, l);
			auto leaseSet = i2p::data::netdb.FindLeaseSet (dest.GetIdentHash ());
			if (leaseSet)
				Connect (*leaseSet);
			else
			{
				i2p::data::netdb.RequestDestination (dest.GetIdentHash (), true, m_Session->localDestination->GetTunnelPool ());
				m_Timer.expires_from_now (boost::posix_time::seconds(SAM_CONNECT_TIMEOUT));
				m_Timer.async_wait (boost::bind (&SAMSocket::HandleStreamDestinationRequestTimer,
					this, boost::asio::placeholders::error, dest.GetIdentHash ()));	
			}
		}
		else	
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);		
	}

	void SAMSocket::Connect (const i2p::data::LeaseSet& remote)
	{
		m_SocketType = eSAMSocketTypeStream;
		m_Session->sockets.push_back (this);
		m_Stream = m_Session->localDestination->CreateStream (remote);
		m_Stream->Send ((uint8_t *)m_Buffer, 0); // connect
		I2PReceive ();			
		SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
	}

	void SAMSocket::HandleStreamDestinationRequestTimer (const boost::system::error_code& ecode, i2p::data::IdentHash ident)
	{
		if (!ecode) // timeout expired
		{
			auto leaseSet = m_Session->localDestination->FindLeaseSet (ident);
			if (leaseSet)
				Connect (*leaseSet);
			else
			{
				LogPrint ("SAM destination to connect not found");
				SendMessageReply (SAM_STREAM_STATUS_CANT_REACH_PEER, strlen(SAM_STREAM_STATUS_CANT_REACH_PEER), true);
			}
		}
	}

	void SAMSocket::HandleNamingLookupDestinationRequestTimer (const boost::system::error_code& ecode, i2p::data::IdentHash ident)
	{
		if (!ecode) // timeout expired
		{
			auto leaseSet = m_Session->localDestination->FindLeaseSet (ident);
			if (leaseSet)
				SendNamingLookupReply (leaseSet);
			else
			{
				LogPrint ("SAM name destination not found");
				size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_KEY_NOT_FOUND, (ident.ToBase32 () + ".b32.i2p").c_str ());
				SendMessageReply (m_Buffer, len, false);
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
		m_Session = m_Owner.FindSession (id);
		if (m_Session)
		{
			if (!m_Session->localDestination->IsAcceptingStreams ())
			{
				m_SocketType = eSAMSocketTypeAcceptor;
				m_Session->sockets.push_back (this);
				m_Session->localDestination->AcceptStreams (std::bind (&SAMSocket::HandleI2PAccept, this, std::placeholders::_1));
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
		auto localDestination = i2p::client::context.CreateNewLocalDestination ();
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
		i2p::data::IdentHash ident;
		if (name == "ME")
			SendNamingLookupReply (nullptr);
		else if (m_Session && i2p::data::netdb.GetAddressBook ().GetIdentHash (name, ident))
		{
			auto leaseSet = m_Session->localDestination->FindLeaseSet (ident);
			if (leaseSet)
				SendNamingLookupReply (leaseSet);
			else
			{
				i2p::data::netdb.RequestDestination (ident, true, m_Session->localDestination->GetTunnelPool ());
				m_Timer.expires_from_now (boost::posix_time::seconds(SAM_NAMING_LOOKUP_TIMEOUT));
				m_Timer.async_wait (boost::bind (&SAMSocket::HandleNamingLookupDestinationRequestTimer,
					this, boost::asio::placeholders::error, ident));
			}	
		}
		else
		{
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
			SendMessageReply (m_Buffer, len, false);
		}
	}	

	void SAMSocket::SendNamingLookupReply (const i2p::data::LeaseSet * leaseSet)
	{
		uint8_t buf[1024];
		char pub[1024];
		const i2p::data::IdentityEx& identity = leaseSet ? leaseSet->GetIdentity () : m_Session->localDestination->GetIdentity ();
		size_t l = identity.ToBuffer (buf, 1024);
		size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, pub, 1024);
		pub[l1] = 0;
		size_t l2 = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY, pub);
		SendMessageReply (m_Buffer, l2, false);
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
			if (ecode != boost::asio::error::operation_aborted)
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
			LogPrint ("SAM incoming I2P connection for session ", m_ID);
			m_Stream = stream;
			auto session = m_Owner.FindSession (m_ID);
			if (session)	
				session->localDestination->StopAcceptingStreams ();	
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
		m_DatagramEndpoint (boost::asio::ip::udp::v4 (), port-1), m_DatagramSocket (m_Service, m_DatagramEndpoint),
		m_NewSocket (nullptr)
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
		ReceiveDatagram ();
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
		ClientDestination * localDestination = nullptr; 
		if (destination != "")
		{
			uint8_t * buf = new uint8_t[destination.length ()];
			size_t l = i2p::data::Base64ToByteStream (destination.c_str (), destination.length (), buf, destination.length ());
			i2p::data::PrivateKeys keys;
			keys.FromBuffer (buf, l);
			delete[] buf;
			localDestination = i2p::client::context.CreateNewLocalDestination (keys);
		}
		else // transient
			localDestination = i2p::client::context.CreateNewLocalDestination (); 
		if (localDestination)
		{
			SAMSession session;
			session.localDestination = localDestination;
			std::unique_lock<std::mutex> l(m_SessionsMutex);
			auto ret = m_Sessions.insert (std::pair<std::string, SAMSession>(id, session));
			if (!ret.second)
				LogPrint ("Session ", id, " already exists");
			return &(ret.first->second);
		}
		return nullptr;
	}

	void SAMBridge::CloseSession (const std::string& id)
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
		{
			for (auto it1 : it->second.sockets)
				delete it1;
			it->second.sockets.clear ();
			it->second.localDestination->Stop ();
			m_Sessions.erase (it);
		}
	}

	SAMSession * SAMBridge::FindSession (const std::string& id)
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
			return &it->second;
		return nullptr;
	}

	void SAMBridge::ReceiveDatagram ()
	{
		m_DatagramSocket.async_receive_from (
			boost::asio::buffer (m_DatagramReceiveBuffer, i2p::datagram::MAX_DATAGRAM_SIZE), 
			m_SenderEndpoint,
			boost::bind (&SAMBridge::HandleReceivedDatagram, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}

	void SAMBridge::HandleReceivedDatagram (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			ReceiveDatagram ();
		}
		else
			LogPrint ("SAM datagram receive error: ", ecode.message ());
	}
}
}
