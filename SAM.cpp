#include <string.h>
#include <stdio.h>
#ifdef _MSC_VER
#include <stdlib.h>
#endif
#include <boost/lexical_cast.hpp>
#include "base64.h"
#include "Identity.h"
#include "Log.h"
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
		Terminate ();
	}	

	void SAMSocket::CloseStream ()
	{
		if (m_Stream)
		{	
			m_Stream->Close ();
			m_Stream.reset ();
		}	
	}	
		
	void SAMSocket::Terminate ()
	{
		CloseStream ();
		
		switch (m_SocketType)
		{
			case eSAMSocketTypeSession:
				m_Owner.CloseSession (m_ID);
			break;
			case eSAMSocketTypeStream:
			{
				if (m_Session)
					m_Session->sockets.remove (shared_from_this ());
				break;
			}
			case eSAMSocketTypeAcceptor:
			{
				if (m_Session)
				{
					m_Session->sockets.remove (shared_from_this ());
					m_Session->localDestination->StopAcceptingStreams ();
				}
				break;
			}
			default:
				;
		}
		m_SocketType = eSAMSocketTypeTerminated;
		m_Socket.close ();
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
			LogPrint ("SAM handshake read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{	
			m_Buffer[bytes_transferred] = 0;
			LogPrint ("SAM handshake ", m_Buffer);
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
					ExtractParams (separator, bytes_transferred - (separator - m_Buffer), params);
					auto it = params.find (SAM_PARAM_MAX);
					// TODO: check MIN as well
					if (it != params.end ())
						version = it->second;
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
				std::bind(&SAMSocket::HandleMessage, shared_from_this (), 
				std::placeholders::_1, std::placeholders::_2));	
		}	
	}

	void SAMSocket::SendMessageReply (const char * msg, size_t len, bool close)
	{
		if (!m_IsSilent || m_SocketType == eSAMSocketTypeAcceptor) 
			boost::asio::async_write (m_Socket, boost::asio::buffer (msg, len), boost::asio::transfer_all (),
				std::bind(&SAMSocket::HandleMessageReplySent, shared_from_this (), 
				std::placeholders::_1, std::placeholders::_2, close));
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

		// create destination	
		m_Session = m_Owner.CreateSession (id, destination == SAM_VALUE_TRANSIENT ? "" : destination, &params); 
		if (m_Session)
		{
			m_SocketType = eSAMSocketTypeSession;
			if (m_Session->localDestination->IsReady ())
			{
				if (style == SAM_VALUE_DATAGRAM)
				{
					auto dest = m_Session->localDestination->CreateDatagramDestination ();
					dest->SetReceiver (std::bind (&SAMSocket::HandleI2PDatagramReceive, shared_from_this (), 
						std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
				}
				SendSessionCreateReplyOk ();
			}
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
			i2p::data::IdentityEx dest;
			dest.FromBase64 (destination);
			context.GetAddressBook ().InsertAddress (dest);
			auto leaseSet = i2p::data::netdb.FindLeaseSet (dest.GetIdentHash ());
			if (leaseSet)
				Connect (*leaseSet);
			else
			{
				m_Session->localDestination->RequestDestination (dest.GetIdentHash (), 
					std::bind (&SAMSocket::HandleLeaseSetRequestComplete,
					shared_from_this (), std::placeholders::_1, dest.GetIdentHash ()));	
			}
		}
		else	
			SendMessageReply (SAM_STREAM_STATUS_INVALID_ID, strlen(SAM_STREAM_STATUS_INVALID_ID), true);		
	}

	void SAMSocket::Connect (const i2p::data::LeaseSet& remote)
	{
		m_SocketType = eSAMSocketTypeStream;
		m_Session->sockets.push_back (shared_from_this ());
		m_Stream = m_Session->localDestination->CreateStream (remote);
		m_Stream->Send ((uint8_t *)m_Buffer, 0); // connect
		I2PReceive ();			
		SendMessageReply (SAM_STREAM_STATUS_OK, strlen(SAM_STREAM_STATUS_OK), false);
	}

	void SAMSocket::HandleLeaseSetRequestComplete (bool success, i2p::data::IdentHash ident)
	{
		const i2p::data::LeaseSet * leaseSet =  nullptr;
		if (success) // timeout expired
			leaseSet = m_Session->localDestination->FindLeaseSet (ident);
		if (leaseSet)
			Connect (*leaseSet);
		else
		{
			LogPrint ("SAM destination to connect not found");
			SendMessageReply (SAM_STREAM_STATUS_CANT_REACH_PEER, strlen(SAM_STREAM_STATUS_CANT_REACH_PEER), true);
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
				m_Session->sockets.push_back (shared_from_this ());
				m_Session->localDestination->AcceptStreams (std::bind (&SAMSocket::HandleI2PAccept, shared_from_this (), std::placeholders::_1));
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
			auto priv = localDestination->GetPrivateKeys ().ToBase64 ();
			auto pub = localDestination->GetIdentity ().ToBase64 ();
#ifdef _MSC_VER
			size_t len = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_DEST_REPLY, pub.c_str (), priv.c_str ());	
#else			                        
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_DEST_REPLY, pub.c_str (), priv.c_str ());
#endif
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
		i2p::data::IdentityEx identity;
		if (name == "ME")
			SendNamingLookupReply (nullptr);
		else if (context.GetAddressBook ().GetAddress (name, identity))
			SendNamingLookupReply (identity);
		else 
		{
#ifdef _MSC_VER
			size_t len = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
#else				
			size_t len = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY_INVALID_KEY, name.c_str());
#endif
			SendMessageReply (m_Buffer, len, false);
		}
	}	

	void SAMSocket::SendNamingLookupReply (const i2p::data::LeaseSet * leaseSet)
	{
		const i2p::data::IdentityEx& identity = leaseSet ? leaseSet->GetIdentity () : m_Session->localDestination->GetIdentity ();
		if (leaseSet)
			// we found LeaseSet for our address, store it to addressbook
			context.GetAddressBook ().InsertAddress (identity);
		SendNamingLookupReply (identity);
	}

	void SAMSocket::SendNamingLookupReply (const i2p::data::IdentityEx& identity)
	{
		auto base64 = identity.ToBase64 ();
#ifdef _MSC_VER
		size_t l = sprintf_s (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY, base64.c_str ()); 	
#else			
		size_t l = snprintf (m_Buffer, SAM_SOCKET_BUFFER_SIZE, SAM_NAMING_REPLY, base64.c_str ());
#endif
		SendMessageReply (m_Buffer, l, false);
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
			std::bind((m_SocketType == eSAMSocketTypeSession) ? &SAMSocket::HandleMessage : &SAMSocket::HandleReceived,
			shared_from_this (), std::placeholders::_1, std::placeholders::_2));
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
				std::bind (&SAMSocket::HandleI2PReceive, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2),
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
        		std::bind (&SAMSocket::HandleWriteI2PData, shared_from_this (), std::placeholders::_1));
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

	void SAMSocket::HandleI2PAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			LogPrint ("SAM incoming I2P connection for session ", m_ID);
			m_Stream = stream;
			context.GetAddressBook ().InsertAddress (stream->GetRemoteIdentity ());
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

	void SAMSocket::HandleI2PDatagramReceive (const i2p::data::IdentityEx& ident, const uint8_t * buf, size_t len)
	{
		auto base64 = ident.ToBase64 ();
#ifdef _MSC_VER
		size_t l = sprintf_s ((char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE, SAM_DATAGRAM_RECEIVED, base64.c_str (), len); 	
#else			
		size_t l = snprintf ((char *)m_StreamBuffer, SAM_SOCKET_BUFFER_SIZE, SAM_DATAGRAM_RECEIVED, base64.c_str (), len); 	
#endif
		if (len < SAM_SOCKET_BUFFER_SIZE - l)	
		{	
			memcpy (m_StreamBuffer + l, buf, len);
			boost::asio::async_write (m_Socket, boost::asio::buffer (m_StreamBuffer, len + l),
        		std::bind (&SAMSocket::HandleWriteI2PData, shared_from_this (), std::placeholders::_1));
		}
		else
			LogPrint (eLogWarning, "Datagram size ", len," exceeds buffer");
	}

	SAMSession::SAMSession (ClientDestination * dest):
		localDestination (dest)
	{
	}
		
	SAMSession::~SAMSession ()
	{
		for (auto it: sockets)
			it->SetSocketType (eSAMSocketTypeTerminated);
		i2p::client::context.DeleteLocalDestination (localDestination);
	}

	void SAMSession::CloseStreams ()
	{
		for (auto it: sockets)
		{	
			it->CloseStream ();
			it->SetSocketType (eSAMSocketTypeTerminated);
		}	
		sockets.clear ();
	}

	SAMBridge::SAMBridge (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		m_DatagramEndpoint (boost::asio::ip::udp::v4 (), port-1), m_DatagramSocket (m_Service, m_DatagramEndpoint)
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
		for (auto it: m_Sessions)
			delete it.second;
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
				LogPrint ("SAM: ", ex.what ());
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
			LogPrint ("New SAM connection from ", socket->GetSocket ().remote_endpoint ());
			socket->ReceiveHandshake ();		
		}
		else
			LogPrint ("SAM accept error: ",  ecode.message ());

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}

	SAMSession * SAMBridge::CreateSession (const std::string& id, const std::string& destination, 
		const std::map<std::string, std::string> * params)
	{
		ClientDestination * localDestination = nullptr; 
		if (destination != "")
		{
			i2p::data::PrivateKeys keys;
			keys.FromBase64 (destination);
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
					signatureType = boost::lexical_cast<int> (it->second);
			}
			localDestination = i2p::client::context.CreateNewLocalDestination (false, signatureType, params); 
		}
		if (localDestination)
		{
			std::unique_lock<std::mutex> l(m_SessionsMutex);
			auto ret = m_Sessions.insert (std::pair<std::string, SAMSession *>(id, new SAMSession (localDestination)));
			if (!ret.second)
				LogPrint ("Session ", id, " already exists");
			return ret.first->second;
		}
		return nullptr;
	}

	void SAMBridge::CloseSession (const std::string& id)
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
		{
			auto session = it->second;
			session->CloseStreams ();
			m_Sessions.erase (it);
			delete session;
		}
	}

	SAMSession * SAMBridge::FindSession (const std::string& id)
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		auto it = m_Sessions.find (id);
		if (it != m_Sessions.end ())
			return it->second;
		return nullptr;
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
			LogPrint ("SAM datagram received ", m_DatagramReceiveBuffer," size=", payloadLen);
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
						auto leaseSet = i2p::data::netdb.FindLeaseSet (dest.GetIdentHash ());
						if (leaseSet)
							session->localDestination->GetDatagramDestination ()->
								SendDatagramTo ((uint8_t *)eol, payloadLen, *leaseSet);
						else
						{
							LogPrint ("SAM datagram destination not found");
							session->localDestination->RequestDestination (dest.GetIdentHash ());
						}	
					}	
					else
						LogPrint ("Session ", sessionID, " not found");
				}
				else
					LogPrint ("Missing destination key");
			}
			else
				LogPrint ("Missing sessionID");
			ReceiveDatagram ();
		}
		else
			LogPrint ("SAM datagram receive error: ", ecode.message ());
	}
}
}
