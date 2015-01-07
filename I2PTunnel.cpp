#include <cassert>
#include "base64.h"
#include "Log.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace client
{
	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner, 
	    boost::asio::ip::tcp::socket * socket, const i2p::data::LeaseSet * leaseSet): 
		I2PServiceHandler(owner), m_Socket (socket), m_RemoteEndpoint (socket->remote_endpoint ()),
		m_IsQuiet (true)
	{
		m_Stream = GetOwner()->GetLocalDestination ()->CreateStream (*leaseSet);
	}	

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner,
	    boost::asio::ip::tcp::socket * socket, std::shared_ptr<i2p::stream::Stream> stream):
		I2PServiceHandler(owner), m_Socket (socket), m_Stream (stream),
		m_RemoteEndpoint (socket->remote_endpoint ()), m_IsQuiet (true)
	{
	}

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
	    boost::asio::ip::tcp::socket * socket, const boost::asio::ip::tcp::endpoint& target, bool quiet):
		I2PServiceHandler(owner), m_Socket (socket), m_Stream (stream),
		m_RemoteEndpoint (target), m_IsQuiet (quiet)
	{
	}

	I2PTunnelConnection::~I2PTunnelConnection ()
	{
		delete m_Socket;
	}	

	void I2PTunnelConnection::I2PConnect (const uint8_t * msg, size_t len)
	{
		if (m_Stream)
		{
			if (msg)
				m_Stream->Send (msg, len); // connect and send
			else	
				m_Stream->Send (m_Buffer, 0); // connect
		}
		StreamReceive ();
		Receive ();
	}
		
	void I2PTunnelConnection::Connect ()
	{
		if (m_Socket)
			m_Socket->async_connect (m_RemoteEndpoint, std::bind (&I2PTunnelConnection::HandleConnect,
				shared_from_this (), std::placeholders::_1));
	}	
		
	void I2PTunnelConnection::Terminate ()
	{
		if (Kill()) return;
		if (m_Stream)
		{
			m_Stream->Close ();
			m_Stream.reset ();
		}	
		m_Socket->close ();
		Done(shared_from_this ());
	}			

	void I2PTunnelConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer(m_Buffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),                
			std::bind(&I2PTunnelConnection::HandleReceived, shared_from_this (), 
			std::placeholders::_1, std::placeholders::_2));
	}	
	
	void I2PTunnelConnection::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint ("I2PTunnel read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{	
			if (m_Stream)
				m_Stream->Send (m_Buffer, bytes_transferred);
			Receive ();
		}
	}	

	void I2PTunnelConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint ("I2PTunnel write error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
			StreamReceive ();
	}

	void I2PTunnelConnection::StreamReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
				std::bind (&I2PTunnelConnection::HandleStreamReceive, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2),
				I2P_TUNNEL_CONNECTION_MAX_IDLE);
	}	

	void I2PTunnelConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint ("I2PTunnel stream read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			boost::asio::async_write (*m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		std::bind (&I2PTunnelConnection::HandleWrite, shared_from_this (), std::placeholders::_1));
		}
	}

	void I2PTunnelConnection::HandleConnect (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint ("I2PTunnel connect error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint ("I2PTunnel connected");
			if (m_IsQuiet)
				StreamReceive ();
			else
			{
				// send destination first like received from I2P
				std::string dest = m_Stream->GetRemoteIdentity ().ToBase64 ();
				dest += "\n";
				memcpy (m_StreamBuffer, dest.c_str (), dest.size ());
				HandleStreamReceive (boost::system::error_code (), dest.size ());
			}	
			Receive ();	
		}
	}

	I2PClientTunnel::I2PClientTunnel (const std::string& destination, int port, ClientDestination * localDestination): 
		I2PService (localDestination),
		m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_Timer (GetService ()), m_Destination (destination), m_DestinationIdentHash (nullptr)
	{
	}	

	I2PClientTunnel::~I2PClientTunnel ()
	{
		Stop ();
	}
	
	void I2PClientTunnel::Start ()
	{
		GetIdentHash();
		m_Acceptor.listen ();
		Accept ();
	}

	void I2PClientTunnel::Stop ()
	{
		m_Acceptor.close();
		m_Timer.cancel ();
		ClearHandlers ();
		auto *originalIdentHash = m_DestinationIdentHash;
		m_DestinationIdentHash = nullptr;
		delete originalIdentHash;
	}

	/* HACK: maybe we should create a caching IdentHash provider in AddressBook */
	const i2p::data::IdentHash * I2PClientTunnel::GetIdentHash ()
	{
		if (!m_DestinationIdentHash)
		{
			i2p::data::IdentHash identHash;
			if (i2p::client::context.GetAddressBook ().GetIdentHash (m_Destination, identHash))
				m_DestinationIdentHash = new i2p::data::IdentHash (identHash);
			else
				LogPrint (eLogWarning,"Remote destination ", m_Destination, " not found");
		}
		return m_DestinationIdentHash;
	}

	
	void I2PClientTunnel::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&I2PClientTunnel::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}	

	void I2PClientTunnel::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			const i2p::data::IdentHash *identHash = GetIdentHash();
			if (identHash)
				GetLocalDestination ()->CreateStream (
					std::bind (&I2PClientTunnel::HandleStreamRequestComplete,
					this, std::placeholders::_1, socket), *identHash);
			else
			{
				LogPrint (eLogError,"Closing socket");
				delete socket;
			}
			Accept ();
		}
		else
		{
			LogPrint (eLogError,"Closing socket on accept because: ", ecode.message ());
			delete socket;
		}
	}

	void I2PClientTunnel::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream, boost::asio::ip::tcp::socket * socket)
	{
		if (stream)
		{
			LogPrint (eLogInfo,"New I2PTunnel connection");
			auto connection = std::make_shared<I2PTunnelConnection>(this, socket, stream);
			AddHandler (connection);
			connection->I2PConnect ();
		}
		else
		{
			LogPrint (eLogError,"Issue when creating the stream, check the previous warnings for more info.");
			delete socket;
		}
	}

	I2PServerTunnel::I2PServerTunnel (const std::string& address, int port, ClientDestination * localDestination): 
		I2PService (localDestination), m_Endpoint (boost::asio::ip::address::from_string (address), port)
	{
	}
	
	void I2PServerTunnel::Start ()
	{
		Accept ();
	}

	void I2PServerTunnel::Stop ()
	{
		ClearHandlers ();
	}	

	void I2PServerTunnel::Accept ()
	{
		auto localDestination = GetLocalDestination ();	
		if (localDestination)
			localDestination->AcceptStreams (std::bind (&I2PServerTunnel::HandleAccept, this, std::placeholders::_1));
		else
			LogPrint ("Local destination not set for server tunnel");
	}

	void I2PServerTunnel::HandleAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{	
			auto conn = std::make_shared<I2PTunnelConnection> (this, stream, new boost::asio::ip::tcp::socket (GetService ()), m_Endpoint);
			AddHandler (conn);
			conn->Connect ();
		}	
	}
}		
}	
