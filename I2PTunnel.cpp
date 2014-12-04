#include "base64.h"
#include "Log.h"
#include "NetDb.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace client
{
	I2PTunnelConnection::I2PTunnelConnection (I2PTunnel * owner, 
	    boost::asio::ip::tcp::socket * socket, const i2p::data::LeaseSet * leaseSet): 
		m_Socket (socket), m_Owner (owner), m_RemoteEndpoint (socket->remote_endpoint ())
	{
		m_Stream = m_Owner->GetLocalDestination ()->CreateStream (*leaseSet);
	}	

	I2PTunnelConnection::I2PTunnelConnection (I2PTunnel * owner, std::shared_ptr<i2p::stream::Stream> stream,  
	    boost::asio::ip::tcp::socket * socket, const boost::asio::ip::tcp::endpoint& target):
		m_Socket (socket), m_Stream (stream), m_Owner (owner), m_RemoteEndpoint (target)
	{
	}

	I2PTunnelConnection::~I2PTunnelConnection ()
	{
		delete m_Socket;
	}	

	void I2PTunnelConnection::I2PConnect (const uint8_t * msg, size_t len)
	{
		if (msg)
			m_Stream->Send (msg, len); // connect and send
		else	
			m_Stream->Send (m_Buffer, 0); // connect
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
		if (m_Stream)
		{
			m_Stream->Close ();
			m_Stream.reset ();
		}	
		m_Socket->close ();
		if (m_Owner)
			m_Owner->RemoveConnection (shared_from_this ());
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
			StreamReceive ();
			Receive ();	
		}
	}

	void I2PTunnel::AddConnection (std::shared_ptr<I2PTunnelConnection> conn)
	{
		m_Connections.insert (conn);
	}
		
	void I2PTunnel::RemoveConnection (std::shared_ptr<I2PTunnelConnection> conn)
	{
		m_Connections.erase (conn);
	}	
	
	void I2PTunnel::ClearConnections ()
	{
		m_Connections.clear ();
	}	
		
	I2PClientTunnel::I2PClientTunnel (boost::asio::io_service& service, const std::string& destination, 
		int port, ClientDestination * localDestination): 
		I2PTunnel (service, localDestination ? localDestination : 
			i2p::client::context.CreateNewLocalDestination (false, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256)), 
		m_Acceptor (service, boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_Timer (service), m_Destination (destination), m_DestinationIdentHash (nullptr), 
		m_RemoteLeaseSet (nullptr)
	{
	}	

	I2PClientTunnel::~I2PClientTunnel ()
	{
		Stop ();
	}
	
	void I2PClientTunnel::Start ()
	{
		i2p::data::IdentHash identHash;
		if (i2p::client::context.GetAddressBook ().GetIdentHash (m_Destination, identHash))
			m_DestinationIdentHash = new i2p::data::IdentHash (identHash);	
		if (!m_DestinationIdentHash)
			LogPrint ("I2PTunnel unknown destination ", m_Destination);
		m_Acceptor.listen ();
		Accept ();
	}

	void I2PClientTunnel::Stop ()
	{
		m_Acceptor.close();
		m_Timer.cancel ();
		ClearConnections ();
		m_DestinationIdentHash = nullptr;
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
			if (!m_DestinationIdentHash)
			{
				i2p::data::IdentHash identHash;
				if (i2p::client::context.GetAddressBook ().GetIdentHash (m_Destination, identHash))
					m_DestinationIdentHash = new i2p::data::IdentHash (identHash);
			}	
			if (m_DestinationIdentHash)
			{
				// try to get a LeaseSet
				m_RemoteLeaseSet = GetLocalDestination ()->FindLeaseSet (*m_DestinationIdentHash);
				if (m_RemoteLeaseSet && m_RemoteLeaseSet->HasNonExpiredLeases ())
					CreateConnection (socket);
				else
				{
					i2p::data::netdb.RequestDestination (*m_DestinationIdentHash, true, GetLocalDestination ()->GetTunnelPool ());
					m_Timer.expires_from_now (boost::posix_time::seconds (I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT));
					m_Timer.async_wait (std::bind (&I2PClientTunnel::HandleDestinationRequestTimer,
						this, std::placeholders::_1, socket));
				}
			}	
			else
			{
				LogPrint ("Remote destination ", m_Destination, " not found");
				delete socket;
			}	
				
			Accept ();
		}
		else
			delete socket;
	}

	void I2PClientTunnel::HandleDestinationRequestTimer (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (m_DestinationIdentHash)
			{
				m_RemoteLeaseSet = GetLocalDestination ()->FindLeaseSet (*m_DestinationIdentHash);
				CreateConnection (socket);
				return;
			}
		}
		delete socket;	
	}

	void I2PClientTunnel::CreateConnection (boost::asio::ip::tcp::socket * socket)
	{
		if (m_RemoteLeaseSet) // leaseSet found
		{	
			LogPrint ("New I2PTunnel connection");
			auto connection = std::make_shared<I2PTunnelConnection>(this, socket, m_RemoteLeaseSet);
			AddConnection (connection);
			connection->I2PConnect ();
		}
		else
		{
			LogPrint ("LeaseSet for I2PTunnel destination not found");
			delete socket;
		}	
	}

	I2PServerTunnel::I2PServerTunnel (boost::asio::io_service& service, const std::string& address, int port, 
		ClientDestination * localDestination): I2PTunnel (service, localDestination),
		m_Endpoint (boost::asio::ip::address::from_string (address), port)
	{
	}
	
	void I2PServerTunnel::Start ()
	{
		Accept ();
	}

	void I2PServerTunnel::Stop ()
	{
		ClearConnections ();
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
			AddConnection (conn);
			conn->Connect ();
		}	
	}
}		
}	
