#include <boost/bind.hpp>
#include "base64.h"
#include "Log.h"
#include "NetDb.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace stream
{
	I2PTunnelConnection::I2PTunnelConnection (I2PTunnel * owner, 
	    boost::asio::ip::tcp::socket * socket, const i2p::data::LeaseSet * leaseSet): 
		m_Socket (socket), m_Owner (owner) 
	{
		m_Stream = m_Owner->GetLocalDestination ()->CreateNewOutgoingStream (*leaseSet);
		m_Stream->Send (m_Buffer, 0); // connect
		StreamReceive ();
		Receive ();
	}	

	I2PTunnelConnection::I2PTunnelConnection (I2PTunnel * owner, Stream * stream,  
	    boost::asio::ip::tcp::socket * socket, const boost::asio::ip::tcp::endpoint& target):
		m_Socket (socket), m_Stream (stream), m_Owner (owner)
	{
		if (m_Socket)
			m_Socket->async_connect (target, boost::bind (&I2PTunnelConnection::HandleConnect,
				this, boost::asio::placeholders::error));
	}

	I2PTunnelConnection::~I2PTunnelConnection ()
	{
		if (m_Stream)
		{
			m_Stream->Close ();
			DeleteStream (m_Stream);
			m_Stream = nullptr;
		}
		delete m_Socket;
	}	

	void I2PTunnelConnection::Terminate ()
	{	
		m_Socket->close ();
		if (m_Owner)
			m_Owner->RemoveConnection (this);
		// TODO: delete		
	}			

	void I2PTunnelConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer(m_Buffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),                
			boost::bind(&I2PTunnelConnection::HandleReceived, this, 
			boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}	
	
	void I2PTunnelConnection::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("I2PTunnel read error: ", ecode.message ());
			m_Stream->Close ();
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
			m_Stream->Close ();
			Terminate ();
		}
		else
			StreamReceive ();
	}

	void I2PTunnelConnection::StreamReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
				boost::bind (&I2PTunnelConnection::HandleStreamReceive, this,
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred),
				I2P_TUNNEL_CONNECTION_MAX_IDLE);
	}	

	void I2PTunnelConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint ("I2PTunnel stream read error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			boost::asio::async_write (*m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		boost::bind (&I2PTunnelConnection::HandleWrite, this, boost::asio::placeholders::error));
		}
	}

	void I2PTunnelConnection::HandleConnect (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint ("I2PTunnel connect error: ", ecode.message ());
			if (m_Stream) m_Stream->Close ();
			DeleteStream (m_Stream);
			m_Stream = nullptr;
		}
		else
		{
			LogPrint ("I2PTunnel connected");
			StreamReceive ();
			Receive ();	
		}
	}

	void I2PTunnel::AddConnection (I2PTunnelConnection * conn)
	{
		m_Connections.insert (conn);
	}
		
	void I2PTunnel::RemoveConnection (I2PTunnelConnection * conn)
	{
		m_Connections.erase (conn);
	}	
	
	void I2PTunnel::ClearConnections ()
	{
		for (auto it: m_Connections)
			delete it;
		m_Connections.clear ();
	}	
		
	I2PClientTunnel::I2PClientTunnel (boost::asio::io_service& service, const std::string& destination, 
		int port, StreamingDestination * localDestination): 
		I2PTunnel (service, localDestination ? localDestination : GetSharedLocalDestination ()), 
		m_Acceptor (service, boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_Destination (destination), m_DestinationIdentHash (nullptr), m_RemoteLeaseSet (nullptr)
	{
	}	

	I2PClientTunnel::~I2PClientTunnel ()
	{
		Stop ();
	}
	
	void I2PClientTunnel::Start ()
	{
		auto pos = m_Destination.find(".b32.i2p");
		if (pos != std::string::npos)
		{
			uint8_t hash[32];
			i2p::data::Base32ToByteStream (m_Destination.c_str(), pos, hash, 32);
			m_DestinationIdentHash = new i2p::data::IdentHash (hash);
		}
		else
		{	
			pos = m_Destination.find (".i2p");
			if (pos != std::string::npos)
			{
				auto identHash = i2p::data::netdb.FindAddress (m_Destination);	
				if (identHash)
					m_DestinationIdentHash = new i2p::data::IdentHash (*identHash);
			}
		}
		if (m_DestinationIdentHash)
		{
			i2p::data::netdb.Subscribe (*m_DestinationIdentHash, GetLocalDestination ()->GetTunnelPool ());
			m_RemoteLeaseSet = i2p::data::netdb.FindLeaseSet (*m_DestinationIdentHash);
		}	
		else
			LogPrint ("I2PTunnel unknown destination ", m_Destination);
		m_Acceptor.listen ();
		Accept ();
	}

	void I2PClientTunnel::Stop ()
	{
		m_Acceptor.close();
		ClearConnections ();
		m_DestinationIdentHash = nullptr;
	}

	void I2PClientTunnel::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, boost::bind (&I2PClientTunnel::HandleAccept, this,
			boost::asio::placeholders::error, newSocket));
	}	

	void I2PClientTunnel::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			if (!m_RemoteLeaseSet)
			{
				// try to get it
				if (m_DestinationIdentHash)
					m_RemoteLeaseSet = i2p::data::netdb.FindLeaseSet (*m_DestinationIdentHash);
				else
				{
					auto identHash = i2p::data::netdb.FindAddress (m_Destination);	
					if (identHash)
					{
						m_DestinationIdentHash = new i2p::data::IdentHash (*identHash);
						i2p::data::netdb.Subscribe (*m_DestinationIdentHash, GetSharedLocalDestination ()->GetTunnelPool ());
					}
				}
			}

			if (m_RemoteLeaseSet) // leaseSet found
			{	
				LogPrint ("New I2PTunnel connection");
				auto connection = new I2PTunnelConnection (this, socket, m_RemoteLeaseSet);
				AddConnection (connection);
			}
			else
			{
				LogPrint ("LeaseSet for I2PTunnel destination not found");
				delete socket;
			}	
			Accept ();
		}
		else
			delete socket;
	}

	I2PServerTunnel::I2PServerTunnel (boost::asio::io_service& service, const std::string& address, int port, 
		StreamingDestination * localDestination): I2PTunnel (service, localDestination),
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
			localDestination->SetAcceptor (std::bind (&I2PServerTunnel::HandleAccept, this, std::placeholders::_1));
		else
			LogPrint ("Local destination not set for server tunnel");
	}

	void I2PServerTunnel::HandleAccept (i2p::stream::Stream * stream)
	{
		if (stream)
			new I2PTunnelConnection (this, stream, new boost::asio::ip::tcp::socket (GetService ()), m_Endpoint);
	}
}		
}	
