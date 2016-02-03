#include <cassert>
#include "Base.h"
#include "Log.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace client
{
	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
		std::shared_ptr<const i2p::data::LeaseSet> leaseSet, int port): 
		I2PServiceHandler(owner), m_Socket (socket), m_RemoteEndpoint (socket->remote_endpoint ()),
		m_IsQuiet (true)
	{
		m_Stream = GetOwner()->GetLocalDestination ()->CreateStream (leaseSet, port);
	}	

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner,
	    std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<i2p::stream::Stream> stream):
		I2PServiceHandler(owner), m_Socket (socket), m_Stream (stream),
		m_RemoteEndpoint (socket->remote_endpoint ()), m_IsQuiet (true)
	{
	}

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
	    std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::asio::ip::tcp::endpoint& target, bool quiet):
		I2PServiceHandler(owner), m_Socket (socket), m_Stream (stream),
		m_RemoteEndpoint (target), m_IsQuiet (quiet)
	{
	}

	I2PTunnelConnection::~I2PTunnelConnection ()
	{
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
			LogPrint (eLogError, "I2PTunnel: read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{	
			if (m_Stream)
			{	
				auto s = shared_from_this ();
				m_Stream->AsyncSend (m_Buffer, bytes_transferred,
					[s](const boost::system::error_code& ecode)
				    {
						if (!ecode)
							s->Receive ();
						else
							s->Terminate ();
					});
			}	
		}
	}	

	void I2PTunnelConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "I2PTunnel: write error: ", ecode.message ());
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
			LogPrint (eLogError, "I2PTunnel: stream read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
			Write (m_StreamBuffer, bytes_transferred);
	}

	void I2PTunnelConnection::Write (const uint8_t * buf, size_t len)
	{
		boost::asio::async_write (*m_Socket, boost::asio::buffer (buf, len), boost::asio::transfer_all (),
        	std::bind (&I2PTunnelConnection::HandleWrite, shared_from_this (), std::placeholders::_1));
	}

	void I2PTunnelConnection::HandleConnect (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "I2PTunnel: connect error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "I2PTunnel: connected");
			if (m_IsQuiet)
				StreamReceive ();
			else
			{
				// send destination first like received from I2P
				std::string dest = m_Stream->GetRemoteIdentity ()->ToBase64 ();
				dest += "\n";
				memcpy (m_StreamBuffer, dest.c_str (), dest.size ());
				HandleStreamReceive (boost::system::error_code (), dest.size ());
			}	
			Receive ();	
		}
	}

	I2PTunnelConnectionHTTP::I2PTunnelConnectionHTTP (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
		std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
		const boost::asio::ip::tcp::endpoint& target, const std::string& host):
		I2PTunnelConnection (owner, stream, socket, target), m_Host (host), m_HeaderSent (false), m_From (stream->GetRemoteIdentity ())
	{
	}

	void I2PTunnelConnectionHTTP::Write (const uint8_t * buf, size_t len)
	{
		if (m_HeaderSent)
			I2PTunnelConnection::Write (buf, len);
		else
		{	
			m_InHeader.clear ();
			m_InHeader.write ((const char *)buf, len);
			std::string line;
			bool endOfHeader = false;
			while (!endOfHeader)
			{
				std::getline(m_InHeader, line);
				if (!m_InHeader.fail ())
				{
					if (line == "\r") endOfHeader = true;
					else
					{	
						if (line.find ("Host:") != std::string::npos)
							m_OutHeader << "Host: " << m_Host << "\r\n";
						else
							m_OutHeader << line << "\n";
					}	
				}
				else
					break;
			}
			// add X-I2P fields
			if (m_From)
			{
				m_OutHeader << X_I2P_DEST_B32 << ": " << context.GetAddressBook ().ToAddress(m_From->GetIdentHash ()) << "\r\n";
				m_OutHeader << X_I2P_DEST_HASH << ": " << m_From->GetIdentHash ().ToBase64 () << "\r\n";
				m_OutHeader << X_I2P_DEST_B64 << ": " << m_From->ToBase64 () << "\r\n";
			}

			if (endOfHeader)
			{
				m_OutHeader << "\r\n"; // end of header
				m_OutHeader << m_InHeader.str ().substr (m_InHeader.tellg ()); // data right after header
				m_HeaderSent = true;
				I2PTunnelConnection::Write ((uint8_t *)m_OutHeader.str ().c_str (), m_OutHeader.str ().length ());
			}
		}	
	}

	/* This handler tries to stablish a connection with the desired server and dies if it fails to do so */
	class I2PClientTunnelHandler: public I2PServiceHandler, public std::enable_shared_from_this<I2PClientTunnelHandler>
	{
		public:
			I2PClientTunnelHandler (I2PClientTunnel * parent, i2p::data::IdentHash destination,
				int destinationPort, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
				I2PServiceHandler(parent), m_DestinationIdentHash(destination), 
				m_DestinationPort (destinationPort), m_Socket(socket) {};
			void Handle();
			void Terminate();
		private:
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
			i2p::data::IdentHash m_DestinationIdentHash;
			int m_DestinationPort;
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
	};

	void I2PClientTunnelHandler::Handle()
	{
		GetOwner()->GetLocalDestination ()->CreateStream ( 
			std::bind (&I2PClientTunnelHandler::HandleStreamRequestComplete, shared_from_this(), std::placeholders::_1), 
			m_DestinationIdentHash, m_DestinationPort);
	}

	void I2PClientTunnelHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			if (Kill()) return;
			LogPrint (eLogDebug, "I2PTunnel: new connection");
			auto connection = std::make_shared<I2PTunnelConnection>(GetOwner(), m_Socket, stream);
			GetOwner()->AddHandler (connection);
			connection->I2PConnect ();
			Done(shared_from_this());
		}
		else
		{
			LogPrint (eLogError, "I2PTunnel: Client Tunnel Issue when creating the stream, check the previous warnings for more info.");
			Terminate();
		}
	}

	void I2PClientTunnelHandler::Terminate()
	{
		if (Kill()) return;
		if (m_Socket)
		{
			m_Socket->close();
			m_Socket = nullptr;
		}
		Done(shared_from_this());
	}

	I2PClientTunnel::I2PClientTunnel (const std::string& name, const std::string& destination, 
	    const std::string& address, int port, std::shared_ptr<ClientDestination> localDestination, int destinationPort): 
		TCPIPAcceptor (address, port, localDestination), m_Name (name), m_Destination (destination), 
		m_DestinationIdentHash (nullptr), m_DestinationPort (destinationPort) 
	{
	}	

	void I2PClientTunnel::Start ()
	{
		TCPIPAcceptor::Start ();
		GetIdentHash();
	}

	void I2PClientTunnel::Stop ()
	{
		TCPIPAcceptor::Stop();
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
				LogPrint (eLogWarning, "I2PTunnel: Remote destination ", m_Destination, " not found");
		}
		return m_DestinationIdentHash;
	}

	std::shared_ptr<I2PServiceHandler> I2PClientTunnel::CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		const i2p::data::IdentHash *identHash = GetIdentHash();
		if (identHash)
			return  std::make_shared<I2PClientTunnelHandler>(this, *identHash, m_DestinationPort, socket);
		else
			return nullptr;
	}

	I2PServerTunnel::I2PServerTunnel (const std::string& name, const std::string& address, 
	    int port, std::shared_ptr<ClientDestination> localDestination, int inport): 
		I2PService (localDestination), m_Name (name), m_Address (address), m_Port (port), m_IsAccessList (false)
	{
		m_PortDestination = localDestination->CreateStreamingDestination (inport > 0 ? inport : port);
	}
	
	void I2PServerTunnel::Start ()
	{
		m_Endpoint.port (m_Port);	
		boost::system::error_code ec;
		auto addr = boost::asio::ip::address::from_string (m_Address, ec);
		if (!ec)	
		{
			m_Endpoint.address (addr);
			Accept ();
		}
		else
		{
			auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(GetService ());
			resolver->async_resolve (boost::asio::ip::tcp::resolver::query (m_Address, ""), 
				std::bind (&I2PServerTunnel::HandleResolve, this, 
					std::placeholders::_1, std::placeholders::_2, resolver));
		}	
	}

	void I2PServerTunnel::Stop ()
	{
		ClearHandlers ();
	}	

	void I2PServerTunnel::HandleResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it, 
		std::shared_ptr<boost::asio::ip::tcp::resolver> resolver)
	{	
		if (!ecode)
		{	
			auto addr = (*it).endpoint ().address ();
			LogPrint (eLogInfo, "I2PTunnel: server tunnel ", (*it).host_name (), " has been resolved to ", addr);
			m_Endpoint.address (addr);
			Accept ();	
		}	
		else
			LogPrint (eLogError, "I2PTunnel: Unable to resolve server tunnel address: ", ecode.message ());
	}

	void I2PServerTunnel::SetAccessList (const std::set<i2p::data::IdentHash>& accessList)
	{
		m_AccessList = accessList;
		m_IsAccessList = true;		
	}

	void I2PServerTunnel::Accept ()
	{
		if (m_PortDestination)
			m_PortDestination->SetAcceptor (std::bind (&I2PServerTunnel::HandleAccept, this, std::placeholders::_1));

		auto localDestination = GetLocalDestination ();	
		if (localDestination)
		{
			if (!localDestination->IsAcceptingStreams ()) // set it as default if not set yet
				localDestination->AcceptStreams (std::bind (&I2PServerTunnel::HandleAccept, this, std::placeholders::_1));
		}
		else
			LogPrint (eLogError, "I2PTunnel: Local destination not set for server tunnel");
	}

	void I2PServerTunnel::HandleAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{	
			if (m_IsAccessList)
			{
				if (!m_AccessList.count (stream->GetRemoteIdentity ()->GetIdentHash ()))
				{
					LogPrint (eLogWarning, "I2PTunnel: Address ", stream->GetRemoteIdentity ()->GetIdentHash ().ToBase32 (), " is not in white list. Incoming connection dropped");
					stream->Close ();
					return;
				}
			}
			CreateI2PConnection (stream);
		}	
	}

	void I2PServerTunnel::CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream)
	{
		auto conn = std::make_shared<I2PTunnelConnection> (this, stream, std::make_shared<boost::asio::ip::tcp::socket> (GetService ()), GetEndpoint ());
		AddHandler (conn);
		conn->Connect ();
	}

	I2PServerTunnelHTTP::I2PServerTunnelHTTP (const std::string& name, const std::string& address, 
	    int port, std::shared_ptr<ClientDestination> localDestination, int inport):
		I2PServerTunnel (name, address, port, localDestination, inport)
	{
	}

	void I2PServerTunnelHTTP::CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream)
	{
		auto conn = std::make_shared<I2PTunnelConnectionHTTP> (this, stream, std::make_shared<boost::asio::ip::tcp::socket> (GetService ()), GetEndpoint (), GetAddress ());
		AddHandler (conn);
		conn->Connect ();
	}
}		
}	
