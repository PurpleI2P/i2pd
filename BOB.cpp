#include <string.h>
#include <boost/lexical_cast.hpp>
#include "Log.h"
#include "NetDb.h"
#include "ClientContext.h"
#include "BOB.h"

namespace i2p
{
namespace client
{
	BOBI2PInboundTunnel::BOBI2PInboundTunnel (boost::asio::io_service& service, int port, ClientDestination * localDestination): 
		I2PTunnel (service, localDestination), 
		m_Acceptor (service, boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_Timer (service), m_ReceivedData (nullptr), m_ReceivedDataLen (0)
	{
	}

	BOBI2PInboundTunnel::~BOBI2PInboundTunnel ()
	{
		Stop ();
	}

	void BOBI2PInboundTunnel::Start ()
	{
		m_Acceptor.listen ();
		Accept ();
	}

	void BOBI2PInboundTunnel::Stop ()
	{
		m_Acceptor.close();
		ClearConnections ();
	}

	void BOBI2PInboundTunnel::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&BOBI2PInboundTunnel::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}	

	void BOBI2PInboundTunnel::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			Accept ();	
			ReceiveAddress (socket);
		}
		else
			delete socket;
	}

	void BOBI2PInboundTunnel::ReceiveAddress (boost::asio::ip::tcp::socket * socket)
	{
		socket->async_read_some (boost::asio::buffer(m_ReceiveBuffer, BOB_COMMAND_BUFFER_SIZE),                
			std::bind(&BOBI2PInboundTunnel::HandleReceivedAddress, this, 
			std::placeholders::_1, std::placeholders::_2, socket));
	}
	
	void BOBI2PInboundTunnel::HandleReceivedAddress (const boost::system::error_code& ecode, std::size_t bytes_transferred,
		boost::asio::ip::tcp::socket * socket)
	{
		if (ecode)
		{
			LogPrint ("BOB inbound tunnel read error: ", ecode.message ());
			delete socket;
		}	
		else
		{
			m_ReceiveBuffer[bytes_transferred] = 0;
			char * eol = strchr (m_ReceiveBuffer, '\n');
			if (eol)
			{
				*eol = 0;
				
				 m_ReceivedData = (uint8_t *)eol + 1;
				 m_ReceivedDataLen = bytes_transferred - (eol - m_ReceiveBuffer + 1);
				i2p::data::IdentHash ident;
				if (!context.GetAddressBook ().GetIdentHash (m_ReceiveBuffer, ident)) 
				{
					LogPrint (eLogError, "BOB address ", m_ReceiveBuffer, " not found");
					delete socket;
					return;
				}
				auto leaseSet = GetLocalDestination ()->FindLeaseSet (ident);
				if (leaseSet)
					CreateConnection (socket, leaseSet);
				else
				{
					i2p::data::netdb.RequestDestination (ident, true, GetLocalDestination ()->GetTunnelPool ());
					m_Timer.expires_from_now (boost::posix_time::seconds (I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT));
					m_Timer.async_wait (std::bind (&BOBI2PInboundTunnel::HandleDestinationRequestTimer,
						this, std::placeholders::_1, socket, ident));
				}
			}
			else
			{
				LogPrint ("BOB missing inbound address ", ecode.message ());
				delete socket;
			}			
		}
	}

	void BOBI2PInboundTunnel::HandleDestinationRequestTimer (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket, i2p::data::IdentHash ident)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto leaseSet = GetLocalDestination ()->FindLeaseSet (ident);
			if (leaseSet)
			{
				CreateConnection (socket, leaseSet);
				return;
			}
			else
				LogPrint ("LeaseSet for BOB inbound destination not found");
		}
		delete socket;	
	}	

	void BOBI2PInboundTunnel::CreateConnection (boost::asio::ip::tcp::socket * socket, const i2p::data::LeaseSet * leaseSet)
	{
		LogPrint ("New BOB inbound connection");
		auto connection = std::make_shared<I2PTunnelConnection>(this, socket, leaseSet);
		AddConnection (connection);
		connection->I2PConnect (m_ReceivedData, m_ReceivedDataLen);
	}

	BOBI2POutboundTunnel::BOBI2POutboundTunnel (boost::asio::io_service& service, const std::string& address, int port, 
		ClientDestination * localDestination, bool quiet): I2PTunnel (service, localDestination),
		m_Endpoint (boost::asio::ip::address::from_string (address), port), m_IsQuiet (quiet)
	{
	}
	
	void BOBI2POutboundTunnel::Start ()
	{
		Accept ();
	}

	void BOBI2POutboundTunnel::Stop ()
	{
		ClearConnections ();
	}	

	void BOBI2POutboundTunnel::Accept ()
	{
		auto localDestination = GetLocalDestination ();	
		if (localDestination)
			localDestination->AcceptStreams (std::bind (&BOBI2POutboundTunnel::HandleAccept, this, std::placeholders::_1));
		else
			LogPrint ("Local destination not set for server tunnel");
	}

	void BOBI2POutboundTunnel::HandleAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{	
			auto conn = std::make_shared<I2PTunnelConnection> (this, stream, new boost::asio::ip::tcp::socket (GetService ()), m_Endpoint, m_IsQuiet);
			AddConnection (conn);
			conn->Connect ();
		}	
	}


	BOBCommandSession::BOBCommandSession (BOBCommandChannel& owner): 
		m_Owner (owner), m_Socket (m_Owner.GetService ()), m_ReceiveBufferOffset (0),
		m_IsOpen (true), m_IsOutbound (false), m_IsQuiet (false), m_Port (0)
	{
	}

	BOBCommandSession::~BOBCommandSession ()
	{
	}

	void BOBCommandSession::Terminate ()
	{
		m_Socket.close ();
		m_IsOpen = false;	
	}

	void BOBCommandSession::Receive ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_ReceiveBuffer + m_ReceiveBufferOffset, BOB_COMMAND_BUFFER_SIZE - m_ReceiveBufferOffset),                
			std::bind(&BOBCommandSession::HandleReceived, shared_from_this (), 
			std::placeholders::_1, std::placeholders::_2));
	}

	void BOBCommandSession::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint ("BOB command channel read error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}	
		else
		{	
			size_t size = m_ReceiveBufferOffset + bytes_transferred; 
			m_ReceiveBuffer[size] = 0;
			char * eol = strchr (m_ReceiveBuffer, '\n');
			if (eol)
			{
				*eol = 0;
				char * operand =  strchr (m_ReceiveBuffer, ' ');
				if (operand)  
				{	
					*operand = 0;
					operand++;
				}	
				else 
					operand = eol;
				// process command
				auto& handlers = m_Owner.GetCommandHandlers ();
				auto it = handlers.find (m_ReceiveBuffer);
				if (it != handlers.end ())
					(this->*(it->second))(operand, eol - operand);
				else	
				{
					LogPrint (eLogError, "BOB unknown command ", m_ReceiveBuffer);
					SendReplyError ("unknown command");
				}

				m_ReceiveBufferOffset = size - (eol - m_ReceiveBuffer) - 1;
				memmove (m_ReceiveBuffer, eol + 1, m_ReceiveBufferOffset);
			}
			else
			{
				if (size < BOB_COMMAND_BUFFER_SIZE)
					m_ReceiveBufferOffset = size;
				else
				{
					LogPrint (eLogError, "Malformed input of the BOB command channel");
					Terminate ();
				}
			}	
		}
	}

	void BOBCommandSession::Send (size_t len)
	{
		boost::asio::async_write (m_Socket, boost::asio::buffer (m_SendBuffer, len), 
			boost::asio::transfer_all (),
			std::bind(&BOBCommandSession::HandleSent, shared_from_this (), 
				std::placeholders::_1, std::placeholders::_2));
	}

	void BOBCommandSession::HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
        {
			LogPrint ("BOB command channel send error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			if (m_IsOpen)
				Receive ();
			else
				Terminate ();	
		}
	}

	void BOBCommandSession::SendReplyOK (const char * msg)
	{
#ifdef _MSC_VER
		size_t len = sprintf_s (m_SendBuffer, BOB_COMMAND_BUFFER_SIZE, BOB_REPLY_OK, msg);
#else		
		size_t len = snprintf (m_SendBuffer, BOB_COMMAND_BUFFER_SIZE, BOB_REPLY_OK, msg);
#endif
		Send (len);
	}

	void BOBCommandSession::SendReplyError (const char * msg)
	{
#ifdef _MSC_VER
		size_t len = sprintf_s (m_SendBuffer, BOB_COMMAND_BUFFER_SIZE, BOB_REPLY_ERROR, msg);
#else		
		size_t len = snprintf (m_SendBuffer, BOB_COMMAND_BUFFER_SIZE, BOB_REPLY_ERROR, msg);
#endif
		Send (len);	
	}

	void BOBCommandSession::ZapCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: zap");
		Terminate ();
	}

	void BOBCommandSession::QuitCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: quit");
		m_IsOpen = false;
		SendReplyOK ("Bye!");
	}

	void BOBCommandSession::StartCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: start ", m_Nickname);
		auto dest = context.CreateNewLocalDestination (m_Keys, true);
		I2PTunnel * tunnel = nullptr;
		if (m_IsOutbound)
			tunnel = new BOBI2POutboundTunnel (m_Owner.GetService (), m_Address, m_Port, dest, m_IsQuiet);		
		else
			tunnel = new BOBI2PInboundTunnel (m_Owner.GetService (), m_Port, dest);
		if (tunnel)
		{
			m_Owner.AddTunnel (m_Nickname, tunnel);
			tunnel->Start ();	
			SendReplyOK ("tunnel starting");
		}
		else
			SendReplyError ("failed to create tunnel");	
	}	
	
	void BOBCommandSession::StopCommandHandler (const char * operand, size_t len)
	{
		auto tunnel = m_Owner.FindTunnel (m_Nickname);
		if (tunnel)
		{
			tunnel->Stop ();
			tunnel->GetLocalDestination ()->Stop ();
			SendReplyOK ("tunnel stopping");
		}
		else
			SendReplyError ("tunnel not found");
	}	
	
	void BOBCommandSession::SetNickCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: setnick");
		m_Nickname = operand;
		std::string msg ("Nickname set to ");
		msg += operand;
		SendReplyOK (msg.c_str ());
	}	

	void BOBCommandSession::GetNickCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: getnick");
		auto tunnel = m_Owner.FindTunnel (operand); 
		if (tunnel)
		{
			m_Keys = tunnel->GetLocalDestination ()->GetPrivateKeys ();
			m_Nickname = operand;
			std::string msg ("Nickname set to ");
			msg += operand;
			SendReplyOK (msg.c_str ());
		}
		else
			SendReplyError ("tunnel not found");	
	}	

	void BOBCommandSession::NewkeysCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: newkeys");
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys ();
		SendReplyOK (m_Keys.GetPublic ().ToBase64 ().c_str ());
	}	

	void BOBCommandSession::SetkeysCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: setkeys");
		m_Keys.FromBase64 (operand);
		SendReplyOK ("keys set");
	}
		
	void BOBCommandSession::GetkeysCommandHandler (const char * operand, size_t len)
	{		
		LogPrint (eLogDebug, "BOB: getkeys");
		SendReplyOK (m_Keys.ToBase64 ().c_str ());
	}	

	void BOBCommandSession::GetdestCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: getdest");
		SendReplyOK (m_Keys.GetPublic ().ToBase64 ().c_str ());
	}	
		
	void BOBCommandSession::OuthostCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: outhost");
		m_IsOutbound = true;
		m_Address = operand;
		SendReplyOK ("outhost set");
	}
		
	void BOBCommandSession::OutportCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: outport");
		m_IsOutbound = true;
		m_Port = boost::lexical_cast<int>(operand);
		SendReplyOK ("outbound port set");
	}	

	void BOBCommandSession::InhostCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: inhost");
		m_IsOutbound = false;
		m_Address = operand;
		SendReplyOK ("inhost set");
	}
		
	void BOBCommandSession::InportCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: inport");
		m_IsOutbound = false;
		m_Port = boost::lexical_cast<int>(operand);
		SendReplyOK ("inbound port set");
	}		

	void BOBCommandSession::QuietCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: quiet");
		m_IsQuiet = true;
		SendReplyOK ("quiet");
	}	
	
	BOBCommandChannel::BOBCommandChannel (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
		// command -> handler
		m_CommandHandlers[BOB_COMMAND_ZAP] = &BOBCommandSession::ZapCommandHandler; 
		m_CommandHandlers[BOB_COMMAND_QUIT] = &BOBCommandSession::QuitCommandHandler;
		m_CommandHandlers[BOB_COMMAND_START] = &BOBCommandSession::StartCommandHandler;
		m_CommandHandlers[BOB_COMMAND_STOP] = &BOBCommandSession::StopCommandHandler;
		m_CommandHandlers[BOB_COMMAND_SETNICK] = &BOBCommandSession::SetNickCommandHandler;
		m_CommandHandlers[BOB_COMMAND_GETNICK] = &BOBCommandSession::GetNickCommandHandler;
		m_CommandHandlers[BOB_COMMAND_NEWKEYS] = &BOBCommandSession::NewkeysCommandHandler;
		m_CommandHandlers[BOB_COMMAND_GETKEYS] = &BOBCommandSession::GetkeysCommandHandler;
		m_CommandHandlers[BOB_COMMAND_SETKEYS] = &BOBCommandSession::SetkeysCommandHandler;
		m_CommandHandlers[BOB_COMMAND_GETDEST] = &BOBCommandSession::GetdestCommandHandler;
		m_CommandHandlers[BOB_COMMAND_OUTHOST] = &BOBCommandSession::OuthostCommandHandler;
		m_CommandHandlers[BOB_COMMAND_OUTPORT] = &BOBCommandSession::OutportCommandHandler;
		m_CommandHandlers[BOB_COMMAND_INHOST] = &BOBCommandSession::InhostCommandHandler;
		m_CommandHandlers[BOB_COMMAND_INPORT] = &BOBCommandSession::InportCommandHandler;
		m_CommandHandlers[BOB_COMMAND_QUIET] = &BOBCommandSession::QuietCommandHandler;
	}

	BOBCommandChannel::~BOBCommandChannel ()
	{
		Stop ();
		for (auto it: m_Tunnels)
			delete it.second;
	}

	void BOBCommandChannel::Start ()
	{
		Accept ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&BOBCommandChannel::Run, this));
	}

	void BOBCommandChannel::Stop ()
	{
		for (auto it: m_Tunnels)
			it.second->Stop ();
		m_IsRunning = false;
		m_Service.stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = nullptr;
		}	
	}

	void BOBCommandChannel::Run () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "BOB: ", ex.what ());
			}	
		}	
	}

	void BOBCommandChannel::AddTunnel (const std::string& name, I2PTunnel * tunnel)
	{
		m_Tunnels[name] = tunnel;
	}	

	I2PTunnel * BOBCommandChannel::FindTunnel (const std::string& name)
	{
		auto it = m_Tunnels.find (name);
		if (it != m_Tunnels.end ())
			return it->second;
		return nullptr;	
	}
		
	void BOBCommandChannel::Accept ()
	{
		auto newSession = std::make_shared<BOBCommandSession> (*this);
		m_Acceptor.async_accept (newSession->GetSocket (), std::bind (&BOBCommandChannel::HandleAccept, this,
			std::placeholders::_1, newSession));
	}

	void BOBCommandChannel::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<BOBCommandSession> session)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();

		if (!ecode)
		{
			LogPrint (eLogInfo, "New BOB command connection from ", session->GetSocket ().remote_endpoint ());
			session->Receive ();	
		}
		else
			LogPrint (eLogError, "BOB accept error: ",  ecode.message ());
	}
}
}

