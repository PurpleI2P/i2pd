#include <string.h>
#include <boost/lexical_cast.hpp>
#include "Log.h"
#include "ClientContext.h"
#include "BOB.h"

namespace i2p
{
namespace client
{
	BOBI2PInboundTunnel::BOBI2PInboundTunnel (int port, ClientDestination * localDestination): 
		BOBI2PTunnel (localDestination), 
		m_Acceptor (localDestination->GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)), m_Timer (localDestination->GetService ())
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
		ClearHandlers ();
	}

	void BOBI2PInboundTunnel::Accept ()
	{
		auto receiver = new AddressReceiver ();
		receiver->socket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*receiver->socket, std::bind (&BOBI2PInboundTunnel::HandleAccept, this,
			std::placeholders::_1, receiver));
	}	

	void BOBI2PInboundTunnel::HandleAccept (const boost::system::error_code& ecode, AddressReceiver * receiver)
	{
		if (!ecode)
		{
			Accept ();	
			ReceiveAddress (receiver);
		}
		else
		{	
			delete receiver->socket;
			delete receiver;
		}	
	}

	void BOBI2PInboundTunnel::ReceiveAddress (AddressReceiver * receiver)
	{
		receiver->socket->async_read_some (boost::asio::buffer(
		        receiver->buffer + receiver->bufferOffset, 
				BOB_COMMAND_BUFFER_SIZE - receiver->bufferOffset),                
			std::bind(&BOBI2PInboundTunnel::HandleReceivedAddress, this, 
				std::placeholders::_1, std::placeholders::_2, receiver));
	}
	
	void BOBI2PInboundTunnel::HandleReceivedAddress (const boost::system::error_code& ecode, std::size_t bytes_transferred,
		AddressReceiver * receiver)
	{
		if (ecode)
		{
			LogPrint ("BOB inbound tunnel read error: ", ecode.message ());
			delete receiver->socket;
			delete receiver;
		}	
		else
		{
			receiver->bufferOffset += bytes_transferred;
			receiver->buffer[receiver->bufferOffset] = 0;
			char * eol = strchr (receiver->buffer, '\n');
			if (eol)
			{
				*eol = 0;
				
				receiver->data = (uint8_t *)eol + 1;
				receiver->dataLen = receiver->bufferOffset - (eol - receiver->buffer + 1);
				i2p::data::IdentHash ident;
				if (!context.GetAddressBook ().GetIdentHash (receiver->buffer, ident)) 
				{
					LogPrint (eLogError, "BOB address ", receiver->buffer, " not found");
					delete receiver->socket;
					delete receiver;
					return;
				}
				auto leaseSet = GetLocalDestination ()->FindLeaseSet (ident);
				if (leaseSet)
					CreateConnection (receiver, leaseSet);
				else
				{
					GetLocalDestination ()->RequestDestination (ident);
					m_Timer.expires_from_now (boost::posix_time::seconds (I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT));
					m_Timer.async_wait (std::bind (&BOBI2PInboundTunnel::HandleDestinationRequestTimer,
						this, std::placeholders::_1, receiver, ident));
				}
			}
			else
			{
				if (receiver->bufferOffset < BOB_COMMAND_BUFFER_SIZE)
					ReceiveAddress (receiver);
				else
				{	
					LogPrint ("BOB missing inbound address ");
					delete receiver->socket;
					delete receiver;
				}	
			}			
		}
	}

	void BOBI2PInboundTunnel::HandleDestinationRequestTimer (const boost::system::error_code& ecode, AddressReceiver * receiver, i2p::data::IdentHash ident)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto leaseSet = GetLocalDestination ()->FindLeaseSet (ident);
			if (leaseSet)
			{
				CreateConnection (receiver, leaseSet);
				return;
			}
			else
				LogPrint ("LeaseSet for BOB inbound destination not found");
		}
		delete receiver->socket;
		delete receiver;
	}	

	void BOBI2PInboundTunnel::CreateConnection (AddressReceiver * receiver, const i2p::data::LeaseSet * leaseSet)
	{
		LogPrint ("New BOB inbound connection");
		auto connection = std::make_shared<I2PTunnelConnection>(this, receiver->socket, leaseSet);
		AddHandler (connection);
		connection->I2PConnect (receiver->data, receiver->dataLen);
		delete receiver;
	}

	BOBI2POutboundTunnel::BOBI2POutboundTunnel (const std::string& address, int port, 
		ClientDestination * localDestination, bool quiet): BOBI2PTunnel (localDestination),
		m_Endpoint (boost::asio::ip::address::from_string (address), port), m_IsQuiet (quiet)
	{
	}
	
	void BOBI2POutboundTunnel::Start ()
	{
		Accept ();
	}

	void BOBI2POutboundTunnel::Stop ()
	{
		ClearHandlers ();
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
			AddHandler (conn);
			conn->Connect ();
		}	
	}

	BOBDestination::BOBDestination (ClientDestination& localDestination):
		m_LocalDestination (localDestination), 
		m_OutboundTunnel (nullptr), m_InboundTunnel (nullptr)
	{
	}
		
	BOBDestination::~BOBDestination ()
	{
		delete m_OutboundTunnel;
		delete m_InboundTunnel;
		i2p::client::context.DeleteLocalDestination (&m_LocalDestination);
	}	

	void BOBDestination::Start ()
	{
		if (m_OutboundTunnel) m_OutboundTunnel->Start ();
		if (m_InboundTunnel) m_InboundTunnel->Start ();
	}
		
	void BOBDestination::Stop ()
	{		
		StopTunnels ();
		m_LocalDestination.Stop ();
	}	

	void BOBDestination::StopTunnels ()
	{
		if (m_OutboundTunnel)
		{	
			m_OutboundTunnel->Stop ();
			delete m_OutboundTunnel;
			m_OutboundTunnel = nullptr;
		}	
		if (m_InboundTunnel)
		{	
			m_InboundTunnel->Stop ();
			delete m_InboundTunnel;
			m_InboundTunnel = nullptr;
		}	
	}	
		
	void BOBDestination::CreateInboundTunnel (int port)
	{
		if (!m_InboundTunnel)
			m_InboundTunnel = new BOBI2PInboundTunnel (port, &m_LocalDestination);
	}
		
	void BOBDestination::CreateOutboundTunnel (const std::string& address, int port, bool quiet)
	{
		if (!m_OutboundTunnel)
			m_OutboundTunnel = new BOBI2POutboundTunnel (address, port, &m_LocalDestination, quiet);
	}	
		
	BOBCommandSession::BOBCommandSession (BOBCommandChannel& owner): 
		m_Owner (owner), m_Socket (m_Owner.GetService ()), m_ReceiveBufferOffset (0),
		m_IsOpen (true), m_IsQuiet (false), m_InPort (0), m_OutPort (0),
		m_CurrentDestination (nullptr)
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
		
	void BOBCommandSession::SendVersion ()
	{
		size_t len = strlen (BOB_VERSION);
		memcpy (m_SendBuffer, BOB_VERSION, len);
		Send (len);
	}

	void BOBCommandSession::SendData (const char * nickname)
	{
#ifdef _MSC_VER
		size_t len = sprintf_s (m_SendBuffer, BOB_COMMAND_BUFFER_SIZE, BOB_DATA, nickname);
#else		
		size_t len = snprintf (m_SendBuffer, BOB_COMMAND_BUFFER_SIZE, BOB_DATA, nickname);
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
		if (!m_CurrentDestination)
		{	
			m_CurrentDestination = new BOBDestination (*i2p::client::context.CreateNewLocalDestination (m_Keys, true, &m_Options));
			m_Owner.AddDestination (m_Nickname, m_CurrentDestination);
		}	
		if (m_InPort)
			m_CurrentDestination->CreateInboundTunnel (m_InPort);
		if (m_OutPort && !m_Address.empty ())
			m_CurrentDestination->CreateOutboundTunnel (m_Address, m_OutPort, m_IsQuiet);
		m_CurrentDestination->Start ();	
		SendReplyOK ("tunnel starting");	
	}	
	
	void BOBCommandSession::StopCommandHandler (const char * operand, size_t len)
	{
		auto dest = m_Owner.FindDestination (m_Nickname);
		if (dest)
		{
			dest->StopTunnels ();
			SendReplyOK ("tunnel stopping");
		}
		else
			SendReplyError ("tunnel not found");
	}	
	
	void BOBCommandSession::SetNickCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: setnick ", operand);
		m_Nickname = operand;
		std::string msg ("Nickname set to ");
		msg += operand;
		SendReplyOK (msg.c_str ());
	}	

	void BOBCommandSession::GetNickCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: getnick ", operand);
		m_CurrentDestination = m_Owner.FindDestination (operand); 
		if (m_CurrentDestination)
		{
			m_Keys = m_CurrentDestination->GetKeys ();
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
		LogPrint (eLogDebug, "BOB: setkeys ", operand);
		m_Keys.FromBase64 (operand);
		SendReplyOK (m_Keys.GetPublic ().ToBase64 ().c_str ());
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
		LogPrint (eLogDebug, "BOB: outhost ", operand);
		m_Address = operand;
		SendReplyOK ("outhost set");
	}
		
	void BOBCommandSession::OutportCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: outport ", operand);
		m_OutPort = boost::lexical_cast<int>(operand);
		SendReplyOK ("outbound port set");
	}	

	void BOBCommandSession::InhostCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: inhost ", operand);
		m_Address = operand;
		SendReplyOK ("inhost set");
	}
		
	void BOBCommandSession::InportCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: inport ", operand);
		m_InPort = boost::lexical_cast<int>(operand);
		SendReplyOK ("inbound port set");
	}		

	void BOBCommandSession::QuietCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: quiet");
		m_IsQuiet = true;
		SendReplyOK ("quiet");
	}	
	
	void BOBCommandSession::LookupCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: lookup ", operand);
		i2p::data::IdentityEx addr;
		if (!context.GetAddressBook ().GetAddress (operand, addr)) 
		{
			SendReplyError ("Address Not found");
			return;
		}		
		SendReplyOK (addr.ToBase64 ().c_str ());
	}

	void BOBCommandSession::ClearCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: clear");
		m_Owner.DeleteDestination (m_Nickname);
		SendReplyOK ("cleared");
	}	

	void BOBCommandSession::ListCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: list");
		auto& destinations = m_Owner.GetDestinations ();
		for (auto it: destinations)
			SendData (it.first.c_str ());
		SendReplyOK ("Listing done");
	}	

	void BOBCommandSession::OptionCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: option ", operand);
		const char * value = strchr (operand, '=');
		if (value)
		{	
			*(const_cast<char *>(value)) = 0;
			m_Options[operand] = value + 1; 
			*(const_cast<char *>(value)) = '=';
			SendReplyOK ("option");
		}	
		else
			SendReplyError ("malformed");
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
		m_CommandHandlers[BOB_COMMAND_LOOKUP] = &BOBCommandSession::LookupCommandHandler;
		m_CommandHandlers[BOB_COMMAND_CLEAR] = &BOBCommandSession::ClearCommandHandler;
		m_CommandHandlers[BOB_COMMAND_LIST] = &BOBCommandSession::ListCommandHandler;
		m_CommandHandlers[BOB_COMMAND_OPTION] = &BOBCommandSession::OptionCommandHandler;
	}

	BOBCommandChannel::~BOBCommandChannel ()
	{
		Stop ();
		for (auto it: m_Destinations)
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
		m_IsRunning = false;
		for (auto it: m_Destinations)
			it.second->Stop ();
		m_Acceptor.cancel ();	
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

	void BOBCommandChannel::AddDestination (const std::string& name, BOBDestination * dest)
	{
		m_Destinations[name] = dest;
	}	

	void BOBCommandChannel::DeleteDestination (const std::string& name)
	{
		auto it = m_Destinations.find (name);
		if (it != m_Destinations.end ())
		{
			it->second->Stop ();
			delete it->second;
			m_Destinations.erase (it);
		}	
	}	
		
	BOBDestination * BOBCommandChannel::FindDestination (const std::string& name)
	{
		auto it = m_Destinations.find (name);
		if (it != m_Destinations.end ())
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
			session->SendVersion ();	
		}
		else
			LogPrint (eLogError, "BOB accept error: ",  ecode.message ());
	}
}
}

