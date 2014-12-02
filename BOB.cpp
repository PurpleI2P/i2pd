#include <string.h>
#include "Log.h"
#include "BOB.h"

namespace i2p
{
namespace client
{
	BOBCommandSession::BOBCommandSession (BOBCommandChannel& owner): 
		m_Owner (owner), m_Socket (m_Owner.GetService ()), m_ReceiveBufferOffset (0),
		m_IsOpen (true)
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
				if (operand) *operand = 0;	
				// process command
				auto handlers = m_Owner.GetCommandHandlers ();
				auto it = handlers.find (m_ReceiveBuffer);
				if (it != handlers.end ())
					(this->*(it->second))(operand, operand ? eol - operand : 0);
				else
					LogPrint (eLogError, "BOB unknown command", m_ReceiveBuffer);

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

	BOBCommandChannel::BOBCommandChannel (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
		m_CommandHandlers[BOB_COMMAND_ZAP] = &BOBCommandSession::ZapCommandHandler; 
		m_CommandHandlers[BOB_COMMAND_QUIT] = &BOBCommandSession::QuitCommandHandler;
	}

	BOBCommandChannel::~BOBCommandChannel ()
	{
		Stop ();
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
			delete it.second;
		m_Tunnels.clear ();
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

