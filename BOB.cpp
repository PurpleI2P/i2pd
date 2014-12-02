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

	void BOBCommandSession::Receive ()
	{
		m_Socket.async_read_some (boost::asio::buffer(m_ReceiveBuffer + m_ReceiveBufferOffset, BOB_COMMAND_BUFFER_SIZE - m_ReceiveBufferOffset),                
			std::bind(&BOBCommandSession::HandleReceived, shared_from_this (), 
			std::placeholders::_1, std::placeholders::_2));
	}

	void BOBCommandSession::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
			LogPrint ("BOB command channel read error: ", ecode.message ());
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
					return;
				}
			}	
			if (m_IsOpen)
				Receive ();
		}
	}

	void BOBCommandSession::ZapCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: zap");
		m_IsOpen = false;
	}

	BOBCommandChannel::BOBCommandChannel (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
		m_CommandHandlers[BOB_COMMAND_ZAP] = &BOBCommandSession::ZapCommandHandler; 
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

