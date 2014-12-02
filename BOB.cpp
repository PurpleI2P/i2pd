#include "Log.h"
#include "BOB.h"

namespace i2p
{
namespace client
{
	BOBDataStream::BOBDataStream (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
		std::shared_ptr<i2p::stream::Stream> stream): m_Socket (socket), m_Stream (stream)
	{
	}

	BOBCommandChannel::BOBCommandChannel (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
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
		m_DataStreams.clear ();
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
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&BOBCommandChannel::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void BOBCommandChannel::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();

		if (!ecode)
		{
			LogPrint (eLogInfo, "New BOB command connection from ", socket->remote_endpoint ());
			// TODO:	
		}
		else
			LogPrint (eLogError, "BOB accept error: ",  ecode.message ());
	}
}
}

