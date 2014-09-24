#include <boost/bind.hpp>
#include "Log.h"
#include "SAM.h"

namespace i2p
{
namespace stream
{
	SAMBridge::SAMBridge (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		m_NewSocket	(nullptr)
	{
	}

	SAMBridge::~SAMBridge ()
	{
		Stop ();
		delete m_NewSocket;
	}	

	void SAMBridge::Start ()
	{
		Accept ();
		m_Thread = new std::thread (std::bind (&SAMBridge::Run, this));
	}

	void SAMBridge::Stop ()
	{
		m_IsRunning = false;
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
		m_NewSocket = new boost::asio::ip::tcp::socket (m_Service);
		m_Acceptor.async_accept (*m_NewSocket, boost::bind (&SAMBridge::HandleAccept, this,
			boost::asio::placeholders::error));
	}

	void SAMBridge::HandleAccept(const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			//TODO:
		}
		else
		{
			delete m_NewSocket;
			m_NewSocket = nullptr;	
		}

		if (ecode != boost::asio::error::operation_aborted)
			Accept ();
	}
}
}
