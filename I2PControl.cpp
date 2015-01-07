#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "Log.h"
#include "I2PControl.h"

namespace i2p
{
namespace client
{
	I2PControlService::I2PControlService (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
	}

	I2PControlService::~I2PControlService ()
	{
		Stop ();
	}

	void I2PControlService::Start ()
	{
		if (!m_IsRunning)
		{
			Accept ();
			m_IsRunning = true;
			m_Thread = new std::thread (std::bind (&I2PControlService::Run, this));
		}
	}

	void I2PControlService::Stop ()
	{
		if (m_IsRunning)
		{
			m_IsRunning = false;
			m_Acceptor.cancel ();	
			m_Service.stop ();
			if (m_Thread)
			{	
				m_Thread->join (); 
				delete m_Thread;
				m_Thread = nullptr;
			}	
		}
	}

	void I2PControlService::Run () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "I2PControl: ", ex.what ());
			}	
		}	
	}

	void I2PControlService::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&I2PControlService::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void I2PControlService::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();

		if (!ecode)
		{
			LogPrint (eLogInfo, "New I2PControl request from ", socket->remote_endpoint ());
			ReadRequest (socket);	
		}
		else
			LogPrint (eLogError, "I2PControl accept error: ",  ecode.message ());
	}

	void I2PControlService::ReadRequest (std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		auto request = std::make_shared<I2PControlBuffer>();
		socket->async_read_some (boost::asio::buffer (*request),                
			std::bind(&I2PControlService::HandleRequestReceived, this, 
			std::placeholders::_1, std::placeholders::_2, socket, request));
	}

	void I2PControlService::HandleRequestReceived (const boost::system::error_code& ecode,
 		size_t bytes_transferred, std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
		std::shared_ptr<I2PControlBuffer> buf)
	{
		if (ecode)
		{
			LogPrint (eLogError, "I2PControl read error: ", ecode.message ());
		}
		else
		{
			std::stringstream ss;
			ss.write (buf->data (), bytes_transferred);
			boost::property_tree::ptree pt;
			boost::property_tree::read_json (ss, pt);
			std::string method = pt.get<std::string>(I2P_CONTROL_PROPERTY_METHOD);
			auto it = m_MethodHanders.find (method);
			if (it != m_MethodHanders.end ())
				(this->*(it->second))();
			else
				LogPrint (eLogWarning, "Unknown I2PControl method ", method);
		}
	}
}
}
