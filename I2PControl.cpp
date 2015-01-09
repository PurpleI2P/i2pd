#include <sstream>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "Log.h"
#include "Timestamp.h"
#include "I2PControl.h"

namespace i2p
{
namespace client
{
	I2PControlService::I2PControlService (int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
		m_MethodHanders[I2P_CONTROL_METHOD_AUTHENTICATE] = &I2PControlService::AuthenticateHandler; 
		m_MethodHanders[I2P_CONTROL_METHOD_ECHO] = &I2PControlService::EchoHandler; 
		m_MethodHanders[I2P_CONTROL_METHOD_ROUTER_INFO] = &I2PControlService::RouterInfoHandler; 
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
			try
			{
				std::stringstream ss;
				ss.write (buf->data (), bytes_transferred);
				boost::property_tree::ptree pt;
				boost::property_tree::read_json (ss, pt);
				std::string method = pt.get<std::string>(I2P_CONTROL_PROPERTY_METHOD);
				auto it = m_MethodHanders.find (method);
				if (it != m_MethodHanders.end ())
				{
					std::map<std::string, std::string> params;
					for (auto& v: pt.get_child (I2P_CONTROL_PROPERTY_PARAMS))
					{
						if (!v.first.empty())
							params[v.first] = v.second.data ();
					}
					std::map<std::string, std::string> results;
					(this->*(it->second))(params, results);
					SendResponse (socket, buf, pt.get<std::string>(I2P_CONTROL_PROPERTY_ID), results);
				}	
				else
					LogPrint (eLogWarning, "Unknown I2PControl method ", method);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "I2PControl handle request: ", ex.what ());
			}
			catch (...)
			{
				LogPrint (eLogError, "I2PControl handle request unknown exception");
			}
		}
	}

	void I2PControlService::SendResponse (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
		std::shared_ptr<I2PControlBuffer> buf, const std::string& id, 
		const std::map<std::string, std::string>& results)
	{
		boost::property_tree::ptree ptr;
		for (auto& result: results)
			ptr.put (result.first, result.second);
		ptr.put (boost::property_tree::ptree::path_type ("xxx.yyy",'/'), "zzz");

		boost::property_tree::ptree pt;
		pt.put (I2P_CONTROL_PROPERTY_ID, id);
		pt.put_child (I2P_CONTROL_PROPERTY_RESULT, ptr);
		pt.put ("jsonrpc", "2.0");		

		std::ostringstream ss;
		boost::property_tree::write_json (ss, pt, false);
		size_t len = ss.str ().length ();
		memcpy (buf->data (), ss.str ().c_str (), len);
		boost::asio::async_write (*socket, boost::asio::buffer (buf->data (), len), 
			boost::asio::transfer_all (),
			std::bind(&I2PControlService::HandleResponseSent, this, 
				std::placeholders::_1, std::placeholders::_2, socket, buf));
	}

	void I2PControlService::HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
		std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf)
	{
		if (ecode)
			LogPrint (eLogError, "I2PControl write error: ", ecode.message ());
		socket->close ();
	}

// handlers

	void I2PControlService::AuthenticateHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		const std::string& api = params.at (I2P_CONTROL_PARAM_API);
		const std::string& password = params.at (I2P_CONTROL_PARAM_PASSWORD);
		LogPrint (eLogDebug, "I2PControl Authenticate API=", api, " Password=", password);
		results[I2P_CONTROL_PARAM_API] = api;
		results[I2P_CONTROL_PARAM_TOKEN] = boost::lexical_cast<std::string>(i2p::util::GetSecondsSinceEpoch ());
	}	

	void I2PControlService::EchoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		const std::string& echo = params.at (I2P_CONTROL_PARAM_ECHO);
		LogPrint (eLogDebug, "I2PControl Echo Echo=", echo);
		results[I2P_CONTROL_PARAM_RESULT] = echo;	
	}

	void I2PControlService::RouterInfoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
	}
}
}
