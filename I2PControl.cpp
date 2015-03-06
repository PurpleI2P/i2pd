// There is bug in boost 1.49 with gcc 4.7 coming with Debian Wheezy
#define GCC47_BOOST149 ((BOOST_VERSION == 104900) && (__GNUC__ == 4) && (__GNUC_MINOR__ == 7))

#include "I2PControl.h"
#include <sstream>
#include <boost/lexical_cast.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/property_tree/ptree.hpp>
#if !GCC47_BOOST149
#include <boost/property_tree/json_parser.hpp>
#endif
#include "Log.h"
#include "NetDb.h"
#include "RouterContext.h"
#include "Daemon.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "Transports.h"

namespace i2p
{
namespace client
{
	I2PControlService::I2PControlService (int port):
		m_Password (I2P_CONTROL_DEFAULT_PASSWORD), m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		m_ShutdownTimer (m_Service)
	{
		m_MethodHandlers[I2P_CONTROL_METHOD_AUTHENTICATE] = &I2PControlService::AuthenticateHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_ECHO] = &I2PControlService::EchoHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_I2PCONTROL] = &I2PControlService::I2PControlHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_ROUTER_INFO] = &I2PControlService::RouterInfoHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_ROUTER_MANAGER] = &I2PControlService::RouterManagerHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_NETWORK_SETTING] = &I2PControlService::NetworkSettingHandler; 

		// RouterInfo
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_UPTIME] = &I2PControlService::UptimeHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS] = &I2PControlService::NetDbKnownPeersHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS] = &I2PControlService::NetDbActivePeersHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_STATUS] = &I2PControlService::StatusHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING] = &I2PControlService::TunnelsParticipatingHandler;

		// RouterManager	
		m_RouterManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN] = &I2PControlService::ShutdownHandler; 
		m_RouterManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL] = &I2PControlService::ShutdownGracefulHandler;
		m_RouterManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_RESEED] = &I2PControlService::ReseedHandler;
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
		socket->async_read_some (
#if BOOST_VERSION >= 104900
			boost::asio::buffer (*request),  
#else
			boost::asio::buffer (request->data (), request->size ()), 
#endif              
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
				bool isHtml = !memcmp (buf->data (), "POST", 4);
				std::stringstream ss;
				ss.write (buf->data (), bytes_transferred);
				if (isHtml)
				{
					std::string header;
					while (!ss.eof () && header != "\r")
						std::getline(ss, header);
					if (ss.eof ())
					{
						LogPrint (eLogError, "Malformed I2PControl request. HTTP header expected");
						return; // TODO:
					}
				}
#if GCC47_BOOST149
				LogPrint (eLogError, "json_read is not supported due bug in boost 1.49 with gcc 4.7");
#else
				boost::property_tree::ptree pt;
				boost::property_tree::read_json (ss, pt);

				std::string method = pt.get<std::string>(I2P_CONTROL_PROPERTY_METHOD);
				auto it = m_MethodHandlers.find (method);
				if (it != m_MethodHandlers.end ())
				{
					std::map<std::string, std::string> params;
					for (auto& v: pt.get_child (I2P_CONTROL_PROPERTY_PARAMS))
					{
						LogPrint (eLogInfo, v.first);
						if (!v.first.empty())
						{
							if (v.first == I2P_CONTROL_PARAM_TOKEN)
							{
								if (!m_Tokens.count (v.second.data ()))
								{
									LogPrint (eLogWarning, "Unknown token ", v.second.data ());
									return;
								}
				
							}	
							else
								params[v.first] = v.second.data ();
						}	
					}
					std::map<std::string, std::string> results;
					(this->*(it->second))(params, results);
					SendResponse (socket, buf, pt.get<std::string>(I2P_CONTROL_PROPERTY_ID), results, isHtml);
				}	
				else
					LogPrint (eLogWarning, "Unknown I2PControl method ", method);
#endif
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
		const std::map<std::string, std::string>& results, bool isHtml)
	{
		boost::property_tree::ptree ptr;
		for (auto& result: results)
			ptr.put (boost::property_tree::ptree::path_type (result.first, '/'), result.second);

		boost::property_tree::ptree pt;
		pt.put (I2P_CONTROL_PROPERTY_ID, id);
		pt.put_child (I2P_CONTROL_PROPERTY_RESULT, ptr);
		pt.put ("jsonrpc", "2.0");		

		std::ostringstream ss;
#if GCC47_BOOST149
		LogPrint (eLogError, "json_write is not supported due bug in boost 1.49 with gcc 4.7");
#else
		boost::property_tree::write_json (ss, pt, false);
#endif
		size_t len = ss.str ().length (), offset = 0;
		if (isHtml)
		{
			std::ostringstream header;
			header << "HTTP/1.1 200 OK\r\n";
			header << "Connection: close\r\n";
			header << "Content-Length: " << boost::lexical_cast<std::string>(len) << "\r\n";
			header << "Content-Type: application/json\r\n";
			header << "Date: ";
			auto facet = new boost::local_time::local_time_facet ("%a, %d %b %Y %H:%M:%S GMT");
			header.imbue(std::locale (header.getloc(), facet));
			header << boost::posix_time::second_clock::local_time() << "\r\n"; 
			header << "\r\n";
			offset = header.str ().size ();
			memcpy (buf->data (), header.str ().c_str (), offset);
		}	
		memcpy (buf->data () + offset, ss.str ().c_str (), len);
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
		if (password != m_Password)
			LogPrint (eLogError, "I2PControl Authenticate Invalid password ", password, " expected ", m_Password);
		results[I2P_CONTROL_PARAM_API] = api;
		std::string token = boost::lexical_cast<std::string>(i2p::util::GetSecondsSinceEpoch ());
		m_Tokens.insert (token);	
		results[I2P_CONTROL_PARAM_TOKEN] = token;
	}	

	void I2PControlService::EchoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		const std::string& echo = params.at (I2P_CONTROL_PARAM_ECHO);
		LogPrint (eLogDebug, "I2PControl Echo Echo=", echo);
		results[I2P_CONTROL_PARAM_RESULT] = echo;	
	}


// I2PControl

	void I2PControlService::I2PControlHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		LogPrint (eLogDebug, "I2PControl I2PControl");
		for (auto& it: params)
		{
			LogPrint (eLogDebug, it.first);
			auto it1 = m_I2PControlHandlers.find (it.first);
			if (it1 != m_I2PControlHandlers.end ())
				(this->*(it1->second))(it.second);	
			else
				LogPrint (eLogError, "I2PControl NetworkSetting unknown request ", it.first);			
		}	
	}

// RouterInfo

	void I2PControlService::RouterInfoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		LogPrint (eLogDebug, "I2PControl RouterInfo");
		for (auto& it: params)
		{
			LogPrint (eLogDebug, it.first);
			auto it1 = m_RouterInfoHandlers.find (it.first);
			if (it1 != m_RouterInfoHandlers.end ())
				(this->*(it1->second))(results);	
			else
				LogPrint (eLogError, "I2PControl RouterInfo unknown request ", it.first);
				
		}
	}

	void I2PControlService::UptimeHandler (std::map<std::string, std::string>& results)
	{
		results[I2P_CONTROL_ROUTER_INFO_UPTIME] = boost::lexical_cast<std::string>(i2p::context.GetUptime ()*1000);	
	}

	void I2PControlService::NetDbKnownPeersHandler (std::map<std::string, std::string>& results)
	{
		results[I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS] = boost::lexical_cast<std::string>(i2p::data::netdb.GetNumRouters ());	
	}

	void I2PControlService::NetDbActivePeersHandler (std::map<std::string, std::string>& results)
	{
		results[I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS] = boost::lexical_cast<std::string>(i2p::transport::transports.GetPeers ().size ());	
	}

	void I2PControlService::StatusHandler (std::map<std::string, std::string>& results)
	{
		results[I2P_CONTROL_ROUTER_INFO_STATUS] = boost::lexical_cast<std::string>((int)i2p::context.GetStatus ());
	}

	void I2PControlService::TunnelsParticipatingHandler (std::map<std::string, std::string>& results)
	{
		results[I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING] = boost::lexical_cast<std::string>(i2p::tunnel::tunnels.GetTransitTunnels ().size ());
	}

// RouterManager
	
	void I2PControlService::RouterManagerHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		LogPrint (eLogDebug, "I2PControl RouterManager");
		for (auto& it: params)
		{
			LogPrint (eLogDebug, it.first);
			auto it1 = m_RouterManagerHandlers.find (it.first);
			if (it1 != m_RouterManagerHandlers.end ())
				(this->*(it1->second))(results);	
			else
				LogPrint (eLogError, "I2PControl RouterManager unknown request ", it.first);			
		}
	}	


	void I2PControlService::ShutdownHandler (std::map<std::string, std::string>& results)	
	{
		LogPrint (eLogInfo, "Shutdown requested");
		results[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN] = "";
		m_ShutdownTimer.expires_from_now (boost::posix_time::seconds(1)); // 1 second to make sure response has been sent
		m_ShutdownTimer.async_wait (
			[](const boost::system::error_code& ecode)
		    {
				Daemon.running = 0; 
			});
	}

	void I2PControlService::ShutdownGracefulHandler (std::map<std::string, std::string>& results)
	{
		i2p::context.SetAcceptsTunnels (false);
		int timeout = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout ();
		LogPrint (eLogInfo, "Graceful shutdown requested. Will shutdown after ", timeout, " seconds");
		results[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL] = "";
		m_ShutdownTimer.expires_from_now (boost::posix_time::seconds(timeout + 1)); // + 1 second
		m_ShutdownTimer.async_wait (
			[](const boost::system::error_code& ecode)
		    {
				Daemon.running = 0; 
			});
	}

	void I2PControlService::ReseedHandler (std::map<std::string, std::string>& results)
	{
		LogPrint (eLogInfo, "Reseed requested");
		results[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN] = "";	
		i2p::data::netdb.Reseed ();
	}

// network setting
	void I2PControlService::NetworkSettingHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results)
	{
		LogPrint (eLogDebug, "I2PControl NetworkSetting");
		for (auto& it: params)
		{
			LogPrint (eLogDebug, it.first);
			auto it1 = m_NetworkSettingHandlers.find (it.first);
			if (it1 != m_NetworkSettingHandlers.end ())
				(this->*(it1->second))(it.second, results);	
			else
				LogPrint (eLogError, "I2PControl NetworkSetting unknown request ", it.first);			
		}
	}

}
}
