// There is bug in boost 1.49 with gcc 4.7 coming with Debian Wheezy
#define GCC47_BOOST149 ((BOOST_VERSION == 104900) && (__GNUC__ == 4) && (__GNUC_MINOR__ >= 7))
#include <stdio.h>
#include <sstream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <boost/lexical_cast.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/property_tree/ini_parser.hpp>
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
#include "version.h"
#include "I2PControl.h"

namespace i2p
{
namespace client
{
	I2PControlService::I2PControlService (const std::string& address, int port):
		m_Password (I2P_CONTROL_DEFAULT_PASSWORD), m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(address), port)),
		m_SSLContext (m_Service, boost::asio::ssl::context::sslv23),
		m_ShutdownTimer (m_Service)
	{
		LoadConfig ();
		// certificate				
		auto path = GetPath ();
		if (!boost::filesystem::exists (path))
		{
			if (!boost::filesystem::create_directory (path))
				LogPrint (eLogError, "Failed to create i2pcontrol directory");
		}	
		if (!boost::filesystem::exists (path / I2P_CONTROL_KEY_FILE) ||
			!boost::filesystem::exists (path / I2P_CONTROL_CERT_FILE))
		{
			// create new certificate
			CreateCertificate ();
			LogPrint (eLogInfo, "I2PControl certificates created");
		}
		m_SSLContext.set_options (boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);
		m_SSLContext.use_certificate_file ((path / I2P_CONTROL_CERT_FILE).string (), boost::asio::ssl::context::pem);
		m_SSLContext.use_private_key_file ((path / I2P_CONTROL_KEY_FILE).string (), boost::asio::ssl::context::pem);

		// handlers
		m_MethodHandlers[I2P_CONTROL_METHOD_AUTHENTICATE] = &I2PControlService::AuthenticateHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_ECHO] = &I2PControlService::EchoHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_I2PCONTROL] = &I2PControlService::I2PControlHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_ROUTER_INFO] = &I2PControlService::RouterInfoHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_ROUTER_MANAGER] = &I2PControlService::RouterManagerHandler; 
		m_MethodHandlers[I2P_CONTROL_METHOD_NETWORK_SETTING] = &I2PControlService::NetworkSettingHandler; 

		// I2PControl
		m_I2PControlHandlers[I2P_CONTROL_I2PCONTROL_PASSWORD] = &I2PControlService::PasswordHandler; 

		// RouterInfo
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_UPTIME] = &I2PControlService::UptimeHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_VERSION] = &I2PControlService::VersionHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_STATUS] = &I2PControlService::StatusHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS] = &I2PControlService::NetDbKnownPeersHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS] = &I2PControlService::NetDbActivePeersHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_NET_STATUS] = &I2PControlService::NetStatusHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING] = &I2PControlService::TunnelsParticipatingHandler;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_BW_IB_1S] = &I2PControlService::InboundBandwidth1S ;
		m_RouterInfoHandlers[I2P_CONTROL_ROUTER_INFO_BW_OB_1S] = &I2PControlService::OutboundBandwidth1S ;

		// RouterManager	
		m_RouterManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN] = &I2PControlService::ShutdownHandler; 
		m_RouterManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL] = &I2PControlService::ShutdownGracefulHandler;
		m_RouterManagerHandlers[I2P_CONTROL_ROUTER_MANAGER_RESEED] = &I2PControlService::ReseedHandler;
	}

	I2PControlService::~I2PControlService ()
	{
		Stop ();
	}

	void I2PControlService::LoadConfig ()
	{
		auto path = GetPath ();
		if (!boost::filesystem::exists (path))
		{
			if (!boost::filesystem::create_directory (path))
				LogPrint (eLogError, "Failed to create i2pcontrol directory");
		}	
		boost::property_tree::ptree pt;
		auto filename = path / I2P_CONTROL_CONFIG_FILE;
		bool isNew = true;
		if (boost::filesystem::exists (filename))
		{	
			try
			{
				boost::property_tree::read_ini (filename.string (), pt);
				isNew = false;
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Can't read ", filename, ": ", ex.what ());
			}	
		}
		m_Password = pt.get (I2P_CONTROL_I2PCONTROL_PASSWORD, I2P_CONTROL_DEFAULT_PASSWORD);
		if (isNew) SaveConfig ();	
	}

	void I2PControlService::SaveConfig ()
	{
		boost::property_tree::ptree pt;
		pt.put (I2P_CONTROL_I2PCONTROL_PASSWORD, m_Password);
		auto filename = GetPath () / I2P_CONTROL_CONFIG_FILE;
		// we take care about directory in LoadConfig	
		try
		{
			boost::property_tree::write_ini (filename.string (), pt);
		}	
		catch (std::exception& ex)
		{
			LogPrint (eLogError, "Can't write ", filename, ": ", ex.what ());
		}	
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
		auto newSocket = std::make_shared<ssl_socket> (m_Service, m_SSLContext);
		m_Acceptor.async_accept (newSocket->lowest_layer(), std::bind (&I2PControlService::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void I2PControlService::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<ssl_socket> socket)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();

		if (!ecode)
		{
			LogPrint (eLogInfo, "New I2PControl request from ", socket->lowest_layer ().remote_endpoint ());
			Handshake (socket);	
		}
		else
			LogPrint (eLogError, "I2PControl accept error: ",  ecode.message ());
	}

	void I2PControlService::Handshake (std::shared_ptr<ssl_socket> socket)
	{
		socket->async_handshake(boost::asio::ssl::stream_base::server,
        	std::bind( &I2PControlService::HandleHandshake, this, std::placeholders::_1, socket));
	}

	void I2PControlService::HandleHandshake (const boost::system::error_code& ecode, std::shared_ptr<ssl_socket> socket)
	{
		if (!ecode)
		{
			//std::this_thread::sleep_for (std::chrono::milliseconds(5));
			ReadRequest (socket);
		}	
		else
			LogPrint (eLogError, "I2PControl handshake error: ",  ecode.message ());
	}

	void I2PControlService::ReadRequest (std::shared_ptr<ssl_socket> socket)
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
 		size_t bytes_transferred, std::shared_ptr<ssl_socket> socket, 
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
					size_t contentLength = 0;
					while (!ss.eof () && header != "\r")
					{	
						std::getline(ss, header);
						auto colon = header.find (':');
						if (colon != std::string::npos && header.substr (0, colon) == "Content-Length")
							contentLength = std::stoi (header.substr (colon + 1));
					}	
					if (ss.eof ())
					{
						LogPrint (eLogError, "Malformed I2PControl request. HTTP header expected");
						return; // TODO:
					}
					std::streamoff rem = contentLength + ss.tellg () - bytes_transferred; // more bytes to read
					if (rem > 0)
					{	
						bytes_transferred = boost::asio::read (*socket, boost::asio::buffer (buf->data (), rem));
						ss.write (buf->data (), bytes_transferred);
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
					std::ostringstream response;
					response << "{\"id\":" << pt.get<std::string>(I2P_CONTROL_PROPERTY_ID) << ",\"result\":{";					

					(this->*(it->second))(pt.get_child (I2P_CONTROL_PROPERTY_PARAMS), response);
					response << "},\"jsonrpc\":\"2.0\"}";
					SendResponse (socket, buf, response, isHtml);
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

	void I2PControlService::InsertParam (std::ostringstream& ss, const std::string& name, int value) const
	{
		ss << "\"" << name << "\":" << value;
	} 

	void I2PControlService::InsertParam (std::ostringstream& ss, const std::string& name, const std::string& value) const
	{
		ss << "\"" << name << "\":";	
		if (value.length () > 0)
			ss << "\"" << value << "\"";
		else
			ss << "null";
	} 
		
	void I2PControlService::InsertParam (std::ostringstream& ss, const std::string& name, double value) const
	{
		ss << "\"" << name << "\":" << std::fixed << std::setprecision(2) << value;
	}	

	void I2PControlService::SendResponse (std::shared_ptr<ssl_socket> socket,
		std::shared_ptr<I2PControlBuffer> buf, std::ostringstream& response, bool isHtml)
	{
		size_t len = response.str ().length (), offset = 0;
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
		memcpy (buf->data () + offset, response.str ().c_str (), len);
		boost::asio::async_write (*socket, boost::asio::buffer (buf->data (), offset + len), 
			boost::asio::transfer_all (),
			std::bind(&I2PControlService::HandleResponseSent, this, 
				std::placeholders::_1, std::placeholders::_2, socket, buf));
	}

	void I2PControlService::HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
		std::shared_ptr<ssl_socket> socket, std::shared_ptr<I2PControlBuffer> buf)
	{
		if (ecode)
			LogPrint (eLogError, "I2PControl write error: ", ecode.message ());
	}

// handlers

	void I2PControlService::AuthenticateHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		int api = params.get<int> (I2P_CONTROL_PARAM_API);
		auto password = params.get<std::string> (I2P_CONTROL_PARAM_PASSWORD);
		LogPrint (eLogDebug, "I2PControl Authenticate API=", api, " Password=", password);
		if (password != m_Password)
			LogPrint (eLogError, "I2PControl Authenticate Invalid password ", password, " expected ", m_Password);
		InsertParam (results, I2P_CONTROL_PARAM_API, api);
		results << ",";
		std::string token = boost::lexical_cast<std::string>(i2p::util::GetSecondsSinceEpoch ());
		m_Tokens.insert (token);	
		InsertParam (results, I2P_CONTROL_PARAM_TOKEN, token);
	}	

	void I2PControlService::EchoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		auto echo = params.get<std::string> (I2P_CONTROL_PARAM_ECHO);
		LogPrint (eLogDebug, "I2PControl Echo Echo=", echo);
		InsertParam (results, I2P_CONTROL_PARAM_RESULT, echo);	
	}


// I2PControl

	void I2PControlService::I2PControlHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		LogPrint (eLogDebug, "I2PControl I2PControl");
		for (auto& it: params)
		{
			LogPrint (eLogDebug, it.first);
			auto it1 = m_I2PControlHandlers.find (it.first);
			if (it1 != m_I2PControlHandlers.end ())
			{
				(this->*(it1->second))(it.second.data ());	
				InsertParam (results, it.first, ""); 
			}
			else
				LogPrint (eLogError, "I2PControl I2PControl unknown request ", it.first);			
		}	
	}

	void I2PControlService::PasswordHandler (const std::string& value)
	{
		LogPrint (eLogDebug, "I2PControl new password=", value);
		m_Password = value;
		m_Tokens.clear ();
		SaveConfig ();
	}

// RouterInfo

	void I2PControlService::RouterInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		LogPrint (eLogDebug, "I2PControl RouterInfo");
		for (auto it = params.begin (); it != params.end (); it++)
		{
			if (it != params.begin ()) results << ",";	
			LogPrint (eLogDebug, it->first);
			auto it1 = m_RouterInfoHandlers.find (it->first);
			if (it1 != m_RouterInfoHandlers.end ())
				(this->*(it1->second))(results);	
			else
				LogPrint (eLogError, "I2PControl RouterInfo unknown request ", it->first);
		}
	}

	void I2PControlService::UptimeHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_UPTIME, (int)i2p::context.GetUptime ()*1000);	
	}

	void I2PControlService::VersionHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_VERSION, VERSION);	
	}	

	void I2PControlService::StatusHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_STATUS, "???"); // TODO:
	}
		
	void I2PControlService::NetDbKnownPeersHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS, i2p::data::netdb.GetNumRouters ());	
	}

	void I2PControlService::NetDbActivePeersHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS, (int)i2p::transport::transports.GetPeers ().size ());	
	}

	void I2PControlService::NetStatusHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_NET_STATUS, (int)i2p::context.GetStatus ());
	}

	void I2PControlService::TunnelsParticipatingHandler (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING, (int)i2p::tunnel::tunnels.GetTransitTunnels ().size ());
	}

	void I2PControlService::InboundBandwidth1S (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_BW_IB_1S, (double)i2p::transport::transports.GetInBandwidth ());
	}

	void I2PControlService::OutboundBandwidth1S (std::ostringstream& results)
	{
		InsertParam (results, I2P_CONTROL_ROUTER_INFO_BW_OB_1S, (double)i2p::transport::transports.GetOutBandwidth ());
	}

// RouterManager
	
	void I2PControlService::RouterManagerHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		LogPrint (eLogDebug, "I2PControl RouterManager");
		for (auto it = params.begin (); it != params.end (); it++)
		{
			if (it != params.begin ()) results << ",";	
			LogPrint (eLogDebug, it->first);
			auto it1 = m_RouterManagerHandlers.find (it->first);
			if (it1 != m_RouterManagerHandlers.end ())
				(this->*(it1->second))(results);	
			else
				LogPrint (eLogError, "I2PControl RouterManager unknown request ", it->first);			
		}
	}	


	void I2PControlService::ShutdownHandler (std::ostringstream& results)	
	{
		LogPrint (eLogInfo, "Shutdown requested");
		InsertParam (results, I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN, "");
		m_ShutdownTimer.expires_from_now (boost::posix_time::seconds(1)); // 1 second to make sure response has been sent
		m_ShutdownTimer.async_wait (
			[](const boost::system::error_code& ecode)
		    {
				Daemon.running = 0; 
			});
	}

	void I2PControlService::ShutdownGracefulHandler (std::ostringstream& results)
	{
		i2p::context.SetAcceptsTunnels (false);
		int timeout = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout ();
		LogPrint (eLogInfo, "Graceful shutdown requested. Will shutdown after ", timeout, " seconds");
		InsertParam (results, I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL, "");
		m_ShutdownTimer.expires_from_now (boost::posix_time::seconds(timeout + 1)); // + 1 second
		m_ShutdownTimer.async_wait (
			[](const boost::system::error_code& ecode)
		    {
				Daemon.running = 0; 
			});
	}

	void I2PControlService::ReseedHandler (std::ostringstream& results)
	{
		LogPrint (eLogInfo, "Reseed requested");
		InsertParam (results, I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN, "");	
		i2p::data::netdb.Reseed ();
	}

// network setting
	void I2PControlService::NetworkSettingHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		LogPrint (eLogDebug, "I2PControl NetworkSetting");
		for (auto it = params.begin (); it != params.end (); it++)
		{
			if (it != params.begin ()) results << ",";	
			LogPrint (eLogDebug, it->first);
			auto it1 = m_NetworkSettingHandlers.find (it->first);
			if (it1 != m_NetworkSettingHandlers.end ())
				(this->*(it1->second))(it->second.data (), results);	
			else
				LogPrint (eLogError, "I2PControl NetworkSetting unknown request ", it->first);			
		}
	}

	// certificate	
	void I2PControlService::CreateCertificate ()
	{
		EVP_PKEY * pkey = EVP_PKEY_new ();
		RSA * rsa = RSA_new ();
		BIGNUM * e = BN_dup (i2p::crypto::GetRSAE ());
		RSA_generate_key_ex (rsa, 4096, e, NULL);
		BN_free (e);
		if (rsa)
		{
			EVP_PKEY_assign_RSA (pkey, rsa);
			X509 * x509 = X509_new ();
			ASN1_INTEGER_set (X509_get_serialNumber (x509), 1);
			X509_gmtime_adj (X509_get_notBefore (x509), 0);
			X509_gmtime_adj (X509_get_notAfter (x509), I2P_CONTROL_CERTIFICATE_VALIDITY*24*60*60); // expiration		
			X509_set_pubkey (x509, pkey); // public key			
			X509_NAME * name = X509_get_subject_name (x509);
			X509_NAME_add_entry_by_txt (name, "C",  MBSTRING_ASC, (unsigned char *)"RU", -1, -1, 0); // country (Russia by default)
			X509_NAME_add_entry_by_txt (name, "O",  MBSTRING_ASC, (unsigned char *)I2P_CONTROL_CERTIFICATE_ORGANIZATION, -1, -1, 0); // organization
			X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC, (unsigned char *)I2P_CONTROL_CERTIFICATE_COMMON_NAME, -1, -1, 0); // common name
			X509_set_issuer_name (x509, name); // set issuer to ourselves
			X509_sign (x509, pkey, EVP_sha1 ()); // sign
			// save key and certificate
			// keys
			auto filename = GetPath () / I2P_CONTROL_KEY_FILE; 
			FILE * f= fopen (filename.string ().c_str (), "wb");
			if (f)
			{
				PEM_write_PrivateKey (f, pkey, NULL, NULL, 0, NULL, NULL);
				fclose (f);
			}
			else
				LogPrint (eLogError, "Can't open file ", filename);
			// certificate			
			filename = GetPath () / I2P_CONTROL_CERT_FILE;
			f= fopen (filename.string ().c_str (), "wb");
			if (f)
			{
				PEM_write_X509 (f, x509);
				fclose (f);
			}
			else
				LogPrint (eLogError, "Can't open file ", filename);

			X509_free (x509);		
		}
		else
			LogPrint (eLogError, "Couldn't create RSA key for certificate");
		EVP_PKEY_free (pkey);
	}

}
}
