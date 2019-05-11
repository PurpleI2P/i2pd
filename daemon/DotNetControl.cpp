#include <stdio.h>
#include <sstream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <boost/lexical_cast.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/property_tree/ini_parser.hpp>

// There is bug in boost 1.49 with gcc 4.7 coming with Debian Wheezy
#define GCC47_BOOST149 ((BOOST_VERSION == 104900) && (__GNUC__ == 4) && (__GNUC_MINOR__ >= 7))
#if !GCC47_BOOST149
#include <boost/property_tree/json_parser.hpp>
#endif

#include "Crypto.h"
#include "FS.h"
#include "Log.h"
#include "Config.h"
#include "NetDb.hpp"
#include "RouterContext.h"
#include "Daemon.h"
#include "Tunnel.h"
#include "Timestamp.h"
#include "Transports.h"
#include "version.h"
#include "util.h"
#include "ClientContext.h"
#include "DotNetControl.h"

namespace dotnet
{
namespace client
{
	DotNetControlService::DotNetControlService (const std::string& address, int port):
		m_IsRunning (false), m_Thread (nullptr),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(address), port)),
		m_SSLContext (boost::asio::ssl::context::sslv23),
		m_ShutdownTimer (m_Service)
	{
		dotnet::config::GetOption("dotnetcontrol.password", m_Password);

		// certificate / keys
		std::string dotnetcp_crt; dotnet::config::GetOption("dotnetcontrol.cert", dotnetcp_crt);
		std::string dotnetcp_key; dotnet::config::GetOption("dotnetcontrol.key",  dotnetcp_key);

		if (dotnetcp_crt.at(0) != '/')
			dotnetcp_crt = dotnet::fs::DataDirPath(dotnetcp_crt);
		if (dotnetcp_key.at(0) != '/')
			dotnetcp_key = dotnet::fs::DataDirPath(dotnetcp_key);
		if (!dotnet::fs::Exists (dotnetcp_crt) || !dotnet::fs::Exists (dotnetcp_key)) {
			LogPrint (eLogInfo, "DotNetControl: creating new certificate for control connection");
			CreateCertificate (dotnetcp_crt.c_str(), dotnetcp_key.c_str());
		} else {
			LogPrint(eLogDebug, "DotNetControl: using cert from ", dotnetcp_crt);
		}
		m_SSLContext.set_options (boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);
		m_SSLContext.use_certificate_file (dotnetcp_crt, boost::asio::ssl::context::pem);
		m_SSLContext.use_private_key_file (dotnetcp_key, boost::asio::ssl::context::pem);

		// handlers
		m_MethodHandlers["Authenticate"]   = &DotNetControlService::AuthenticateHandler;
		m_MethodHandlers["Echo"]           = &DotNetControlService::EchoHandler;
		m_MethodHandlers["DotNetControl"]     = &DotNetControlService::DotNetControlHandler;
		m_MethodHandlers["RouterInfo"]     = &DotNetControlService::RouterInfoHandler;
		m_MethodHandlers["RouterManager"]  = &DotNetControlService::RouterManagerHandler;
		m_MethodHandlers["NetworkSetting"] = &DotNetControlService::NetworkSettingHandler;
		m_MethodHandlers["ClientServicesInfo"]     = &DotNetControlService::ClientServicesInfoHandler;

		// DotNetControl
		m_DotNetControlHandlers["dotnetcontrol.password"] = &DotNetControlService::PasswordHandler;

		// RouterInfo
		m_RouterInfoHandlers["dotnet.router.uptime"]  = &DotNetControlService::UptimeHandler;
		m_RouterInfoHandlers["dotnet.router.version"] = &DotNetControlService::VersionHandler;
		m_RouterInfoHandlers["dotnet.router.status"]  = &DotNetControlService::StatusHandler;
		m_RouterInfoHandlers["dotnet.router.netdb.knownpeers"]   = &DotNetControlService::NetDbKnownPeersHandler;
		m_RouterInfoHandlers["dotnet.router.netdb.activepeers"]  = &DotNetControlService::NetDbActivePeersHandler;
		m_RouterInfoHandlers["dotnet.router.net.bw.inbound.1s"]  = &DotNetControlService::InboundBandwidth1S;
		m_RouterInfoHandlers["dotnet.router.net.bw.outbound.1s"] = &DotNetControlService::OutboundBandwidth1S;
		m_RouterInfoHandlers["dotnet.router.net.status"]         = &DotNetControlService::NetStatusHandler;
		m_RouterInfoHandlers["dotnet.router.net.tunnels.participating"] = &DotNetControlService::TunnelsParticipatingHandler;
		m_RouterInfoHandlers["dotnet.router.net.tunnels.successrate"] =
&DotNetControlService::TunnelsSuccessRateHandler;
		m_RouterInfoHandlers["dotnet.router.net.total.received.bytes"]  = &DotNetControlService::NetTotalReceivedBytes;
		m_RouterInfoHandlers["dotnet.router.net.total.sent.bytes"]      = &DotNetControlService::NetTotalSentBytes;

		// RouterManager
		m_RouterManagerHandlers["Reseed"]           = &DotNetControlService::ReseedHandler;
		m_RouterManagerHandlers["Shutdown"]         = &DotNetControlService::ShutdownHandler;
		m_RouterManagerHandlers["ShutdownGraceful"] = &DotNetControlService::ShutdownGracefulHandler;

		// NetworkSetting
		m_NetworkSettingHandlers["dotnet.router.net.bw.in"]  = &DotNetControlService::InboundBandwidthLimit;
		m_NetworkSettingHandlers["dotnet.router.net.bw.out"] = &DotNetControlService::OutboundBandwidthLimit;

		// ClientServicesInfo
		m_ClientServicesInfoHandlers["DotNetTunnel"] = &DotNetControlService::DotNetTunnelInfoHandler;
		m_ClientServicesInfoHandlers["HTTPProxy"] = &DotNetControlService::HTTPProxyInfoHandler;
		m_ClientServicesInfoHandlers["SOCKS"] = &DotNetControlService::SOCKSInfoHandler;
		m_ClientServicesInfoHandlers["SAM"] = &DotNetControlService::SAMInfoHandler;
		m_ClientServicesInfoHandlers["BOB"] = &DotNetControlService::BOBInfoHandler;
		m_ClientServicesInfoHandlers["DNCP"] = &DotNetControlService::DNCPInfoHandler;
	}

	DotNetControlService::~DotNetControlService ()
	{
		Stop ();
	}

	void DotNetControlService::Start ()
	{
		if (!m_IsRunning)
		{
			Accept ();
			m_IsRunning = true;
			m_Thread = new std::thread (std::bind (&DotNetControlService::Run, this));
		}
	}

	void DotNetControlService::Stop ()
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

	void DotNetControlService::Run ()
	{
		while (m_IsRunning)
		{
			try {
				m_Service.run ();
			} catch (std::exception& ex) {
				LogPrint (eLogError, "DotNetControl: runtime exception: ", ex.what ());
			}
		}
	}

	void DotNetControlService::Accept ()
	{
		auto newSocket = std::make_shared<ssl_socket> (m_Service, m_SSLContext);
		m_Acceptor.async_accept (newSocket->lowest_layer(), std::bind (&DotNetControlService::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void DotNetControlService::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<ssl_socket> socket)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();

		if (ecode) {
			LogPrint (eLogError, "DotNetControl: accept error: ",  ecode.message ());
			return;
		}
		LogPrint (eLogDebug, "DotNetControl: new request from ", socket->lowest_layer ().remote_endpoint ());
		Handshake (socket);
	}

	void DotNetControlService::Handshake (std::shared_ptr<ssl_socket> socket)
	{
		socket->async_handshake(boost::asio::ssl::stream_base::server,
		std::bind( &DotNetControlService::HandleHandshake, this, std::placeholders::_1, socket));
	}

	void DotNetControlService::HandleHandshake (const boost::system::error_code& ecode, std::shared_ptr<ssl_socket> socket)
	{
		if (ecode) {
			LogPrint (eLogError, "DotNetControl: handshake error: ", ecode.message ());
			return;
		}
		//std::this_thread::sleep_for (std::chrono::milliseconds(5));
		ReadRequest (socket);
	}

	void DotNetControlService::ReadRequest (std::shared_ptr<ssl_socket> socket)
	{
		auto request = std::make_shared<DotNetControlBuffer>();
		socket->async_read_some (
#if defined(BOOST_ASIO_HAS_STD_ARRAY)
			boost::asio::buffer (*request),
#else
			boost::asio::buffer (request->data (), request->size ()),
#endif
			std::bind(&DotNetControlService::HandleRequestReceived, this,
			std::placeholders::_1, std::placeholders::_2, socket, request));
	}

	void DotNetControlService::HandleRequestReceived (const boost::system::error_code& ecode,
		size_t bytes_transferred, std::shared_ptr<ssl_socket> socket,
		std::shared_ptr<DotNetControlBuffer> buf)
	{
		if (ecode)
		{
			LogPrint (eLogError, "DotNetControl: read error: ", ecode.message ());
			return;
		}
		else
		{
			bool isHtml = !memcmp (buf->data (), "POST", 4);
			try
			{
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
						LogPrint (eLogError, "DotNetControl: malformed request, HTTP header expected");
						return; // TODO:
					}
					std::streamoff rem = contentLength + ss.tellg () - bytes_transferred; // more bytes to read
					if (rem > 0)
					{
						bytes_transferred = boost::asio::read (*socket, boost::asio::buffer (buf->data (), rem));
						ss.write (buf->data (), bytes_transferred);
					}
				}
				std::ostringstream response;
#if GCC47_BOOST149
				LogPrint (eLogError, "DotNetControl: json_read is not supported due bug in boost 1.49 with gcc 4.7");
				response << "{\"id\":null,\"error\":";
				response << "{\"code\":-32603,\"message\":\"JSON requests is not supported with this version of boost\"},";
				response << "\"jsonrpc\":\"2.0\"}";
#else
				boost::property_tree::ptree pt;
				boost::property_tree::read_json (ss, pt);

				std::string id     = pt.get<std::string>("id");
				std::string method = pt.get<std::string>("method");
				auto it = m_MethodHandlers.find (method);
				if (it != m_MethodHandlers.end ())
				{
					response << "{\"id\":" << id << ",\"result\":{";
					(this->*(it->second))(pt.get_child ("params"), response);
					response << "},\"jsonrpc\":\"2.0\"}";
				}
				else
				{
					LogPrint (eLogWarning, "DotNetControl: unknown method ", method);
					response << "{\"id\":null,\"error\":";
					response << "{\"code\":-32601,\"message\":\"Method not found\"},";
					response << "\"jsonrpc\":\"2.0\"}";
				}
#endif
				SendResponse (socket, buf, response, isHtml);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "DotNetControl: exception when handle request: ", ex.what ());
				std::ostringstream response;
				response << "{\"id\":null,\"error\":";
				response << "{\"code\":-32700,\"message\":\"" << ex.what () << "\"},";
				response << "\"jsonrpc\":\"2.0\"}";
				SendResponse (socket, buf, response, isHtml);
			}
			catch (...)
			{
				LogPrint (eLogError, "DotNetControl: handle request unknown exception");
			}
		}
	}

	void DotNetControlService::InsertParam (std::ostringstream& ss, const std::string& name, int value) const
	{
		ss << "\"" << name << "\":" << value;
	}

	void DotNetControlService::InsertParam (std::ostringstream& ss, const std::string& name, const std::string& value) const
	{
		ss << "\"" << name << "\":";
		if (value.length () > 0)
			ss << "\"" << value << "\"";
		else
			ss << "null";
	}

	void DotNetControlService::InsertParam (std::ostringstream& ss, const std::string& name, double value) const
	{
		ss << "\"" << name << "\":" << std::fixed << std::setprecision(2) << value;
	}

	void DotNetControlService::InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const
	{
		std::ostringstream buf;
		boost::property_tree::write_json (buf, value, false);
		ss << "\"" << name << "\":" << buf.str();
	}

	void DotNetControlService::SendResponse (std::shared_ptr<ssl_socket> socket,
		std::shared_ptr<DotNetControlBuffer> buf, std::ostringstream& response, bool isHtml)
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
			std::bind(&DotNetControlService::HandleResponseSent, this,
				std::placeholders::_1, std::placeholders::_2, socket, buf));
	}

	void DotNetControlService::HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
		std::shared_ptr<ssl_socket> socket, std::shared_ptr<DotNetControlBuffer> buf)
	{
		if (ecode) {
			LogPrint (eLogError, "DotNetControl: write error: ", ecode.message ());
		}
	}

// handlers

	void DotNetControlService::AuthenticateHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		int api       = params.get<int> ("API");
		auto password = params.get<std::string> ("Password");
		LogPrint (eLogDebug, "DotNetControl: Authenticate API=", api, " Password=", password);
		if (password != m_Password) {
			LogPrint (eLogError, "DotNetControl: Authenticate - Invalid password: ", password);
			return;
		}
		InsertParam (results, "API", api);
		results << ",";
		std::string token = boost::lexical_cast<std::string>(dotnet::util::GetSecondsSinceEpoch ());
		m_Tokens.insert (token);
		InsertParam (results, "Token", token);
	}

	void DotNetControlService::EchoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		auto echo = params.get<std::string> ("Echo");
		LogPrint (eLogDebug, "DotNetControl Echo Echo=", echo);
		InsertParam (results, "Result", echo);
	}


// DotNetControl

	void DotNetControlService::DotNetControlHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto& it: params)
		{
			LogPrint (eLogDebug, "DotNetControl: DotNetControl request: ", it.first);
			auto it1 = m_DotNetControlHandlers.find (it.first);
			if (it1 != m_DotNetControlHandlers.end ())
			{
				(this->*(it1->second))(it.second.data ());
				InsertParam (results, it.first, "");
			}
			else
				LogPrint (eLogError, "DotNetControl: DotNetControl unknown request: ", it.first);
		}
	}

	void DotNetControlService::PasswordHandler (const std::string& value)
	{
		LogPrint (eLogWarning, "DotNetControl: new password=", value, ", to make it persistent you should update your config!");
		m_Password = value;
		m_Tokens.clear ();
	}

// RouterInfo

	void DotNetControlService::RouterInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto it = params.begin (); it != params.end (); it++)
		{
			LogPrint (eLogDebug, "DotNetControl: RouterInfo request: ", it->first);
			auto it1 = m_RouterInfoHandlers.find (it->first);
			if (it1 != m_RouterInfoHandlers.end ())
			{
				if (it != params.begin ()) results << ",";
				(this->*(it1->second))(results);
			}
			else
				LogPrint (eLogError, "DotNetControl: RouterInfo unknown request ", it->first);
		}
	}

	void DotNetControlService::UptimeHandler (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.uptime", (int)dotnet::context.GetUptime ()*1000);
	}

	void DotNetControlService::VersionHandler (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.version", VERSION);
	}

	void DotNetControlService::StatusHandler (std::ostringstream& results)
	{
		auto dest = dotnet::client::context.GetSharedLocalDestination ();
		InsertParam (results, "dotnet.router.status", (dest && dest->IsReady ()) ? "1" : "0");
	}

	void DotNetControlService::NetDbKnownPeersHandler (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.netdb.knownpeers", dotnet::data::netdb.GetNumRouters ());
	}

	void DotNetControlService::NetDbActivePeersHandler (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.netdb.activepeers", (int)dotnet::transport::transports.GetPeers ().size ());
	}

	void DotNetControlService::NetStatusHandler (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.net.status", (int)dotnet::context.GetStatus ());
	}

	void DotNetControlService::TunnelsParticipatingHandler (std::ostringstream& results)
	{
		int transit = dotnet::tunnel::tunnels.GetTransitTunnels ().size ();
		InsertParam (results, "dotnet.router.net.tunnels.participating", transit);
	}

	void DotNetControlService::TunnelsSuccessRateHandler (std::ostringstream& results)
	{
		int rate = dotnet::tunnel::tunnels.GetTunnelCreationSuccessRate ();
		InsertParam (results, "dotnet.router.net.tunnels.successrate", rate);
	}

	void DotNetControlService::InboundBandwidth1S (std::ostringstream& results)
	{
		double bw = dotnet::transport::transports.GetInBandwidth ();
		InsertParam (results, "dotnet.router.net.bw.inbound.1s", bw);
	}

	void DotNetControlService::OutboundBandwidth1S (std::ostringstream& results)
	{
		double bw = dotnet::transport::transports.GetOutBandwidth ();
		InsertParam (results, "dotnet.router.net.bw.outbound.1s", bw);
	}

	void DotNetControlService::NetTotalReceivedBytes (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.net.total.received.bytes", (double)dotnet::transport::transports.GetTotalReceivedBytes ());
	}

	void DotNetControlService::NetTotalSentBytes (std::ostringstream& results)
	{
		InsertParam (results, "dotnet.router.net.total.sent.bytes",     (double)dotnet::transport::transports.GetTotalSentBytes ());
	}


// RouterManager

	void DotNetControlService::RouterManagerHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto it = params.begin (); it != params.end (); it++)
		{
			if (it != params.begin ()) results << ",";
			LogPrint (eLogDebug, "DotNetControl: RouterManager request: ", it->first);
			auto it1 = m_RouterManagerHandlers.find (it->first);
			if (it1 != m_RouterManagerHandlers.end ()) {
				(this->*(it1->second))(results);
			} else
				LogPrint (eLogError, "DotNetControl: RouterManager unknown request: ", it->first);
		}
	}


	void DotNetControlService::ShutdownHandler (std::ostringstream& results)
	{
		LogPrint (eLogInfo, "DotNetControl: Shutdown requested");
		InsertParam (results, "Shutdown", "");
		m_ShutdownTimer.expires_from_now (boost::posix_time::seconds(1)); // 1 second to make sure response has been sent
		m_ShutdownTimer.async_wait (
			[](const boost::system::error_code& ecode)
		    {
				Daemon.running = 0;
			});
	}

	void DotNetControlService::ShutdownGracefulHandler (std::ostringstream& results)
	{
		dotnet::context.SetAcceptsTunnels (false);
		int timeout = dotnet::tunnel::tunnels.GetTransitTunnelsExpirationTimeout ();
		LogPrint (eLogInfo, "DotNetControl: Graceful shutdown requested, ", timeout, " seconds remains");
		InsertParam (results, "ShutdownGraceful", "");
		m_ShutdownTimer.expires_from_now (boost::posix_time::seconds(timeout + 1)); // + 1 second
		m_ShutdownTimer.async_wait (
			[](const boost::system::error_code& ecode)
		    {
				Daemon.running = 0;
			});
	}

	void DotNetControlService::ReseedHandler (std::ostringstream& results)
	{
		LogPrint (eLogInfo, "DotNetControl: Reseed requested");
		InsertParam (results, "Reseed", "");
		dotnet::data::netdb.Reseed ();
	}

// network setting
	void DotNetControlService::NetworkSettingHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto it = params.begin (); it != params.end (); it++)
		{
			LogPrint (eLogDebug, "DotNetControl: NetworkSetting request: ", it->first);
			auto it1 = m_NetworkSettingHandlers.find (it->first);
			if (it1 != m_NetworkSettingHandlers.end ()) {
				if (it != params.begin ()) results << ",";
				(this->*(it1->second))(it->second.data (), results);
			} else
				LogPrint (eLogError, "DotNetControl: NetworkSetting unknown request: ", it->first);
		}
	}

	void DotNetControlService::InboundBandwidthLimit (const std::string& value, std::ostringstream& results)
	{
		if (value != "null")
			dotnet::context.SetBandwidth (std::atoi(value.c_str()));
		int bw = dotnet::context.GetBandwidthLimit();
		InsertParam (results, "dotnet.router.net.bw.in", bw);
	}

	void DotNetControlService::OutboundBandwidthLimit (const std::string& value, std::ostringstream& results)
	{
		if (value != "null")
			dotnet::context.SetBandwidth (std::atoi(value.c_str()));
		int bw = dotnet::context.GetBandwidthLimit();
		InsertParam (results, "dotnet.router.net.bw.out", bw);
	}

	// certificate
	void DotNetControlService::CreateCertificate (const char *crt_path, const char *key_path)
	{
		FILE *f = NULL;
		EVP_PKEY * pkey = EVP_PKEY_new ();
		RSA * rsa = RSA_new ();
		BIGNUM * e = BN_dup (dotnet::crypto::GetRSAE ());
		RSA_generate_key_ex (rsa, 4096, e, NULL);
		BN_free (e);
		if (rsa)
		{
			EVP_PKEY_assign_RSA (pkey, rsa);
			X509 * x509 = X509_new ();
			ASN1_INTEGER_set (X509_get_serialNumber (x509), 1);
			X509_gmtime_adj (X509_getm_notBefore (x509), 0);
			X509_gmtime_adj (X509_getm_notAfter (x509), DOTNET_CONTROL_CERTIFICATE_VALIDITY*24*60*60); // expiration
			X509_set_pubkey (x509, pkey); // public key
			X509_NAME * name = X509_get_subject_name (x509);
			X509_NAME_add_entry_by_txt (name, "C",  MBSTRING_ASC, (unsigned char *)"A1", -1, -1, 0); // country (Anonymous proxy)
			X509_NAME_add_entry_by_txt (name, "O",  MBSTRING_ASC, (unsigned char *)DOTNET_CONTROL_CERTIFICATE_ORGANIZATION, -1, -1, 0); // organization
			X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC, (unsigned char *)DOTNET_CONTROL_CERTIFICATE_COMMON_NAME, -1, -1, 0); // common name
			X509_set_issuer_name (x509, name); // set issuer to ourselves
			X509_sign (x509, pkey, EVP_sha1 ()); // sign

			// save cert
			if ((f = fopen (crt_path, "wb")) != NULL) {
				LogPrint (eLogInfo, "DotNetControl: saving new cert to ", crt_path);
				PEM_write_X509 (f, x509);
				fclose (f);
			} else {
				LogPrint (eLogError, "DotNetControl: can't write cert: ", strerror(errno));
			}

			// save key
			if ((f = fopen (key_path, "wb")) != NULL) {
				LogPrint (eLogInfo, "DotNetControl: saving cert key to ", key_path);
				PEM_write_PrivateKey (f, pkey, NULL, NULL, 0, NULL, NULL);
				fclose (f);
			} else {
				LogPrint (eLogError, "DotNetControl: can't write key: ", strerror(errno));
			}

			X509_free (x509);
		} else {
			LogPrint (eLogError, "DotNetControl: can't create RSA key for certificate");
		}
		EVP_PKEY_free (pkey);
	}

// ClientServicesInfo

	void DotNetControlService::ClientServicesInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto it = params.begin (); it != params.end (); it++)
		{
			LogPrint (eLogDebug, "DotNetControl: ClientServicesInfo request: ", it->first);
			auto it1 = m_ClientServicesInfoHandlers.find (it->first);
			if (it1 != m_ClientServicesInfoHandlers.end ())
			{
				if (it != params.begin ()) results << ",";
				(this->*(it1->second))(results);
			}
			else
				LogPrint (eLogError, "DotNetControl: ClientServicesInfo unknown request ", it->first);
		}
	}

	void DotNetControlService::DotNetTunnelInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		boost::property_tree::ptree client_tunnels, server_tunnels;

		for (auto& it: dotnet::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			boost::property_tree::ptree ct;
			ct.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));
			client_tunnels.add_child(it.second->GetName (), ct);
		}

		auto& serverTunnels = dotnet::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				boost::property_tree::ptree st;
				st.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));
				st.put("port", it.second->GetLocalPort ());
				server_tunnels.add_child(it.second->GetName (), st);
			}
		}

		auto& clientForwards = dotnet::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				boost::property_tree::ptree ct;
				ct.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));
				client_tunnels.add_child(it.second->GetName (), ct);
			}
		}

		auto& serverForwards = dotnet::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				boost::property_tree::ptree st;
				st.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));
				server_tunnels.add_child(it.second->GetName (), st);
			}
		}

		pt.add_child("client", client_tunnels);
		pt.add_child("server", server_tunnels);

		InsertParam (results, "DotNetTunnel", pt);
	}

	void DotNetControlService::HTTPProxyInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;

		auto httpProxy = dotnet::client::context.GetHttpProxy ();
		if (httpProxy)
		{
			auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
			pt.put("enabled", true);
			pt.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "HTTPProxy", pt);
	}

	void DotNetControlService::SOCKSInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;

		auto socksProxy = dotnet::client::context.GetSocksProxy ();
		if (socksProxy)
		{
			auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
			pt.put("enabled", true);
			pt.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "SOCKS", pt);
	}

	void DotNetControlService::SAMInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		auto sam = dotnet::client::context.GetSAMBridge ();
		if (sam)
		{
			pt.put("enabled", true);
			boost::property_tree::ptree sam_sessions;
			for (auto& it: sam->GetSessions ())
			{
				boost::property_tree::ptree sam_session, sam_session_sockets;
				auto& name = it.second->localDestination->GetNickname ();
				auto& ident = it.second->localDestination->GetIdentHash();
				sam_session.put("name", name);
				sam_session.put("address", dotnet::client::context.GetAddressBook ().ToAddress(ident));

				for (const auto& socket: sam->ListSockets(it.first))
				{
					boost::property_tree::ptree stream;
					stream.put("type", socket->GetSocketType ());
					stream.put("peer", socket->GetSocket ().remote_endpoint());

					sam_session_sockets.push_back(std::make_pair("", stream));
				}
				sam_session.add_child("sockets", sam_session_sockets);
				sam_sessions.add_child(it.first, sam_session);
			}

			pt.add_child("sessions", sam_sessions);
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "SAM", pt);
	}

	void DotNetControlService::BOBInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		auto bob = dotnet::client::context.GetBOBCommandChannel ();
		if (bob)
		{
			/* TODO more info */
			pt.put("enabled", true);
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "BOB", pt);
	}

	void DotNetControlService::DNCPInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		auto dncp = dotnet::client::context.GetDNCPServer ();
		if (dncp)
		{
			/* TODO more info */
			pt.put("enabled", true);
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "DNCP", pt);
	}
}
}
