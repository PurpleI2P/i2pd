/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2P_CONTROL_H__
#define I2P_CONTROL_H__

#include <inttypes.h>
#include <thread>
#include <memory>
#include <array>
#include <string>
#include <sstream>
#include <map>
#include <set>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/property_tree/ptree.hpp>

namespace i2p
{
namespace client
{
	const size_t I2P_CONTROL_MAX_REQUEST_SIZE = 1024;
	typedef std::array<char, I2P_CONTROL_MAX_REQUEST_SIZE> I2PControlBuffer;

	const long I2P_CONTROL_CERTIFICATE_VALIDITY = 365*10; // 10 years
	const char I2P_CONTROL_CERTIFICATE_COMMON_NAME[] = "i2pd.i2pcontrol";
	const char I2P_CONTROL_CERTIFICATE_ORGANIZATION[] = "Purple I2P";

	class I2PControlService
	{
		typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

		public:

			I2PControlService (const std::string& address, int port);
			~I2PControlService ();

			void Start ();
			void Stop ();

		private:

			void Run ();
			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<ssl_socket> socket);
			void Handshake (std::shared_ptr<ssl_socket> socket);
			void HandleHandshake (const boost::system::error_code& ecode, std::shared_ptr<ssl_socket> socket);
			void ReadRequest (std::shared_ptr<ssl_socket> socket);
			void HandleRequestReceived (const boost::system::error_code& ecode, size_t bytes_transferred,
				std::shared_ptr<ssl_socket> socket, std::shared_ptr<I2PControlBuffer> buf);
			void SendResponse (std::shared_ptr<ssl_socket> socket,
				std::shared_ptr<I2PControlBuffer> buf, std::ostringstream& response, bool isHtml);
			void HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
				std::shared_ptr<ssl_socket> socket, std::shared_ptr<I2PControlBuffer> buf);

			void CreateCertificate (const char *crt_path, const char *key_path);

		private:

			void InsertParam (std::ostringstream& ss, const std::string& name, int value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, double value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, const std::string& value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const;

			// methods
			typedef void (I2PControlService::*MethodHandler)(const boost::property_tree::ptree& params, std::ostringstream& results);

			void AuthenticateHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void EchoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void I2PControlHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void RouterInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void RouterManagerHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void NetworkSettingHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void ClientServicesInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);

			// I2PControl
			typedef void (I2PControlService::*I2PControlRequestHandler)(const std::string& value);
			void PasswordHandler (const std::string& value);

			// RouterInfo
			typedef void (I2PControlService::*RouterInfoRequestHandler)(std::ostringstream& results);
			void UptimeHandler (std::ostringstream& results);
			void VersionHandler (std::ostringstream& results);
			void StatusHandler (std::ostringstream& results);
			void NetDbKnownPeersHandler (std::ostringstream& results);
			void NetDbActivePeersHandler (std::ostringstream& results);
			void NetStatusHandler (std::ostringstream& results);
			void TunnelsParticipatingHandler (std::ostringstream& results);
			void TunnelsSuccessRateHandler (std::ostringstream& results);
			void InboundBandwidth1S (std::ostringstream& results);
			void OutboundBandwidth1S (std::ostringstream& results);
			void NetTotalReceivedBytes (std::ostringstream& results);
			void NetTotalSentBytes (std::ostringstream& results);

			// RouterManager
			typedef void (I2PControlService::*RouterManagerRequestHandler)(std::ostringstream& results);
			void ShutdownHandler (std::ostringstream& results);
			void ShutdownGracefulHandler (std::ostringstream& results);
			void ReseedHandler (std::ostringstream& results);

			// NetworkSetting
			typedef void (I2PControlService::*NetworkSettingRequestHandler)(const std::string& value, std::ostringstream& results);
			void InboundBandwidthLimit  (const std::string& value, std::ostringstream& results);
			void OutboundBandwidthLimit (const std::string& value, std::ostringstream& results);

			// ClientServicesInfo
			typedef void (I2PControlService::*ClientServicesInfoRequestHandler)(std::ostringstream& results);
			void I2PTunnelInfoHandler (std::ostringstream& results);
			void HTTPProxyInfoHandler (std::ostringstream& results);
			void SOCKSInfoHandler (std::ostringstream& results);
			void SAMInfoHandler (std::ostringstream& results);
			void BOBInfoHandler (std::ostringstream& results);
			void I2CPInfoHandler (std::ostringstream& results);

		private:

			std::string m_Password;
			bool m_IsRunning;
			std::thread * m_Thread;

			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::ssl::context m_SSLContext;
			boost::asio::deadline_timer m_ShutdownTimer;
			std::set<std::string> m_Tokens;

			std::map<std::string, MethodHandler> m_MethodHandlers;
			std::map<std::string, I2PControlRequestHandler> m_I2PControlHandlers;
			std::map<std::string, RouterInfoRequestHandler> m_RouterInfoHandlers;
			std::map<std::string, RouterManagerRequestHandler> m_RouterManagerHandlers;
			std::map<std::string, NetworkSettingRequestHandler> m_NetworkSettingHandlers;
			std::map<std::string, ClientServicesInfoRequestHandler> m_ClientServicesInfoHandlers;
	};
}
}

#endif
