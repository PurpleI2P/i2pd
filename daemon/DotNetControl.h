#ifndef DOTNET_CONTROL_H__
#define DOTNET_CONTROL_H__

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

namespace dotnet
{
namespace client
{
	const size_t DOTNET_CONTROL_MAX_REQUEST_SIZE = 1024;
	typedef std::array<char, DOTNET_CONTROL_MAX_REQUEST_SIZE> DotNetControlBuffer;

	const long DOTNET_CONTROL_CERTIFICATE_VALIDITY = 365*10; // 10 years
	const char DOTNET_CONTROL_CERTIFICATE_COMMON_NAME[] = "dotnet.dotnetcontrol";
	const char DOTNET_CONTROL_CERTIFICATE_ORGANIZATION[] = "Purple DOTNET";

	class DotNetControlService
	{
		typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;
		public:

			DotNetControlService (const std::string& address, int port);
			~DotNetControlService ();

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
				std::shared_ptr<ssl_socket> socket, std::shared_ptr<DotNetControlBuffer> buf);
			void SendResponse (std::shared_ptr<ssl_socket> socket,
				std::shared_ptr<DotNetControlBuffer> buf, std::ostringstream& response, bool isHtml);
			void HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
				std::shared_ptr<ssl_socket> socket, std::shared_ptr<DotNetControlBuffer> buf);

			void CreateCertificate (const char *crt_path, const char *key_path);

		private:

			void InsertParam (std::ostringstream& ss, const std::string& name, int value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, double value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, const std::string& value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const;

			// methods
			typedef void (DotNetControlService::*MethodHandler)(const boost::property_tree::ptree& params, std::ostringstream& results);

			void AuthenticateHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void EchoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void DotNetControlHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void RouterInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void RouterManagerHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void NetworkSettingHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void ClientServicesInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);

			// DotNetControl
			typedef void (DotNetControlService::*DotNetControlRequestHandler)(const std::string& value);
			void PasswordHandler (const std::string& value);

			// RouterInfo
			typedef void (DotNetControlService::*RouterInfoRequestHandler)(std::ostringstream& results);
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
			typedef void (DotNetControlService::*RouterManagerRequestHandler)(std::ostringstream& results);
			void ShutdownHandler (std::ostringstream& results);
			void ShutdownGracefulHandler (std::ostringstream& results);
			void ReseedHandler (std::ostringstream& results);

			// NetworkSetting
			typedef void (DotNetControlService::*NetworkSettingRequestHandler)(const std::string& value, std::ostringstream& results);
			void InboundBandwidthLimit  (const std::string& value, std::ostringstream& results);
			void OutboundBandwidthLimit (const std::string& value, std::ostringstream& results);

			// ClientServicesInfo
			typedef void (DotNetControlService::*ClientServicesInfoRequestHandler)(std::ostringstream& results);
			void DotNetTunnelInfoHandler (std::ostringstream& results);
			void HTTPProxyInfoHandler (std::ostringstream& results);
			void SOCKSInfoHandler (std::ostringstream& results);
			void SAMInfoHandler (std::ostringstream& results);
			void BOBInfoHandler (std::ostringstream& results);
			void DNCPInfoHandler (std::ostringstream& results);

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
			std::map<std::string, DotNetControlRequestHandler> m_DotNetControlHandlers;
			std::map<std::string, RouterInfoRequestHandler> m_RouterInfoHandlers;
			std::map<std::string, RouterManagerRequestHandler> m_RouterManagerHandlers;
			std::map<std::string, NetworkSettingRequestHandler> m_NetworkSettingHandlers;
			std::map<std::string, ClientServicesInfoRequestHandler> m_ClientServicesInfoHandlers;
	};
}
}

#endif
