#ifndef I2P_CONTROL_H__
#define I2P_CONTROL_H__

#include <inttypes.h>
#include <thread>
#include <memory>
#include <array>
#include <string>
#include <map>
#include <set>
#include <boost/asio.hpp>

namespace i2p
{
namespace client
{
	const size_t I2P_CONTROL_MAX_REQUEST_SIZE = 1024;
	typedef std::array<char, I2P_CONTROL_MAX_REQUEST_SIZE> I2PControlBuffer;		

	const char I2P_CONTROL_DEFAULT_PASSWORD[] = "itoopie";	

	const char I2P_CONTROL_PROPERTY_ID[] = "id";
	const char I2P_CONTROL_PROPERTY_METHOD[] = "method";
	const char I2P_CONTROL_PROPERTY_PARAMS[] = "params";
	const char I2P_CONTROL_PROPERTY_RESULT[] = "result";

	// methods	
	const char I2P_CONTROL_METHOD_AUTHENTICATE[] = "Authenticate";
	const char I2P_CONTROL_METHOD_ECHO[] = "Echo";
	const char I2P_CONTROL_METHOD_I2PCONTROL[] = "I2PControl";		
	const char I2P_CONTROL_METHOD_ROUTER_INFO[] = "RouterInfo";	
	const char I2P_CONTROL_METHOD_ROUTER_MANAGER[] = "RouterManager";	
	const char I2P_CONTROL_METHOD_NETWORK_SETTING[] = "NetworkSetting";	

	// params
	const char I2P_CONTROL_PARAM_API[] = "API";			
	const char I2P_CONTROL_PARAM_PASSWORD[] = "Password";	
	const char I2P_CONTROL_PARAM_TOKEN[] = "Token";	
	const char I2P_CONTROL_PARAM_ECHO[] = "Echo";	
	const char I2P_CONTROL_PARAM_RESULT[] = "Result";	

	// I2PControl
	const char I2P_CONTROL_I2PCONTROL_ADDRESS[] = "i2pcontrol.address";		
	const char I2P_CONTROL_I2PCONTROL_PASSWORD[] = "i2pcontrol.password";
	const char I2P_CONTROL_I2PCONTROL_PORT[] = "i2pcontrol.port";		

	// RouterInfo requests
	const char I2P_CONTROL_ROUTER_INFO_UPTIME[] = "i2p.router.uptime";
	const char I2P_CONTROL_ROUTER_INFO_NETDB_KNOWNPEERS[] = "i2p.router.netdb.knownpeers";
	const char I2P_CONTROL_ROUTER_INFO_NETDB_ACTIVEPEERS[] = "i2p.router.netdb.activepeers";
	const char I2P_CONTROL_ROUTER_INFO_STATUS[] = "i2p.router.net.status";	
	const char I2P_CONTROL_ROUTER_INFO_TUNNELS_PARTICIPATING[] = "i2p.router.net.tunnels.participating";	
		
	// RouterManager requests
	const char I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN[] = "Shutdown";
	const char I2P_CONTROL_ROUTER_MANAGER_SHUTDOWN_GRACEFUL[] = "ShutdownGraceful";
	const char I2P_CONTROL_ROUTER_MANAGER_RESEED[] = "Reseed";		

	class I2PControlService
	{
		public:

			I2PControlService (int port);
			~I2PControlService ();

			void Start ();
			void Stop ();

		private:

			void Run ();
			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);	
			void ReadRequest (std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			void HandleRequestReceived (const boost::system::error_code& ecode, size_t bytes_transferred, 
				std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf);
			void SendResponse (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<I2PControlBuffer> buf, const std::string& id, 
				const std::map<std::string, std::string>& results, bool isHtml);
			void HandleResponseSent (const boost::system::error_code& ecode, std::size_t bytes_transferred,
				std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<I2PControlBuffer> buf);

		private:

			// methods
			typedef void (I2PControlService::*MethodHandler)(const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);

			void AuthenticateHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void EchoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void I2PControlHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void RouterInfoHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void RouterManagerHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);
			void NetworkSettingHandler (const std::map<std::string, std::string>& params, std::map<std::string, std::string>& results);			

			// I2PControl
			typedef void (I2PControlService::*I2PControlRequestHandler)(const std::string& value);

			// RouterInfo
			typedef void (I2PControlService::*RouterInfoRequestHandler)(std::map<std::string, std::string>& results);
			void UptimeHandler (std::map<std::string, std::string>& results);
			void NetDbKnownPeersHandler (std::map<std::string, std::string>& results);
			void NetDbActivePeersHandler (std::map<std::string, std::string>& results);	
			void StatusHandler (std::map<std::string, std::string>& results);		
			void TunnelsParticipatingHandler (std::map<std::string, std::string>& results);

			// RouterManager
			typedef void (I2PControlService::*RouterManagerRequestHandler)(std::map<std::string, std::string>& results);
			void ShutdownHandler (std::map<std::string, std::string>& results);
			void ShutdownGracefulHandler (std::map<std::string, std::string>& results);
			void ReseedHandler (std::map<std::string, std::string>& results);

			// NetworkSetting
			typedef void (I2PControlService::*NetworkSettingRequestHandler)(const std::string& value, std::map<std::string, std::string>& results);	

		private:

			std::string m_Password;
			bool m_IsRunning;
			std::thread * m_Thread;	

			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_ShutdownTimer;
			std::set<std::string> m_Tokens;
			
			std::map<std::string, MethodHandler> m_MethodHandlers;
			std::map<std::string, I2PControlRequestHandler> m_I2PControlHandlers;
			std::map<std::string, RouterInfoRequestHandler> m_RouterInfoHandlers;
			std::map<std::string, RouterManagerRequestHandler> m_RouterManagerHandlers;
			std::map<std::string, NetworkSettingRequestHandler> m_NetworkSettingHandlers;
	};
}
}

#endif

