/*
* Copyright (c) 2013-2022, The PurpleI2P Project
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
#include "I2PControlHandlers.h"

namespace i2p
{
namespace client
{
	const size_t I2P_CONTROL_MAX_REQUEST_SIZE = 1024;
	typedef std::array<char, I2P_CONTROL_MAX_REQUEST_SIZE> I2PControlBuffer;

	const long I2P_CONTROL_CERTIFICATE_VALIDITY = 365*10; // 10 years
	const char I2P_CONTROL_CERTIFICATE_COMMON_NAME[] = "i2pd.i2pcontrol";
	const char I2P_CONTROL_CERTIFICATE_ORGANIZATION[] = "Purple I2P";

	class I2PControlService: public I2PControlHandlers
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

			// methods
			typedef void (I2PControlService::*MethodHandler)(const boost::property_tree::ptree& params, std::ostringstream& results);

			void AuthenticateHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void EchoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void I2PControlHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void RouterManagerHandler (const boost::property_tree::ptree& params, std::ostringstream& results);

			// I2PControl
			typedef void (I2PControlService::*I2PControlRequestHandler)(const std::string& value);
			void PasswordHandler (const std::string& value);

			// RouterManager
			typedef void (I2PControlService::*RouterManagerRequestHandler)(std::ostringstream& results);
			void ShutdownHandler (std::ostringstream& results);
			void ShutdownGracefulHandler (std::ostringstream& results);
			void ReseedHandler (std::ostringstream& results);

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
			std::map<std::string, RouterManagerRequestHandler> m_RouterManagerHandlers;
	};
}
}

#endif
