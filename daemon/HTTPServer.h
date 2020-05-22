/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <map>
#include <thread>
#include <boost/asio.hpp>
#include <sstream>
#include "HTTP.h"

namespace i2p
{
namespace http
{
	const size_t HTTP_CONNECTION_BUFFER_SIZE = 8192;
	const int TOKEN_EXPIRATION_TIMEOUT = 30; // in seconds

	class HTTPConnection: public std::enable_shared_from_this<HTTPConnection>
	{
		public:

			HTTPConnection (std::string serverhost, std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			void Receive ();

		private:

			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void Terminate     (const boost::system::error_code& ecode);

			void RunRequest ();
			bool CheckAuth     (const HTTPReq & req);
			void HandleRequest (const HTTPReq & req);
			void HandlePage    (const HTTPReq & req, HTTPRes & res, std::stringstream& data);
			void HandleCommand (const HTTPReq & req, HTTPRes & res, std::stringstream& data);
			void SendReply     (HTTPRes & res, std::string & content);
			uint32_t CreateToken ();

		private:

			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			char m_Buffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
			size_t m_BufferLen;
			std::string m_SendBuffer;
			bool needAuth;
			std::string user;
			std::string pass;
			std::string expected_host;

			static std::map<uint32_t, uint32_t> m_Tokens; // token->timestamp in seconds
	};

	class HTTPServer
	{
		public:

			HTTPServer (const std::string& address, int port);
			~HTTPServer ();

			void Start ();
			void Stop ();

		private:

			void Run ();
			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode,
				std::shared_ptr<boost::asio::ip::tcp::socket> newSocket);
			void CreateConnection(std::shared_ptr<boost::asio::ip::tcp::socket> newSocket);

		private:

			bool m_IsRunning;
			std::unique_ptr<std::thread> m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			std::string m_Hostname;
	};

	//all the below functions are also used by Qt GUI, see mainwindow.cpp -> getStatusPageHtml
	enum OutputFormatEnum { forWebConsole, forQtUi };
	void ShowStatus (std::stringstream& s, bool includeHiddenContent, OutputFormatEnum outputFormat);
	void ShowLocalDestinations (std::stringstream& s);
	void ShowLeasesSets(std::stringstream& s);
	void ShowTunnels (std::stringstream& s);
	void ShowTransitTunnels (std::stringstream& s);
	void ShowTransports (std::stringstream& s);
	void ShowSAMSessions (std::stringstream& s);
	void ShowI2PTunnels (std::stringstream& s);
	void ShowLocalDestination (std::stringstream& s, const std::string& b32, uint32_t token);
} // http
} // i2p

#endif /* HTTP_SERVER_H__ */
