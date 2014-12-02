#ifndef BOB_H__
#define BOB_H__

#include <inttypes.h>
#include <thread>
#include <memory>
#include <map>
#include <string>
#include <boost/asio.hpp>
#include "I2PTunnel.h"

namespace i2p
{
namespace client
{
	const size_t BOB_COMMAND_BUFFER_SIZE = 1024;
	const char BOB_COMMAND_ZAP[] = "zap";
	const char BOB_COMMAND_QUIT[] = "quit";		

	const char BOB_REPLY_OK[] = "OK %s\n";
	const char BOB_REPLY_ERROR[] = "ERROR %s\n";

	class BOBCommandChannel;
	class BOBCommandSession: public std::enable_shared_from_this<BOBCommandSession>
	{
		public:

			BOBCommandSession (BOBCommandChannel& owner);
			~BOBCommandSession ();	
			void Terminate ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			void Receive ();

			// command handlers
			void ZapCommandHandler (const char * operand, size_t len);
			void QuitCommandHandler (const char * operand, size_t len);

		private:

			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			void Send (size_t len);
			void HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void SendReplyOK (const char * msg);
			void SendReplyError (const char * msg);

		private:

			BOBCommandChannel& m_Owner;
			boost::asio::ip::tcp::socket m_Socket;
			char m_ReceiveBuffer[BOB_COMMAND_BUFFER_SIZE + 1], m_SendBuffer[BOB_COMMAND_BUFFER_SIZE + 1];
			size_t m_ReceiveBufferOffset;
			bool m_IsOpen;
	};
	typedef void (BOBCommandSession::*BOBCommandHandler)(const char * operand, size_t len);

	class BOBCommandChannel
	{
		public:

			BOBCommandChannel (int port);
			~BOBCommandChannel ();

			void Start ();
			void Stop ();

			boost::asio::io_service& GetService () { return m_Service; };
			std::map<std::string, BOBCommandHandler>& GetCommandHandlers () { return m_CommandHandlers; };

		private:

			void Run ();
			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<BOBCommandSession> session);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			std::map<std::string, I2PTunnel *> m_Tunnels;
			std::map<std::string, BOBCommandHandler> m_CommandHandlers;
	};	
}
}

#endif

