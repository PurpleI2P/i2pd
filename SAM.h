#ifndef SAM_H__
#define SAM_H__

#include <inttypes.h>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	const size_t SAM_SOCKET_BUFFER_SIZE = 4096;
	const int SAM_SOCKET_CONNECTION_MAX_IDLE = 3600; // in seconds	
	const char SAM_HANDSHAKE[] = "HELLO VERSION";
	const char SAM_HANDSHAKE_REPLY[] = "HELLO REPLY RESULT=OK VERSION=3.1";

	class SAMBridge;
	class SAMSocket
	{
		public:

			SAMSocket (SAMBridge& owner);
			~SAMSocket ();			

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			void ReceiveHandshake ();

		private:

			void Terminate ();
			void HandleHandshakeReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleHandshakeReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			void StreamReceive ();	
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleWriteStreamData (const boost::system::error_code& ecode);

		private:

			SAMBridge& m_Owner;
			boost::asio::ip::tcp::socket m_Socket;
			char m_Buffer[SAM_SOCKET_BUFFER_SIZE + 1];
			uint8_t m_StreamBuffer[SAM_SOCKET_BUFFER_SIZE];
			Stream * m_Stream;
	};	

	class SAMBridge
	{
		public:

			SAMBridge (int port);
			~SAMBridge ();

			void Start ();
			void Stop ();
			
			boost::asio::io_service& GetService () { return m_Service; };

		private:

			void Run ();

			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			SAMSocket * m_NewSocket;
	};		
}
}

#endif

