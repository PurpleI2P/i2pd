#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

#include <sstream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "Streaming.h"

namespace i2p
{
namespace util
{
	class HTTPConnection
	{
		protected:

			struct header
			{
			  std::string name;
			  std::string value;
			};

			struct request
			{
			  std::string method;
			  std::string uri;
			  std::string host;
			  int http_version_major;
			  int http_version_minor;
			  std::vector<header> headers;
			};

			struct reply
			{
				std::vector<header> headers;
				std::string content;

				std::vector<boost::asio::const_buffer> to_buffers (int status);
			};

		public:

			HTTPConnection (boost::asio::ip::tcp::socket * socket): m_Socket (socket), m_Stream (nullptr) { Receive (); };
			virtual ~HTTPConnection() { delete m_Socket; }

		private:

			void Terminate ();
			void Receive ();
			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void AsyncStreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleWriteReply(const boost::system::error_code& ecode);
			void HandleWrite (const boost::system::error_code& ecode);
			void SendReply (const std::string& content, int status = 200);

			void HandleRequest ();
			void FillContent (std::stringstream& s);
			std::string ExtractAddress ();

			// for eepsite
			void EepAccept (i2p::stream::StreamingDestination * destination);
			void HandleEepAccept (i2p::stream::Stream * stream);
			
		protected:

			boost::asio::ip::tcp::socket * m_Socket;
			i2p::stream::Stream * m_Stream;
			char m_Buffer[8192], m_StreamBuffer[8192];
			request m_Request;
			reply m_Reply;

		protected:


			virtual void HandleDestinationRequest(const std::string& address, const std::string& uri);
			virtual void HandleDestinationRequest(const std::string& address, const std::string& method, const std::string& data, const std::string& uri);
			virtual void RunRequest ();

		public:

			static const std::string itoopieImage;
	};

	class HTTPServer
	{
		public:

			HTTPServer (int port);
			virtual ~HTTPServer ();

			void Start ();
			void Stop ();

		private:

			void Run ();
 			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode);
			
		private:

			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::ip::tcp::socket * m_NewSocket;

		protected:
			virtual void CreateConnection(boost::asio::ip::tcp::socket * m_NewSocket);
	};

	// TODO: move away
	class EepSiteDummyConnection
	{
		public:

			EepSiteDummyConnection (i2p::stream::Stream * stream): m_Stream (stream) {};
			void AsyncStreamReceive ();
			
		private:

			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			
		private:

			i2p::stream::Stream * m_Stream;
			char m_StreamBuffer[8192];
	};	
}
}

#endif


