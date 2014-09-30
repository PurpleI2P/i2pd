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
	const size_t HTTP_CONNECTION_BUFFER_SIZE = 8192;	
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

			HTTPConnection (boost::asio::ip::tcp::socket * socket): 
				m_Socket (socket), m_Stream (nullptr), m_BufferLen (0) { Receive (); };
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

			void HandleRequest (const std::string& address);
			void HandleCommand (const std::string& command, std::stringstream& s);
			void ShowTransports (std::stringstream& s);
			void ShowTunnels (std::stringstream& s);
			void ShowTransitTunnels (std::stringstream& s);
			void ShowLocalDestinations (std::stringstream& s);
			void ShowLocalDestination (const std::string& b32, std::stringstream& s);
			void StartAcceptingTunnels (std::stringstream& s);
			void StopAcceptingTunnels (std::stringstream& s);
			void FillContent (std::stringstream& s);
			std::string ExtractAddress ();
			void ExtractParams (const std::string& str, std::map<std::string, std::string>& params);
			
			
		protected:

			boost::asio::ip::tcp::socket * m_Socket;
			i2p::stream::Stream * m_Stream;
			char m_Buffer[HTTP_CONNECTION_BUFFER_SIZE + 1], m_StreamBuffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
			size_t m_BufferLen;
			request m_Request;
			reply m_Reply;

		protected:
	
			virtual void RunRequest ();
			void HandleDestinationRequest(const std::string& address, const std::string& uri);
			void SendToAddress (const std::string& address, const char * buf, size_t len);
			void SendToDestination (const i2p::data::IdentHash& destination, const char * buf, size_t len);

		public:

			static const std::string itoopieImage;
			static const std::string itoopieFavicon;
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
}
}

#endif


