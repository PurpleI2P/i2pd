#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

#include <sstream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/array.hpp>

namespace i2p
{
namespace util
{
	class HTTPConnection
	{
		struct header
		{
		  std::string name;
		  std::string value;
		};
	
		struct request
		{
		  std::string method;
		  std::string uri;
		  int http_version_major;
		  int http_version_minor;
		  std::vector<header> headers;
		};

		struct reply
		{
			std::vector<header> headers;
			std::string content;

			std::vector<boost::asio::const_buffer> to_buffers();
		};
	
		public:

			HTTPConnection (boost::asio::ip::tcp::socket * socket): m_Socket (socket) { Receive (); };
			~HTTPConnection () { delete m_Socket; }

		private:

			void Terminate ();
			void Receive ();
			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);			
			void HandleWrite(const boost::system::error_code& ecode);

			void HandleRequest ();
			void FillContent (std::stringstream& s);

		private:
	
			boost::asio::ip::tcp::socket * m_Socket;
			boost::array<char, 8192> m_Buffer;
			request m_Request;
			reply m_Reply;
	};	

	class HTTPServer
	{
		public:

			HTTPServer (int port);
			~HTTPServer ();

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
	};		
}
}

#endif


