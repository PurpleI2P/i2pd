#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

#include <sstream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/array.hpp>

namespace i2p
{
namespace proxy
{
	const std::string itoopieImage = "<img alt=\"\" src=\"data:image/png;base64,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\" />";

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
		  std::string host;
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

			HTTPConnection (boost::asio::ip::tcp::socket * socket): m_Socket (socket), m_Stream (nullptr) { Receive (); };
			~HTTPConnection () { delete m_Socket; }

		private:

			void Terminate ();
			void Receive ();
			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void AsyncStreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleWriteReply(const boost::system::error_code& ecode);
			void HandleWrite (const boost::system::error_code& ecode);
			void SendReply (const std::string& content);

			void HandleDestinationRequest (const std::string& address, const std::string& uri);
			void ExtractRequest (request& m_Request);
			void parseHeaders(const std::string& h, std::vector<header>& hm);
			
		private:
	
			i2p::stream::Stream * m_Stream;
			boost::asio::ip::tcp::socket * m_Socket;
			char m_Buffer[8192], m_StreamBuffer[8192];
			request m_Request;
			reply m_Reply;
	};	

	class HTTPProxy
	{
		public:

			HTTPProxy (int port);
			~HTTPProxy ();

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


