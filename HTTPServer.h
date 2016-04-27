#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

namespace i2p {
namespace http {
	extern const char *itoopieImage;
	extern const char *itoopieFavicon;
	const size_t HTTP_CONNECTION_BUFFER_SIZE = 8192;	

	class HTTPConnection: public std::enable_shared_from_this<HTTPConnection>
	{
		public:

			HTTPConnection (std::shared_ptr<boost::asio::ip::tcp::socket> socket): 
				m_Socket (socket), m_Timer (socket->get_io_service ()), 
				m_BufferLen (0) {};
			void Receive ();
			
		private:

			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void Terminate     (const boost::system::error_code& ecode);

			void SendReply (const std::string& content, int code = 200);
			void SendError (const std::string& message);

			void RunRequest ();
			void HandleRequest (const std::string& uri);
			void HandlePage    (std::stringstream& s, const std::string& request);
			void HandleCommand (std::stringstream& s, const std::string& request);

			/* pages */
			void ShowJumpServices      (std::stringstream& s, const std::string& address);
			void ShowTransports        (std::stringstream& s);
			void ShowTunnels           (std::stringstream& s);
			void ShowStatus            (std::stringstream& s);
			void ShowTransitTunnels    (std::stringstream& s);
			void ShowLocalDestinations (std::stringstream& s);
			void ShowLocalDestination  (std::stringstream& s, const std::string& b32);
			void ShowSAMSessions       (std::stringstream& s);
			void ShowSAMSession        (std::stringstream& s, const std::string& id);
			void ShowI2PTunnels        (std::stringstream& s);
			/* commands */
			void StartAcceptingTunnels (std::stringstream& s);
			void StopAcceptingTunnels  (std::stringstream& s);
			void RunPeerTest           (std::stringstream& s);

		private:

			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			boost::asio::deadline_timer m_Timer;
			char m_Buffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
			size_t m_BufferLen;
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

			std::unique_ptr<std::thread> m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::tcp::acceptor m_Acceptor;
	};
} // http
} // i2p

#endif /* HTTP_SERVER_H__ */
