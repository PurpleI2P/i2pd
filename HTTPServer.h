#ifndef HTTP_SERVER_H__
#define HTTP_SERVER_H__

namespace i2p {
namespace http {
	extern const char *itoopieImage;
	extern const char *itoopieFavicon;
	const size_t HTTP_CONNECTION_BUFFER_SIZE = 8192;	
	const int HTTP_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds

	class HTTPConnection: public std::enable_shared_from_this<HTTPConnection>
	{
		public:

			HTTPConnection (std::shared_ptr<boost::asio::ip::tcp::socket> socket): 
				m_Socket (socket), m_Timer (socket->get_io_service ()), 
				m_Stream (nullptr), m_BufferLen (0) {};
			void Receive ();
			
		private:

			void Terminate ();
			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void AsyncStreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleWriteReply(const boost::system::error_code& ecode);
			void HandleWrite (const boost::system::error_code& ecode);
			void SendReply (const std::string& content, int status = 200);
			void SendError (const std::string& message);

			void HandleRequest (const std::string& address);
			void HandleCommand (const std::string& command, std::stringstream& s);
			void ShowJumpServices (const std::string& address, std::stringstream& s);
			void ShowTransports (std::stringstream& s);
			void ShowTunnels (std::stringstream& s);
			void ShowTransitTunnels (std::stringstream& s);
			void ShowLocalDestinations (std::stringstream& s);
			void ShowLocalDestination (const std::string& b32, std::stringstream& s);
			void ShowSAMSessions (std::stringstream& s);
			void ShowSAMSession (const std::string& id, std::stringstream& s);
			void ShowI2PTunnels (std::stringstream& s);
			void StartAcceptingTunnels (std::stringstream& s);
			void StopAcceptingTunnels (std::stringstream& s);
			void RunPeerTest (std::stringstream& s);
			void FillContent (std::stringstream& s);
			std::string ExtractAddress ();
			void ExtractParams (const std::string& str, std::map<std::string, std::string>& params);
			
		protected:

			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			boost::asio::deadline_timer m_Timer;
			std::shared_ptr<i2p::stream::Stream> m_Stream;
			char m_Buffer[HTTP_CONNECTION_BUFFER_SIZE + 1], m_StreamBuffer[HTTP_CONNECTION_BUFFER_SIZE + 1];
			size_t m_BufferLen;

		protected:
	
			virtual void RunRequest ();
			void HandleDestinationRequest(const std::string& address, const std::string& uri);
			void SendToAddress (const std::string& address, int port, const char * buf, size_t len);
			void HandleDestinationRequestTimeout (const boost::system::error_code& ecode, 
				i2p::data::IdentHash destination, int port, const char * buf, size_t len);
			void SendToDestination (std::shared_ptr<const i2p::data::LeaseSet> remote, int port, const char * buf, size_t len);

		public:

	};

	class HTTPServer
	{
		public:

			HTTPServer (const std::string& address, int port);
			virtual ~HTTPServer ();

			void Start ();
			void Stop ();

		private:

			void Run ();
 			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode,
				std::shared_ptr<boost::asio::ip::tcp::socket> newSocket);
			
		private:

			std::unique_ptr<std::thread> m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::tcp::acceptor m_Acceptor;

		protected:
			virtual void CreateConnection(std::shared_ptr<boost::asio::ip::tcp::socket> newSocket);
	};
} // http
} // i2p

#endif /* HTTP_SERVER_H__ */
