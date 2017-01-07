#ifndef I2PSERVICE_H__
#define I2PSERVICE_H__

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <memory>
#include <boost/asio.hpp>
#include "Destination.h"
#include "Identity.h"

namespace i2p
{
namespace client
{
	class I2PServiceHandler;
	class I2PService
	{
		public:
			I2PService (std::shared_ptr<ClientDestination> localDestination  = nullptr);
			I2PService (i2p::data::SigningKeyType kt);
			virtual ~I2PService () { ClearHandlers (); }

			inline void AddHandler (std::shared_ptr<I2PServiceHandler> conn)
			{
				std::unique_lock<std::mutex> l(m_HandlersMutex);
				m_Handlers.insert(conn);
			}
			inline void RemoveHandler (std::shared_ptr<I2PServiceHandler> conn)
			{
				std::unique_lock<std::mutex> l(m_HandlersMutex);
				m_Handlers.erase(conn);
			}
			inline void ClearHandlers ()
			{
				std::unique_lock<std::mutex> l(m_HandlersMutex);
				m_Handlers.clear();
			}

			inline std::shared_ptr<ClientDestination> GetLocalDestination () { return m_LocalDestination; }
			inline std::shared_ptr<const ClientDestination> GetLocalDestination () const  { return m_LocalDestination; }
			inline void SetLocalDestination (std::shared_ptr<ClientDestination> dest) { m_LocalDestination = dest; }
			void CreateStream (StreamRequestComplete streamRequestComplete, const std::string& dest, int port = 0);

			inline boost::asio::io_service& GetService () { return m_LocalDestination->GetService (); }

			virtual void Start () = 0;
			virtual void Stop () = 0;

			virtual const char* GetName() { return "Generic I2P Service"; }
		private:

			std::shared_ptr<ClientDestination> m_LocalDestination;
			std::unordered_set<std::shared_ptr<I2PServiceHandler> > m_Handlers;
			std::mutex m_HandlersMutex;
	};

	/*Simple interface for I2PHandlers, allows detection of finalization amongst other things */
	class I2PServiceHandler
	{
		public:
			I2PServiceHandler(I2PService * parent) : m_Service(parent), m_Dead(false) { }
			virtual ~I2PServiceHandler() { }
			//If you override this make sure you call it from the children
			virtual void Handle() {}; //Start handling the socket
		protected:
			// Call when terminating or handing over to avoid race conditions
			inline bool Kill () { return m_Dead.exchange(true); }
			// Call to know if the handler is dead
			inline bool Dead () { return m_Dead; }
			// Call when done to clean up (make sure Kill is called first)
			inline void Done (std::shared_ptr<I2PServiceHandler> me) { if(m_Service) m_Service->RemoveHandler(me); }
			// Call to talk with the owner
			inline I2PService * GetOwner() { return m_Service; }
		private:
			I2PService *m_Service;
			std::atomic<bool> m_Dead; //To avoid cleaning up multiple times
	};

	const size_t TCP_IP_PIPE_BUFFER_SIZE = 8192 * 8;

	// bidirectional pipe for 2 tcp/ip sockets
	class TCPIPPipe: public I2PServiceHandler, public std::enable_shared_from_this<TCPIPPipe> {
	public:
		TCPIPPipe(I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> upstream, std::shared_ptr<boost::asio::ip::tcp::socket> downstream);
		~TCPIPPipe();
		void Start();
	protected:
		void Terminate();
		void AsyncReceiveUpstream();
		void AsyncReceiveDownstream();
		void HandleUpstreamReceived(const boost::system::error_code & ecode, std::size_t bytes_transferred);
		void HandleDownstreamReceived(const boost::system::error_code & ecode, std::size_t bytes_transferred);
		void HandleUpstreamWrite(const boost::system::error_code & ecode);
		void HandleDownstreamWrite(const boost::system::error_code & ecode);
		void UpstreamWrite(size_t len);
		void DownstreamWrite(size_t len);
	private:
		uint8_t m_upstream_to_down_buf[TCP_IP_PIPE_BUFFER_SIZE], m_downstream_to_up_buf[TCP_IP_PIPE_BUFFER_SIZE];
		uint8_t m_upstream_buf[TCP_IP_PIPE_BUFFER_SIZE], m_downstream_buf[TCP_IP_PIPE_BUFFER_SIZE];
		std::shared_ptr<boost::asio::ip::tcp::socket> m_up, m_down;
	};
	
	/* TODO: support IPv6 too */
	//This is a service that listens for connections on the IP network and interacts with I2P
	class TCPIPAcceptor: public I2PService
	{
		public:
			TCPIPAcceptor (const std::string& address, int port, std::shared_ptr<ClientDestination> localDestination = nullptr) :
				I2PService(localDestination),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::address::from_string(address), port)),
				m_Timer (GetService ()) {}
			TCPIPAcceptor (const std::string& address, int port, i2p::data::SigningKeyType kt) :
				I2PService(kt),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::address::from_string(address), port)),
				m_Timer (GetService ()) {}
			virtual ~TCPIPAcceptor () { TCPIPAcceptor::Stop(); }
			//If you override this make sure you call it from the children
			void Start ();
			//If you override this make sure you call it from the children
			void Stop ();

			const boost::asio::ip::tcp::acceptor& GetAcceptor () const { return m_Acceptor; };

    virtual const char* GetName() { return "Generic TCP/IP accepting daemon"; }

		protected:
			virtual std::shared_ptr<I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket) = 0;
		private:
			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
	};
}
}

#endif
