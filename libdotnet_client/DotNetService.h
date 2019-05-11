#ifndef DOTNETSERVICE_H__
#define DOTNETSERVICE_H__

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <memory>
#include <boost/asio.hpp>
#include "Destination.h"
#include "Identity.h"
#include "AddressBook.h"

namespace dotnet
{
namespace client
{
	class DotNetServiceHandler;
	class DotNetService : public std::enable_shared_from_this<DotNetService>
	{
		public:
			typedef std::function<void(const boost::system::error_code &)> ReadyCallback;

		public:
			DotNetService (std::shared_ptr<ClientDestination> localDestination  = nullptr);
			DotNetService (dotnet::data::SigningKeyType kt);
			virtual ~DotNetService ();

			inline void AddHandler (std::shared_ptr<DotNetServiceHandler> conn)
			{
				std::unique_lock<std::mutex> l(m_HandlersMutex);
				m_Handlers.insert(conn);
			}
			inline void RemoveHandler (std::shared_ptr<DotNetServiceHandler> conn)
			{
				std::unique_lock<std::mutex> l(m_HandlersMutex);
				m_Handlers.erase(conn);
			}
			void ClearHandlers ();

			void SetConnectTimeout(uint32_t timeout);

			void AddReadyCallback(ReadyCallback cb);

			inline std::shared_ptr<ClientDestination> GetLocalDestination () { return m_LocalDestination; }
			inline std::shared_ptr<const ClientDestination> GetLocalDestination () const  { return m_LocalDestination; }
			inline void SetLocalDestination (std::shared_ptr<ClientDestination> dest)
			{
				if (m_LocalDestination) m_LocalDestination->Release ();
				if (dest) dest->Acquire ();
				m_LocalDestination = dest;
			}
			void CreateStream (StreamRequestComplete streamRequestComplete, const std::string& dest, int port = 0);
			void CreateStream(StreamRequestComplete complete, std::shared_ptr<const Address> address, int port);
			inline boost::asio::io_service& GetService () { return m_LocalDestination->GetService (); }

			virtual void Start () = 0;
			virtual void Stop () = 0;

			virtual const char* GetName() { return "Generic .NET Service"; }

		private:
			void TriggerReadyCheckTimer();
			void HandleReadyCheckTimer(const boost::system::error_code & ec);

		private:
			std::shared_ptr<ClientDestination> m_LocalDestination;
			std::unordered_set<std::shared_ptr<DotNetServiceHandler> > m_Handlers;
			std::mutex m_HandlersMutex;
			std::vector<std::pair<ReadyCallback, uint32_t> > m_ReadyCallbacks;
			boost::asio::deadline_timer m_ReadyTimer;
            bool m_ReadyTimerTriggered;
			uint32_t m_ConnectTimeout;

            const size_t NEVER_TIMES_OUT = 0;
      
		public:
			bool isUpdated; // transient, used during reload only
	};

	/*Simple interface for DOTNETHandlers, allows detection of finalization amongst other things */
	class DotNetServiceHandler
	{
		public:
			DotNetServiceHandler(DotNetService * parent) : m_Service(parent), m_Dead(false) { }
			virtual ~DotNetServiceHandler() { }
			//If you override this make sure you call it from the children
			virtual void Handle() {}; //Start handling the socket

			void Terminate () { Kill (); };

		protected:
			// Call when terminating or handing over to avoid race conditions
			inline bool Kill () { return m_Dead.exchange(true); }
			// Call to know if the handler is dead
			inline bool Dead () { return m_Dead; }
			// Call when done to clean up (make sure Kill is called first)
			inline void Done (std::shared_ptr<DotNetServiceHandler> me) { if(m_Service) m_Service->RemoveHandler(me); }
			// Call to talk with the owner
			inline DotNetService * GetOwner() { return m_Service; }

		private:
			DotNetService *m_Service;
			std::atomic<bool> m_Dead; //To avoid cleaning up multiple times
	};

	const size_t TCP_IP_PIPE_BUFFER_SIZE = 8192 * 8;

	// bidirectional pipe for 2 tcp/ip sockets
	class TCPIPPipe: public DotNetServiceHandler, public std::enable_shared_from_this<TCPIPPipe>
	{
		public:
			TCPIPPipe(DotNetService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> upstream, std::shared_ptr<boost::asio::ip::tcp::socket> downstream);
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
	//This is a service that listens for connections on the IP network and interacts with DOTNET
	class TCPIPAcceptor: public DotNetService
	{
		public:
			TCPIPAcceptor (const std::string& address, int port, std::shared_ptr<ClientDestination> localDestination = nullptr) :
				DotNetService(localDestination),
				m_LocalEndpoint (boost::asio::ip::address::from_string(address), port),
				m_Timer (GetService ()) {}
			TCPIPAcceptor (const std::string& address, int port, dotnet::data::SigningKeyType kt) :
				DotNetService(kt),
				m_LocalEndpoint (boost::asio::ip::address::from_string(address), port),
				m_Timer (GetService ()) {}
			virtual ~TCPIPAcceptor () { TCPIPAcceptor::Stop(); }
			//If you override this make sure you call it from the children
			void Start ();
			//If you override this make sure you call it from the children
			void Stop ();

			const boost::asio::ip::tcp::endpoint& GetLocalEndpoint () const  { return m_LocalEndpoint; };

			virtual const char* GetName() { return "Generic TCP/IP accepting daemon"; }

		protected:
			virtual std::shared_ptr<DotNetServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket) = 0;

		private:
			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			boost::asio::ip::tcp::endpoint m_LocalEndpoint;
			std::unique_ptr<boost::asio::ip::tcp::acceptor> m_Acceptor;
			boost::asio::deadline_timer m_Timer;
	};
}
}

#endif
