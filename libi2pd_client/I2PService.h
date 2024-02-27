/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2PSERVICE_H__
#define I2PSERVICE_H__

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <memory>
#include <boost/asio.hpp>
#include "Destination.h"
#include "Identity.h"
#include "AddressBook.h"

namespace i2p
{
namespace client
{
	class I2PServiceHandler;
	class I2PService : public std::enable_shared_from_this<I2PService>
	{
		public:

			typedef std::function<void(const boost::system::error_code &)> ReadyCallback;

		public:

			I2PService (std::shared_ptr<ClientDestination> localDestination = nullptr);
			I2PService (i2p::data::SigningKeyType kt);
			virtual ~I2PService ();

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
			void ClearHandlers ();

			void SetConnectTimeout(uint32_t timeout);

			void AddReadyCallback(ReadyCallback cb);

			inline std::shared_ptr<ClientDestination> GetLocalDestination () { return m_LocalDestination; }
			inline std::shared_ptr<const ClientDestination> GetLocalDestination () const { return m_LocalDestination; }
			inline void SetLocalDestination (std::shared_ptr<ClientDestination> dest)
			{
				if (m_LocalDestination) m_LocalDestination->Release ();
				if (dest) dest->Acquire ();
				m_LocalDestination = dest;
			}
			void CreateStream (StreamRequestComplete streamRequestComplete, const std::string& dest, uint16_t port = 0);
			void CreateStream(StreamRequestComplete complete, std::shared_ptr<const Address> address, uint16_t port);
			inline boost::asio::io_service& GetService () { return m_LocalDestination->GetService (); }

			virtual void Start () = 0;
			virtual void Stop () = 0;

			virtual const char* GetName() { return "Generic I2P Service"; }

		private:

			void TriggerReadyCheckTimer();
			void HandleReadyCheckTimer(const boost::system::error_code & ec);

		private:

			std::shared_ptr<ClientDestination> m_LocalDestination;
			std::unordered_set<std::shared_ptr<I2PServiceHandler> > m_Handlers;
			std::mutex m_HandlersMutex;
			std::vector<std::pair<ReadyCallback, uint32_t> > m_ReadyCallbacks;
			boost::asio::deadline_timer m_ReadyTimer;
			bool m_ReadyTimerTriggered;
			uint32_t m_ConnectTimeout;

			const size_t NEVER_TIMES_OUT = 0;

		public:

			bool isUpdated; // transient, used during reload only
	};

	/*Simple interface for I2PHandlers, allows detection of finalization amongst other things */
	class I2PServiceHandler
	{
		public:

			I2PServiceHandler(I2PService * parent) : m_Service(parent), m_Dead(false) { }
			virtual ~I2PServiceHandler() { }
			//If you override this make sure you call it from the children
			virtual void Handle() {}; //Start handling the socket
			virtual void Start () {}; 

			void Terminate () { Kill (); };

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

	const size_t SOCKETS_PIPE_BUFFER_SIZE = 8192 * 8;

	// bidirectional pipe for 2 stream sockets
	template<typename SocketUpstream, typename SocketDownstream>
	class SocketsPipe: public I2PServiceHandler, 
		public std::enable_shared_from_this<SocketsPipe<SocketUpstream, SocketDownstream> >
	{
		public:

			SocketsPipe(I2PService * owner, std::shared_ptr<SocketUpstream> upstream, std::shared_ptr<SocketDownstream> downstream):
				I2PServiceHandler(owner), m_up(upstream), m_down(downstream)
			{
				boost::asio::socket_base::receive_buffer_size option(SOCKETS_PIPE_BUFFER_SIZE);
				upstream->set_option(option);
				downstream->set_option(option);
			}	
			~SocketsPipe() { Terminate(); }
			
			void Start() override
			{
				Transfer (m_up, m_down, m_upstream_to_down_buf, SOCKETS_PIPE_BUFFER_SIZE); // receive from upstream
				Transfer (m_down, m_up, m_downstream_to_up_buf, SOCKETS_PIPE_BUFFER_SIZE); // receive from upstream
			}	

		private:

			void Terminate()
			{
				if(Kill()) return;
				if (m_up)
				{
					if (m_up->is_open())
						m_up->close();
					m_up = nullptr;
				}
				if (m_down)
				{
					if (m_down->is_open())
						m_down->close();
					m_down = nullptr;
				}
				Done(SocketsPipe<SocketUpstream, SocketDownstream>::shared_from_this());
			}
			
			template<typename From, typename To>
			void Transfer (std::shared_ptr<From> from, std::shared_ptr<To> to, uint8_t * buf, size_t len)
			{
				if (!from || !to || !buf) return;
				auto s = SocketsPipe<SocketUpstream, SocketDownstream>::shared_from_this ();
				from->async_read_some(boost::asio::buffer(buf, len),
					[from, to, s, buf, len](const boost::system::error_code& ecode, std::size_t transferred)
				    {
						if (ecode == boost::asio::error::operation_aborted) return;
						if (!ecode)
						{
							boost::asio::async_write(*to, boost::asio::buffer(buf, transferred), boost::asio::transfer_all(),
								[from, to, s, buf, len](const boost::system::error_code& ecode, std::size_t transferred)
				    			{
									(void) transferred;
									if (ecode == boost::asio::error::operation_aborted) return;
									if (!ecode)
										s->Transfer (from, to, buf, len);
									else
									{
										LogPrint(eLogWarning, "SocketsPipe: Write error:" , ecode.message());
										s->Terminate();
									}	
								});	
						}	
						else
						{
							LogPrint(eLogWarning, "SocketsPipe: Read error:" , ecode.message());
							s->Terminate();
						}	
					});	
			}
			
		private:

			uint8_t m_upstream_to_down_buf[SOCKETS_PIPE_BUFFER_SIZE], m_downstream_to_up_buf[SOCKETS_PIPE_BUFFER_SIZE];			
			std::shared_ptr<SocketUpstream> m_up;
			std::shared_ptr<SocketDownstream> m_down;
	};

	template<typename SocketUpstream, typename SocketDownstream>
	std::shared_ptr<I2PServiceHandler> CreateSocketsPipe (I2PService * owner, std::shared_ptr<SocketUpstream> upstream, std::shared_ptr<SocketDownstream> downstream)
	{
		return std::make_shared<SocketsPipe<SocketUpstream, SocketDownstream> >(owner, upstream, downstream);
	}	
	
	//This is a service that listens for connections on the IP network or local socket and interacts with I2P
	template<typename Protocol>
	class ServiceAcceptor: public I2PService
	{
		public:

			ServiceAcceptor (const typename Protocol::endpoint& localEndpoint, std::shared_ptr<ClientDestination> localDestination = nullptr) :
				I2PService(localDestination), m_LocalEndpoint (localEndpoint) {}
			
			virtual ~ServiceAcceptor () { Stop(); }
			void Start () override
			{
				m_Acceptor.reset (new typename Protocol::acceptor (GetService (), m_LocalEndpoint));
				// update the local end point in case port has been set zero and got updated now
				m_LocalEndpoint = m_Acceptor->local_endpoint();
				m_Acceptor->listen ();
				Accept ();
			}	
			void Stop () override
			{	
				if (m_Acceptor)
				{
					m_Acceptor->close();
					m_Acceptor.reset (nullptr);
				}
				ClearHandlers();
			}
			const typename Protocol::endpoint& GetLocalEndpoint () const { return m_LocalEndpoint; };

			const char* GetName() override { return "Generic TCP/IP accepting daemon"; }

		protected:

			virtual std::shared_ptr<I2PServiceHandler> CreateHandler(std::shared_ptr<typename Protocol::socket> socket) = 0;

		private:

			void Accept()
			{
				auto newSocket = std::make_shared<typename Protocol::socket> (GetService ());
				m_Acceptor->async_accept (*newSocket,
					[newSocket, this](const boost::system::error_code& ecode)
				    {
						if (ecode == boost::asio::error::operation_aborted) return;
						if (!ecode)
						{
							LogPrint(eLogDebug, "ServiceAcceptor: ", GetName(), " accepted");
							auto handler = CreateHandler(newSocket);
							if (handler)
							{
								AddHandler(handler);
								handler->Handle();
							}
							else
								newSocket->close();
							Accept();
						}	
						else
							LogPrint (eLogError, "ServiceAcceptor: ", GetName(), " closing socket on accept because: ", ecode.message ());
					});	
			}	
			
		private:
			
			typename Protocol::endpoint m_LocalEndpoint;
			std::unique_ptr<typename Protocol::acceptor> m_Acceptor;
	};

	class TCPIPAcceptor: public ServiceAcceptor<boost::asio::ip::tcp>
	{
		public:

			TCPIPAcceptor (const std::string& address, uint16_t port, std::shared_ptr<ClientDestination> localDestination = nullptr) :
				ServiceAcceptor (boost::asio::ip::tcp::endpoint (boost::asio::ip::address::from_string(address), port), localDestination) {}
	};	
}
}

#endif
