#ifndef SOCKS4A_H__
#define SOCKS4A_H__

#include <memory>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Streaming.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace proxy
{

	const size_t socks_buffer_size = 8192;

	class SOCKS4AServer;
	class SOCKS4AHandler {

		private:
            enum state {
                    INITIAL,
                    OKAY,
                    END
            };

            void GotClientRequest(boost::system::error_code & ecode, std::string & host, uint16_t port);
            void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
            void Terminate();
            void CloseSock();
            void CloseStream();
            void AsyncSockRead();
            void SocksFailed();
            void SentSocksFailed(const boost::system::error_code & ecode);
            void SentConnectionSuccess(const boost::system::error_code & ecode);
            void ConnectionSuccess();
            void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
            
            uint8_t m_sock_buff[socks_buffer_size];
            
	    SOCKS4AServer * m_parent;
            boost::asio::ip::tcp::socket * m_sock;
            std::shared_ptr<i2p::stream::Stream> m_stream;
            state m_state;
		
            
		public:
			SOCKS4AHandler(SOCKS4AServer * parent, boost::asio::ip::tcp::socket * sock) : 
				m_parent(parent), m_sock(sock), m_stream(nullptr), m_state(INITIAL)
				{ AsyncSockRead(); }

			~SOCKS4AHandler() { CloseSock(); CloseStream(); }
			bool isComplete() { return m_state == END; }
	};

	class SOCKS4AServer: public i2p::client::I2PTunnel
	{
		public:
			SOCKS4AServer(int port) : I2PTunnel(nullptr),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
				m_Timer (GetService ()) {};
			~SOCKS4AServer() { Stop(); }

			void Start ();
			void Stop ();

		private:

			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);

		private:

			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
	};	

	typedef SOCKS4AServer SOCKSProxy;
}
}


#endif
