#ifndef SOCKS4A_H__
#define SOCKS4A_H__

#include <thread>
#include <boost/asio.hpp>
#include <vector>
#include <mutex>

#include "Identity.h"
#include "Streaming.h"

namespace i2p
{
namespace proxy
{

	constexpr size_t socks_buffer_size = 8192;

	class SOCKS4AHandler {

		private:
            enum state {
                    INITIAL,
                    OKAY,
                    END
            };

            void GotClientRequest(boost::system::error_code & ecode, std::string & host, uint16_t port);
            void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
            void HandleSockForward(const boost::system::error_code & ecode, std::size_t bytes_transfered);
            void HandleStreamRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
            void Terminate();
            void CloseSock();
            void CloseStream();
            void AsyncSockRead();
            void AsyncStreamRead();
            void SocksFailed();
            void LeaseSetTimeout(const boost::system::error_code & ecode);
            void StreamWrote(const boost::system::error_code & ecode);		  
            void SockWrote(const boost::system::error_code & ecode);
            void SentConnectionSuccess(const boost::system::error_code & ecode);
            void ConnectionSuccess();
            
            uint8_t m_sock_buff[socks_buffer_size];
            uint8_t m_stream_buff[socks_buffer_size];
            
            boost::asio::io_service * m_ios;
            boost::asio::ip::tcp::socket * m_sock;
            boost::asio::deadline_timer m_ls_timer;
            i2p::stream::Stream * m_stream;
            i2p::data::LeaseSet * m_ls;
            i2p::data::IdentHash m_dest;
            state m_state;
		
            
		public:
			SOCKS4AHandler(boost::asio::io_service * ios, boost::asio::ip::tcp::socket * sock) : 
				m_ios(ios), m_sock(sock), m_ls_timer(*ios),
				m_stream(nullptr), m_ls(nullptr), m_state(INITIAL) { AsyncSockRead(); }

			~SOCKS4AHandler() { CloseSock(); CloseStream(); }
			bool isComplete() { return m_state == END; }
	};

	class SOCKS4AServer {
		public:
			SOCKS4AServer(int port) : m_run(false), 
									  m_thread(nullptr), 
									  m_work(m_ios),
									  m_acceptor(m_ios, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
									  m_new_sock(nullptr) { }
			~SOCKS4AServer() { Stop(); }
			void Start();
			void Stop();
		
			boost::asio::io_service& GetService () { return m_ios; };	

		private:
		
			void Run();
			void Accept();
			void HandleAccept(const boost::system::error_code& ecode);

			bool m_run;
			std::thread * m_thread;
			boost::asio::io_service m_ios;
			boost::asio::io_service::work m_work;
            boost::asio::ip::tcp::acceptor m_acceptor;
			boost::asio::ip::tcp::socket * m_new_sock;
		

	};

	typedef SOCKS4AServer SOCKSProxy;
}
}


#endif
