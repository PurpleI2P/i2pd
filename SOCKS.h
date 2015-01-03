#ifndef SOCKS4A_H__
#define SOCKS4A_H__

#include <climits>
#include <memory>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Streaming.h"
#include "I2PTunnel.h"

#ifdef MAC_OSX
 /*
 *  - MAXHOSTNAMELEN from <sys/param.h>
 *    on MacOS X 10.3, FreeBSD 6.0, NetBSD 3.0, OpenBSD 3.8, AIX 5.1, HP-UX 11,
 *    IRIX 6.5, OSF/1 5.1, Interix 3.5, Haiku,
 *  - MAXHOSTNAMELEN from <netdb.h>
 *    on Solaris 10, Cygwin, BeOS,
 *  - 256 on mingw.
 *
 * */
#define HOST_NAME_MAX 256
#endif

namespace i2p
{
namespace proxy
{

	const size_t socks_buffer_size = 8192;

	class SOCKS4AServer;
	class SOCKS4AHandler {

		private:
			enum state {
				GET_VERSION,
				SOCKS4A,
				READY
			};
			enum parseState {
				GET4A_COMMAND,
				GET4A_PORT1,
				GET4A_PORT2,
				GET4A_IP1,
				GET4A_IP2,
				GET4A_IP3,
				GET4A_IP4,
				GET4A_IDENT,
				GET4A_HOST,
				DONE
			};

			void GotClientRequest(boost::system::error_code & ecode, std::string & host, uint16_t port);
			std::size_t HandleData(uint8_t *sock_buff, std::size_t len);
			std::size_t HandleVersion(uint8_t *sock_buff);
			std::size_t HandleSOCKS4A(uint8_t *sock_buff, std::size_t len);
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
			parseState m_pstate;
			uint8_t m_command;
			uint16_t m_port;
			uint32_t m_ip;
			std::string m_destination;
		
            
		public:
			SOCKS4AHandler(SOCKS4AServer * parent, boost::asio::ip::tcp::socket * sock) : 
				m_parent(parent), m_sock(sock), m_stream(nullptr), m_state(GET_VERSION)
				{ AsyncSockRead(); m_destination.reserve(HOST_NAME_MAX+1); }

			~SOCKS4AHandler() { CloseSock(); CloseStream(); }
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
