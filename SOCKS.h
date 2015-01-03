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
#include <sys/param.h>
#define HOST_NAME_MAX MAXHOSTNAMELEN
#endif

namespace i2p
{
namespace proxy
{

	const size_t socks_buffer_size = 8192;

	class SOCKSServer;
	class SOCKSHandler {

		private:
			enum state {
				GET_VERSION,
				SOCKS4A,
				SOCKS5_S1, //Authentication negotiation
				SOCKS5_S2, //Authentication
				SOCKS5_S3, //Request
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
				GET5_AUTHNUM,
				GET5_AUTH,
				GET5_REQUESTV,
				GET5_COMMAND,
				GET5_GETRSV,
				GET5_GETADDRTYPE,
				GET5_IPV4_1,
				GET5_IPV4_2,
				GET5_IPV4_3,
				GET5_IPV4_4,
				GET5_IPV6_1,
				GET5_IPV6_2,
				GET5_IPV6_3,
				GET5_IPV6_4,
				GET5_IPV6_5,
				GET5_IPV6_6,
				GET5_IPV6_7,
				GET5_IPV6_8,
				GET5_IPV6_9,
				GET5_IPV6_10,
				GET5_IPV6_11,
				GET5_IPV6_12,
				GET5_IPV6_13,
				GET5_IPV6_14,
				GET5_IPV6_15,
				GET5_IPV6_16,
				GET5_HOST_SIZE,
				GET5_HOST,
				GET5_PORT1,
				GET5_PORT2,
				DONE
			};

			void GotClientRequest(boost::system::error_code & ecode, std::string & host, uint16_t port);
			std::size_t HandleData(uint8_t *sock_buff, std::size_t len);
			std::size_t HandleVersion(uint8_t *sock_buff);
			std::size_t HandleSOCKS4A(uint8_t *sock_buff, std::size_t len);
			std::size_t HandleSOCKS5Step1(uint8_t *sock_buff, std::size_t len);
			std::size_t HandleSOCKS5Step3(uint8_t *sock_buff, std::size_t len);
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Terminate();
			void CloseSock();
			void CloseStream();
			void AsyncSockRead();
			void Socks5AuthNegoFailed();
			void Socks5ChooseAuth();
			void SocksRequestFailed();
			void SocksRequestSuccess();
			void SentSocksFailed(const boost::system::error_code & ecode);
			//HACK: we need to pass the shared_ptr to ensure the buffer will live enough
			void SentSocksResponse(const boost::system::error_code & ecode, std::shared_ptr<std::vector<uint8_t>> response);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);

			uint8_t m_sock_buff[socks_buffer_size];
            
			SOCKSServer * m_parent;
			boost::asio::ip::tcp::socket * m_sock;
			std::shared_ptr<i2p::stream::Stream> m_stream;
			state m_state;
			parseState m_pstate;
			uint8_t m_command;
			uint16_t m_port;
			uint32_t m_ip;
			std::string m_destination;
			uint8_t m_authleft; //Authentication methods left
			//TODO: this will probably be more elegant as enums
			uint8_t m_authchosen; //Authentication chosen
			uint8_t m_addrtype; //Address type chosen
			uint8_t m_addrleft; //Address type chosen
			uint8_t m_error; //Address type chosen
			uint8_t m_socksv; //Address type chosen
			bool m_need_more; //Address type chosen

		public:
			SOCKSHandler(SOCKSServer * parent, boost::asio::ip::tcp::socket * sock) : 
				m_parent(parent), m_sock(sock), m_stream(nullptr), m_state(GET_VERSION),
				m_authchosen(0xff), m_addrtype(0x01), m_error(0x01)
				{ AsyncSockRead(); m_destination.reserve(HOST_NAME_MAX+1); }

			~SOCKSHandler() { CloseSock(); CloseStream(); }
	};

	class SOCKSServer: public i2p::client::I2PTunnel
	{
		public:
			SOCKSServer(int port) : I2PTunnel(nullptr),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
				m_Timer (GetService ()) {};
			~SOCKSServer() { Stop(); }

			void Start ();
			void Stop ();

		private:

			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);

		private:

			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
	};	

	typedef SOCKSServer SOCKSProxy;
}
}


#endif
