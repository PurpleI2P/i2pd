#ifndef SOCKS_H__
#define SOCKS_H__

#include <memory>
#include <string>
#include <set>
#include <boost/asio.hpp>
#include <mutex>
#include <atomic>
#include "Identity.h"
#include "Streaming.h"
#include "I2PTunnel.h"

namespace i2p
{
namespace proxy
{

	const size_t socks_buffer_size = 8192;
	const size_t max_socks_hostname_size = 255; // Limit for socks5 and bad idea to traverse

	struct SOCKSDnsAddress {
		uint8_t size;
		char value[max_socks_hostname_size];
		void FromString (std::string str) {
			size = str.length();
			if (str.length() > max_socks_hostname_size) size = max_socks_hostname_size;
			memcpy(value,str.c_str(),size);
		}
		std::string ToString() { return std::string(value, size); }
		void push_back (char c) { value[size++] = c; }
	};

	class SOCKSServer;
	class SOCKSHandler: public std::enable_shared_from_this<SOCKSHandler> {
		private:
			enum state {
				GET_SOCKSV,
				GET_COMMAND,
				GET_PORT,
				GET_IPV4,
				GET4_IDENT,
				GET4A_HOST,
				GET5_AUTHNUM,
				GET5_AUTH,
				GET5_REQUESTV,
				GET5_GETRSV,
				GET5_GETADDRTYPE,
				GET5_IPV6,
				GET5_HOST_SIZE,
				GET5_HOST,
				DONE
			};
			enum authMethods {
				AUTH_NONE = 0, //No authentication, skip to next step
				AUTH_GSSAPI = 1, //GSSAPI authentication
				AUTH_USERPASSWD = 2, //Username and password
				AUTH_UNACCEPTABLE = 0xff //No acceptable method found
			};
			enum addrTypes {
				ADDR_IPV4 = 1, //IPv4 address (4 octets)
				ADDR_DNS = 3, // DNS name (up to 255 octets)
				ADDR_IPV6 = 4 //IPV6 address (16 octets)
			};
			enum errTypes {
				SOCKS5_OK = 0, // No error for SOCKS5
				SOCKS5_GEN_FAIL = 1, // General server failure
				SOCKS5_RULE_DENIED = 2, // Connection disallowed by ruleset
				SOCKS5_NET_UNREACH = 3, // Network unreachable
				SOCKS5_HOST_UNREACH = 4, // Host unreachable
				SOCKS5_CONN_REFUSED = 5, // Connection refused by the peer
				SOCKS5_TTL_EXPIRED = 6, // TTL Expired
				SOCKS5_CMD_UNSUP = 7, // Command unsuported
				SOCKS5_ADDR_UNSUP = 8, // Address type unsuported
				SOCKS4_OK = 90, // No error for SOCKS4
				SOCKS4_FAIL = 91, // Failed establishing connecting or not allowed
				SOCKS4_IDENTD_MISSING = 92, // Couldn't connect to the identd server
				SOCKS4_IDENTD_DIFFER = 93 // The ID reported by the application and by identd differ
			};
			enum cmdTypes {
				CMD_CONNECT = 1, // TCP Connect
				CMD_BIND = 2, // TCP Bind
				CMD_UDP = 3 // UDP associate
			};
			enum socksVersions {
				SOCKS4 = 4, // SOCKS4
				SOCKS5 = 5 // SOCKS5
			};
			union address {
				uint32_t ip;
				SOCKSDnsAddress dns;
				uint8_t ipv6[16];
			};

			void EnterState(state nstate, uint8_t parseleft = 1);
			bool HandleData(uint8_t *sock_buff, std::size_t len);
			void ValidateSOCKSRequest();
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Done();
			void Terminate();
			void AsyncSockRead();
			boost::asio::const_buffers_1 GenerateSOCKS5SelectAuth(authMethods method);
			boost::asio::const_buffers_1 GenerateSOCKS4Response(errTypes error, uint32_t ip, uint16_t port);
			boost::asio::const_buffers_1 GenerateSOCKS5Response(errTypes error, addrTypes type, const address &addr, uint16_t port);
			bool Socks5ChooseAuth();
			void SocksRequestFailed(errTypes error);
			void SocksRequestSuccess();
			void SentSocksFailed(const boost::system::error_code & ecode);
			void SentSocksDone(const boost::system::error_code & ecode);
			void SentSocksResponse(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);

			uint8_t m_sock_buff[socks_buffer_size];
			SOCKSServer * m_parent;
			boost::asio::ip::tcp::socket * m_sock;
			std::shared_ptr<i2p::stream::Stream> m_stream;
			uint8_t m_response[7+max_socks_hostname_size];
			address m_address; //Address
			uint32_t m_4aip; //Used in 4a requests
			uint16_t m_port;
			uint8_t m_command;
			uint8_t m_parseleft; //Octets left to parse
			authMethods m_authchosen; //Authentication chosen
			addrTypes m_addrtype; //Address type chosen
			socksVersions m_socksv; //Socks version
			cmdTypes m_cmd; // Command requested
			state m_state;
			std::atomic<bool> dead; //To avoid cleaning up multiple times

		public:
			SOCKSHandler(SOCKSServer * parent, boost::asio::ip::tcp::socket * sock) : 
				m_parent(parent), m_sock(sock), m_stream(nullptr),
				m_authchosen(AUTH_UNACCEPTABLE), m_addrtype(ADDR_IPV4), dead(false)
				{ m_address.ip = 0; AsyncSockRead(); EnterState(GET_SOCKSV); }
			~SOCKSHandler() { Terminate(); }
	};

	class SOCKSServer: public i2p::client::I2PTunnel
	{
		private:
			std::set<std::shared_ptr<SOCKSHandler> > m_Handlers;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
			std::mutex m_HandlersMutex;

		private:

			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);

		public:
			SOCKSServer(int port) : I2PTunnel(nullptr),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
				m_Timer (GetService ()) {};
			~SOCKSServer() { Stop(); }

			void Start ();
			void Stop ();
			void AddHandler (std::shared_ptr<SOCKSHandler> handler);
			void RemoveHandler (std::shared_ptr<SOCKSHandler> handler);
			void ClearHandlers ();
	};

	typedef SOCKSServer SOCKSProxy;
}
}


#endif
