/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cstring>
#include <cassert>
#include <string>
#include <atomic>
#include "SOCKS.h"
#include "Identity.h"
#include "Streaming.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"
#include "I2PTunnel.h"
#include "I2PService.h"
#include "util.h"

namespace i2p
{
namespace proxy
{
	static const size_t socks_buffer_size = 8192;
	static const size_t max_socks_hostname_size = 255; // Limit for socks5 and bad idea to traverse

	static const size_t SOCKS_FORWARDER_BUFFER_SIZE = 8192;

	static const size_t SOCKS_UPSTREAM_SOCKS4A_REPLY_SIZE = 8;

	struct SOCKSDnsAddress
	{
		uint8_t size;
		char value[max_socks_hostname_size];
		void FromString (const std::string& str)
		{
			size = str.length();
			if (str.length() > max_socks_hostname_size) size = max_socks_hostname_size;
			memcpy(value,str.c_str(),size);
		}
		std::string ToString() { return std::string(value, size); }
		void push_back (char c) { value[size++] = c; }
	};

	class SOCKSServer;
	class SOCKSHandler: public i2p::client::I2PServiceHandler, public std::enable_shared_from_this<SOCKSHandler>
	{
		private:

			enum state
			{
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
				READY,
				UPSTREAM_RESOLVE,
				UPSTREAM_CONNECT,
				UPSTREAM_HANDSHAKE
			};
			enum authMethods
			{
				AUTH_NONE = 0, //No authentication, skip to next step
				AUTH_GSSAPI = 1, //GSSAPI authentication
				AUTH_USERPASSWD = 2, //Username and password
				AUTH_UNACCEPTABLE = 0xff //No acceptable method found
			};
			enum addrTypes
			{
				ADDR_IPV4 = 1, //IPv4 address (4 octets)
				ADDR_DNS = 3, // DNS name (up to 255 octets)
				ADDR_IPV6 = 4 //IPV6 address (16 octets)
			};
			enum errTypes
			{
				SOCKS5_OK = 0, // No error for SOCKS5
				SOCKS5_GEN_FAIL = 1, // General server failure
				SOCKS5_RULE_DENIED = 2, // Connection disallowed by ruleset
				SOCKS5_NET_UNREACH = 3, // Network unreachable
				SOCKS5_HOST_UNREACH = 4, // Host unreachable
				SOCKS5_CONN_REFUSED = 5, // Connection refused by the peer
				SOCKS5_TTL_EXPIRED = 6, // TTL Expired
				SOCKS5_CMD_UNSUP = 7, // Command unsupported
				SOCKS5_ADDR_UNSUP = 8, // Address type unsupported
				SOCKS4_OK = 90, // No error for SOCKS4
				SOCKS4_FAIL = 91, // Failed establishing connecting or not allowed
				SOCKS4_IDENTD_MISSING = 92, // Couldn't connect to the identd server
				SOCKS4_IDENTD_DIFFER = 93 // The ID reported by the application and by identd differ
			};
			enum cmdTypes
			{
				CMD_CONNECT = 1, // TCP Connect
				CMD_BIND = 2, // TCP Bind
				CMD_UDP = 3 // UDP associate
			};
			enum socksVersions
			{
				SOCKS4 = 4, // SOCKS4
				SOCKS5 = 5 // SOCKS5
			};
			union address
			{
				uint32_t ip;
				SOCKSDnsAddress dns;
				uint8_t ipv6[16];
			};

			void EnterState(state nstate, uint8_t parseleft = 1);
			bool HandleData(uint8_t *sock_buff, std::size_t len);
			bool ValidateSOCKSRequest();
			void HandleSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void Terminate();
			void AsyncSockRead();
			boost::asio::const_buffers_1 GenerateSOCKS5SelectAuth(authMethods method);
			boost::asio::const_buffers_1 GenerateSOCKS4Response(errTypes error, uint32_t ip, uint16_t port);
			boost::asio::const_buffers_1 GenerateSOCKS5Response(errTypes error, addrTypes type, const address &addr, uint16_t port);
			boost::asio::const_buffers_1 GenerateUpstreamRequest();
			bool Socks5ChooseAuth();
			void SocksRequestFailed(errTypes error);
			void SocksRequestSuccess();
			void SentSocksFailed(const boost::system::error_code & ecode);
			void SentSocksDone(const boost::system::error_code & ecode);
			void SentSocksResponse(const boost::system::error_code & ecode);
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
			void ForwardSOCKS();

			void SocksUpstreamSuccess();
			void AsyncUpstreamSockRead();
			void SendUpstreamRequest();
			void HandleUpstreamData(uint8_t * buff, std::size_t len);
			void HandleUpstreamSockSend(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void HandleUpstreamSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered);
			void HandleUpstreamConnected(const boost::system::error_code & ecode,
			boost::asio::ip::tcp::resolver::iterator itr);
			void HandleUpstreamResolved(const boost::system::error_code & ecode,
				boost::asio::ip::tcp::resolver::iterator itr);

			boost::asio::ip::tcp::resolver m_proxy_resolver;
			uint8_t m_sock_buff[socks_buffer_size];
			std::shared_ptr<boost::asio::ip::tcp::socket> m_sock, m_upstreamSock;
			std::shared_ptr<i2p::stream::Stream> m_stream;
			uint8_t *m_remaining_data; //Data left to be sent
			uint8_t *m_remaining_upstream_data; //upstream data left to be forwarded
			uint8_t m_response[7+max_socks_hostname_size];
			uint8_t m_upstream_response[SOCKS_UPSTREAM_SOCKS4A_REPLY_SIZE];
			uint8_t m_upstream_request[14+max_socks_hostname_size];
			std::size_t m_upstream_response_len;
			address m_address; //Address
			std::size_t m_remaining_data_len; //Size of the data left to be sent
			uint32_t m_4aip; //Used in 4a requests
			uint16_t m_port;
			uint8_t m_command;
			uint8_t m_parseleft; //Octets left to parse
			authMethods m_authchosen; //Authentication chosen
			addrTypes m_addrtype; //Address type chosen
			socksVersions m_socksv; //Socks version
			cmdTypes m_cmd; // Command requested
			state m_state;
			const bool m_UseUpstreamProxy; // do we want to use the upstream proxy for non i2p addresses?
			const std::string m_UpstreamProxyAddress;
			const uint16_t m_UpstreamProxyPort;

		public:

			SOCKSHandler(SOCKSServer * parent, std::shared_ptr<boost::asio::ip::tcp::socket> sock, const std::string & upstreamAddr, const uint16_t upstreamPort, const bool useUpstream) :
				I2PServiceHandler(parent),
				m_proxy_resolver(parent->GetService()),
				m_sock(sock), m_stream(nullptr),
				m_authchosen(AUTH_UNACCEPTABLE), m_addrtype(ADDR_IPV4),
				m_UseUpstreamProxy(useUpstream),
				m_UpstreamProxyAddress(upstreamAddr),
				m_UpstreamProxyPort(upstreamPort)
				{ m_address.ip = 0; EnterState(GET_SOCKSV); }

			~SOCKSHandler() { Terminate(); }
			void Handle() { AsyncSockRead(); }
	};

	void SOCKSHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug, "SOCKS: async sock read");
		if (m_sock) {
			m_sock->async_receive(boost::asio::buffer(m_sock_buff, socks_buffer_size),
				std::bind(&SOCKSHandler::HandleSockRecv, shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError,"SOCKS: no socket for read");
		}
	}

	void SOCKSHandler::Terminate()
	{
		if (Kill()) return;
		if (m_sock)
		{
			LogPrint(eLogDebug, "SOCKS: closing socket");
			m_sock->close();
			m_sock = nullptr;
		}
		if (m_upstreamSock)
		{
			LogPrint(eLogDebug, "SOCKS: closing upstream socket");
			m_upstreamSock->close();
			m_upstreamSock = nullptr;
		}
		if (m_stream)
		{
			LogPrint(eLogDebug, "SOCKS: closing stream");
			m_stream.reset ();
		}
		Done(shared_from_this());
	}

	boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS4Response(SOCKSHandler::errTypes error, uint32_t ip, uint16_t port)
	{
		assert(error >= SOCKS4_OK);
		m_response[0] = '\x00';           // version
		m_response[1] = error;            // response code
		htobe16buf(m_response + 2, port); // port
		htobe32buf(m_response + 4, ip);   // IP
		return boost::asio::const_buffers_1(m_response,8);
	}

	boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS5Response(SOCKSHandler::errTypes error, SOCKSHandler::addrTypes type, const SOCKSHandler::address &addr, uint16_t port)
	{
		size_t size = 6;        // header + port
		assert(error <= SOCKS5_ADDR_UNSUP);
		m_response[0] = '\x05'; // version
		m_response[1] = error;  // response code
		m_response[2] = '\x00'; // reserved
		m_response[3] = type;   // address type
		switch (type)
		{
			case ADDR_IPV4:
				size += 4;
				htobe32buf(m_response + 4, addr.ip);
				htobe16buf(m_response + size - 2, port);
				break;
			case ADDR_IPV6:
				size += 16;
				memcpy(m_response + 4, addr.ipv6, 16);
				htobe16buf(m_response + size - 2, port);
				break;
			case ADDR_DNS:
				std::string address(addr.dns.value, addr.dns.size);
				if(address.substr(addr.dns.size - 4, 4) == ".i2p") // overwrite if requested address inside I2P
				{
					m_response[3] = ADDR_IPV4;
					size += 4;
					memset(m_response + 4, 0, 6); // six HEX zeros
				}
				else
				{
					size += (1 + addr.dns.size); /* name length + resolved address */
					m_response[4] = addr.dns.size;
					memcpy(m_response + 5, addr.dns.value, addr.dns.size);
					htobe16buf(m_response + size - 2, port);
				}
				break;
		}
		return boost::asio::const_buffers_1(m_response, size);
	}

	boost::asio::const_buffers_1 SOCKSHandler::GenerateUpstreamRequest()
	{
		size_t upstreamRequestSize = 0;
		// TODO: negotiate with upstream
		// SOCKS 4a
		m_upstream_request[0] = '\x04'; //version
		m_upstream_request[1] = m_cmd;
		htobe16buf(m_upstream_request + 2, m_port);
		m_upstream_request[4] = 0;
		m_upstream_request[5] = 0;
		m_upstream_request[6] = 0;
		m_upstream_request[7] = 1;
		// user id
		m_upstream_request[8] = 'i';
		m_upstream_request[9] = '2';
		m_upstream_request[10] = 'p';
		m_upstream_request[11] = 'd';
		m_upstream_request[12] = 0;
		upstreamRequestSize += 13;
		if (m_address.dns.size <= max_socks_hostname_size - ( upstreamRequestSize + 1) ) {
			// bounds check okay
			memcpy(m_upstream_request + upstreamRequestSize, m_address.dns.value, m_address.dns.size);
			upstreamRequestSize += m_address.dns.size;
			// null terminate
			m_upstream_request[++upstreamRequestSize] = 0;
		} else {
			LogPrint(eLogError, "SOCKS: BUG!!! m_addr.dns.sizs > max_socks_hostname - ( upstreamRequestSize + 1 ) )");
		}
		return boost::asio::const_buffers_1(m_upstream_request, upstreamRequestSize);
	}

	bool SOCKSHandler::Socks5ChooseAuth()
	{
		m_response[0] = '\x05'; // Version
		m_response[1] = m_authchosen; // Response code
		boost::asio::const_buffers_1 response(m_response, 2);
		if (m_authchosen == AUTH_UNACCEPTABLE)
		{
			LogPrint(eLogWarning, "SOCKS: v5 authentication negotiation failed");
			boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksFailed, shared_from_this(), std::placeholders::_1));
			return false;
		}
		else
		{
			LogPrint(eLogDebug, "SOCKS: v5 choosing authentication method: ", m_authchosen);
			boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksResponse, shared_from_this(), std::placeholders::_1));
			return true;
		}
	}

	/* All hope is lost beyond this point */
	void SOCKSHandler::SocksRequestFailed(SOCKSHandler::errTypes error)
	{
		boost::asio::const_buffers_1 response(nullptr,0);
		assert(error != SOCKS4_OK && error != SOCKS5_OK);
		switch (m_socksv)
		{
			case SOCKS4:
				LogPrint(eLogWarning, "SOCKS: v4 request failed: ", error);
				if (error < SOCKS4_OK) error = SOCKS4_FAIL; // Transparently map SOCKS5 errors
				response = GenerateSOCKS4Response(error, m_4aip, m_port);
			break;
			case SOCKS5:
				LogPrint(eLogWarning, "SOCKS: v5 request failed: ", error);
				response = GenerateSOCKS5Response(error, m_addrtype, m_address, m_port);
			break;
		}
		boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksFailed,
			shared_from_this(), std::placeholders::_1));
	}

	void SOCKSHandler::SocksRequestSuccess()
	{
		boost::asio::const_buffers_1 response(nullptr,0);
		// TODO: this should depend on things like the command type and callbacks may change
		switch (m_socksv)
		{
			case SOCKS4:
				LogPrint(eLogInfo, "SOCKS: v4 connection success");
				response = GenerateSOCKS4Response(SOCKS4_OK, m_4aip, m_port);
			break;
			case SOCKS5:
				LogPrint(eLogInfo, "SOCKS: v5 connection success");
				auto s = i2p::client::context.GetAddressBook().ToAddress(GetOwner()->GetLocalDestination()->GetIdentHash());
				address ad; ad.dns.FromString(s);
				// HACK only 16 bits passed in port as SOCKS5 doesn't allow for more
				response = GenerateSOCKS5Response(SOCKS5_OK, ADDR_DNS, ad, m_stream->GetRecvStreamID());
			break;
		}
		boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksDone, shared_from_this(), std::placeholders::_1));
	}

	void SOCKSHandler::EnterState(SOCKSHandler::state nstate, uint8_t parseleft) {
		switch (nstate)
		{
			case GET_PORT: parseleft = 2; break;
			case GET_IPV4: m_addrtype = ADDR_IPV4; m_address.ip = 0; parseleft = 4; break;
			case GET4_IDENT: m_4aip = m_address.ip; break;
			case GET4A_HOST:
			case GET5_HOST: m_addrtype = ADDR_DNS; m_address.dns.size = 0; break;
			case GET5_IPV6: m_addrtype = ADDR_IPV6; parseleft = 16; break;
			default:;
		}
		m_parseleft = parseleft;
		m_state = nstate;
	}

	bool SOCKSHandler::ValidateSOCKSRequest()
	{
		if ( m_cmd != CMD_CONNECT )
		{
			// TODO: we need to support binds and other shit!
			LogPrint(eLogError, "SOCKS: unsupported command: ", m_cmd);
			SocksRequestFailed(SOCKS5_CMD_UNSUP);
			return false;
		}
		// TODO: we may want to support other address types!
		if ( m_addrtype != ADDR_DNS )
		{
			switch (m_socksv)
			{
				case SOCKS5:
					LogPrint(eLogError, "SOCKS: v5 unsupported address type: ", m_addrtype);
				break;
				case SOCKS4:
					LogPrint(eLogError, "SOCKS: request with v4a rejected because it's actually SOCKS4");
				break;
			}
			SocksRequestFailed(SOCKS5_ADDR_UNSUP);
			return false;
		}
		return true;
	}

	bool SOCKSHandler::HandleData(uint8_t *sock_buff, std::size_t len)
	{
		assert(len); // This should always be called with a least a byte left to parse
		while (len > 0)
		{
			switch (m_state)
			{
				case GET_SOCKSV:
					m_socksv = (SOCKSHandler::socksVersions) *sock_buff;
					switch (*sock_buff)
					{
						case SOCKS4:
							EnterState(GET_COMMAND); //Initialize the parser at the right position
						break;
						case SOCKS5:
							EnterState(GET5_AUTHNUM); //Initialize the parser at the right position
						break;
						default:
							LogPrint(eLogError, "SOCKS: rejected invalid version: ", ((int)*sock_buff));
							Terminate();
							return false;
					}
				break;
				case GET5_AUTHNUM:
					EnterState(GET5_AUTH, *sock_buff);
				break;
				case GET5_AUTH:
					m_parseleft --;
					if (*sock_buff == AUTH_NONE)
						m_authchosen = AUTH_NONE;
					if ( m_parseleft == 0 )
					{
						if (!Socks5ChooseAuth()) return false;
						EnterState(GET5_REQUESTV);
					}
				break;
				case GET_COMMAND:
					switch (*sock_buff)
					{
						case CMD_CONNECT:
						case CMD_BIND:
						break;
						case CMD_UDP:
							if (m_socksv == SOCKS5) break;
#if (__cplusplus >= 201703L) // C++ 17 or higher
							[[fallthrough]];
#endif
						default:
							LogPrint(eLogError, "SOCKS: invalid command: ", ((int)*sock_buff));
							SocksRequestFailed(SOCKS5_GEN_FAIL);
							return false;
					}
					m_cmd = (SOCKSHandler::cmdTypes)*sock_buff;
					switch (m_socksv)
					{
						case SOCKS5: EnterState(GET5_GETRSV); break;
						case SOCKS4: EnterState(GET_PORT); break;
					}
				break;
				case GET_PORT:
					m_port = (m_port << 8)|((uint16_t)*sock_buff);
					m_parseleft--;
					if (m_parseleft == 0)
					{
						switch (m_socksv)
						{
							case SOCKS5: EnterState(READY); break;
							case SOCKS4: EnterState(GET_IPV4); break;
						}
					}
				break;
				case GET_IPV4:
					m_address.ip = (m_address.ip << 8)|((uint32_t)*sock_buff);
					m_parseleft--;
					if (m_parseleft == 0)
					{
						switch (m_socksv)
						{
							case SOCKS5: EnterState(GET_PORT); break;
							case SOCKS4: EnterState(GET4_IDENT); m_4aip = m_address.ip; break;
						}
					}
				break;
				case GET4_IDENT:
					if (!*sock_buff)
					{
						if( m_4aip == 0 || m_4aip > 255 )
							EnterState(READY);
						else
							EnterState(GET4A_HOST);
					}
				break;
				case GET4A_HOST:
					if (!*sock_buff)
					{
						EnterState(READY);
						break;
					}
					if (m_address.dns.size >= max_socks_hostname_size)
					{
						LogPrint(eLogError, "SOCKS: v4a req failed: destination is too large");
						SocksRequestFailed(SOCKS4_FAIL);
						return false;
					}
					m_address.dns.push_back(*sock_buff);
				break;
				case GET5_REQUESTV:
					if (*sock_buff != SOCKS5)
					{
						LogPrint(eLogError,"SOCKS: v5 rejected unknown request version: ", ((int)*sock_buff));
						SocksRequestFailed(SOCKS5_GEN_FAIL);
						return false;
					}
					EnterState(GET_COMMAND);
				break;
				case GET5_GETRSV:
					if ( *sock_buff != 0 )
					{
						LogPrint(eLogError, "SOCKS: v5 unknown reserved field: ", ((int)*sock_buff));
						SocksRequestFailed(SOCKS5_GEN_FAIL);
						return false;
					}
					EnterState(GET5_GETADDRTYPE);
				break;
				case GET5_GETADDRTYPE:
					switch (*sock_buff)
					{
						case ADDR_IPV4: EnterState(GET_IPV4); break;
						case ADDR_IPV6: EnterState(GET5_IPV6); break;
						case ADDR_DNS : EnterState(GET5_HOST_SIZE); break;
						default:
							LogPrint(eLogError, "SOCKS: v5 unknown address type: ", ((int)*sock_buff));
							SocksRequestFailed(SOCKS5_GEN_FAIL);
							return false;
					}
				break;
				case GET5_IPV6:
					m_address.ipv6[16-m_parseleft] = *sock_buff;
					m_parseleft--;
					if (m_parseleft == 0) EnterState(GET_PORT);
				break;
				case GET5_HOST_SIZE:
					EnterState(GET5_HOST, *sock_buff);
				break;
				case GET5_HOST:
					m_address.dns.push_back(*sock_buff);
					m_parseleft--;
					if (m_parseleft == 0) EnterState(GET_PORT);
				break;
				default:
					LogPrint(eLogError, "SOCKS: parse state?? ", m_state);
					Terminate();
					return false;
			}
			sock_buff++;
			len--;
			if (m_state == READY)
			{
				m_remaining_data_len = len;
				m_remaining_data = sock_buff;
				return ValidateSOCKSRequest();
			}
		}
		return true;
	}

	void SOCKSHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug, "SOCKS: received ", len, " bytes");
		if(ecode)
		{
			LogPrint(eLogWarning, "SOCKS: recv got error: ", ecode);
			Terminate();
			return;
		}

		if (HandleData(m_sock_buff, len))
		{
			if (m_state == READY)
			{
				const std::string addr = m_address.dns.ToString();
				LogPrint(eLogInfo, "SOCKS: requested ", addr, ":" , m_port);
				const size_t addrlen = addr.size();
				// does it end with .i2p?
				if ( addr.rfind(".i2p") == addrlen - 4) {
					// yes it does, make an i2p session
					GetOwner()->CreateStream ( std::bind (&SOCKSHandler::HandleStreamRequestComplete,
							shared_from_this(), std::placeholders::_1), m_address.dns.ToString(), m_port);
				} else if (m_UseUpstreamProxy) {
					// forward it to upstream proxy
					ForwardSOCKS();
				} else {
					// no upstream proxy
					SocksRequestFailed(SOCKS5_ADDR_UNSUP);
				}
			}
			else
				AsyncSockRead();
		}
	}

	void SOCKSHandler::SentSocksFailed(const boost::system::error_code & ecode)
	{
		if (ecode)
			LogPrint (eLogError, "SOCKS: closing socket after sending failure because: ", ecode.message ());
		Terminate();
	}

	void SOCKSHandler::SentSocksDone(const boost::system::error_code & ecode)
	{
		if (!ecode)
		{
			if (Kill()) return;
			LogPrint (eLogInfo, "SOCKS: new I2PTunnel connection");
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>(GetOwner(), m_sock, m_stream);
			GetOwner()->AddHandler (connection);
			connection->I2PConnect (m_remaining_data,m_remaining_data_len);
			Done(shared_from_this());
		}
		else
		{
			LogPrint (eLogError, "SOCKS: closing socket after completion reply because: ", ecode.message ());
			Terminate();
		}
	}

	void SOCKSHandler::SentSocksResponse(const boost::system::error_code & ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "SOCKS: closing socket after sending reply because: ", ecode.message ());
			Terminate();
		}
	}

	void SOCKSHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			m_stream = stream;
			SocksRequestSuccess();
		}
		else
		{
			LogPrint (eLogError, "SOCKS: error when creating the stream, check the previous warnings for more info");
			SocksRequestFailed(SOCKS5_HOST_UNREACH);
		}
	}

	void SOCKSHandler::ForwardSOCKS()
	{
		LogPrint(eLogInfo, "SOCKS: forwarding to upstream");
		EnterState(UPSTREAM_RESOLVE);
		boost::asio::ip::tcp::resolver::query q(m_UpstreamProxyAddress, std::to_string(m_UpstreamProxyPort));
		m_proxy_resolver.async_resolve(q, std::bind(&SOCKSHandler::HandleUpstreamResolved, shared_from_this(),
			std::placeholders::_1, std::placeholders::_2));
	}

	void SOCKSHandler::AsyncUpstreamSockRead()
	{
		LogPrint(eLogDebug, "SOCKS: async upstream sock read");
		if (m_upstreamSock) {
			m_upstreamSock->async_read_some(boost::asio::buffer(m_upstream_response, SOCKS_UPSTREAM_SOCKS4A_REPLY_SIZE),
				std::bind(&SOCKSHandler::HandleUpstreamSockRecv, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError, "SOCKS: no upstream socket for read");
			SocksRequestFailed(SOCKS5_GEN_FAIL);
		}
	}

	void SOCKSHandler::HandleUpstreamSockRecv(const boost::system::error_code & ecode, std::size_t bytes_transfered)
	{
		if (ecode) {
			if (m_state == UPSTREAM_HANDSHAKE ) {
				// we are trying to handshake but it failed
				SocksRequestFailed(SOCKS5_NET_UNREACH);
			} else {
				LogPrint(eLogError, "SOCKS: bad state when reading from upstream: ", (int) m_state);
			}
			return;
		}
		HandleUpstreamData(m_upstream_response, bytes_transfered);
	}

	void SOCKSHandler::SocksUpstreamSuccess()
	{
		LogPrint(eLogInfo, "SOCKS: upstream success");
		boost::asio::const_buffers_1 response(nullptr, 0);
		switch (m_socksv)
		{
			case SOCKS4:
				LogPrint(eLogInfo, "SOCKS: v4 connection success");
				response = GenerateSOCKS4Response(SOCKS4_OK, m_4aip, m_port);
			break;
			case SOCKS5:
				LogPrint(eLogInfo, "SOCKS: v5 connection success");
				//HACK only 16 bits passed in port as SOCKS5 doesn't allow for more
				response = GenerateSOCKS5Response(SOCKS5_OK, ADDR_DNS, m_address, m_port);
			break;
		}
		m_sock->send(response);
		auto forwarder = std::make_shared<i2p::client::TCPIPPipe>(GetOwner(), m_sock, m_upstreamSock);
		m_upstreamSock = nullptr;
		m_sock = nullptr;
		GetOwner()->AddHandler(forwarder);
		forwarder->Start();
		Terminate();

	}

	void SOCKSHandler::HandleUpstreamData(uint8_t * dataptr, std::size_t len)
	{
		if (m_state == UPSTREAM_HANDSHAKE) {
			m_upstream_response_len += len;
			// handle handshake data
			if (m_upstream_response_len < SOCKS_UPSTREAM_SOCKS4A_REPLY_SIZE) {
				// too small, continue reading
				AsyncUpstreamSockRead();
			} else if (len == SOCKS_UPSTREAM_SOCKS4A_REPLY_SIZE) {
				// just right
				uint8_t resp = m_upstream_response[1];
				if (resp == SOCKS4_OK) {
					// we have connected !
					SocksUpstreamSuccess();
				} else {
					// upstream failure
					LogPrint(eLogError, "SOCKS: upstream proxy failure: ", (int) resp);
					// TODO: runtime error?
					SocksRequestFailed(SOCKS5_GEN_FAIL);
				}
			} else {
				// too big
				SocksRequestFailed(SOCKS5_GEN_FAIL);
			}
		} else {
			// invalid state
			LogPrint(eLogError, "SOCKS: invalid state reading from upstream: ", (int) m_state);
		}
	}

	void SOCKSHandler::SendUpstreamRequest()
	{
		LogPrint(eLogInfo, "SOCKS: negotiating with upstream proxy");
		EnterState(UPSTREAM_HANDSHAKE);
		if (m_upstreamSock) {
			boost::asio::write(*m_upstreamSock, GenerateUpstreamRequest());
			AsyncUpstreamSockRead();
		} else {
			LogPrint(eLogError, "SOCKS: no upstream socket to send handshake to");
		}
	}

	void SOCKSHandler::HandleUpstreamConnected(const boost::system::error_code & ecode, boost::asio::ip::tcp::resolver::iterator itr)
	{
		if (ecode) {
			LogPrint(eLogWarning, "SOCKS: could not connect to upstream proxy: ", ecode.message());
			SocksRequestFailed(SOCKS5_NET_UNREACH);
			return;
		}
		LogPrint(eLogInfo, "SOCKS: connected to upstream proxy");
		SendUpstreamRequest();
	}

	void SOCKSHandler::HandleUpstreamResolved(const boost::system::error_code & ecode, boost::asio::ip::tcp::resolver::iterator itr)
	{
		if (ecode) {
			// error resolving
			LogPrint(eLogWarning, "SOCKS: upstream proxy", m_UpstreamProxyAddress, " not resolved: ", ecode.message());
			SocksRequestFailed(SOCKS5_NET_UNREACH);
			return;
		}
		LogPrint(eLogInfo, "SOCKS: upstream proxy resolved");
		EnterState(UPSTREAM_CONNECT);
		auto & service = GetOwner()->GetService();
		m_upstreamSock = std::make_shared<boost::asio::ip::tcp::socket>(service);
		boost::asio::async_connect(*m_upstreamSock, itr,
			std::bind(&SOCKSHandler::HandleUpstreamConnected,
			shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

	SOCKSServer::SOCKSServer(const std::string& name, const std::string& address, int port,
		bool outEnable, const std::string& outAddress, uint16_t outPort,
		std::shared_ptr<i2p::client::ClientDestination> localDestination) :
			TCPIPAcceptor (address, port, localDestination ? localDestination : i2p::client::context.GetSharedLocalDestination ()), m_Name (name)
	{
		m_UseUpstreamProxy = false;
		if (outAddress.length() > 0 && outEnable)
			SetUpstreamProxy(outAddress, outPort);
	}

	std::shared_ptr<i2p::client::I2PServiceHandler> SOCKSServer::CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		return std::make_shared<SOCKSHandler> (this, socket, m_UpstreamProxyAddress, m_UpstreamProxyPort, m_UseUpstreamProxy);
	}

	void SOCKSServer::SetUpstreamProxy(const std::string & addr, const uint16_t port)
	{
		m_UpstreamProxyAddress = addr;
		m_UpstreamProxyPort = port;
		m_UseUpstreamProxy = true;
	}
}
}
