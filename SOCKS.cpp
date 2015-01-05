#include "SOCKS.h"
#include "Identity.h"
#include "NetDb.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"
#include <cstring>
#include <cassert>

namespace i2p
{
namespace proxy
{
	void SOCKSHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug,"--- SOCKS async sock read");
		if(m_sock) {
			m_sock->async_receive(boost::asio::buffer(m_sock_buff, socks_buffer_size),
						std::bind(&SOCKSHandler::HandleSockRecv, this,
								std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError,"--- SOCKS no socket for read");
		}
	}

	void SOCKSHandler::Done() {
		if (m_parent) m_parent->RemoveHandler (shared_from_this ());
	}

	void SOCKSHandler::Terminate() {
		if (dead.exchange(true)) return;
		if (m_sock) {
			LogPrint(eLogDebug,"--- SOCKS close sock");
			m_sock->close();
			delete m_sock;
			m_sock = nullptr;
		}
		if (m_stream) {
			LogPrint(eLogDebug,"--- SOCKS close stream");
			m_stream.reset ();
		}
		Done();
	}

	boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS4Response(SOCKSHandler::errTypes error, uint32_t ip, uint16_t port)
	{
		assert(error >= SOCKS4_OK);
		m_response[0] = '\x00'; //Version
		m_response[1] = error; //Response code
		htobe16buf(m_response+2,port); //Port
		htobe32buf(m_response+4,ip); //IP
		return boost::asio::const_buffers_1(m_response,8);
	}

	boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS5Response(SOCKSHandler::errTypes error, SOCKSHandler::addrTypes type,
								   const SOCKSHandler::address &addr, uint16_t port)
	{
		size_t size;
		assert(error <= SOCKS5_ADDR_UNSUP);
		m_response[0] = '\x05'; //Version
		m_response[1] = error; //Response code
		m_response[2] = '\x00'; //RSV
		m_response[3] = type; //Address type
		switch (type) {
			case ADDR_IPV4:
				size = 10;
				htobe32buf(m_response+4,addr.ip);
				break;
			case ADDR_IPV6:
				size = 22;
				memcpy(m_response+4,addr.ipv6, 16);
				break;
			case ADDR_DNS:
				size = 7+addr.dns.size;
				m_response[4] = addr.dns.size;
				memcpy(m_response+5,addr.dns.value, addr.dns.size);
				break;
		}
		htobe16buf(m_response+size-2,port); //Port
		return boost::asio::const_buffers_1(m_response,size);
	}

	bool SOCKSHandler::Socks5ChooseAuth()
	{
		m_response[0] = '\x05'; //Version
		m_response[1] = m_authchosen; //Response code
		boost::asio::const_buffers_1 response(m_response,2);
		if (m_authchosen == AUTH_UNACCEPTABLE) {
			LogPrint(eLogWarning,"--- SOCKS5 authentication negotiation failed");
			boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksFailed, this, std::placeholders::_1));
			return false;
		} else {
			LogPrint(eLogDebug,"--- SOCKS5 choosing authentication method: ", m_authchosen);
			boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksResponse, this, std::placeholders::_1));
			return true;
		}
	}

	/* All hope is lost beyond this point */
	void SOCKSHandler::SocksRequestFailed(SOCKSHandler::errTypes error)
	{
		boost::asio::const_buffers_1 response(nullptr,0);
		assert(error != SOCKS4_OK && error != SOCKS5_OK);
		switch (m_socksv) {
			case SOCKS4:
				LogPrint(eLogWarning,"--- SOCKS4 failed: ", error);
				if (error < SOCKS4_OK) error = SOCKS4_FAIL; //Transparently map SOCKS5 errors
				response = GenerateSOCKS4Response(error, m_4aip, m_port);
				break;
			case SOCKS5:
				LogPrint(eLogWarning,"--- SOCKS5 failed: ", error);
				response = GenerateSOCKS5Response(error, m_addrtype, m_address, m_port);
				break;
		}
		boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksFailed, this, std::placeholders::_1));
	}

	void SOCKSHandler::SocksRequestSuccess()
	{
		boost::asio::const_buffers_1 response(nullptr,0);
		//TODO: this should depend on things like the command type and callbacks may change
		switch (m_socksv) {
			case SOCKS4:
				LogPrint(eLogInfo,"--- SOCKS4 connection success");
				response = GenerateSOCKS4Response(SOCKS4_OK, m_4aip, m_port);
				break;
			case SOCKS5:
				LogPrint(eLogInfo,"--- SOCKS5 connection success");
				auto s = i2p::client::context.GetAddressBook().ToAddress(m_parent->GetLocalDestination()->GetIdentHash());
				address ad; ad.dns.FromString(s);
				//HACK only 16 bits passed in port as SOCKS5 doesn't allow for more
				response = GenerateSOCKS5Response(SOCKS5_OK, ADDR_DNS, ad, m_stream->GetRecvStreamID());
				break;
		}
		boost::asio::async_write(*m_sock, response, std::bind(&SOCKSHandler::SentSocksDone, this, std::placeholders::_1));
	}

	void SOCKSHandler::EnterState(SOCKSHandler::state nstate, uint8_t parseleft) {
		switch (nstate) {
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

	void SOCKSHandler::ValidateSOCKSRequest() {
		if ( m_cmd != CMD_CONNECT ) {
			//TODO: we need to support binds and other shit!
			LogPrint(eLogError,"--- SOCKS unsupported command: ", m_cmd);
			SocksRequestFailed(SOCKS5_CMD_UNSUP);
			return;
		}
		//TODO: we may want to support other address types!
		if ( m_addrtype != ADDR_DNS ) {
			switch (m_socksv) {
				case SOCKS5:
					LogPrint(eLogError,"--- SOCKS5 unsupported address type: ", m_addrtype);
					break;
				case SOCKS4:
					LogPrint(eLogError,"--- SOCKS4a rejected because it's actually SOCKS4");
					break;
			}
			SocksRequestFailed(SOCKS5_ADDR_UNSUP);
			return;
		}
		//TODO: we may want to support other domains
		if(m_addrtype == ADDR_DNS && m_address.dns.ToString().find(".i2p") == std::string::npos) {
			LogPrint(eLogError,"--- SOCKS invalid hostname: ", m_address.dns.ToString());
			SocksRequestFailed(SOCKS5_ADDR_UNSUP);
			return;
		}
	}

	bool SOCKSHandler::HandleData(uint8_t *sock_buff, std::size_t len)
	{
		assert(len); // This should always be called with a least a byte left to parse
		while (len > 0) {
			switch (m_state) {
				case GET_SOCKSV:
					m_socksv = (SOCKSHandler::socksVersions) *sock_buff;
					switch (*sock_buff) {
						case SOCKS4:
							EnterState(GET_COMMAND); //Initialize the parser at the right position
							break;
						case SOCKS5:
							EnterState(GET5_AUTHNUM); //Initialize the parser at the right position
							break;
						default:
							LogPrint(eLogError,"--- SOCKS rejected invalid version: ", ((int)*sock_buff));
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
					if ( m_parseleft == 0 ) {
						if (!Socks5ChooseAuth()) return false;
						EnterState(GET5_REQUESTV);
					}
					break;
				case GET_COMMAND:
					switch (*sock_buff) {
						case CMD_CONNECT:
						case CMD_BIND:
							break;
						case CMD_UDP:
							if (m_socksv == SOCKS5) break;
						default:
							LogPrint(eLogError,"--- SOCKS invalid command: ", ((int)*sock_buff));
							SocksRequestFailed(SOCKS5_GEN_FAIL);
							return false;
					}
					m_cmd = (SOCKSHandler::cmdTypes)*sock_buff;
					switch (m_socksv) {
						case SOCKS5: EnterState(GET5_GETRSV); break;
						case SOCKS4: EnterState(GET_PORT); break;
					}
					break;
				case GET_PORT:
					m_port = (m_port << 8)|((uint16_t)*sock_buff);
					m_parseleft--;
					if (m_parseleft == 0) {
						switch (m_socksv) {
							case SOCKS5: EnterState(DONE); break;
							case SOCKS4: EnterState(GET_IPV4); break;
						}
					}
					break;
				case GET_IPV4:
					m_address.ip = (m_address.ip << 8)|((uint32_t)*sock_buff);
					m_parseleft--;
					if (m_parseleft == 0) {
						switch (m_socksv) {
							case SOCKS5: EnterState(GET_PORT); break;
							case SOCKS4: EnterState(GET4_IDENT); m_4aip = m_address.ip; break;
						}
					}
					break;
				case GET4_IDENT:
					if (!*sock_buff) {
						if( m_4aip == 0 || m_4aip > 255 ) {
							EnterState(DONE);
						} else {
							EnterState(GET4A_HOST);
						}
					}
					break;
				case GET4A_HOST:
					if (!*sock_buff) {
						EnterState(DONE);
						break;
					}
					if (m_address.dns.size >= max_socks_hostname_size) {
						LogPrint(eLogError,"--- SOCKS4a destination is too large");
						SocksRequestFailed(SOCKS4_FAIL);
						return false;
					}
					m_address.dns.push_back(*sock_buff);
					break;
				case GET5_REQUESTV:
					if (*sock_buff != SOCKS5) {
						LogPrint(eLogError,"--- SOCKS5 rejected unknown request version: ", ((int)*sock_buff));
						SocksRequestFailed(SOCKS5_GEN_FAIL);
						return false;
					}
					EnterState(GET_COMMAND);
					break;
				case GET5_GETRSV:
					if ( *sock_buff != 0 ) {
						LogPrint(eLogError,"--- SOCKS5 unknown reserved field: ", ((int)*sock_buff));
						SocksRequestFailed(SOCKS5_GEN_FAIL);
						return false;
					}
					EnterState(GET5_GETADDRTYPE);
					break;
				case GET5_GETADDRTYPE:
					switch (*sock_buff) {
						case ADDR_IPV4: EnterState(GET_IPV4); break;
						case ADDR_IPV6: EnterState(GET5_IPV6); break;
						case ADDR_DNS : EnterState(GET5_HOST_SIZE); break;
						default:
							LogPrint(eLogError,"--- SOCKS5 unknown address type: ", ((int)*sock_buff));
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
					LogPrint(eLogError,"--- SOCKS parse state?? ", m_state);
					Terminate();
					return false;
			}
			sock_buff++;
			len--;
			if (len && m_state == DONE) {
				LogPrint(eLogError,"--- SOCKS rejected because we can't handle extra data");
				SocksRequestFailed(SOCKS5_GEN_FAIL);
				return false;
			}
		}
		return true;
	}

	void SOCKSHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug,"--- SOCKS sock recv: ", len);
		if(ecode) {
			LogPrint(eLogWarning," --- SOCKS sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		if (HandleData(m_sock_buff, len)) {
			if (m_state == DONE) {
				LogPrint(eLogInfo,"--- SOCKS requested ", m_address.dns.ToString(), ":" , m_port);
				m_parent->GetLocalDestination ()->CreateStream (
						std::bind (&SOCKSHandler::HandleStreamRequestComplete,
						this, std::placeholders::_1), m_address.dns.ToString(), m_port);
			} else {
				AsyncSockRead();
			}
		}

	}

	void SOCKSHandler::SentSocksFailed(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			Terminate();
		} else {
			LogPrint (eLogError,"--- SOCKS Closing socket after sending failure because: ", ecode.message ());
			Terminate();
		}
	}

	void SOCKSHandler::SentSocksDone(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			if (dead.exchange(true)) return;
			LogPrint (eLogInfo,"--- SOCKS New I2PTunnel connection");
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>((i2p::client::I2PTunnel *)m_parent, m_sock, m_stream);
			m_parent->AddConnection (connection);
			connection->I2PConnect ();
			Done();
		}
		else
		{
			LogPrint (eLogError,"--- SOCKS Closing socket after completion reply because: ", ecode.message ());
			Terminate();
		}
	}

	void SOCKSHandler::SentSocksResponse(const boost::system::error_code & ecode)
	{
		if (ecode) {
			LogPrint (eLogError,"--- SOCKS Closing socket after sending reply because: ", ecode.message ());
			Terminate();
		}
	}

	void SOCKSHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream) {
			m_stream = stream;
			SocksRequestSuccess();
		} else {
			LogPrint (eLogError,"--- SOCKS Issue when creating the stream, check the previous warnings for more info.");
			SocksRequestFailed(SOCKS5_HOST_UNREACH);
		}
	}

	void SOCKSServer::Start ()
	{
		m_Acceptor.listen ();
		Accept ();
	}

	void SOCKSServer::Stop ()
	{
		m_Acceptor.close();
		m_Timer.cancel ();
		ClearConnections ();
		ClearHandlers();
	}

	void SOCKSServer::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&SOCKSServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void  SOCKSServer::AddHandler (std::shared_ptr<SOCKSHandler> handler) {
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		m_Handlers.insert (handler);
	}

	void  SOCKSServer::RemoveHandler (std::shared_ptr<SOCKSHandler> handler)
	{
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		m_Handlers.erase (handler);
	}

	void  SOCKSServer::ClearHandlers ()
	{
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		m_Handlers.clear ();
	}

	void SOCKSServer::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			LogPrint(eLogDebug,"--- SOCKS accepted");
			AddHandler(std::make_shared<SOCKSHandler> (this, socket));
			Accept();
		}
		else
		{
			LogPrint (eLogError,"--- SOCKS Closing socket on accept because: ", ecode.message ());
			delete socket;
		}
	}

}
}
