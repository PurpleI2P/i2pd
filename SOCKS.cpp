#include "SOCKS.h"
#include "Identity.h"
#include "NetDb.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"
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

	void SOCKSHandler::Terminate() {
		CloseStream();
		CloseSock();
		delete this; // HACK: ew
	}

	void SOCKSHandler::Socks5AuthNegoFailed()
	{
		LogPrint(eLogWarning,"--- SOCKS5 authentication negotiation failed");
		boost::asio::async_write(*m_sock, boost::asio::buffer("\x05\xff",2),
					 std::bind(&SOCKSHandler::SentSocksFailed, this,
						     std::placeholders::_1));
	}

	void SOCKSHandler::Socks5ChooseAuth()
	{
		LogPrint(eLogDebug,"--- SOCKS5 choosing authentication method");
		//TODO: Choose right method
		boost::asio::async_write(*m_sock, boost::asio::buffer("\x05\x00",2),
					 std::bind(&SOCKSHandler::SentSocksResponse, this,
						     std::placeholders::_1, nullptr));
	}

	static const char *socks5Replies[9] = {
		"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x06\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00",
		"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00" };

	/* All hope is lost */
	void SOCKSHandler::SocksRequestFailed()
	{
		switch (m_socksv) {
			case SOCKS4:
				LogPrint(eLogWarning,"--- SOCKS4 failed");
				//TODO: send the right response
				boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5b\x00\x00\x00\x00\x00\x00",8),
							std::bind(&SOCKSHandler::SentSocksFailed, this, std::placeholders::_1));
				break;
			case SOCKS5:
				assert(m_error <= SOCKS5_ADDR_UNSUP);
				LogPrint(eLogWarning,"--- SOCKS5 failed");
				//TODO: use error properly and address type m_error
				boost::asio::async_write(*m_sock, boost::asio::buffer(socks5Replies[m_error],10),
							std::bind(&SOCKSHandler::SentSocksFailed, this, std::placeholders::_1));
				break;
		}
	}

	void SOCKSHandler::SocksRequestSuccess()
	{
		std::shared_ptr<std::vector<uint8_t>> response(new std::vector<uint8_t>);
		switch (m_socksv) {
			case SOCKS4:
				LogPrint(eLogInfo,"--- SOCKS4 connection success");
				//TODO: send the right response
				boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5a\x00\x00\x00\x00\x00\x00",8),
							std::bind(&SOCKSHandler::SentSocksResponse, this,
								std::placeholders::_1, nullptr));
				break;
			case SOCKS5:
				LogPrint(eLogInfo,"--- SOCKS5 connection success");
				//TODO: send the right response using the port? and the localside i2p address
				boost::asio::async_write(*m_sock, boost::asio::buffer("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",10),
							std::bind(&SOCKSHandler::SentSocksResponse, this,
								std::placeholders::_1, response));
				break;
		}
	}


	void SOCKSHandler::CloseSock()
	{
		if (m_sock) {
			LogPrint(eLogDebug,"--- SOCKS close sock");
			m_sock->close();
			delete m_sock;
			m_sock = nullptr;
		}
	}

       void SOCKSHandler::CloseStream()
       {
               if (m_stream) {
                       LogPrint(eLogDebug,"--- SOCKS close stream");
                       m_stream.reset ();
               }
       }

	std::size_t SOCKSHandler::HandleData(uint8_t *sock_buff, std::size_t len)
	{
		assert(len); // This should always be called with a least a byte left to parse
		switch (m_state) {
			case GET_VERSION:
				return HandleVersion(sock_buff);
			case SOCKS5_AUTHNEGO:
				return HandleSOCKS5AuthNego(sock_buff,len);
			case SOCKS_REQUEST:
				return HandleSOCKSRequest(sock_buff,len);
			default:
				LogPrint(eLogError,"--- SOCKS state?? ", m_state);
				Terminate();
				return 0;
		}
	}

	std::size_t SOCKSHandler::HandleVersion(uint8_t *sock_buff)
	{
		switch (*sock_buff) {
			case SOCKS4:
				m_state = SOCKS_REQUEST; // Switch to the 4 handler
				m_pstate = GET_COMMAND; //Initialize the parser at the right position
				break;
			case SOCKS5:
				m_state = SOCKS5_AUTHNEGO; // Switch to the 5 handler
				m_pstate = GET5_AUTHNUM; //Initialize the parser at the right position
				break;
			default:
				LogPrint(eLogError,"--- SOCKS rejected invalid version: ", ((int)*sock_buff));
				Terminate();
				return 0;
		}
		m_socksv = (SOCKSHandler::socksVersions) *sock_buff;
		return 1;
	}

	std::size_t SOCKSHandler::HandleSOCKS5AuthNego(uint8_t *sock_buff, std::size_t len)
	{
		std::size_t rv = 0;
		while (len > 0) {
			rv++;
			switch (m_pstate)
			{
				case GET5_AUTHNUM:
					m_authleft = *sock_buff;
					m_pstate = GET5_AUTH;
					break;
				case GET5_AUTH:
					m_authleft --;
					if (*sock_buff == AUTH_NONE)
						m_authchosen = AUTH_NONE;
					if ( m_authleft == 0 ) {
						if (m_authchosen == AUTH_UNACCEPTABLE) {
							//TODO: we maybe want support for other methods!
							LogPrint(eLogError,"--- SOCKS5 couldn't negotiate authentication");
							Socks5AuthNegoFailed();
							return 0;
						}
						m_pstate = GET5_REQUESTV;
						m_state = SOCKS_REQUEST;
						m_need_more = false;
						Socks5ChooseAuth();
						return rv;
					}
					break;
				default:
					LogPrint(eLogError,"--- SOCKS5 parse state?? ", m_pstate);
					Terminate();
					return 0;
			}
			sock_buff++;
			len--;
		}
		return rv;
	}

	bool SOCKSHandler::ValidateSOCKSRequest() {
		if ( m_cmd != CMD_CONNECT ) {
			//TODO: we need to support binds and other shit!
			LogPrint(eLogError,"--- SOCKS unsupported command: ", m_cmd);
			m_error = SOCKS5_CMD_UNSUP;
			SocksRequestFailed();
			return false;
		}
		//TODO: we may want to support other address types!
		if ( m_addrtype != ADDR_DNS ) {
			switch (m_socksv) {
				case SOCKS5:
					LogPrint(eLogError,"--- SOCKS5 unsupported address type: ", m_addrtype);
					m_error = SOCKS5_ADDR_UNSUP;
					break;
				case SOCKS4:
					LogPrint(eLogError,"--- SOCKS4a rejected because it's actually SOCKS4");
					break;
			}
			SocksRequestFailed();
			return false;
		}
		//TODO: we may want to support other domains
		if(m_addrtype == ADDR_DNS && m_destination.find(".i2p") == std::string::npos) {
			LogPrint(eLogError,"--- SOCKS invalid hostname: ", m_destination);
			m_error = SOCKS5_ADDR_UNSUP;
			SocksRequestFailed();
			return false;
		}
		return true;
	}
	std::size_t SOCKSHandler::HandleSOCKSRequest(uint8_t *sock_buff, std::size_t len)
	{
		std::size_t rv = 0;
		while (len > 0) {
			rv++;
			switch (m_pstate)
			{
				case GET_COMMAND:
					switch (*sock_buff) {
						case CMD_CONNECT:
						case CMD_BIND:
							break;
						case CMD_UDP:
							if (m_socksv == SOCKS5) break;
						default:
							LogPrint(eLogError,"--- SOCKS invalid command: ", ((int)*sock_buff));
							m_error = SOCKS5_GEN_FAIL;
							SocksRequestFailed();
							return 0;
					}
					m_cmd = (SOCKSHandler::cmdTypes)*sock_buff;
					switch (m_socksv) {
						case SOCKS5: m_pstate = GET5_GETRSV; break;
						case SOCKS4: m_pstate = GET_PORT;  m_addrleft = 2; break;
					}
					break;
				case GET_PORT:
					m_port = (m_port << 8)|((uint16_t)*sock_buff);
					m_addrleft--;
					if (m_addrleft == 0) {
						switch (m_socksv) {
							case SOCKS5: m_pstate = DONE; break;
							case SOCKS4: m_pstate = GET_IPV4; m_addrleft = 4; break;
						}
					}
					break;
				case GET_IPV4:
					m_ip = (m_ip << 8)|((uint32_t)*sock_buff);
					m_addrleft--;
					if (m_addrleft == 0) {
						switch (m_socksv) {
							case SOCKS5: m_pstate = GET_PORT;  m_addrleft = 2; break;
							case SOCKS4: m_pstate = GET4_IDENT; break;
						}
					}
					break;
				case GET4_IDENT:
					if (!*sock_buff) {
						if( m_ip == 0 || m_ip > 255 ) {
							m_addrtype = ADDR_IPV4;
							m_pstate = DONE;
						} else {
							m_addrtype = ADDR_DNS;
							m_pstate = GET4A_HOST;
						}
					}
					break;
				case GET4A_HOST:
					if (!*sock_buff) {
						m_pstate = DONE;
						break;
					}
					if (m_destination.size() > max_socks_hostname_size) {
						LogPrint(eLogError,"--- SOCKS4a destination is too large");
						SocksRequestFailed();
						return 0;
					}
					m_destination.push_back(*sock_buff);
					break;
				case GET5_REQUESTV:
					if (*sock_buff != SOCKS5) {
						LogPrint(eLogError,"--- SOCKS5 rejected unknown request version: ", ((int)*sock_buff));
						m_error = SOCKS5_GEN_FAIL;
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET_COMMAND;
					break;
				case GET5_GETRSV:
					if ( *sock_buff != 0 ) {
						LogPrint(eLogError,"--- SOCKS5 unknown reserved field: ", ((int)*sock_buff));
						m_error = SOCKS5_GEN_FAIL;
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET5_GETADDRTYPE;
					break;
				case GET5_GETADDRTYPE:
					switch (*sock_buff) {
						case ADDR_IPV4: m_pstate = GET_IPV4; m_addrleft = 4; break;
						case ADDR_IPV6: m_pstate = GET5_IPV6; m_addrleft = 16; break;
						case ADDR_DNS : m_pstate = GET5_HOST_SIZE; break;
						default:
							LogPrint(eLogError,"--- SOCKS5 unknown address type: ", ((int)*sock_buff));
							m_error = SOCKS5_GEN_FAIL;
							SocksRequestFailed();
							return 0;
					}
					m_addrtype = (SOCKSHandler::addrTypes)*sock_buff;
					break;
				case GET5_IPV6:
					m_ipv6[16-m_addrleft] = *sock_buff;
					m_addrleft--;
					if (m_addrleft == 0) {
						m_pstate = GET_PORT;
						m_addrleft = 2;
					}
					break;
				case GET5_HOST_SIZE:
					m_addrleft = *sock_buff;
					m_pstate = GET5_HOST;
					break;
				case GET5_HOST:
					m_destination.push_back(*sock_buff);
					m_addrleft--;
					if (m_addrleft == 0) {
						m_pstate = GET_PORT;
						m_addrleft = 2;
					}
					break;
				default:
					LogPrint(eLogError,"--- SOCKS parse state?? ", m_pstate);
					Terminate();
					return 0;
			}
			if (m_pstate == DONE) {
				m_state = READY;
				m_need_more = false;
				return (ValidateSOCKSRequest() ? rv : 0);
			}
			sock_buff++;
			len--;
		}
		return rv;
	}

	void SOCKSHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug,"--- SOCKS sock recv: ", len);
		if(ecode) {
			LogPrint(eLogWarning," --- SOCKS sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		std::size_t pos = 0;
		m_need_more = true;
		while (pos != len && m_state != READY && m_need_more) {
			assert(pos < len); //We are overflowing the buffer otherwise
			std::size_t rv = HandleData(m_sock_buff + pos, len - pos);
			if (!rv) return; //Something went wrong die misserably
			pos += rv;
		}

		assert(!(m_state == READY && m_need_more));

		if (m_state == READY) {
			LogPrint(eLogInfo,"--- SOCKS requested ", m_destination, ":" , m_port);
			if (pos != len) {
				LogPrint(eLogError,"--- SOCKS rejected because we can't handle extra data");
				SocksRequestFailed();
				return ;
			}

			m_parent->GetLocalDestination ()->CreateStream (
					std::bind (&SOCKSHandler::HandleStreamRequestComplete,
					this, std::placeholders::_1), m_destination, m_port);
		} else if (m_need_more) {
			LogPrint (eLogDebug,"--- SOCKS Need more data");
			AsyncSockRead();
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
	
	void SOCKSHandler::SentSocksResponse(const boost::system::error_code & ecode, std::shared_ptr<std::vector<uint8_t>> response)
	{
		response.reset(); // Information wants to be free, so does memory
		if (!ecode) {
			if(m_state == READY) {
				LogPrint (eLogInfo,"--- SOCKS New I2PTunnel connection");
				auto connection = std::make_shared<i2p::client::I2PTunnelConnection>((i2p::client::I2PTunnel *)m_parent, m_sock, m_stream);
				m_parent->AddConnection (connection);
				connection->I2PConnect ();
			} else {
				LogPrint (eLogDebug,"--- SOCKS Go to next state");
				AsyncSockRead();
			}
		}
		else
		{
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
			m_error = SOCKS5_HOST_UNREACH;
			LogPrint (eLogError,"--- SOCKS Issue when creating the stream, check the previous warnings for more info.");
			SocksRequestFailed();
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
	}

	void SOCKSServer::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&SOCKSServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}	

	void SOCKSServer::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			LogPrint(eLogDebug,"--- SOCKS accepted");
			new SOCKSHandler(this, socket);
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
