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
			case 4:
				LogPrint(eLogWarning,"--- SOCKS4 failed");
				//TODO: send the right response
				boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5b\x00\x00\x00\x00\x00\x00",8),
							std::bind(&SOCKSHandler::SentSocksFailed, this, std::placeholders::_1));
				break;
			case 5:
				assert(m_error <= 8);
				LogPrint(eLogWarning,"--- SOCKS5 failed");
				//TODO: use error properly and address type m_error
				boost::asio::async_write(*m_sock, boost::asio::buffer(socks5Replies[m_error],10),
							std::bind(&SOCKSHandler::SentSocksFailed, this, std::placeholders::_1));
				break;
			default:
				LogPrint (eLogError,"--- SOCKS had invalid version");
				Terminate();
				break;
		}
	}

	void SOCKSHandler::SocksRequestSuccess()
	{
		std::shared_ptr<std::vector<uint8_t>> response(new std::vector<uint8_t>);
		switch (m_socksv) {
			case 4:
				LogPrint(eLogInfo,"--- SOCKS4 connection success");
				//TODO: send the right response
				boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5a\x00\x00\x00\x00\x00\x00",8),
							std::bind(&SOCKSHandler::SentSocksResponse, this,
								std::placeholders::_1, nullptr));
				break;
			case 5:
				LogPrint(eLogInfo,"--- SOCKS5 connection success");
				//TODO: send the right response using the port? and the localside i2p address
				boost::asio::async_write(*m_sock, boost::asio::buffer("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",10),
							std::bind(&SOCKSHandler::SentSocksResponse, this,
								std::placeholders::_1, response));
				break;
			default:
				LogPrint (eLogError,"--- SOCKS had invalid version");
				Terminate();
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
			case SOCKS4A:
				return HandleSOCKS4A(sock_buff,len);
			case SOCKS5_S1:
				return HandleSOCKS5Step1(sock_buff,len);
			case SOCKS5_S3:
				return HandleSOCKS5Step3(sock_buff,len);
			default:
				LogPrint(eLogError,"--- SOCKS state?? ", m_state);
				Terminate();
				return 0;
		}
	}

	std::size_t SOCKSHandler::HandleVersion(uint8_t *sock_buff)
	{
		switch (*sock_buff) {
			case 4:
				m_state = SOCKS4A; // Switch to the 4a handler
				m_pstate = GET4A_COMMAND; //Initialize the parser at the right position
				m_socksv = 4;
				return 1;
			case 5:
				m_state = SOCKS5_S1; // Switch to the 4a handler
				m_pstate = GET5_AUTHNUM; //Initialize the parser at the right position
				m_socksv = 5;
				return 1;
			default:
				LogPrint(eLogError,"--- SOCKS rejected invalid version", ((int)*sock_buff));
				Terminate();
				return 0;
		}
	}

	std::size_t SOCKSHandler::HandleSOCKS4A(uint8_t *sock_buff, std::size_t len)
	{
		std::size_t rv = 0;
		while (len > 0) {
			rv++;
			switch (m_pstate)
			{
				case GET4A_COMMAND:
					if ( *sock_buff != 1 ) {
						//TODO: we need to support binds and other shit!
						LogPrint(eLogError,"--- SOCKS4a unsupported command", ((int)*sock_buff));
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET4A_PORT1;
					break;
				case GET4A_PORT1:
					m_port = ((uint16_t)*sock_buff) << 8;
					m_pstate = GET4A_PORT2;
					break;
				case GET4A_PORT2:
					m_port |= ((uint16_t)*sock_buff);
					m_pstate = GET4A_IP1;
					break;
				case GET4A_IP1:
					m_ip = ((uint32_t)*sock_buff) << 24;
					m_pstate = GET4A_IP2;
					break;
				case GET4A_IP2:
					m_ip |= ((uint32_t)*sock_buff) << 16;
					m_pstate = GET4A_IP3;
					break;
				case GET4A_IP3:
					m_ip |= ((uint32_t)*sock_buff) << 8;
					m_pstate = GET4A_IP4;
					break;
				case GET4A_IP4:
					m_ip |= ((uint32_t)*sock_buff);
					m_pstate = GET4A_IDENT;
					if( m_ip == 0 || m_ip > 255 ) {
						LogPrint(eLogError,"--- SOCKS4a rejected because it's actually SOCKS4");
						SocksRequestFailed();
						return 0;
					}
					break;
				case GET4A_IDENT:
					if (!*sock_buff)
						m_pstate = GET4A_HOST;
					break;
				case GET4A_HOST:
					if (!*sock_buff) {
						m_pstate = DONE;
						m_state = READY;
						m_need_more = false;
						return rv;
					}
					if (m_destination.size() > max_socks_hostname_size) {
						LogPrint(eLogError,"--- SOCKS4a destination is too large ");
						SocksRequestFailed();
						return 0;
					}
					m_destination.push_back(*sock_buff);
					break;
				default:
					LogPrint(eLogError,"--- SOCKS4a parse state?? ", m_pstate);
					Terminate();
					return 0;
			}
			sock_buff++;
			len--;
		}
		return rv;
	}

	std::size_t SOCKSHandler::HandleSOCKS5Step1(uint8_t *sock_buff, std::size_t len)
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
					if (*sock_buff == 0)
						m_authchosen = 0;
					if ( m_authleft == 0 ) {
						if (m_authchosen == 0xff) {
							//TODO: we maybe want support for other methods!
							LogPrint(eLogError,"--- SOCKS5 couldn't negotiate authentication");
							Socks5AuthNegoFailed();
							return 0;
						}
						m_pstate = GET5_REQUESTV;
						m_state = SOCKS5_S3;
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

	//TODO this may be merged with the SOCKS4a code
	std::size_t SOCKSHandler::HandleSOCKS5Step3(uint8_t *sock_buff, std::size_t len)
	{
		std::size_t rv = 0;
		while (len > 0) {
			rv++;
			switch (m_pstate)
			{
				case GET5_REQUESTV:
					if (*sock_buff != 5) {
						LogPrint(eLogError,"--- SOCKS rejected unknown request version", ((int)*sock_buff));
						m_error = 0x7;
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET5_COMMAND;
					break;
				case GET5_COMMAND:
					if ( *sock_buff != 1 ) {
						//TODO: we need to support binds and other shit!
						LogPrint(eLogError,"--- SOCKS5 unsupported command", ((int)*sock_buff));
						m_error = 0x7;
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET5_GETRSV;
					break;
				case GET5_GETRSV:
					if ( *sock_buff != 0 ) {
						LogPrint(eLogError,"--- SOCKS5 unknown reserved field", ((int)*sock_buff));
						m_error = 0x7;
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET5_GETADDRTYPE;
					break;
				case GET5_GETADDRTYPE:
					if ( *sock_buff != 0x3 ) {
						//TODO: we may want to support other address types!
						LogPrint(eLogError,"--- SOCKS5 unsupported address type", ((int)*sock_buff));
						m_error = 0x8;
						SocksRequestFailed();
						return 0;
					}
					m_pstate = GET5_HOST_SIZE;
					break;
				case GET5_HOST_SIZE:
					m_addrleft = *sock_buff;
					m_pstate = GET5_HOST;
					break;
				case GET5_HOST:
					m_destination.push_back(*sock_buff);
					m_addrleft--;
					if (m_addrleft == 0)
						m_pstate = GET5_PORT1;
					break;
				case GET5_PORT1:
					m_port = ((uint16_t)*sock_buff) << 8;
					m_pstate = GET5_PORT2;
					break;
				case GET5_PORT2:
					m_port |= ((uint16_t)*sock_buff);
					m_pstate = DONE;
					m_state = READY;
					m_need_more = false;
					return rv;
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
				LogPrint(eLogError,"--- SOCKS rejected because be can't handle extra data");
				SocksRequestFailed();
				return ;
			}
			if(m_destination.find(".i2p") == std::string::npos) {
				LogPrint(eLogError,"--- SOCKS invalid hostname: ", m_destination);
				SocksRequestFailed();
				return;
			}

			m_parent->GetLocalDestination ()->CreateStream (
					std::bind (&SOCKSHandler::HandleStreamRequestComplete,
					this, std::placeholders::_1), m_destination, m_port);
		} else if (m_need_more)
			AsyncSockRead();
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
			m_error = 0x4;
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
