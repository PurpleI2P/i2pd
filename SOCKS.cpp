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
	const uint8_t socks_leaseset_timeout = 10;
	const uint8_t socks_timeout = 60;

	void SOCKS4AHandler::AsyncSockRead()
	{
		LogPrint(eLogDebug,"--- SOCKS async sock read");
		if(m_sock) {
			m_sock->async_receive(boost::asio::buffer(m_sock_buff, socks_buffer_size),
						std::bind(&SOCKS4AHandler::HandleSockRecv, this,
								std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError,"--- SOCKS no socket for read");
		}
	}

	void SOCKS4AHandler::Terminate() {
		CloseStream();
		CloseSock();
		delete this; // HACK: ew
	}

	void SOCKS4AHandler::SocksFailed()
	{
		LogPrint(eLogWarning,"--- SOCKS failed");
		//TODO: send the right response
		boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5b 12345"),
					 std::bind(&SOCKS4AHandler::SentSocksFailed, this,
						     std::placeholders::_1));
	}

	void SOCKS4AHandler::CloseSock()
	{
		if (m_sock) {
			LogPrint(eLogDebug,"--- SOCKS close sock");
			m_sock->close();
			delete m_sock;
			m_sock = nullptr;
		}
	}

       void SOCKS4AHandler::CloseStream()
       {
               if (m_stream) {
                       LogPrint(eLogDebug,"--- SOCKS close stream");
                       m_stream.reset ();
               }
       }

	const size_t socks_hostname_size = 1024;
	const size_t socks_ident_size = 1024;
	const size_t destb32_len = 52;

	std::size_t SOCKS4AHandler::HandleData(uint8_t *sock_buff, std::size_t len)
	{
		assert(len); // This should always be called with a least a byte left to parse
		switch (m_state) {
			case GET_VERSION:
				return HandleVersion(sock_buff);
			case SOCKS4A:
				return HandleSOCKS4A(sock_buff,len);
			default:
				LogPrint(eLogError,"--- SOCKS state?? ", m_state);
				Terminate();
				return 0;
		}
	}

	std::size_t SOCKS4AHandler::HandleVersion(uint8_t *sock_buff)
	{
		switch (*sock_buff) {
			case 4:
				m_state = SOCKS4A; // Switch to the 4a handler
				m_pstate = GET4A_COMMAND; //Initialize the parser at the right position
				return 1;
			default:
				LogPrint(eLogError,"--- SOCKS rejected invalid version", ((int)*sock_buff));
				Terminate();
				return 0;
		}
	}

	std::size_t SOCKS4AHandler::HandleSOCKS4A(uint8_t *sock_buff, std::size_t len)
	{
		std::size_t rv = 0;
		while (len > 0) {
			rv++;
			switch (m_pstate)
			{
				case GET4A_COMMAND:
					if ( *sock_buff != 1 ) {
						LogPrint(eLogError,"--- SOCKS4a unsupported command", ((int)*sock_buff));
						SocksFailed();
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
						SocksFailed();
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
						return rv;
					}
					if (m_destination.size() > HOST_NAME_MAX) {
						LogPrint(eLogError,"--- SOCKS4a destination is too large ");
						SocksFailed();
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

	void SOCKS4AHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint(eLogDebug,"--- SOCKS sock recv: ", len);
		if(ecode) {
			LogPrint(eLogWarning," --- SOCKS sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		std::size_t pos = 0;
		while (pos != len && m_state != READY) {
			assert(pos < len); //We are overflowing the buffer otherwise
			std::size_t rv = HandleData(m_sock_buff + pos, len - pos);
			if (!rv) return; //Something went wrong die misserably
			pos += rv;
		}

		if (m_state == READY) {
			LogPrint(eLogInfo,"--- SOCKS requested ", m_destination, ":" , m_port);
			if (pos != len) {
				LogPrint(eLogError,"--- SOCKS rejected because be can't handle extra data");
				SocksFailed();
				return ;
			}
			if(m_destination.find(".i2p") == std::string::npos) {
				LogPrint(eLogError,"--- SOCKS invalid hostname: ", m_destination);
				SocksFailed();
				return;
			}

			// TODO: Pass port see m_port
			m_parent->GetLocalDestination ()->CreateStream (
					std::bind (&SOCKS4AHandler::HandleStreamRequestComplete,
					this, std::placeholders::_1), m_destination);
		}
	}

	void SOCKS4AHandler::ConnectionSuccess()
	{
		LogPrint(eLogInfo,"--- SOCKS connection success");
		//TODO: send the right response
		boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5a 12345"),
					 std::bind(&SOCKS4AHandler::SentConnectionSuccess, this,
						     std::placeholders::_1));
	}

	void SOCKS4AHandler::SentSocksFailed(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			Terminate();
		}
		else
		{
			LogPrint (eLogError,"--- SOCKS Closing socket after sending failure because: ", ecode.message ());
			Terminate();
		}
	}
	
	void SOCKS4AHandler::SentConnectionSuccess(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			LogPrint (eLogInfo,"--- SOCKS New I2PTunnel connection");
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>((i2p::client::I2PTunnel *)m_parent, m_sock, m_stream);
			m_parent->AddConnection (connection);
			connection->I2PConnect ();
		}
		else
		{
			LogPrint (eLogError,"--- SOCKS Closing socket after sending success because: ", ecode.message ());
			Terminate();
		}
	}
	
	void SOCKS4AHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			m_stream = stream;
			ConnectionSuccess();
		}
		else
		{
			LogPrint (eLogError,"--- SOCKS Issue when creating the stream, check the previous warnings for more info.");
			SocksFailed();
		}
	}


	void SOCKS4AServer::Start ()
	{
		m_Acceptor.listen ();
		Accept ();
	}

	void SOCKS4AServer::Stop ()
	{
		m_Acceptor.close();
		m_Timer.cancel ();
		ClearConnections ();
	}

	void SOCKS4AServer::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&SOCKS4AServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}	

	void SOCKS4AServer::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			LogPrint(eLogDebug,"--- SOCKS accepted");
			new SOCKS4AHandler(this, socket);
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
