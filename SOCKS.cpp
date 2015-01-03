#include "SOCKS.h"
#include "Identity.h"
#include "NetDb.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PEndian.h"
#include <cstring>

namespace i2p
{
namespace proxy
{
	const uint8_t socks_leaseset_timeout = 10;
	const uint8_t socks_timeout = 60;

	void SOCKS4AHandler::AsyncSockRead()
	{
		LogPrint("--- socks4a async sock read");
		if(m_sock) {
			if (m_state == INITIAL) {
				m_sock->async_receive(boost::asio::buffer(m_sock_buff, socks_buffer_size),
						      std::bind(&SOCKS4AHandler::HandleSockRecv, this,
								 std::placeholders::_1, std::placeholders::_2));
			} else {
				LogPrint("--- socks4a state?? ", m_state);
			}
		} else {
			LogPrint("--- socks4a no socket for read");
		}
	}

	void SOCKS4AHandler::Terminate() {
		CloseStream();
		CloseSock();
		delete this; // HACK: ew
	}

	void SOCKS4AHandler::SocksFailed()
	{
		LogPrint("--- socks4a failed");
		//TODO: send the right response
		boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5b 12345"),
					 std::bind(&SOCKS4AHandler::SentSocksFailed, this,
						     std::placeholders::_1));
	}

	void SOCKS4AHandler::CloseSock()
	{
		if (m_sock) {
			LogPrint("--- socks4a close sock");
			m_sock->close();
			delete m_sock;
			m_sock = nullptr;
		}
	}

       void SOCKS4AHandler::CloseStream()
       {
               if (m_stream) {
                       LogPrint("--- socks4a close stream");
                       m_stream.reset ();
               }
       }

	const size_t socks_hostname_size = 1024;
	const size_t socks_ident_size = 1024;
	const size_t destb32_len = 52;

	void SOCKS4AHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint("--- socks4a sock recv: ", len);
		//TODO: we may not have received all the data :(
		if(ecode) {
			LogPrint(" --- sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		char hostbuff[socks_hostname_size];
		char identbuff[socks_ident_size];
		std::memset(hostbuff, 0, sizeof(hostbuff));
		std::memset(identbuff, 0, sizeof(hostbuff));
		std::string dest;

		uint16_t port = 0;
		uint32_t address = 0;
		uint16_t idx1 = 0;
		uint16_t idx2 = 0;

		LogPrint(eLogDebug,"--- socks4a state initial ", len);

		// check valid request
		if( m_sock_buff[0] != 4 || m_sock_buff[1] != 1 || m_sock_buff[len-1] ) {
			LogPrint(eLogError,"--- socks4a rejected invalid");
			SocksFailed();
			return;
		}

		// get port
		port = bufbe16toh(m_sock_buff + 2);
		
		// get address
		address = bufbe32toh(m_sock_buff + 4);

		// check valid request
		if( address == 0 || address > 255 ) {
			LogPrint(eLogError,"--- socks4a rejected because it's actually socks4");
			SocksFailed();
			return;
		}

		// read ident 
		do {
			LogPrint(eLogDebug,"--- socks4a ", (int) m_sock_buff[9+idx1]);
			identbuff[idx1] = m_sock_buff[8+idx1];
		} while( identbuff[idx1++] && idx1 < socks_ident_size );

		LogPrint(eLogInfo,"--- socks4a ident ", identbuff);
		// read hostname
		do {
			hostbuff[idx2] = m_sock_buff[8+idx1+idx2];
		} while( hostbuff[idx2++] && idx2 < socks_hostname_size );

		LogPrint(eLogInfo,"--- socks4a requested ", hostbuff, ":" , port);

		dest = std::string(hostbuff);
		if(dest.find(".i2p") == std::string::npos) {
			LogPrint("--- socks4a invalid hostname: ", dest);
			SocksFailed();
			return;
		}
		
		m_parent->GetLocalDestination ()->CreateStream (
				std::bind (&SOCKS4AHandler::HandleStreamRequestComplete,
				this, std::placeholders::_1), dest);
	}
	
	void SOCKS4AHandler::ConnectionSuccess()
	{
		LogPrint(eLogInfo,"--- socks4a connection success");
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
			LogPrint (eLogError,"--- socks4a Closing socket after sending failure because: ", ecode.message ());
			Terminate();
		}
	}
	
	void SOCKS4AHandler::SentConnectionSuccess(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			LogPrint (eLogInfo,"--- socks4a New I2PTunnel connection");
			auto connection = std::make_shared<i2p::client::I2PTunnelConnection>((i2p::client::I2PTunnel *)m_parent, m_sock, m_stream);
			m_parent->AddConnection (connection);
			connection->I2PConnect ();
		}
		else
		{
			LogPrint (eLogError,"--- socks4a Closing socket after sending success because: ", ecode.message ());
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
			LogPrint (eLogError,"--- socks4a Issue when creating the stream, check the previous warnings for more info.");
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
			LogPrint(eLogDebug,"--- socks4a accepted");
			new SOCKS4AHandler(this, socket);
			Accept();
		}
		else
		{
			LogPrint (eLogError,"--- socks4a Closing socket on accept because: ", ecode.message ());
			delete socket;
		}
	}

}
}
