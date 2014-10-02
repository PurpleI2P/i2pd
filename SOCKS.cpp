#include "SOCKS.h"
#include "Identity.h"
#include "NetDb.h"
#include <cstring>
#include <stdexcept>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind.hpp>

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
						      boost::bind(&SOCKS4AHandler::HandleSockRecv, this,
								  boost::asio::placeholders::error,
								  boost::asio::placeholders::bytes_transferred));
			} else { 
				m_sock->async_receive(boost::asio::buffer(m_sock_buff, socks_buffer_size),
						      boost::bind(&SOCKS4AHandler::HandleSockForward, this,
								  boost::asio::placeholders::error,
								  boost::asio::placeholders::bytes_transferred));
			}
		} else {
			LogPrint("--- socks4a no socket for read");
		}
	}
	
	void SOCKS4AHandler::AsyncStreamRead()
	{
		
		LogPrint("--- socks4a async stream read");
		if (m_stream) {
			m_stream->AsyncReceive(
				boost::asio::buffer(m_stream_buff, socks_buffer_size),
				boost::bind(&SOCKS4AHandler::HandleStreamRecv, this,
					    boost::asio::placeholders::error, 
					    boost::asio::placeholders::bytes_transferred), socks_timeout);
		} else {
			LogPrint("--- socks4a no stream for read");
		}
	}

        void SOCKS4AHandler::Terminate() {
                CloseStream();
                CloseSock();
                delete this; // ew
        }
	
	void SOCKS4AHandler::SocksFailed()
	{
		LogPrint("--- socks4a failed");
		m_sock->send(boost::asio::buffer("\x00\x5b 12345"));
		Terminate();
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
			delete m_stream;
			m_stream = nullptr;
		}
	}

	const size_t socks_hostname_size = 1024;
	const size_t socks_ident_size = 1024;
	const size_t destb32_len = 52;
	
	void SOCKS4AHandler::HandleSockForward(const boost::system::error_code & ecode, std::size_t len)
	{
		if(ecode) {
			LogPrint("--- socks4a forward got error: ", ecode);
			Terminate();
			return;
		}
		
		LogPrint("--- socks4a sock forward: ", len);
		m_stream->Send(m_sock_buff, len);
	}

	void SOCKS4AHandler::HandleSockRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		LogPrint("--- socks4a sock recv: ", len);
		
		if(ecode) {
			LogPrint(" --- sock recv got error: ", ecode);
                        Terminate();
			return;
		}

		if (m_state == INITIAL) {

			char hostbuff[socks_hostname_size];
			char identbuff[socks_ident_size];
			std::memset(hostbuff, 0, sizeof(hostbuff));
			std::memset(identbuff, 0, sizeof(hostbuff));
			std::string dest;
			// get port
			uint16_t port = 0;
			uint16_t idx1 = 0;
			uint16_t idx2 = 0;
				
			LogPrint("--- socks4a state initial ", len);

			// check valid request
			if( m_sock_buff[0] != 4 || m_sock_buff[1] != 1 || m_sock_buff[len-1] ) {
				LogPrint("--- socks4a rejected invalid");
				SocksFailed();
				return;
			}

			// get port
			port = m_sock_buff[3] | m_sock_buff[2] << 8;

			// read ident 
			do {
				LogPrint("--- socks4a ", (int) m_sock_buff[9+idx1]);
				identbuff[idx1] = m_sock_buff[8+idx1];
			} while( identbuff[idx1++] && idx1 < socks_ident_size );

			LogPrint("--- socks4a ident ", identbuff);
			// read hostname
			do {
				hostbuff[idx2] = m_sock_buff[8+idx1+idx2];
			} while( hostbuff[idx2++] && idx2 < socks_hostname_size );

			LogPrint("--- socks4a requested ", hostbuff, ":" , port);

			dest = std::string(hostbuff);
			if(dest.find(".b32.i2p") == std::string::npos) {
				LogPrint("--- socks4a invalid hostname: ", dest);
				SocksFailed();
				return;
			}
				
			if ( i2p::data::Base32ToByteStream(hostbuff, destb32_len, (uint8_t *) m_dest, 32) != 32 ) {
				LogPrint("--- sock4a invalid b32: ", dest);
			}
			
			LogPrint("--- sock4a find lease set");
			m_ls = i2p::data::netdb.FindLeaseSet(m_dest);
			if (!m_ls || m_ls->HasNonExpiredLeases()) {
				i2p::data::netdb.Subscribe(m_dest);
				m_ls_timer.expires_from_now(boost::posix_time::seconds(socks_leaseset_timeout));
				m_ls_timer.async_wait(boost::bind(&SOCKS4AHandler::LeaseSetTimeout, this, boost::asio::placeholders::error));
			} else {
				ConnectionSuccess();
			}
		} else {
			LogPrint("--- socks4a state?? ", m_state);
		}
	}
	
	void SOCKS4AHandler::HandleStreamRecv(const boost::system::error_code & ecode, std::size_t len)
	{
		if(ecode) { LogPrint("--- socks4a stream recv error: ", ecode); m_state = END; }
		switch(m_state) {
		case INITIAL:
		case END:
			Terminate();
                        return;
		case OKAY:
			LogPrint("--- socks4a stream recv ", len);
			boost::asio::async_write(*m_sock, boost::asio::buffer(m_stream_buff, len), 
						 boost::bind(&SOCKS4AHandler::StreamWrote, this, 
							     boost::asio::placeholders::error));
		}
	}
	
	void SOCKS4AHandler::SockWrote(const boost::system::error_code & ecode)
	{
		LogPrint("--- socks4a sock wrote");
		if(ecode) { LogPrint("--- socks4a SockWrote error: ",ecode); }
		else { AsyncSockRead(); }
	}

	void SOCKS4AHandler::StreamWrote(const boost::system::error_code & ecode)
	{
		
		LogPrint("--- socks4a stream wrote");
		if(ecode) { LogPrint("--- socks4a StreamWrote error: ",ecode); }
		else { AsyncStreamRead(); }
	}

	void SOCKS4AHandler::LeaseSetTimeout(const boost::system::error_code & ecode)
	{
		m_ls = i2p::data::netdb.FindLeaseSet(m_dest);
		if(m_ls) {
			ConnectionSuccess();
		} else {
			LogPrint("--- socks4a ls timeout");
			SocksFailed();
		}
	}

	void SOCKS4AHandler::ConnectionSuccess()
	{
		LogPrint("--- socks4a connection success");
		boost::asio::async_write(*m_sock, boost::asio::buffer("\x00\x5a 12345"),
					 boost::bind(&SOCKS4AHandler::SentConnectionSuccess, this,
						     boost::asio::placeholders::error));
	}

	void SOCKS4AHandler::SentConnectionSuccess(const boost::system::error_code & ecode)
	{
		LogPrint("--- socks4a making connection");
		m_stream = i2p::stream::CreateStream(*m_ls);
		m_state = OKAY;
		LogPrint("--- socks4a state is ", m_state);
		AsyncSockRead();
		AsyncStreamRead();
	}

	void SOCKS4AServer::Run()
	{
		LogPrint("--- socks4a run");
		m_run = true;
		while(m_run) {
			try {
				m_ios.run();
			} catch (std::runtime_error & exc) {
				LogPrint("--- socks4a exception: ", exc.what());
			}
		}
	}
	
	void SOCKS4AServer::Accept()
	{
		m_new_sock = new boost::asio::ip::tcp::socket(m_ios);
		m_acceptor.async_accept(*m_new_sock, 
					boost::bind(
						&SOCKS4AServer::HandleAccept, this, boost::asio::placeholders::error));
	}

	void SOCKS4AServer::Start()
	{
                m_run = true;
		m_thread = new std::thread(std::bind(&SOCKS4AServer::Run, this));
		m_acceptor.listen();
		Accept();
	}
	
	void SOCKS4AServer::Stop()
	{
		m_acceptor.close();
		m_run = false;
		m_ios.stop();
		if (m_thread) {
			m_thread->join();
			delete m_thread;
			m_thread = nullptr;
		}
	}
		
	void SOCKS4AServer::HandleAccept(const boost::system::error_code & ecode)
	{
		if (!ecode) {
			LogPrint("--- socks4a accepted");
			new SOCKS4AHandler(&m_ios, m_new_sock);
			Accept();
		}
	}
}
}
