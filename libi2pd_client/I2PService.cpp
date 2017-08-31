#include "Destination.h"
#include "Identity.h"
#include "ClientContext.h"
#include "I2PService.h"
#include <boost/asio/error.hpp>

namespace i2p
{
namespace client
{
	static const i2p::data::SigningKeyType I2P_SERVICE_DEFAULT_KEY_TYPE = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256;

	I2PService::I2PService (std::shared_ptr<ClientDestination> localDestination):
		m_LocalDestination (localDestination ? localDestination :
			i2p::client::context.CreateNewLocalDestination (false, I2P_SERVICE_DEFAULT_KEY_TYPE)),
    m_ReadyTimer(m_LocalDestination->GetService()),
		m_ConnectTimeout(0),
			isUpdated (true)
	{
		m_LocalDestination->Acquire ();
	}

	I2PService::I2PService (i2p::data::SigningKeyType kt):
		m_LocalDestination (i2p::client::context.CreateNewLocalDestination (false, kt)),
		m_ReadyTimer(m_LocalDestination->GetService()),
		m_ConnectTimeout(0),
		isUpdated (true)
	{
		m_LocalDestination->Acquire ();
	}

	I2PService::~I2PService ()
	{
		ClearHandlers ();
		if (m_LocalDestination) m_LocalDestination->Release ();
	}

	void I2PService::ClearHandlers ()
	{
		if(m_ConnectTimeout)
			m_ReadyTimer.cancel();
		std::unique_lock<std::mutex> l(m_HandlersMutex);
		for (auto it: m_Handlers)
			it->Terminate ();
		m_Handlers.clear();
	}

	void I2PService::SetConnectTimeout(uint32_t timeout)
	{
		if(timeout && !m_ConnectTimeout)
		{
				TriggerReadyCheckTimer();
		}
		else if (m_ConnectTimeout && !timeout)
		{
			m_ReadyTimer.cancel();
		}
		m_ConnectTimeout = timeout;
	}

	void I2PService::AddReadyCallback(ReadyCallback cb)
	{
		uint32_t now = i2p::util::GetSecondsSinceEpoch();
		uint32_t tm = now + m_ConnectTimeout;
		LogPrint(eLogDebug, "I2PService::AddReadyCallback() ", tm, " ", now);
		m_ReadyCallbacks.push_back({cb, tm});
	}

	void I2PService::TriggerReadyCheckTimer()
	{
		m_ReadyTimer.expires_from_now(boost::posix_time::seconds (1));
		m_ReadyTimer.async_wait(std::bind(&I2PService::HandleReadyCheckTimer, this, std::placeholders::_1));
	}

	void I2PService::HandleReadyCheckTimer(const boost::system::error_code &ec)
	{
		if(ec || m_LocalDestination->IsReady())
		{
			for(auto & itr : m_ReadyCallbacks)
				itr.first(ec);
			m_ReadyCallbacks.clear();
		}
		else if(!m_LocalDestination->IsReady())
		{
			// expire timed out requests
			uint32_t now = i2p::util::GetSecondsSinceEpoch ();
			auto itr = m_ReadyCallbacks.begin();
			while(itr != m_ReadyCallbacks.end())
			{
				if(itr->second >= now)
				{
					itr->first(boost::asio::error::timed_out);
					itr = m_ReadyCallbacks.erase(itr);
				}
				else
					++itr;
			}
		}
		if(!ec)
			TriggerReadyCheckTimer();
	}

	void I2PService::CreateStream (StreamRequestComplete streamRequestComplete, const std::string& dest, int port) {
		assert(streamRequestComplete);
		i2p::data::IdentHash identHash;
		if (i2p::client::context.GetAddressBook ().GetIdentHash (dest, identHash))
		{
			CreateStream(streamRequestComplete, identHash, port);
		}
		else
		{
			LogPrint (eLogWarning, "I2PService: Remote destination not found: ", dest);
			streamRequestComplete (nullptr);
		}
	}

	void I2PService::CreateStream(StreamRequestComplete streamRequestComplete, const i2p::data::IdentHash & identHash, int port)
	{
		if(m_ConnectTimeout)
		{
			if(m_LocalDestination->IsReady())
				m_LocalDestination->CreateStream (streamRequestComplete, identHash, port);
			else
			{
				AddReadyCallback([this, streamRequestComplete, identHash, port] (const boost::system::error_code & ec) {
						if(ec)
						{
							LogPrint(eLogWarning, "I2PService::CeateStream() ", ec.message());
							streamRequestComplete(nullptr);
						}
						else
							this->m_LocalDestination->CreateStream(streamRequestComplete, identHash, port);
					});
			}
		}
		else
			m_LocalDestination->CreateStream(streamRequestComplete, identHash, port);
	}

	TCPIPPipe::TCPIPPipe(I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> upstream, std::shared_ptr<boost::asio::ip::tcp::socket> downstream) : I2PServiceHandler(owner), m_up(upstream), m_down(downstream)
	{
		boost::asio::socket_base::receive_buffer_size option(TCP_IP_PIPE_BUFFER_SIZE);
		upstream->set_option(option);
		downstream->set_option(option);
	}

	TCPIPPipe::~TCPIPPipe()
	{
		Terminate();
	}

	void TCPIPPipe::Start()
	{
		AsyncReceiveUpstream();
		AsyncReceiveDownstream();
	}

	void TCPIPPipe::Terminate()
	{
		if(Kill()) return;
		if (m_up) {
			if (m_up->is_open()) {
				m_up->close();
			}
			m_up = nullptr;
		}
		if (m_down) {
			if (m_down->is_open()) {
				m_down->close();
			}
			m_down = nullptr;
		}
		Done(shared_from_this());
	}

	void TCPIPPipe::AsyncReceiveUpstream()
	{
		if (m_up) {
			m_up->async_read_some(boost::asio::buffer(m_upstream_to_down_buf, TCP_IP_PIPE_BUFFER_SIZE),
															std::bind(&TCPIPPipe::HandleUpstreamReceived, shared_from_this(),
																				std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError, "TCPIPPipe: upstream receive: no socket");
		}
	}

	void TCPIPPipe::AsyncReceiveDownstream()
	{
		if (m_down) {
			m_down->async_read_some(boost::asio::buffer(m_downstream_to_up_buf, TCP_IP_PIPE_BUFFER_SIZE),
															std::bind(&TCPIPPipe::HandleDownstreamReceived, shared_from_this(),
																				std::placeholders::_1, std::placeholders::_2));
		} else {
			LogPrint(eLogError, "TCPIPPipe: downstream receive: no socket");
		}
	}

	void TCPIPPipe::UpstreamWrite(size_t len)
	{
		if (m_up) {
			LogPrint(eLogDebug, "TCPIPPipe: upstream: ", (int) len, " bytes written");
			boost::asio::async_write(*m_up, boost::asio::buffer(m_upstream_buf, len),
															 boost::asio::transfer_all(),
															 std::bind(&TCPIPPipe::HandleUpstreamWrite,
																				 shared_from_this(),
																				 std::placeholders::_1)
															 );
		} else {
			LogPrint(eLogError, "TCPIPPipe: upstream write: no socket");
		}
	}

	void TCPIPPipe::DownstreamWrite(size_t len)
	{
		if (m_down) {
			LogPrint(eLogDebug, "TCPIPPipe: downstream: ", (int) len, " bytes written");
			boost::asio::async_write(*m_down, boost::asio::buffer(m_downstream_buf, len),
															 boost::asio::transfer_all(),
															 std::bind(&TCPIPPipe::HandleDownstreamWrite,
																				 shared_from_this(),
																				 std::placeholders::_1)
															 );
		} else {
			LogPrint(eLogError, "TCPIPPipe: downstream write: no socket");
		}
	}


	void TCPIPPipe::HandleDownstreamReceived(const boost::system::error_code & ecode, std::size_t bytes_transfered)
	{
		LogPrint(eLogDebug, "TCPIPPipe: downstream: ", (int) bytes_transfered, " bytes received");
		if (ecode) {
			LogPrint(eLogError, "TCPIPPipe: downstream read error:" , ecode.message());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate();
		} else {
			if (bytes_transfered > 0 ) {
				memcpy(m_upstream_buf, m_downstream_to_up_buf, bytes_transfered);
			}
			UpstreamWrite(bytes_transfered);
		}
	}

	void TCPIPPipe::HandleDownstreamWrite(const boost::system::error_code & ecode) {
		if (ecode) {
			LogPrint(eLogError, "TCPIPPipe: downstream write error:" , ecode.message());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate();
		} else {
			AsyncReceiveUpstream();
		}
	}

	void TCPIPPipe::HandleUpstreamWrite(const boost::system::error_code & ecode) {
		if (ecode) {
			LogPrint(eLogError, "TCPIPPipe: upstream write error:" , ecode.message());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate();
		} else {
			AsyncReceiveDownstream();
		}
	}

	void TCPIPPipe::HandleUpstreamReceived(const boost::system::error_code & ecode, std::size_t bytes_transfered)
	{
		LogPrint(eLogDebug, "TCPIPPipe: upstream ", (int)bytes_transfered, " bytes received");
		if (ecode) {
			LogPrint(eLogError, "TCPIPPipe: upstream read error:" , ecode.message());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate();
		} else {
			if (bytes_transfered > 0 ) {
				memcpy(m_downstream_buf, m_upstream_to_down_buf, bytes_transfered);
			}
			DownstreamWrite(bytes_transfered);
		}
	}

	void TCPIPAcceptor::Start ()
	{
		m_Acceptor.reset (new boost::asio::ip::tcp::acceptor (GetService (), m_LocalEndpoint));
		m_Acceptor->listen ();
		Accept ();
	}

	void TCPIPAcceptor::Stop ()
	{
		if (m_Acceptor)
		{
			m_Acceptor->close();
			m_Acceptor.reset (nullptr);
		}
		m_Timer.cancel ();
		ClearHandlers();
	}

	void TCPIPAcceptor::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (GetService ());
		m_Acceptor->async_accept (*newSocket, std::bind (&TCPIPAcceptor::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void TCPIPAcceptor::HandleAccept (const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (!ecode)
		{
			LogPrint(eLogDebug, "I2PService: ", GetName(), " accepted");
			auto handler = CreateHandler(socket);
			if (handler)
			{
				AddHandler(handler);
				handler->Handle();
			}
			else
				socket->close();
			Accept();
		}
		else
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogError, "I2PService: ", GetName(), " closing socket on accept because: ", ecode.message ());
		}
	}
}
}
