#ifndef NTCP_SESSION_H__
#define NTCP_SESSION_H__

#include <inttypes.h>
#include <map>
#include <memory>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>
#include "Crypto.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "DNNPProtocol.h"
#include "TransportSession.h"
#include "CryptoWorker.h"

namespace dotnet
{
namespace transport
{
	struct NTCPPhase1
	{
		uint8_t pubKey[256];
		uint8_t HXxorHI[32];
	};

	struct NTCPPhase2
	{
		uint8_t pubKey[256];
		struct
		{
			uint8_t hxy[32];
			uint8_t timestamp[4];
			uint8_t filler[12];
		} encrypted;
	};

	struct NTCPWork;

	const size_t NTCP_MAX_MESSAGE_SIZE = 16384;
	const size_t NTCP_BUFFER_SIZE = 1028; // fits 1 tunnel data message
	const int NTCP_CONNECT_TIMEOUT = 5; // 5 seconds
	const int NTCP_ESTABLISH_TIMEOUT = 10; // 10 seconds
	const int NTCP_TERMINATION_TIMEOUT = 120; // 2 minutes
	const int NTCP_TERMINATION_CHECK_TIMEOUT = 30; // 30 seconds
	const size_t NTCP_DEFAULT_PHASE3_SIZE = 2/*size*/ + dotnet::data::DEFAULT_IDENTITY_SIZE/*387*/ + 4/*ts*/ + 15/*padding*/ + 40/*signature*/; // 448
	const int NTCP_CLOCK_SKEW = 60; // in seconds
	const int NTCP_MAX_OUTGOING_QUEUE_SIZE = 200; // how many messages we can queue up

	class NTCPServer;
	class NTCPSession: public TransportSession, public std::enable_shared_from_this<NTCPSession>
	{
		public:

			NTCPSession (NTCPServer& server, std::shared_ptr<const dotnet::data::RouterInfo> in_RemoteRouter = nullptr);
			~NTCPSession ();
			void Terminate ();
			void Done ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			boost::asio::io_service & GetService();
			bool IsEstablished () const { return m_IsEstablished; };
			bool IsTerminated () const { return m_IsTerminated; };

			void ClientLogin ();
			void ServerLogin ();
			void SendDNNPMessages (const std::vector<std::shared_ptr<DNNPMessage> >& msgs);

		private:

			void PostDNNPMessages (std::vector<std::shared_ptr<DNNPMessage> > msgs);
			void Connected ();
			void SendTimeSyncMessage ();
			void SetIsEstablished (bool isEstablished) { m_IsEstablished = isEstablished; }

			void CreateAESKey (uint8_t * pubKey);

			// client
			void SendPhase3 ();
			void HandlePhase1Sent (const boost::system::error_code& ecode,  std::size_t bytes_transferred);
			void HandlePhase2Received (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandlePhase2 (NTCPWork * work=nullptr);
			void HandlePhase3Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA);
			void HandlePhase4Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA);

			//server
			void SendPhase2 (NTCPWork * work=nullptr);
			void SendPhase4 (uint32_t tsA, uint32_t tsB);
			void HandlePhase1Received (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandlePhase2Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB);
			void HandlePhase3Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB);
			void HandlePhase3ExtraReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB, size_t paddingLen);
			void HandlePhase3 (uint32_t tsB, size_t paddingLen);
			void HandlePhase4Sent (const boost::system::error_code& ecode,  std::size_t bytes_transferred);

			// common
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			bool DecryptNextBlock (const uint8_t * encrypted);

			void Send (std::shared_ptr<dotnet::DNNPMessage> msg);
			boost::asio::const_buffers_1 CreateMsgBuffer (std::shared_ptr<DNNPMessage> msg);
			void Send (const std::vector<std::shared_ptr<DNNPMessage> >& msgs);
			void HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, std::vector<std::shared_ptr<DNNPMessage> > msgs);

		private:

			NTCPServer& m_Server;
			boost::asio::ip::tcp::socket m_Socket;
			bool m_IsEstablished, m_IsTerminated;

			dotnet::crypto::CBCDecryption m_Decryption;
			dotnet::crypto::CBCEncryption m_Encryption;

			struct Establisher
			{
				NTCPPhase1 phase1;
				NTCPPhase2 phase2;
			} * m_Establisher;

			dotnet::crypto::AESAlignedBuffer<NTCP_BUFFER_SIZE + 16> m_ReceiveBuffer;
			dotnet::crypto::AESAlignedBuffer<16> m_TimeSyncBuffer;
			int m_ReceiveBufferOffset;

			std::shared_ptr<DNNPMessage> m_NextMessage;
			size_t m_NextMessageOffset;
			dotnet::DNNPMessagesHandler m_Handler;

			bool m_IsSending;
			std::vector<std::shared_ptr<DNNPMessage> > m_SendQueue;
	};

	// TODO: move to NTCP.h/.cpp
	class NTCPServer
	{
		public:

			typedef dotnet::worker::ThreadPool<NTCPSession> Pool;

			enum RemoteAddressType
			{
				eIP4Address,
				eIP6Address,
				eHostname
			};

			enum ProxyType
			{
				eNoProxy,
				eSocksProxy,
				eHTTPProxy
			};


			NTCPServer (int workers=4);
			~NTCPServer ();

			void Start ();
			void Stop ();

			bool AddNTCPSession (std::shared_ptr<NTCPSession> session);
			void RemoveNTCPSession (std::shared_ptr<NTCPSession> session);
			std::shared_ptr<NTCPSession> FindNTCPSession (const dotnet::data::IdentHash& ident);
			void ConnectWithProxy (const std::string& addr, uint16_t port, RemoteAddressType addrtype, std::shared_ptr<NTCPSession> conn);
			void Connect(const boost::asio::ip::address & address, uint16_t port, std::shared_ptr<NTCPSession> conn);

			bool IsBoundV4() const { return m_NTCPAcceptor != nullptr; };
			bool IsBoundV6() const { return m_NTCPV6Acceptor != nullptr; };
			bool NetworkIsReady() const { return IsBoundV4() || IsBoundV6() ||	UsingProxy(); };
			bool UsingProxy() const { return m_ProxyType != eNoProxy; };

			void UseProxy(ProxyType proxy, const std::string & address, uint16_t port);

			boost::asio::io_service& GetService () { return m_Service; };

			void SetSessionLimits(uint16_t softLimit, uint16_t hardLimit) { m_SoftLimit = softLimit; m_HardLimit = hardLimit; }
			bool ShouldLimit() const { return ShouldHardLimit() || ShouldSoftLimit(); }
			void Work(std::shared_ptr<NTCPSession> conn, Pool::WorkFunc work)
			{
				m_CryptoPool->Offer({conn, work});
			}
		private:

			/** @brief return true for hard limit */
			bool ShouldHardLimit() const { return m_HardLimit && m_NTCPSessions.size() >= m_HardLimit; }

			/** @brief return true for probabalistic soft backoff */
			bool ShouldSoftLimit() const
			{
				auto sessions = m_NTCPSessions.size();
				return sessions && m_SoftLimit && m_SoftLimit < sessions && ( rand() % sessions ) <= m_SoftLimit;
			}
			void Run ();
			void HandleAccept (std::shared_ptr<NTCPSession> conn, const boost::system::error_code& error);
			void HandleAcceptV6 (std::shared_ptr<NTCPSession> conn, const boost::system::error_code& error);

			void HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCPSession> conn, std::shared_ptr<boost::asio::deadline_timer> timer);

			void HandleProxyConnect(const boost::system::error_code& ecode, std::shared_ptr<NTCPSession> conn, std::shared_ptr<boost::asio::deadline_timer> timer, const std::string & host, uint16_t port, RemoteAddressType adddrtype);
			void AfterSocksHandshake(std::shared_ptr<NTCPSession> conn, std::shared_ptr<boost::asio::deadline_timer> timer, const std::string & host, uint16_t port, RemoteAddressType adddrtype);

			// timer
			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::deadline_timer m_TerminationTimer;
			boost::asio::ip::tcp::acceptor * m_NTCPAcceptor, * m_NTCPV6Acceptor;
			std::map<dotnet::data::IdentHash, std::shared_ptr<NTCPSession> > m_NTCPSessions; // access from m_Thread only
			std::list<std::shared_ptr<NTCPSession> > m_PendingIncomingSessions;

			ProxyType m_ProxyType;
			std::string m_ProxyAddress;
			uint16_t m_ProxyPort;
			boost::asio::ip::tcp::resolver m_Resolver;
			boost::asio::ip::tcp::endpoint * m_ProxyEndpoint;

			std::shared_ptr<Pool> m_CryptoPool;

			uint16_t m_SoftLimit, m_HardLimit;
		public:

			// for HTTP/DotNetControl
			const decltype(m_NTCPSessions)& GetNTCPSessions () const { return m_NTCPSessions; };
	};
}
}

#endif
