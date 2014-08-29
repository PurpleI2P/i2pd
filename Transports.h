#ifndef TRANSPORTS_H__
#define TRANSPORTS_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>
#include <queue>
#include <string>
#include <boost/asio.hpp>
#include "NTCPSession.h"
#include "SSU.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "Identity.h"

namespace i2p
{
	class DHKeysPairSupplier
	{
		public:

			DHKeysPairSupplier (int size): m_QueueSize (size), m_IsRunning (false), m_Thread (nullptr) {};
			~DHKeysPairSupplier ();
			void Start ();
			void Stop ();
			i2p::data::DHKeysPair * Acquire ();

		private:

			void Run ();
			void CreateDHKeysPairs (int num);

		private:

			int m_QueueSize;
			std::queue<i2p::data::DHKeysPair *> m_Queue;

			bool m_IsRunning;
			std::thread * m_Thread;	
			std::condition_variable m_Acquired;
			std::mutex m_AcquiredMutex;
	};

	class Transports
	{
		public:

			Transports ();
			~Transports ();

			void Start ();
			void Stop ();
			
			boost::asio::io_service& GetService () { return m_Service; };
			i2p::data::DHKeysPair * GetNextDHKeysPair ();	

			void AddNTCPSession (i2p::ntcp::NTCPSession * session);
			void RemoveNTCPSession (i2p::ntcp::NTCPSession * session);
			
			i2p::ntcp::NTCPSession * GetNextNTCPSession ();
			i2p::ntcp::NTCPSession * FindNTCPSession (const i2p::data::IdentHash& ident);

			void SendMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg);
			void CloseSession (const i2p::data::RouterInfo * router);
			
		private:

			void Run ();
			void HandleAccept (i2p::ntcp::NTCPServerConnection * conn, const boost::system::error_code& error);
			void HandleResendTimer (const boost::system::error_code& ecode, boost::asio::deadline_timer * timer,
				const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg);
			void PostMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg);
			void PostCloseSession (const i2p::data::RouterInfo * router);
			
			void DetectExternalIP ();
			
		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::tcp::acceptor * m_NTCPAcceptor;

			std::map<i2p::data::IdentHash, i2p::ntcp::NTCPSession *> m_NTCPSessions;
			i2p::ssu::SSUServer * m_SSUServer;

			DHKeysPairSupplier m_DHKeysPairSupplier;

		public:

			// for HTTP only
			const decltype(m_NTCPSessions)& GetNTCPSessions () const { return m_NTCPSessions; };
			const i2p::ssu::SSUServer * GetSSUServer () const { return m_SSUServer; };
	};	

	extern Transports transports;
}	

#endif
