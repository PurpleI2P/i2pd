#ifndef TRANSPORTS_H__
#define TRANSPORTS_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>
#include <queue>
#include <string>
#include <cryptopp/osrng.h>
#include <boost/asio.hpp>
#include "TransportSession.h"
#include "NTCPSession.h"
#include "SSU.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "Identity.h"

namespace i2p
{
namespace transport
{
	class DHKeysPairSupplier
	{
		public:

			DHKeysPairSupplier (int size);
			~DHKeysPairSupplier ();
			void Start ();
			void Stop ();
			DHKeysPair * Acquire ();
			void Return (DHKeysPair * pair);

		private:

			void Run ();
			void CreateDHKeysPairs (int num);

		private:

			const int m_QueueSize;
			std::queue<DHKeysPair *> m_Queue;

			bool m_IsRunning;
			std::thread * m_Thread;	
			std::condition_variable m_Acquired;
			std::mutex m_AcquiredMutex;
			CryptoPP::AutoSeededRandomPool m_Rnd;
	};

	class Transports
	{
		public:

			Transports ();
			~Transports ();

			void Start ();
			void Stop ();
			
			boost::asio::io_service& GetService () { return m_Service; };
			i2p::transport::DHKeysPair * GetNextDHKeysPair ();	
			void ReuseDHKeysPair (DHKeysPair * pair);

			void AddNTCPSession (NTCPSession * session);
			void RemoveNTCPSession (NTCPSession * session);
			
			NTCPSession * GetNextNTCPSession ();
			NTCPSession * FindNTCPSession (const i2p::data::IdentHash& ident);

			void SendMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg);
			void CloseSession (const i2p::data::RouterInfo * router);
			
		private:

			void Run ();
			void HandleAccept (NTCPServerConnection * conn, const boost::system::error_code& error);
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

			std::map<i2p::data::IdentHash, NTCPSession *> m_NTCPSessions;
			SSUServer * m_SSUServer;

			DHKeysPairSupplier m_DHKeysPairSupplier;

		public:

			// for HTTP only
			const decltype(m_NTCPSessions)& GetNTCPSessions () const { return m_NTCPSessions; };
			const SSUServer * GetSSUServer () const { return m_SSUServer; };
	};	

	extern Transports transports;
}	
}

#endif
