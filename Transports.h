#ifndef TRANSPORTS_H__
#define TRANSPORTS_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <map>
#include <vector>
#include <queue>
#include <string>
#include <memory>
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

	struct Peer
	{
		int numAttempts;
		std::shared_ptr<const i2p::data::RouterInfo> router;
		std::shared_ptr<TransportSession> session;
		uint64_t creationTime;
		std::vector<i2p::I2NPMessage *> delayedMessages;

		~Peer ()
		{
			for (auto it :delayedMessages)
				i2p::DeleteI2NPMessage (it);			
		}	
	};	
	
	const size_t SESSION_CREATION_TIMEOUT = 10; // in seconds
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

			void SendMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg);
			void SendMessages (const i2p::data::IdentHash& ident, const std::vector<i2p::I2NPMessage *>& msgs);
			void CloseSession (std::shared_ptr<const i2p::data::RouterInfo> router);

			void PeerConnected (std::shared_ptr<TransportSession> session);
			void PeerDisconnected (std::shared_ptr<TransportSession> session);
			
		private:

			void Run ();
			void RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident);
			void HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident);
			void PostMessage (i2p::data::IdentHash ident, i2p::I2NPMessage * msg);
			void PostMessages (i2p::data::IdentHash ident, std::vector<i2p::I2NPMessage *> msgs);
			void PostCloseSession (std::shared_ptr<const i2p::data::RouterInfo> router);
			bool ConnectToPeer (const i2p::data::IdentHash& ident, Peer& peer);
			void HandlePeerCleanupTimer (const boost::system::error_code& ecode);			

			void NTCPResolve (const std::string& addr, const i2p::data::IdentHash& ident);
			void HandleNTCPResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it,
 				i2p::data::IdentHash ident, std::shared_ptr<boost::asio::ip::tcp::resolver> resolver);

			void DetectExternalIP ();
			
		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::deadline_timer m_PeerCleanupTimer;

			NTCPServer * m_NTCPServer;
			SSUServer * m_SSUServer;
			std::map<i2p::data::IdentHash, Peer> m_Peers;
			
			DHKeysPairSupplier m_DHKeysPairSupplier;

		public:

			// for HTTP only
			const NTCPServer * GetNTCPServer () const { return m_NTCPServer; };
			const SSUServer * GetSSUServer () const { return m_SSUServer; };
			const decltype(m_Peers)& GetPeers () const { return m_Peers; };
	};	

	extern Transports transports;
}	
}

#endif
