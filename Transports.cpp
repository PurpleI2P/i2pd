#include "Log.h"
#include "Crypto.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "NetDb.h"
#include "Transports.h"

using namespace i2p::data;

namespace i2p
{
namespace transport
{
	DHKeysPairSupplier::DHKeysPairSupplier (int size):
		m_QueueSize (size), m_IsRunning (false), m_Thread (nullptr)
	{
	}	

	DHKeysPairSupplier::~DHKeysPairSupplier ()
	{
		Stop ();
	}

	void DHKeysPairSupplier::Start ()
	{
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&DHKeysPairSupplier::Run, this));
	}

	void DHKeysPairSupplier::Stop ()
	{
		m_IsRunning = false;
		m_Acquired.notify_one ();	
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
	}

	void DHKeysPairSupplier::Run ()
	{
		while (m_IsRunning)
		{
			int num;
			while ((num = m_QueueSize - m_Queue.size ()) > 0)
				CreateDHKeysPairs (num);
			std::unique_lock<std::mutex>	l(m_AcquiredMutex);
			m_Acquired.wait (l); // wait for element gets aquired
		}
	}		

	void DHKeysPairSupplier::CreateDHKeysPairs (int num)
	{
		if (num > 0)
		{
			i2p::crypto::DHKeys dh;
			for (int i = 0; i < num; i++)
			{
				auto pair = std::make_shared<i2p::crypto::DHKeys> ();
				pair->GenerateKeys ();
				std::unique_lock<std::mutex>	l(m_AcquiredMutex);
				m_Queue.push (pair);
			}
		}
	}

	std::shared_ptr<i2p::crypto::DHKeys> DHKeysPairSupplier::Acquire ()
	{
		{
			std::unique_lock<std::mutex>	l(m_AcquiredMutex);
			if (!m_Queue.empty ())
			{
				auto pair = m_Queue.front ();
				m_Queue.pop ();
				m_Acquired.notify_one ();
				return pair;
			}	
		}	
		// queue is empty, create new
		auto pair = std::make_shared<i2p::crypto::DHKeys> ();
		pair->GenerateKeys ();
		return pair;
	}

	void DHKeysPairSupplier::Return (std::shared_ptr<i2p::crypto::DHKeys> pair)
	{
		std::unique_lock<std::mutex>	l(m_AcquiredMutex);
		m_Queue.push (pair);
	}

	Transports transports;	
	
	Transports::Transports (): 
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service), m_PeerCleanupTimer (m_Service),
		m_NTCPServer (nullptr), m_SSUServer (nullptr), m_DHKeysPairSupplier (5), // 5 pre-generated keys
		m_TotalSentBytes(0), m_TotalReceivedBytes(0), m_InBandwidth (0), m_OutBandwidth (0),
		m_LastInBandwidthUpdateBytes (0), m_LastOutBandwidthUpdateBytes (0), m_LastBandwidthUpdateTime (0)	
	{		
	}
		
	Transports::~Transports () 
	{ 
		Stop ();
	}	

	void Transports::Start (bool enableNTCP, bool enableSSU)
	{
		m_DHKeysPairSupplier.Start ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&Transports::Run, this));
		// create acceptors
		auto& addresses = context.GetRouterInfo ().GetAddresses ();
		for (auto address : addresses)
		{
			if (!m_NTCPServer && enableNTCP)
			{
				m_NTCPServer = new NTCPServer ();
				m_NTCPServer->Start ();
				if (!(m_NTCPServer->IsBoundV6() || m_NTCPServer->IsBoundV4())) {
					/** failed to bind to NTCP */
					LogPrint(eLogError, "Transports: failed to bind to TCP");
					m_NTCPServer->Stop();
					delete m_NTCPServer;
					m_NTCPServer = nullptr;
				}
			}	
			
			if (address->transportStyle == RouterInfo::eTransportSSU && address->host.is_v4 ())
			{
				if (!m_SSUServer && enableSSU)
				{	
					m_SSUServer = new SSUServer (address->port);
					LogPrint (eLogInfo, "Transports: Start listening UDP port ", address->port);
					try {
						m_SSUServer->Start ();
					} catch ( std::exception & ex ) {
						LogPrint(eLogError, "Transports: Failed to bind to UDP port", address->port);
						delete m_SSUServer;
						m_SSUServer = nullptr;
						continue;
					}
					DetectExternalIP ();
				}
				else
					LogPrint (eLogError, "Transports: SSU server already exists");
			}
		}	
		m_PeerCleanupTimer.expires_from_now (boost::posix_time::seconds(5*SESSION_CREATION_TIMEOUT));
		m_PeerCleanupTimer.async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));
	}
		
	void Transports::Stop ()
	{	
		m_PeerCleanupTimer.cancel ();	
		m_Peers.clear ();
		if (m_SSUServer)
		{
			m_SSUServer->Stop ();
			delete m_SSUServer;
			m_SSUServer = nullptr;
		}	
		if (m_NTCPServer)
		{
			m_NTCPServer->Stop ();
			delete m_NTCPServer;
			m_NTCPServer = nullptr;
		}	

		m_DHKeysPairSupplier.Stop ();
		m_IsRunning = false;
		m_Service.stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = nullptr;
		}	
	}	

	void Transports::Run () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Transports: runtime exception: ", ex.what ());
			}	
		}	
	}
		
	void Transports::UpdateBandwidth ()
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (m_LastBandwidthUpdateTime > 0)
		{
			auto delta = ts - m_LastBandwidthUpdateTime;
			if (delta > 0)
			{
				m_InBandwidth = (m_TotalReceivedBytes - m_LastInBandwidthUpdateBytes)*1000/delta; // per second 
				m_OutBandwidth = (m_TotalSentBytes - m_LastOutBandwidthUpdateBytes)*1000/delta; // per second 
			} 
		}
		m_LastBandwidthUpdateTime = ts;
		m_LastInBandwidthUpdateBytes = m_TotalReceivedBytes;	
		m_LastOutBandwidthUpdateBytes = m_TotalSentBytes;		
	}

	bool Transports::IsBandwidthExceeded () const
	{
		auto limit = i2p::context.GetBandwidthLimit() * 1024; // convert to bytes
		auto bw = std::max (m_InBandwidth, m_OutBandwidth);
		return bw > limit;
	}

	void Transports::SendMessage (const i2p::data::IdentHash& ident, std::shared_ptr<i2p::I2NPMessage> msg)
	{
		SendMessages (ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > {msg });															
	}	

	void Transports::SendMessages (const i2p::data::IdentHash& ident, const std::vector<std::shared_ptr<i2p::I2NPMessage> >& msgs)
	{
		m_Service.post (std::bind (&Transports::PostMessages, this, ident, msgs));
	}	

	void Transports::PostMessages (i2p::data::IdentHash ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > msgs)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
		{	
			// we send it to ourself
			for (auto it: msgs)
				i2p::HandleI2NPMessage (it);
			return;
		}	
		auto it = m_Peers.find (ident);
		if (it == m_Peers.end ())
		{
			bool connected = false; 
			try
			{
				auto r = netdb.FindRouter (ident);
				{
					std::unique_lock<std::mutex>	l(m_PeersMutex);	
					it = m_Peers.insert (std::pair<i2p::data::IdentHash, Peer>(ident, { 0, r, {},
						i2p::util::GetSecondsSinceEpoch (), {} })).first;
				}
				connected = ConnectToPeer (ident, it->second);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Transports: PostMessages exception:", ex.what ());
			}
			if (!connected) return;
		}	
		if (!it->second.sessions.empty ())
			it->second.sessions.front ()->SendI2NPMessages (msgs);
		else
		{	
			for (auto it1: msgs)
				it->second.delayedMessages.push_back (it1);
		}	
	}	
		
	bool Transports::ConnectToPeer (const i2p::data::IdentHash& ident, Peer& peer)
	{
		if (peer.router) // we have RI already
		{	
			if (!peer.numAttempts) // NTCP
			{
				peer.numAttempts++;
				auto address = peer.router->GetNTCPAddress (!context.SupportsV6 ());
				if (address && m_NTCPServer)
				{
#if BOOST_VERSION >= 104900
					if (!address->host.is_unspecified ()) // we have address now
#else
					boost::system::error_code ecode;
					address->host.to_string (ecode);
					if (!ecode)
#endif
					{
						if (!peer.router->UsesIntroducer () && !peer.router->IsUnreachable ())
						{	
							auto s = std::make_shared<NTCPSession> (*m_NTCPServer, peer.router);
							m_NTCPServer->Connect (address->host, address->port, s);
							return true;
						}
					}
					else // we don't have address
					{
						if (address->addressString.length () > 0) // trying to resolve
						{
							LogPrint (eLogDebug, "Transports: Resolving NTCP ", address->addressString);
							NTCPResolve (address->addressString, ident);
							return true;
						}
					}
				}	
				else
					LogPrint (eLogDebug, "Transports: NTCP address is not present for ", i2p::data::GetIdentHashAbbreviation (ident), ", trying SSU");
			}
			if (peer.numAttempts == 1)// SSU
			{
				peer.numAttempts++;
				if (m_SSUServer && peer.router->IsSSU (!context.SupportsV6 ()))
				{
					auto address = peer.router->GetSSUAddress (!context.SupportsV6 ());
#if BOOST_VERSION >= 104900
					if (!address->host.is_unspecified ()) // we have address now
#else
					boost::system::error_code ecode;
					address->host.to_string (ecode);
					if (!ecode)
#endif
					{
						m_SSUServer->CreateSession (peer.router, address->host, address->port);
						return true;
					}
					else // we don't have address
					{
						if (address->addressString.length () > 0) // trying to resolve
						{
							LogPrint (eLogDebug, "Transports: Resolving SSU ", address->addressString);
							SSUResolve (address->addressString, ident);
							return true;
						}
					}
				}
			}	
			LogPrint (eLogError, "Transports: No NTCP or SSU addresses available");
			peer.Done ();
			std::unique_lock<std::mutex>	l(m_PeersMutex);	
			m_Peers.erase (ident);
			return false;
		}	
		else // otherwise request RI
		{
			LogPrint (eLogInfo, "Transports: RouterInfo for ", ident.ToBase64 (), " not found, requested");
			i2p::data::netdb.RequestDestination (ident, std::bind (
				&Transports::RequestComplete, this, std::placeholders::_1, ident));
		}	
		return true;
	}	
	
	void Transports::RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident)
	{
		m_Service.post (std::bind (&Transports::HandleRequestComplete, this, r, ident));
	}		
	
	void Transports::HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, i2p::data::IdentHash ident)
	{
		auto it = m_Peers.find (ident);
		if (it != m_Peers.end ())
		{	
			if (r)
			{
				LogPrint (eLogDebug, "Transports: RouterInfo for ", ident.ToBase64 (), " found, Trying to connect");
				it->second.router = r;
				ConnectToPeer (ident, it->second);
			}	
			else
			{
				LogPrint (eLogError, "Transports: RouterInfo not found, Failed to send messages");
				std::unique_lock<std::mutex>	l(m_PeersMutex);	
				m_Peers.erase (it);
			}	
		}	
	}	

	void Transports::NTCPResolve (const std::string& addr, const i2p::data::IdentHash& ident)
	{
		auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(m_Service);
		resolver->async_resolve (boost::asio::ip::tcp::resolver::query (addr, ""), 
			std::bind (&Transports::HandleNTCPResolve, this, 
				std::placeholders::_1, std::placeholders::_2, ident, resolver));
	}

	void Transports::HandleNTCPResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it, 
		i2p::data::IdentHash ident, std::shared_ptr<boost::asio::ip::tcp::resolver> resolver)
	{
		auto it1 = m_Peers.find (ident);
		if (it1 != m_Peers.end ())
		{
			auto& peer = it1->second;
			if (!ecode && peer.router)
			{
				while (it != boost::asio::ip::tcp::resolver::iterator())
				{	
					auto address = (*it).endpoint ().address ();
					LogPrint (eLogDebug, "Transports: ", (*it).host_name (), " has been resolved to ", address);
					if (address.is_v4 () || context.SupportsV6 ())
					{
						auto addr = peer.router->GetNTCPAddress (); // TODO: take one we requested
						if (addr)
						{
							auto s = std::make_shared<NTCPSession> (*m_NTCPServer, peer.router);
							m_NTCPServer->Connect (address, addr->port, s);
							return;
						}
						break;
					}	
					else
						LogPrint (eLogInfo, "Transports: NTCP ", address, " is not supported");
					it++;
				}	
			}
			LogPrint (eLogError, "Transports: Unable to resolve NTCP address: ", ecode.message ());
			std::unique_lock<std::mutex>	l(m_PeersMutex);		
			m_Peers.erase (it1);
		}
	}

	void Transports::SSUResolve (const std::string& addr, const i2p::data::IdentHash& ident)
	{
		auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(m_Service);
		resolver->async_resolve (boost::asio::ip::tcp::resolver::query (addr, ""), 
			std::bind (&Transports::HandleSSUResolve, this, 
				std::placeholders::_1, std::placeholders::_2, ident, resolver));
	}

	void Transports::HandleSSUResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it, 
		i2p::data::IdentHash ident, std::shared_ptr<boost::asio::ip::tcp::resolver> resolver)
	{
		auto it1 = m_Peers.find (ident);
		if (it1 != m_Peers.end ())
		{
			auto& peer = it1->second;
			if (!ecode && peer.router)
			{
				while (it != boost::asio::ip::tcp::resolver::iterator())
				{	
					auto address = (*it).endpoint ().address ();
					LogPrint (eLogDebug, "Transports: ", (*it).host_name (), " has been resolved to ", address);
					if (address.is_v4 () || context.SupportsV6 ())
					{
						auto addr = peer.router->GetSSUAddress (); // TODO: take one we requested
						if (addr)
						{
							m_SSUServer->CreateSession (peer.router, address, addr->port);
							return;
						}
						break;
					}
					else
						LogPrint (eLogInfo, "Transports: SSU ", address, " is not supported");
					it++;
				}	
			}
			LogPrint (eLogError, "Transports: Unable to resolve SSU address: ", ecode.message ());
			std::unique_lock<std::mutex>	l(m_PeersMutex);	
			m_Peers.erase (it1);
		}
	}

	void Transports::CloseSession (std::shared_ptr<const i2p::data::RouterInfo> router)
	{
		if (!router) return;
		m_Service.post (std::bind (&Transports::PostCloseSession, this, router));		 
	}	

	void Transports::PostCloseSession (std::shared_ptr<const i2p::data::RouterInfo> router)
	{
		auto ssuSession = m_SSUServer ? m_SSUServer->FindSession (router) : nullptr;
		if (ssuSession) // try SSU first
		{	
			m_SSUServer->DeleteSession (ssuSession);
			LogPrint (eLogDebug, "Transports: SSU session closed");
		}	
		// TODO: delete NTCP
		auto ntcpSession = m_NTCPServer ? m_NTCPServer->FindNTCPSession(router->GetIdentHash()) : nullptr;
		if (ntcpSession) 
		{
			m_NTCPServer->RemoveNTCPSession(ntcpSession);
			LogPrint(eLogDebug, "Transports: NTCP session closed");
		}
	}	
		
	void Transports::DetectExternalIP ()
	{
		if (m_SSUServer)
		{
			i2p::context.SetStatus (eRouterStatusTesting);
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomPeerTestRouter ();
				if (router	&& router->IsSSU (!context.SupportsV6 ()))
					m_SSUServer->CreateSession (router, true);	// peer test	
				else
				{
					// if not peer test capable routers found pick any
					router = i2p::data::netdb.GetRandomRouter ();
					if (router && router->IsSSU ())
						m_SSUServer->CreateSession (router);		// no peer test
				}
			}	
		}
		else
			LogPrint (eLogError, "Transports: Can't detect external IP. SSU is not available");
	}

	void Transports::PeerTest ()
	{
		if (m_SSUServer)
		{
			bool statusChanged = false;
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomPeerTestRouter ();
				if (router && router->IsSSU (!context.SupportsV6 ()))
				{	
					if (!statusChanged)
					{	
						statusChanged = true;
						i2p::context.SetStatus (eRouterStatusTesting); // first time only
					}	
					m_SSUServer->CreateSession (router, true);	// peer test	
				}	
			}	
		}
	}	
		
	std::shared_ptr<i2p::crypto::DHKeys> Transports::GetNextDHKeysPair ()
	{
		return m_DHKeysPairSupplier.Acquire ();
	}

	void Transports::ReuseDHKeysPair (std::shared_ptr<i2p::crypto::DHKeys> pair)
	{
		m_DHKeysPairSupplier.Return (pair);
	}

	void Transports::PeerConnected (std::shared_ptr<TransportSession> session)
	{
		m_Service.post([session, this]()
		{		
			auto remoteIdentity = session->GetRemoteIdentity (); 
			if (!remoteIdentity) return;
			auto ident = remoteIdentity->GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				bool sendDatabaseStore = true;
				if (it->second.delayedMessages.size () > 0)
				{
					// check if first message is our DatabaseStore (publishing)
					auto firstMsg = it->second.delayedMessages[0];
					if (firstMsg && firstMsg->GetTypeID () == eI2NPDatabaseStore &&
							i2p::data::IdentHash(firstMsg->GetPayload () + DATABASE_STORE_KEY_OFFSET) == i2p::context.GetIdentHash ())
						sendDatabaseStore = false; // we have it in the list already
				}	
				if (sendDatabaseStore)
					session->SendI2NPMessages ({ CreateDatabaseStoreMsg () });
				it->second.sessions.push_back (session);
				session->SendI2NPMessages (it->second.delayedMessages);
				it->second.delayedMessages.clear ();
			}
			else // incoming connection
			{
				session->SendI2NPMessages ({ CreateDatabaseStoreMsg () }); // send DatabaseStore
				std::unique_lock<std::mutex>	l(m_PeersMutex);	
				m_Peers.insert (std::make_pair (ident, Peer{ 0, nullptr, { session }, i2p::util::GetSecondsSinceEpoch (), {} }));
			}
		});			
	}
		
	void Transports::PeerDisconnected (std::shared_ptr<TransportSession> session)
	{
		m_Service.post([session, this]()
		{	 
			auto remoteIdentity = session->GetRemoteIdentity (); 
			if (!remoteIdentity) return;
			auto ident = remoteIdentity->GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				it->second.sessions.remove (session);
				if (it->second.sessions.empty ()) // TODO: why?
				{	
					if (it->second.delayedMessages.size () > 0)
						ConnectToPeer (ident, it->second);
					else
					{
						std::unique_lock<std::mutex>	l(m_PeersMutex);	
						m_Peers.erase (it);
					}
				}
			}
		});	
	}	

	bool Transports::IsConnected (const i2p::data::IdentHash& ident) const
	{	
		std::unique_lock<std::mutex> l(m_PeersMutex);		
		auto it = m_Peers.find (ident);
		return it != m_Peers.end ();
	}	
		
	void Transports::HandlePeerCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_Peers.begin (); it != m_Peers.end (); )
			{
				if (it->second.sessions.empty () && ts > it->second.creationTime + SESSION_CREATION_TIMEOUT)
				{
					LogPrint (eLogWarning, "Transports: Session to peer ", it->first.ToBase64 (), " has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
					std::unique_lock<std::mutex>	l(m_PeersMutex);	
					it = m_Peers.erase (it);
				}
				else
					it++;
			}
			UpdateBandwidth (); // TODO: use separate timer(s) for it
			if (i2p::context.GetStatus () == eRouterStatusTesting) // if still testing,	 repeat peer test
				DetectExternalIP ();
			m_PeerCleanupTimer.expires_from_now (boost::posix_time::seconds(5*SESSION_CREATION_TIMEOUT));
			m_PeerCleanupTimer.async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));
		}	
	}

	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer () const
	{
		if (m_Peers.empty ()) return nullptr;
		std::unique_lock<std::mutex> l(m_PeersMutex);	
		auto it = m_Peers.begin ();
		std::advance (it, rand () % m_Peers.size ());	
		return it != m_Peers.end () ? it->second.router : nullptr;
	}
}
}

