#include <cryptopp/dh.h>
#include "Log.h"
#include "CryptoConst.h"
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
			std::unique_lock<std::mutex>  l(m_AcquiredMutex);
			m_Acquired.wait (l); // wait for element gets aquired
		}
	}		

	void DHKeysPairSupplier::CreateDHKeysPairs (int num)
	{
		if (num > 0)
		{
			CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
			for (int i = 0; i < num; i++)
			{
				i2p::transport::DHKeysPair * pair = new i2p::transport::DHKeysPair ();
				dh.GenerateKeyPair(m_Rnd, pair->privateKey, pair->publicKey);
				std::unique_lock<std::mutex>  l(m_AcquiredMutex);
				m_Queue.push (pair);
			}
		}
	}

	DHKeysPair * DHKeysPairSupplier::Acquire ()
	{
		if (!m_Queue.empty ())
		{
			std::unique_lock<std::mutex>  l(m_AcquiredMutex);
			auto pair = m_Queue.front ();
			m_Queue.pop ();
			m_Acquired.notify_one ();
			return pair;
		}	
		else // queue is empty, create new
		{
			DHKeysPair * pair = new DHKeysPair ();
			CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
			dh.GenerateKeyPair(m_Rnd, pair->privateKey, pair->publicKey);
			return pair;
		}
	}

	void DHKeysPairSupplier::Return (DHKeysPair * pair)
	{
		std::unique_lock<std::mutex>  l(m_AcquiredMutex);
		m_Queue.push (pair);
	}

	Transports transports;	
	
	Transports::Transports (): 
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service), m_PeerCleanupTimer (m_Service),
		m_NTCPServer (nullptr), m_SSUServer (nullptr), 
		m_DHKeysPairSupplier (5) // 5 pre-generated keys
	{		
	}
		
	Transports::~Transports () 
	{ 
		Stop ();
	}	

	void Transports::Start ()
	{
		m_DHKeysPairSupplier.Start ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&Transports::Run, this));
		// create acceptors
		auto addresses = context.GetRouterInfo ().GetAddresses ();
		for (auto& address : addresses)
		{
			if (!m_NTCPServer)
			{	
				m_NTCPServer = new NTCPServer (address.port);
				m_NTCPServer->Start ();
			}	
			
			if (address.transportStyle == RouterInfo::eTransportSSU && address.host.is_v4 ())
			{
				if (!m_SSUServer)
				{	
					m_SSUServer = new SSUServer (address.port);
					LogPrint ("Start listening UDP port ", address.port);
					m_SSUServer->Start ();	
					DetectExternalIP ();
				}
				else
					LogPrint ("SSU server already exists");
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
				LogPrint ("Transports: ", ex.what ());
			}	
		}	
	}
		

	void Transports::SendMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		m_Service.post (std::bind (&Transports::PostMessage, this, ident, msg));                             
	}	

	void Transports::SendMessages (const i2p::data::IdentHash& ident, const std::vector<i2p::I2NPMessage *>& msgs)
	{
		m_Service.post (std::bind (&Transports::PostMessages, this, ident, msgs));
	}	
		
	void Transports::PostMessage (i2p::data::IdentHash ident, i2p::I2NPMessage * msg)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
		{	
			// we send it to ourself
			i2p::HandleI2NPMessage (msg);
			return;
		}	

		auto it = m_Peers.find (ident);
		if (it == m_Peers.end ())
		{
			auto r = netdb.FindRouter (ident);
			it = m_Peers.insert (std::pair<i2p::data::IdentHash, Peer>(ident, { 0, r, nullptr,
				i2p::util::GetSecondsSinceEpoch () })).first;
			if (!ConnectToPeer (ident, it->second))
			{
				DeleteI2NPMessage (msg);
				return;
			}	
		}	
		if (it->second.session)
			it->second.session->SendI2NPMessage (msg);
		else
			it->second.delayedMessages.push_back (msg);
	}	

	void Transports::PostMessages (i2p::data::IdentHash ident, std::vector<i2p::I2NPMessage *> msgs)
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
			auto r = netdb.FindRouter (ident);
			it = m_Peers.insert (std::pair<i2p::data::IdentHash, Peer>(ident, { 0, r, nullptr,
				i2p::util::GetSecondsSinceEpoch () })).first;
			if (!ConnectToPeer (ident, it->second))
			{
				for (auto it1: msgs)
					DeleteI2NPMessage (it1);
				return;
			}	
		}	
		if (it->second.session)
			it->second.session->SendI2NPMessages (msgs);
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
				if (address)
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
							LogPrint (eLogInfo, "Resolving ", address->addressString);
							NTCPResolve (address->addressString, ident);
							return true;
						}
					}
				}	
			}
			else  if (peer.numAttempts == 1)// SSU
			{
				peer.numAttempts++;
				if (m_SSUServer)
				{	
					if (m_SSUServer->GetSession (peer.router))
						return true;
				}
			}	
			LogPrint (eLogError, "No NTCP and SSU addresses available");
			if (peer.session) peer.session->Done ();
			m_Peers.erase (ident);
			return false;
		}	
		else // otherwise request RI
		{
			LogPrint ("Router not found. Requested");
			i2p::data::netdb.RequestDestination (ident, std::bind (
				&Transports::RequestComplete, this, std::placeholders::_1, ident));
		}	
		return true;
	}	
	
	void Transports::RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident)
	{
		m_Service.post (std::bind (&Transports::HandleRequestComplete, this, r, ident));
	}		
	
	void Transports::HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident)
	{
		auto it = m_Peers.find (ident);
		if (it != m_Peers.end ())
		{	
			if (r)
			{
				LogPrint ("Router found. Trying to connect");
				it->second.router = r;
				ConnectToPeer (ident, it->second);
			}	
			else
			{
				LogPrint ("Router not found. Failed to send messages");
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
				auto address = (*it).endpoint ().address ();
				LogPrint (eLogInfo, (*it).host_name (), " has been resolved to ", address);
				auto addr = peer.router->GetNTCPAddress ();
				if (addr)
				{
					auto s = std::make_shared<NTCPSession> (*m_NTCPServer, peer.router);
					m_NTCPServer->Connect (address, addr->port, s);
					return;
				}	
			}
			LogPrint (eLogError, "Unable to resolve NTCP address: ", ecode.message ());
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
			LogPrint ("SSU session closed");	
		}	
		// TODO: delete NTCP
	}	
		
	void Transports::DetectExternalIP ()
	{
		if (m_SSUServer)
		{
			i2p::context.SetStatus (eRouterStatusTesting);
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomPeerTestRouter ();
				if (router  && router->IsSSU ())
					m_SSUServer->GetSession (router, true);  // peer test	
				else
				{
					// if not peer test capable routers found pick any
					router = i2p::data::netdb.GetRandomRouter ();
					if (router && router->IsSSU ())
						m_SSUServer->GetSession (router);  	// no peer test
				}
			}	
		}
		else
			LogPrint (eLogError, "Can't detect external IP. SSU is not available");
	}
			
	DHKeysPair * Transports::GetNextDHKeysPair ()
	{
		return m_DHKeysPairSupplier.Acquire ();
	}

	void Transports::ReuseDHKeysPair (DHKeysPair * pair)
	{
		m_DHKeysPairSupplier.Return (pair);
	}

	void Transports::PeerConnected (std::shared_ptr<TransportSession> session)
	{
		m_Service.post([session, this]()
		{   
			auto ident = session->GetRemoteIdentity ().GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				if (!it->second.session)
				{
					it->second.session = session;
					session->SendI2NPMessages (it->second.delayedMessages);
					it->second.delayedMessages.clear ();
				}
				else
				{
					LogPrint (eLogError, "Session for ", ident.ToBase64 ().substr (0, 4), " already exists");
					session->Done ();
				}
			}
			else // incoming connection
				m_Peers.insert (std::make_pair (ident, Peer{ 0, nullptr, session, i2p::util::GetSecondsSinceEpoch () }));
		});			
	}
		
	void Transports::PeerDisconnected (std::shared_ptr<TransportSession> session)
	{
		m_Service.post([session, this]()
		{  
			auto ident = session->GetRemoteIdentity ().GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end () && (!it->second.session || it->second.session == session))
			{
				if (it->second.delayedMessages.size () > 0)
					ConnectToPeer (ident, it->second);
				else
					m_Peers.erase (it);
			}
		});	
	}	

	void Transports::HandlePeerCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_Peers.begin (); it != m_Peers.end (); )
			{
				if (!it->second.session && ts > it->second.creationTime + SESSION_CREATION_TIMEOUT)
				{
					LogPrint (eLogError, "Session to peer ", it->first.ToBase64 (), " has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
					it = m_Peers.erase (it);
				}
				else
					it++;
			}
			m_PeerCleanupTimer.expires_from_now (boost::posix_time::seconds(5*SESSION_CREATION_TIMEOUT));
			m_PeerCleanupTimer.async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));
		}	
	}
}
}

