#include <cryptopp/dh.h>
#include <boost/bind.hpp>
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
		m_Thread (nullptr), m_Work (m_Service), m_NTCPAcceptor (nullptr), m_NTCPV6Acceptor (nullptr), 
		m_SSUServer (nullptr), m_DHKeysPairSupplier (5) // 5 pre-generated keys
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
			if (address.transportStyle == RouterInfo::eTransportNTCP && address.host.is_v4 ())
			{	
				m_NTCPAcceptor = new boost::asio::ip::tcp::acceptor (m_Service,
					boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), address.port));

				LogPrint ("Start listening TCP port ", address.port);	
				auto conn = new NTCPServerConnection (m_Service);
				m_NTCPAcceptor->async_accept(conn->GetSocket (), boost::bind (&Transports::HandleAccept, this, 
					conn, boost::asio::placeholders::error));	
				
				if (context.SupportsV6 ())
				{
					m_NTCPV6Acceptor = new boost::asio::ip::tcp::acceptor (m_Service);
					m_NTCPV6Acceptor->open (boost::asio::ip::tcp::v6());
					m_NTCPV6Acceptor->set_option (boost::asio::ip::v6_only (true));
					m_NTCPV6Acceptor->bind (boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), address.port));
					m_NTCPV6Acceptor->listen ();

					LogPrint ("Start listening V6 TCP port ", address.port);	
					auto conn = new NTCPServerConnection (m_Service);
					m_NTCPV6Acceptor->async_accept(conn->GetSocket (), boost::bind (&Transports::HandleAcceptV6,
						this, conn, boost::asio::placeholders::error));
				}	
			}	
			else if (address.transportStyle == RouterInfo::eTransportSSU && address.host.is_v4 ())
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
	}
		
	void Transports::Stop ()
	{	
		if (m_SSUServer)
		{
			m_SSUServer->Stop ();
			delete m_SSUServer;
			m_SSUServer = nullptr;
		}	
		
		for (auto session: m_NTCPSessions)
			delete session.second;
		m_NTCPSessions.clear ();
		delete m_NTCPAcceptor;
		m_NTCPAcceptor = nullptr;
		delete m_NTCPV6Acceptor;
		m_NTCPV6Acceptor = nullptr;

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
		
	void Transports::AddNTCPSession (NTCPSession * session)
	{
		if (session)
			m_NTCPSessions[session->GetRemoteIdentity ().GetIdentHash ()] = session;
	}	

	void Transports::RemoveNTCPSession (NTCPSession * session)
	{
		if (session)
			m_NTCPSessions.erase (session->GetRemoteIdentity ().GetIdentHash ());
	}	
		
	void Transports::HandleAccept (NTCPServerConnection * conn, const boost::system::error_code& error)
	{		
		if (!error)
		{
			LogPrint ("Connected from ", conn->GetSocket ().remote_endpoint().address ().to_string ());
			conn->ServerLogin ();
		}
		else
			delete conn;

		if (error != boost::asio::error::operation_aborted)
		{
    		conn = new NTCPServerConnection (m_Service);
			m_NTCPAcceptor->async_accept(conn->GetSocket (), boost::bind (&Transports::HandleAccept, this, 
				conn, boost::asio::placeholders::error));
		}	
	}

	void Transports::HandleAcceptV6 (NTCPServerConnection * conn, const boost::system::error_code& error)
	{		
		if (!error)
		{
			LogPrint ("Connected from ", conn->GetSocket ().remote_endpoint().address ().to_string ());
			conn->ServerLogin ();
		}
		else
			delete conn;

		if (error != boost::asio::error::operation_aborted)
		{
    		conn = new NTCPServerConnection (m_Service);
			m_NTCPV6Acceptor->async_accept(conn->GetSocket (), boost::bind (&Transports::HandleAcceptV6, this, 
				conn, boost::asio::placeholders::error));
		}	
	}

	NTCPSession * Transports::GetNextNTCPSession ()
	{
		for (auto session: m_NTCPSessions)
			if (session.second->IsEstablished ())
				return session.second;
		return 0;
	}	

	NTCPSession * Transports::FindNTCPSession (const i2p::data::IdentHash& ident)
	{
		auto it = m_NTCPSessions.find (ident);
		if (it != m_NTCPSessions.end ())
			return it->second;
		return 0;
	}	

	void Transports::SendMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
			// we send it to ourself
			i2p::HandleI2NPMessage (msg);
		else
			m_Service.post (boost::bind (&Transports::PostMessage, this, ident, msg));                             
	}	

	void Transports::PostMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		auto session = FindNTCPSession (ident);
		if (session)
			session->SendI2NPMessage (msg);
		else
		{
			auto r = netdb.FindRouter (ident);
			if (r)
			{	
				auto ssuSession = m_SSUServer ? m_SSUServer->FindSession (r.get ()) : nullptr;
				if (ssuSession)
					ssuSession->SendI2NPMessage (msg);
				else
				{	
					// existing session not found. create new 
					// try NTCP first if message size < 16K
					auto address = r->GetNTCPAddress (!context.SupportsV6 ()); 
					if (address && !r->UsesIntroducer () && !r->IsUnreachable () && msg->GetLength () < NTCP_MAX_MESSAGE_SIZE)
					{	
						auto s = new NTCPClient (m_Service, address->host, address->port, r);
						AddNTCPSession (s);
						s->SendI2NPMessage (msg);
					}	
					else
					{	
						// then SSU					
						auto s = m_SSUServer ? m_SSUServer->GetSession (r) : nullptr;
						if (s)
							s->SendI2NPMessage (msg);
						else
						{
							LogPrint ("No NTCP and SSU addresses available");
							DeleteI2NPMessage (msg); 
						}
					}
				}	
			}
			else
			{
				LogPrint ("Router not found. Requested");
				i2p::data::netdb.RequestDestination (ident);
				auto resendTimer = new boost::asio::deadline_timer (m_Service);
				resendTimer->expires_from_now (boost::posix_time::seconds(5)); // 5 seconds
				resendTimer->async_wait (boost::bind (&Transports::HandleResendTimer,
					this, boost::asio::placeholders::error, resendTimer, ident, msg));			
			}	
		}	
	}	

	void Transports::HandleResendTimer (const boost::system::error_code& ecode, 
		boost::asio::deadline_timer * timer, const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		auto r = netdb.FindRouter (ident);
		if (r)
		{
			LogPrint ("Router found. Sending message");
			PostMessage (ident, msg);
		}	
		else
		{
			LogPrint ("Router not found. Failed to send message");
			DeleteI2NPMessage (msg);
		}	
		delete timer;
	}	
		
	void Transports::CloseSession (const i2p::data::RouterInfo * router)
	{
		if (!router) return;
		m_Service.post (boost::bind (&Transports::PostCloseSession, this, router));    
	}	

	void Transports::PostCloseSession (const i2p::data::RouterInfo * router)
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
		for (int i = 0; i < 5; i++)
		{
			auto router = i2p::data::netdb.GetRandomRouter ();
			if (router && router->IsSSU () && m_SSUServer)
				m_SSUServer->GetSession (router, true);  // peer test	
		}	
	}
			
	DHKeysPair * Transports::GetNextDHKeysPair ()
	{
		return m_DHKeysPairSupplier.Acquire ();
	}

	void Transports::ReuseDHKeysPair (DHKeysPair * pair)
	{
		m_DHKeysPairSupplier.Return (pair);
	}
}
}

