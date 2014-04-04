#include <boost/bind.hpp>
#include "Log.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "NetDb.h"
#include "Transports.h"

using namespace i2p::data;

namespace i2p
{
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
			for (int i = 0; i < num; i++)
			{
				i2p::data::DHKeysPair * pair = new i2p::data::DHKeysPair ();
				i2p::data::CreateRandomDHKeysPair (pair);
				m_Queue.push (pair);
			}
		}
	}

	i2p::data::DHKeysPair * DHKeysPairSupplier::Acquire ()
	{
		if (!m_Queue.empty ())
		{
			auto pair = m_Queue.front ();
			m_Queue.pop ();
			m_Acquired.notify_one ();
			return pair;
		}	
		else // queue is empty, create new
		{
			i2p::data::DHKeysPair * pair = new i2p::data::DHKeysPair ();
			i2p::data::CreateRandomDHKeysPair (pair);
			return pair;
		}
	}

	Transports transports;	
	
	Transports::Transports (): 
		m_Thread (nullptr), m_Work (m_Service), m_NTCPAcceptor (nullptr), 
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
		m_Timer = new boost::asio::deadline_timer (m_Service);
		// create acceptors
		auto addresses = context.GetRouterInfo ().GetAddresses ();
		for (auto& address : addresses)
		{
			if (address.transportStyle == RouterInfo::eTransportNTCP)
			{	
				m_NTCPAcceptor = new boost::asio::ip::tcp::acceptor (m_Service,
					boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), address.port));

				LogPrint ("Start listening TCP port ", address.port);	
				auto conn = new i2p::ntcp::NTCPServerConnection (m_Service);
				m_NTCPAcceptor->async_accept(conn->GetSocket (), boost::bind (&Transports::HandleAccept, this, 
					conn, boost::asio::placeholders::error));
			}	
			else if (address.transportStyle == RouterInfo::eTransportSSU)
			{
				if (!m_SSUServer)
				{	
					m_SSUServer = new i2p::ssu::SSUServer (m_Service, address.port);
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
		for (auto session: m_NTCPSessions)
			delete session.second;
		m_NTCPSessions.clear ();
		delete m_NTCPAcceptor;

		if (m_Timer)
		{	
			m_Timer->cancel ();
			delete m_Timer;
		}
		
		if (m_SSUServer)
		{
			m_SSUServer->Stop ();
			delete m_SSUServer;
		}

		m_DHKeysPairSupplier.Stop ();
		m_IsRunning = false;
		m_Service.stop ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
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
		
	void Transports::AddNTCPSession (i2p::ntcp::NTCPSession * session)
	{
		if (session)
			m_NTCPSessions[session->GetRemoteRouterInfo ().GetIdentHash ()] = session;
	}	

	void Transports::RemoveNTCPSession (i2p::ntcp::NTCPSession * session)
	{
		if (session)
			m_NTCPSessions.erase (session->GetRemoteRouterInfo ().GetIdentHash ());
	}	
		
	void Transports::HandleAccept (i2p::ntcp::NTCPServerConnection * conn, const boost::system::error_code& error)
	{		
		if (!error)
		{
			LogPrint ("Connected from ", conn->GetSocket ().remote_endpoint().address ().to_string ());
			conn->ServerLogin ();
		}
		else
		{
			delete conn;
		}

    	conn = new i2p::ntcp::NTCPServerConnection (m_Service);
		m_NTCPAcceptor->async_accept(conn->GetSocket (), boost::bind (&Transports::HandleAccept, this, 
			conn, boost::asio::placeholders::error));
	}

	i2p::ntcp::NTCPSession * Transports::GetNextNTCPSession ()
	{
		for (auto session: m_NTCPSessions)
			if (session.second->IsEstablished ())
				return session.second;
		return 0;
	}	

	i2p::ntcp::NTCPSession * Transports::FindNTCPSession (const i2p::data::IdentHash& ident)
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
			RouterInfo * r = netdb.FindRouter (ident);
			if (r)
			{	
				auto ssuSession = m_SSUServer ? m_SSUServer->FindSession (r) : nullptr;
				if (ssuSession)
					ssuSession->SendI2NPMessage (msg);
				else
				{	
					// existing session not found. create new 
					// try NTCP first
					auto address = r->GetNTCPAddress ();
					if (address)
					{	
						auto s = new i2p::ntcp::NTCPClient (m_Service, address->host, address->port, *r);
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
							LogPrint ("No NTCP and SSU addresses available");
					}
				}	
			}
			else
			{
				LogPrint ("Router not found. Requested");
				i2p::data::netdb.RequestDestination (ident);
			}	
		}	
	}	

	void Transports::DetectExternalIP ()
	{
		for (int i = 0; i < 5; i ++)
		{
			auto router = i2p::data::netdb.GetRandomRouter ();
			if (router && router->IsSSU () && m_SSUServer)
				m_SSUServer->GetSession (router); 	
		}	
		if (m_Timer)
		{	
			m_Timer->expires_from_now (boost::posix_time::seconds(5)); // 5 seconds
			m_Timer->async_wait (boost::bind (&Transports::HandleTimer, this, boost::asio::placeholders::error));
		}	
	}
		
	void Transports::HandleTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			// end of external IP detection
			if (m_SSUServer)
				 m_SSUServer->DeleteAllSessions ();
		}	
	}	
		
	i2p::data::DHKeysPair * Transports::GetNextDHKeysPair ()
	{
		return m_DHKeysPairSupplier.Acquire ();
	}
}
