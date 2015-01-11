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
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service), 
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
	}
		
	void Transports::Stop ()
	{	
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
		m_Service.post (boost::bind (&Transports::PostMessage, this, ident, msg));                             
	}	

	void Transports::PostMessage (const i2p::data::IdentHash& ident, i2p::I2NPMessage * msg)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
		{	
			// we send it to ourself
			i2p::HandleI2NPMessage (msg);
			return;
		}	
		std::shared_ptr<TransportSession> session = m_NTCPServer->FindNTCPSession (ident);
		if (!session)
		{
			auto r = netdb.FindRouter (ident);
			if (r)
			{	
				if (m_SSUServer)
					session = m_SSUServer->FindSession (r);
				if (!session)
				{	
					// existing session not found. create new 
					// try NTCP first if message size < 16K
					auto address = r->GetNTCPAddress (!context.SupportsV6 ()); 
					if (address && !r->UsesIntroducer () && !r->IsUnreachable () && msg->GetLength () < NTCP_MAX_MESSAGE_SIZE)
					{	
						auto s = std::make_shared<NTCPSession> (*m_NTCPServer, r);
						session = s;
						m_NTCPServer->Connect (address->host, address->port, s);
					}	
					else
					{	
						// then SSU					
						if (m_SSUServer)
							session = m_SSUServer->GetSession (r);
						if (!session)
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
		if (session)
			session->SendI2NPMessage (msg);	
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
		
	void Transports::CloseSession (std::shared_ptr<const i2p::data::RouterInfo> router)
	{
		if (!router) return;
		m_Service.post (boost::bind (&Transports::PostCloseSession, this, router));    
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

