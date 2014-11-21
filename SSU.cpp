#include <string.h>
#include <boost/bind.hpp>
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "SSU.h"

namespace i2p
{
namespace transport
{
	SSUServer::SSUServer (int port): m_Thread (nullptr), m_Work (m_Service),
		m_Endpoint (boost::asio::ip::udp::v4 (), port), m_EndpointV6 (boost::asio::ip::udp::v6 (), port),
		m_Socket (m_Service, m_Endpoint), m_SocketV6 (m_Service), m_IntroducersUpdateTimer (m_Service)	
	{
		m_Socket.set_option (boost::asio::socket_base::receive_buffer_size (65535));
		m_Socket.set_option (boost::asio::socket_base::send_buffer_size (65535));
		if (context.SupportsV6 ())
		{
			m_SocketV6.open (boost::asio::ip::udp::v6());
			m_SocketV6.set_option (boost::asio::ip::v6_only (true));
			m_SocketV6.set_option (boost::asio::socket_base::receive_buffer_size (65535));
			m_SocketV6.set_option (boost::asio::socket_base::send_buffer_size (65535));
			m_SocketV6.bind (m_EndpointV6);
		}
	}
	
	SSUServer::~SSUServer ()
	{
		for (auto it: m_Sessions)
			delete it.second;
	}

	void SSUServer::Start ()
	{
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&SSUServer::Run, this));
		m_Service.post (boost::bind (&SSUServer::Receive, this));  
		if (context.SupportsV6 ())
			m_Service.post (boost::bind (&SSUServer::ReceiveV6, this));  
		if (i2p::context.IsUnreachable ())
			ScheduleIntroducersUpdateTimer ();
	}

	void SSUServer::Stop ()
	{
		DeleteAllSessions ();
		m_IsRunning = false;
		m_Service.stop ();
		m_Socket.close ();
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = 0;
		}	
	}

	void SSUServer::Run () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU server: ", ex.what ());
			}	
		}	
	}
		
	void SSUServer::AddRelay (uint32_t tag, const boost::asio::ip::udp::endpoint& relay)
	{
		m_Relays[tag] = relay;
	}	

	SSUSession * SSUServer::FindRelaySession (uint32_t tag)
	{
		auto it = m_Relays.find (tag);
		if (it != m_Relays.end ())
			return FindSession (it->second);
		return nullptr;
	}

	void SSUServer::Send (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& to)
	{
		if (to.protocol () == boost::asio::ip::udp::v4()) 
			m_Socket.send_to (boost::asio::buffer (buf, len), to);
		else
			m_SocketV6.send_to (boost::asio::buffer (buf, len), to);
	}	

	void SSUServer::Receive ()
	{
		m_Socket.async_receive_from (boost::asio::buffer (m_ReceiveBuffer, SSU_MTU_V4), m_SenderEndpoint,
			boost::bind (&SSUServer::HandleReceivedFrom, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}

	void SSUServer::ReceiveV6 ()
	{
		m_SocketV6.async_receive_from (boost::asio::buffer (m_ReceiveBufferV6, SSU_MTU_V6), m_SenderEndpointV6,
			boost::bind (&SSUServer::HandleReceivedFromV6, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}	

	void SSUServer::HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			HandleReceivedBuffer (m_SenderEndpoint, m_ReceiveBuffer, bytes_transferred);
			Receive ();
		}
		else
			LogPrint ("SSU receive error: ", ecode.message ());
	}

	void SSUServer::HandleReceivedFromV6 (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			HandleReceivedBuffer (m_SenderEndpointV6, m_ReceiveBufferV6, bytes_transferred);
			ReceiveV6 ();
		}
		else
			LogPrint ("SSU V6 receive error: ", ecode.message ());
	}

	void SSUServer::HandleReceivedBuffer (boost::asio::ip::udp::endpoint& from, uint8_t * buf, std::size_t bytes_transferred)
	{
		SSUSession * session = nullptr;
		auto it = m_Sessions.find (from);
		if (it != m_Sessions.end ())
			session = it->second;
		if (!session)
		{
			session = new SSUSession (*this, from);
			m_Sessions[from] = session;
			LogPrint ("New SSU session from ", from.address ().to_string (), ":", from.port (), " created");
		}
		session->ProcessNextMessage (buf, bytes_transferred, from);
	}

	SSUSession * SSUServer::FindSession (const i2p::data::RouterInfo * router) const
	{
		if (!router) return nullptr;
		auto address = router->GetSSUAddress (true); // v4 only
 		if (!address) return nullptr;
		auto session = FindSession (boost::asio::ip::udp::endpoint (address->host, address->port));
		if (session || !context.SupportsV6 ())
			return session;
		// try v6
		address = router->GetSSUV6Address (); 
		if (!address) return nullptr;
		return FindSession (boost::asio::ip::udp::endpoint (address->host, address->port));
	}	

	SSUSession * SSUServer::FindSession (const boost::asio::ip::udp::endpoint& e) const
	{
		auto it = m_Sessions.find (e);
		if (it != m_Sessions.end ())
			return it->second;
		else
			return nullptr;
	}
		
	SSUSession * SSUServer::GetSession (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest)
	{
		SSUSession * session = nullptr;
		if (router)
		{
			auto address = router->GetSSUAddress (!context.SupportsV6 ());
			if (address)
			{
				boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
				auto it = m_Sessions.find (remoteEndpoint);
				if (it != m_Sessions.end ())
					session = it->second;
				else
				{
					// otherwise create new session					
					session = new SSUSession (*this, remoteEndpoint, router, peerTest);
					m_Sessions[remoteEndpoint] = session;
					
					if (!router->UsesIntroducer ())
					{
						// connect directly						
						LogPrint ("Creating new SSU session to [", router->GetIdentHashAbbreviation (), "] ",
							remoteEndpoint.address ().to_string (), ":", remoteEndpoint.port ());
						session->Connect ();
					}
					else
					{
						// connect through introducer
						int numIntroducers = address->introducers.size ();
						if (numIntroducers > 0)
						{
							SSUSession * introducerSession = nullptr;
							const i2p::data::RouterInfo::Introducer * introducer = nullptr;
							// we might have a session to introducer already
							for (int i = 0; i < numIntroducers; i++)
							{
								introducer = &(address->introducers[i]);
								it = m_Sessions.find (boost::asio::ip::udp::endpoint (introducer->iHost, introducer->iPort));
								if (it != m_Sessions.end ())
								{
									introducerSession = it->second;
									break; 
								}	
							}

							if (introducerSession) // session found 
								LogPrint ("Session to introducer already exists");
							else // create new
							{
								LogPrint ("Creating new session to introducer");
								introducer = &(address->introducers[0]); // TODO:
								boost::asio::ip::udp::endpoint introducerEndpoint (introducer->iHost, introducer->iPort);
								introducerSession = new SSUSession (*this, introducerEndpoint, router);
								m_Sessions[introducerEndpoint] = introducerSession;													
							}	
							// introduce
							LogPrint ("Introduce new SSU session to [", router->GetIdentHashAbbreviation (), 
									"] through introducer ", introducer->iHost, ":", introducer->iPort);
							session->WaitForIntroduction ();	
							if (i2p::context.GetRouterInfo ().UsesIntroducer ()) // if we are unreachable
								Send (m_ReceiveBuffer, 0, remoteEndpoint); // send HolePunch
							introducerSession->Introduce (introducer->iTag, introducer->iKey);
						}
						else
						{	
							LogPrint (eLogWarning, "Can't connect to unreachable router. No introducers presented");
							m_Sessions.erase (remoteEndpoint);
							delete session;
							session = nullptr;
						}	
					}
				}
			}
			else
				LogPrint (eLogWarning, "Router ", router->GetIdentHashAbbreviation (), " doesn't have SSU address");
		}
		return session;
	}

	void SSUServer::DeleteSession (SSUSession * session)
	{
		if (session)
		{
			session->Close ();
			m_Sessions.erase (session->GetRemoteEndpoint ());
			delete session;
		}	
	}	

	void SSUServer::DeleteAllSessions ()
	{
		for (auto it: m_Sessions)
		{
			it.second->Close ();
			delete it.second;			
		}	
		m_Sessions.clear ();
	}

	template<typename Filter>
	SSUSession * SSUServer::GetRandomSession (Filter filter)
	{
		std::vector<SSUSession *> filteredSessions;
		for (auto s :m_Sessions)
			if (filter (s.second)) filteredSessions.push_back (s.second);
		if (filteredSessions.size () > 0)
		{
			auto ind = i2p::context.GetRandomNumberGenerator ().GenerateWord32 (0, filteredSessions.size ()-1);
			return filteredSessions[ind];
		}
		return nullptr;	
	}

	SSUSession * SSUServer::GetRandomEstablishedSession (const SSUSession * excluded)
	{
		return GetRandomSession (
			[excluded](SSUSession * session)->bool 
			{ 
				return session->GetState () == eSessionStateEstablished &&
					session != excluded; 
			}
								);
	}

	std::set<SSUSession *> SSUServer::FindIntroducers (int maxNumIntroducers)
	{
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		std::set<SSUSession *> ret;
		for (int i = 0; i < maxNumIntroducers; i++)
		{
			auto session = GetRandomSession (
				[&ret, ts](SSUSession * session)->bool 
				{ 
					return session->GetRelayTag () && !ret.count (session) &&
						session->GetState () == eSessionStateEstablished &&
						ts < session->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_DURATION; 
				}
											);	
			if (session)
			{
				ret.insert (session);
				break;
			}	
		}
		return ret;
	}

	void SSUServer::ScheduleIntroducersUpdateTimer ()
	{
		m_IntroducersUpdateTimer.expires_from_now (boost::posix_time::seconds(SSU_KEEP_ALIVE_INTERVAL));
		m_IntroducersUpdateTimer.async_wait (boost::bind (&SSUServer::HandleIntroducersUpdateTimer,
			this, boost::asio::placeholders::error));	
	}

	void SSUServer::HandleIntroducersUpdateTimer (const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			// timeout expired
			std::list<boost::asio::ip::udp::endpoint> newList;
			size_t numIntroducers = 0;
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it :m_Introducers)
			{	
				auto session = FindSession (it);
				if (session && ts < session->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_DURATION)
				{
					session->SendKeepAlive ();
					newList.push_back (it);
					numIntroducers++;
				}
				else	
					i2p::context.RemoveIntroducer (it);
			}

			if (numIntroducers < SSU_MAX_NUM_INTRODUCERS)
			{
				// create new
				auto introducers = FindIntroducers (SSU_MAX_NUM_INTRODUCERS);
				if (introducers.size () > 0)
				{
					for (auto it1: introducers)
					{
						auto router = it1->GetRemoteRouter ();
						if (router && i2p::context.AddIntroducer (*router, it1->GetRelayTag ()))
						{	
							newList.push_back (it1->GetRemoteEndpoint ());
							if (newList.size () >= SSU_MAX_NUM_INTRODUCERS) break;
						}	
					}	
				}	
			}	
			m_Introducers = newList;
			ScheduleIntroducersUpdateTimer ();
		}	
	}	
}
}

