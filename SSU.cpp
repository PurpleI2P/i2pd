#include <string.h>
#include <boost/bind.hpp>
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "NetDb.h"
#include "SSU.h"

namespace i2p
{
namespace transport
{
	SSUServer::SSUServer (int port): m_Thread (nullptr), m_ThreadV6 (nullptr), m_ReceiversThread (nullptr),
		m_Work (m_Service), m_WorkV6 (m_ServiceV6), m_ReceiversWork (m_ReceiversService), 
		m_Endpoint (boost::asio::ip::udp::v4 (), port), m_EndpointV6 (boost::asio::ip::udp::v6 (), port), 
		m_Socket (m_ReceiversService, m_Endpoint), m_SocketV6 (m_ReceiversService), 
		m_IntroducersUpdateTimer (m_Service), m_PeerTestsCleanupTimer (m_Service)	
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
	}

	void SSUServer::Start ()
	{
		m_IsRunning = true;
		m_ReceiversThread = new std::thread (std::bind (&SSUServer::RunReceivers, this)); 
		m_Thread = new std::thread (std::bind (&SSUServer::Run, this));
		m_ReceiversService.post (std::bind (&SSUServer::Receive, this));  
		if (context.SupportsV6 ())
		{	
			m_ThreadV6 = new std::thread (std::bind (&SSUServer::RunV6, this));
			m_ReceiversService.post (std::bind (&SSUServer::ReceiveV6, this));  
		}
		SchedulePeerTestsCleanupTimer ();	
		ScheduleIntroducersUpdateTimer (); // wait for 30 seconds and decide if we need introducers
	}

	void SSUServer::Stop ()
	{
		DeleteAllSessions ();
		m_IsRunning = false;
		m_Service.stop ();
		m_Socket.close ();
		m_ServiceV6.stop ();
		m_SocketV6.close ();
		m_ReceiversService.stop ();
		if (m_ReceiversThread)
		{	
			m_ReceiversThread->join (); 
			delete m_ReceiversThread;
			m_ReceiversThread = nullptr;
		}
		if (m_Thread)
		{	
			m_Thread->join (); 
			delete m_Thread;
			m_Thread = nullptr;
		}
		if (m_ThreadV6)
		{	
			m_ThreadV6->join (); 
			delete m_ThreadV6;
			m_ThreadV6 = nullptr;
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

	void SSUServer::RunV6 () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_ServiceV6.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU V6 server: ", ex.what ());
			}	
		}	
	}	

	void SSUServer::RunReceivers () 
	{ 
		while (m_IsRunning)
		{
			try
			{	
				m_ReceiversService.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU receivers: ", ex.what ());
			}	
		}	
	}	
	
	void SSUServer::AddRelay (uint32_t tag, const boost::asio::ip::udp::endpoint& relay)
	{
		m_Relays[tag] = relay;
	}	

	std::shared_ptr<SSUSession> SSUServer::FindRelaySession (uint32_t tag)
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
		SSUPacket * packet = new SSUPacket ();
		m_Socket.async_receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V4), packet->from,
			std::bind (&SSUServer::HandleReceivedFrom, this, std::placeholders::_1, std::placeholders::_2, packet)); 
	}

	void SSUServer::ReceiveV6 ()
	{
		SSUPacket * packet = new SSUPacket ();
		m_SocketV6.async_receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V6), packet->from,
			std::bind (&SSUServer::HandleReceivedFromV6, this, std::placeholders::_1, std::placeholders::_2, packet)); 
	}	

	void SSUServer::HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet)
	{
		if (!ecode)
		{
			packet->len = bytes_transferred;
			std::vector<SSUPacket *> packets;
			packets.push_back (packet);

			boost::system::error_code ec;
			size_t moreBytes = m_Socket.available(ec);
			while (moreBytes && packets.size () < 25)
			{
				packet = new SSUPacket ();
				packet->len = m_Socket.receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V4), packet->from);
				packets.push_back (packet);
				moreBytes = m_Socket.available();
			}

			m_Service.post (std::bind (&SSUServer::HandleReceivedPackets, this, packets));
			Receive ();
		}
		else
		{	
			LogPrint ("SSU receive error: ", ecode.message ());
			delete packet;
		}	
	}

	void SSUServer::HandleReceivedFromV6 (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet)
	{
		if (!ecode)
		{
			packet->len = bytes_transferred;
			std::vector<SSUPacket *> packets;
			packets.push_back (packet);

			size_t moreBytes = m_SocketV6.available ();
			while (moreBytes && packets.size () < 25)
			{
				packet = new SSUPacket ();
				packet->len = m_SocketV6.receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V6), packet->from);
				packets.push_back (packet);
				moreBytes = m_SocketV6.available();
			}

			m_ServiceV6.post (std::bind (&SSUServer::HandleReceivedPackets, this, packets));
			ReceiveV6 ();
		}
		else
		{	
			LogPrint ("SSU V6 receive error: ", ecode.message ());
			delete packet;
		}	
	}

	void SSUServer::HandleReceivedPackets (std::vector<SSUPacket *> packets)
	{
		std::shared_ptr<SSUSession> session;	
		for (auto it1: packets)
		{
			auto packet = it1;
			if (!session || session->GetRemoteEndpoint () != packet->from) // we received packet for other session than previous
			{
				if (session) session->FlushData ();
				auto it = m_Sessions.find (packet->from);
				if (it != m_Sessions.end ())
					session = it->second;
				if (!session)
				{
					session = std::make_shared<SSUSession> (*this, packet->from);
					session->WaitForConnect ();
					{
						std::unique_lock<std::mutex> l(m_SessionsMutex);
						m_Sessions[packet->from] = session;
					}	
					LogPrint ("New SSU session from ", packet->from.address ().to_string (), ":", packet->from.port (), " created");
				}
			}
			session->ProcessNextMessage (packet->buf, packet->len, packet->from);
			delete packet;
		}
		if (session) session->FlushData ();
	}

	std::shared_ptr<SSUSession> SSUServer::FindSession (std::shared_ptr<const i2p::data::RouterInfo> router) const
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

	std::shared_ptr<SSUSession> SSUServer::FindSession (const boost::asio::ip::udp::endpoint& e) const
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		auto it = m_Sessions.find (e);
		if (it != m_Sessions.end ())
			return it->second;
		else
			return nullptr;
	}
		
	std::shared_ptr<SSUSession> SSUServer::GetSession (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest)
	{
		std::shared_ptr<SSUSession> session;
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
					session = std::make_shared<SSUSession> (*this, remoteEndpoint, router, peerTest);
					{
						std::unique_lock<std::mutex> l(m_SessionsMutex);
						m_Sessions[remoteEndpoint] = session;
					}
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
							std::shared_ptr<SSUSession> introducerSession;
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
								introducerSession = std::make_shared<SSUSession> (*this, introducerEndpoint, router);
								std::unique_lock<std::mutex> l(m_SessionsMutex);
								m_Sessions[introducerEndpoint] = introducerSession;													
							}	
							// introduce
							LogPrint ("Introduce new SSU session to [", router->GetIdentHashAbbreviation (), 
									"] through introducer ", introducer->iHost, ":", introducer->iPort);
							session->WaitForIntroduction ();	
							if (i2p::context.GetRouterInfo ().UsesIntroducer ()) // if we are unreachable
							{
								uint8_t buf[1];
								Send (buf, 0, remoteEndpoint); // send HolePunch
							}	
							introducerSession->Introduce (introducer->iTag, introducer->iKey);
						}
						else
						{	
							LogPrint (eLogWarning, "Can't connect to unreachable router. No introducers presented");
							std::unique_lock<std::mutex> l(m_SessionsMutex);
							m_Sessions.erase (remoteEndpoint);
							session.reset ();
						}	
					}
				}
			}
			else
				LogPrint (eLogWarning, "Router ", router->GetIdentHashAbbreviation (), " doesn't have SSU address");
		}
		return session;
	}

	void SSUServer::DeleteSession (std::shared_ptr<SSUSession> session)
	{
		if (session)
		{
			session->Close ();
			std::unique_lock<std::mutex> l(m_SessionsMutex);	
			m_Sessions.erase (session->GetRemoteEndpoint ());
		}	
	}	

	void SSUServer::DeleteAllSessions ()
	{
		std::unique_lock<std::mutex> l(m_SessionsMutex);
		for (auto it: m_Sessions)
			it.second->Close ();
		m_Sessions.clear ();
	}

	template<typename Filter>
	std::shared_ptr<SSUSession> SSUServer::GetRandomSession (Filter filter)
	{
		std::vector<std::shared_ptr<SSUSession> > filteredSessions;
		for (auto s :m_Sessions)
			if (filter (s.second)) filteredSessions.push_back (s.second);
		if (filteredSessions.size () > 0)
		{
			auto ind = i2p::context.GetRandomNumberGenerator ().GenerateWord32 (0, filteredSessions.size ()-1);
			return filteredSessions[ind];
		}
		return nullptr;	
	}

	std::shared_ptr<SSUSession> SSUServer::GetRandomEstablishedSession (std::shared_ptr<const SSUSession> excluded)
	{
		return GetRandomSession (
			[excluded](std::shared_ptr<SSUSession> session)->bool 
			{ 
				return session->GetState () == eSessionStateEstablished && !session->IsV6 () && 
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
				[&ret, ts](std::shared_ptr<SSUSession> session)->bool 
				{ 
					return session->GetRelayTag () && !ret.count (session.get ()) &&
						session->GetState () == eSessionStateEstablished &&
						ts < session->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_DURATION; 
				}
											);	
			if (session)
			{
				ret.insert (session.get ());
				break;
			}	
		}
		return ret;
	}

	void SSUServer::ScheduleIntroducersUpdateTimer ()
	{
		m_IntroducersUpdateTimer.expires_from_now (boost::posix_time::seconds(SSU_KEEP_ALIVE_INTERVAL));
		m_IntroducersUpdateTimer.async_wait (std::bind (&SSUServer::HandleIntroducersUpdateTimer,
			this, std::placeholders::_1));	
	}

	void SSUServer::HandleIntroducersUpdateTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			// timeout expired
			if (i2p::context.GetStatus () != eRouterStatusFirewalled) return; // we don't need introducers anymore
			if (!i2p::context.IsUnreachable ()) i2p::context.SetUnreachable ();
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
			if (m_Introducers.empty ())
			{
				auto introducer = i2p::data::netdb.GetRandomIntroducer ();
				if (introducer)
					GetSession (introducer);
			}	
			ScheduleIntroducersUpdateTimer ();
		}	
	}

	void SSUServer::NewPeerTest (uint32_t nonce, PeerTestParticipant role)
	{
		m_PeerTests[nonce] = { i2p::util::GetMillisecondsSinceEpoch (), role };
	}

	PeerTestParticipant SSUServer::GetPeerTestParticipant (uint32_t nonce)
	{
		auto it = m_PeerTests.find (nonce);
		if (it != m_PeerTests.end ())
			return it->second.role;
		else
			return ePeerTestParticipantUnknown;
	}	

	void SSUServer::UpdatePeerTest (uint32_t nonce, PeerTestParticipant role)
	{
		auto it = m_PeerTests.find (nonce);
		if (it != m_PeerTests.end ())
			it->second.role = role;
	}	
	
	void SSUServer::RemovePeerTest (uint32_t nonce)
	{
		m_PeerTests.erase (nonce);
	}	

	void SSUServer::SchedulePeerTestsCleanupTimer ()
	{
		m_PeerTestsCleanupTimer.expires_from_now (boost::posix_time::seconds(SSU_PEER_TEST_TIMEOUT));
		m_PeerTestsCleanupTimer.async_wait (std::bind (&SSUServer::HandlePeerTestsCleanupTimer,
			this, std::placeholders::_1));	
	}

	void SSUServer::HandlePeerTestsCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			int numDeleted = 0;	
			uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();	
			for (auto it = m_PeerTests.begin (); it != m_PeerTests.end ();)
			{
				if (ts > it->second.creationTime + SSU_PEER_TEST_TIMEOUT*1000LL)
				{
					numDeleted++;
					it = m_PeerTests.erase (it);
				}
				else
					it++;	 
			}
			if (numDeleted > 0)
				LogPrint (eLogInfo, numDeleted, " peer tests have been expired");
			SchedulePeerTestsCleanupTimer ();
		}
	}
}
}

