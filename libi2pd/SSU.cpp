#include <string.h>
#include <boost/bind.hpp>
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "NetDb.hpp"
#include "SSU.h"

namespace i2p
{
namespace transport
{

	SSUServer::SSUServer (const boost::asio::ip::address & addr, int port):
		m_OnlyV6(true), m_IsRunning(false),
		m_Thread (nullptr), m_ThreadV6 (nullptr), m_ReceiversThread (nullptr),
		m_ReceiversThreadV6 (nullptr), m_Work (m_Service), m_WorkV6 (m_ServiceV6),
		m_ReceiversWork (m_ReceiversService), m_ReceiversWorkV6 (m_ReceiversServiceV6),
		m_EndpointV6 (addr, port), m_Socket (m_ReceiversService, m_Endpoint),
		m_SocketV6 (m_ReceiversServiceV6), m_IntroducersUpdateTimer (m_Service),
		m_PeerTestsCleanupTimer (m_Service), m_TerminationTimer (m_Service),
		m_TerminationTimerV6 (m_ServiceV6)
	{
		OpenSocketV6 ();
	}

	SSUServer::SSUServer (int port):
		m_OnlyV6(false), m_IsRunning(false),
		m_Thread (nullptr), m_ThreadV6 (nullptr), m_ReceiversThread (nullptr),
		m_ReceiversThreadV6 (nullptr), 	m_Work (m_Service), m_WorkV6 (m_ServiceV6),
		m_ReceiversWork (m_ReceiversService), m_ReceiversWorkV6 (m_ReceiversServiceV6),
		m_Endpoint (boost::asio::ip::udp::v4 (), port), m_EndpointV6 (boost::asio::ip::udp::v6 (), port),
		m_Socket (m_ReceiversService), m_SocketV6 (m_ReceiversServiceV6),
		m_IntroducersUpdateTimer (m_Service), m_PeerTestsCleanupTimer (m_Service),
		m_TerminationTimer (m_Service), m_TerminationTimerV6 (m_ServiceV6)
	{
		OpenSocket ();
		if (context.SupportsV6 ())
			OpenSocketV6 ();
	}

	SSUServer::~SSUServer ()
	{
	}

	void SSUServer::OpenSocket ()
	{
		m_Socket.open (boost::asio::ip::udp::v4());
		m_Socket.set_option (boost::asio::socket_base::receive_buffer_size (SSU_SOCKET_RECEIVE_BUFFER_SIZE));
		m_Socket.set_option (boost::asio::socket_base::send_buffer_size (SSU_SOCKET_SEND_BUFFER_SIZE));
		m_Socket.bind (m_Endpoint);
	}

	void SSUServer::OpenSocketV6 ()
	{
		m_SocketV6.open (boost::asio::ip::udp::v6());
		m_SocketV6.set_option (boost::asio::ip::v6_only (true));
		m_SocketV6.set_option (boost::asio::socket_base::receive_buffer_size (SSU_SOCKET_RECEIVE_BUFFER_SIZE));
		m_SocketV6.set_option (boost::asio::socket_base::send_buffer_size (SSU_SOCKET_SEND_BUFFER_SIZE));
		m_SocketV6.bind (m_EndpointV6);
	}

	void SSUServer::Start ()
	{
		m_IsRunning = true;
		if (!m_OnlyV6)
		{
			m_ReceiversThread = new std::thread (std::bind (&SSUServer::RunReceivers, this));
			m_Thread = new std::thread (std::bind (&SSUServer::Run, this));
			m_ReceiversService.post (std::bind (&SSUServer::Receive, this));
			ScheduleTermination ();
		}
		if (context.SupportsV6 ())
		{
			m_ReceiversThreadV6 = new std::thread (std::bind (&SSUServer::RunReceiversV6, this));
			m_ThreadV6 = new std::thread (std::bind (&SSUServer::RunV6, this));
			m_ReceiversServiceV6.post (std::bind (&SSUServer::ReceiveV6, this));
			ScheduleTerminationV6 ();
		}
		SchedulePeerTestsCleanupTimer ();
		ScheduleIntroducersUpdateTimer (); // wait for 30 seconds and decide if we need introducers
	}

	void SSUServer::Stop ()
	{
		DeleteAllSessions ();
		m_IsRunning = false;
		m_TerminationTimer.cancel ();
		m_TerminationTimerV6.cancel ();
		m_Service.stop ();
		m_Socket.close ();
		m_ServiceV6.stop ();
		m_SocketV6.close ();
		m_ReceiversService.stop ();
		m_ReceiversServiceV6.stop ();
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
		if (m_ReceiversThreadV6)
		{
			m_ReceiversThreadV6->join ();
			delete m_ReceiversThreadV6;
			m_ReceiversThreadV6 = nullptr;
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
				LogPrint (eLogError, "SSU: server runtime exception: ", ex.what ());
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
				LogPrint (eLogError, "SSU: v6 server runtime exception: ", ex.what ());
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
				LogPrint (eLogError, "SSU: receivers runtime exception: ", ex.what ());
				if (m_IsRunning)
				{
					// restart socket
					m_Socket.close ();
					OpenSocket ();
					Receive ();
				}	
			}
		}
	}

	void SSUServer::RunReceiversV6 ()
	{
		while (m_IsRunning)
		{
			try
			{
				m_ReceiversServiceV6.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU: v6 receivers runtime exception: ", ex.what ());
				if (m_IsRunning)
				{
					m_SocketV6.close ();
					OpenSocketV6 ();
					ReceiveV6 ();
				}	
			}
		}
	}

	void SSUServer::AddRelay (uint32_t tag, std::shared_ptr<SSUSession> relay)
	{
		m_Relays[tag] = relay;
	}

	void SSUServer::RemoveRelay (uint32_t tag)
	{
		m_Relays.erase (tag);
	}

	std::shared_ptr<SSUSession> SSUServer::FindRelaySession (uint32_t tag)
	{
		auto it = m_Relays.find (tag);
		if (it != m_Relays.end ())
		{
			if (it->second->GetState () == eSessionStateEstablished)
				return it->second;
			else
				m_Relays.erase (it);
		}
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
			if (!ec)
			{
				while (moreBytes && packets.size () < 25)
				{
					packet = new SSUPacket ();
					packet->len = m_Socket.receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V4), packet->from, 0, ec);
					if (!ec)
					{
						packets.push_back (packet);
						moreBytes = m_Socket.available(ec);
						if (ec) break;
					}
					else
					{
						LogPrint (eLogError, "SSU: receive_from error: ", ec.message ());
						delete packet;
						break;
					}
				}
			}

			m_Service.post (std::bind (&SSUServer::HandleReceivedPackets, this, packets, &m_Sessions));
			Receive ();
		}
		else
		{
			delete packet;
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU: receive error: ", ecode.message ());
				m_Socket.close ();
				OpenSocket ();
				Receive ();
			}
		}
	}

	void SSUServer::HandleReceivedFromV6 (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet)
	{
		if (!ecode)
		{
			packet->len = bytes_transferred;
			std::vector<SSUPacket *> packets;
			packets.push_back (packet);

			boost::system::error_code ec;
			size_t moreBytes = m_SocketV6.available (ec);
			if (!ec)
			{
				while (moreBytes && packets.size () < 25)
				{
					packet = new SSUPacket ();
					packet->len = m_SocketV6.receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V6), packet->from, 0, ec);
					if (!ec)
					{
						packets.push_back (packet);
						moreBytes = m_SocketV6.available(ec);
						if (ec) break;
					}
					else
					{
						LogPrint (eLogError, "SSU: v6 receive_from error: ", ec.message ());
						delete packet;
						break;
					}
				}
			}

			m_ServiceV6.post (std::bind (&SSUServer::HandleReceivedPackets, this, packets, &m_SessionsV6));
			ReceiveV6 ();
		}
		else
		{
			delete packet;
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU: v6 receive error: ", ecode.message ());
				m_SocketV6.close ();
				OpenSocketV6 ();
				ReceiveV6 ();
			}
		}
	}

	void SSUServer::HandleReceivedPackets (std::vector<SSUPacket *> packets,
		std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSUSession> > * sessions)
	{
		std::shared_ptr<SSUSession> session;
		for (auto& packet: packets)
		{
			try
			{
				if (!session || session->GetRemoteEndpoint () != packet->from) // we received packet for other session than previous
				{
					if (session) 
					{ 
						session->FlushData (); 
						session = nullptr; 
					}
					auto it = sessions->find (packet->from);
					if (it != sessions->end ())
						session = it->second;
					if (!session)
					{
						session = std::make_shared<SSUSession> (*this, packet->from);
						session->WaitForConnect ();
						(*sessions)[packet->from] = session;
						LogPrint (eLogDebug, "SSU: new session from ", packet->from.address ().to_string (), ":", packet->from.port (), " created");
					}
				}
				session->ProcessNextMessage (packet->buf, packet->len, packet->from);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU: HandleReceivedPackets ", ex.what ());
				if (session) session->FlushData ();
				session = nullptr;
			}
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
		auto& sessions = e.address ().is_v6 () ?  m_SessionsV6 : m_Sessions;
		auto it = sessions.find (e);
		if (it != sessions.end ())
			return it->second;
		else
			return nullptr;
	}

	void SSUServer::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest, bool v4only)
	{
		auto address = router->GetSSUAddress (v4only || !context.SupportsV6 ());
		if (address)
			CreateSession (router, address->host, address->port, peerTest);
		else
			LogPrint (eLogWarning, "SSU: Router ", i2p::data::GetIdentHashAbbreviation (router->GetIdentHash ()), " doesn't have SSU address");
	}

	void SSUServer::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
		const boost::asio::ip::address& addr, int port, bool peerTest)
	{
		if (router)
		{
			if (router->UsesIntroducer ())
				m_Service.post (std::bind (&SSUServer::CreateSessionThroughIntroducer, this, router, peerTest)); // always V4 thread
			else
			{
				boost::asio::ip::udp::endpoint remoteEndpoint (addr, port);
				auto& s = addr.is_v6 () ? m_ServiceV6 : m_Service;
				s.post (std::bind (&SSUServer::CreateDirectSession, this, router, remoteEndpoint, peerTest));
			}
		}
	}

	void SSUServer::CreateDirectSession (std::shared_ptr<const i2p::data::RouterInfo> router, boost::asio::ip::udp::endpoint remoteEndpoint, bool peerTest)
	{
		auto& sessions = remoteEndpoint.address ().is_v6 () ? m_SessionsV6 : m_Sessions;
		auto it = sessions.find (remoteEndpoint);
		if (it != sessions.end ())
		{
			auto session = it->second;
			if (peerTest && session->GetState () == eSessionStateEstablished)
				session->SendPeerTest ();
		}
		else
		{
			// otherwise create new session
			auto session = std::make_shared<SSUSession> (*this, remoteEndpoint, router, peerTest);
			sessions[remoteEndpoint] = session;
			// connect
			LogPrint (eLogDebug, "SSU: Creating new session to [", i2p::data::GetIdentHashAbbreviation (router->GetIdentHash ()), "] ",
				remoteEndpoint.address ().to_string (), ":", remoteEndpoint.port ());
			session->Connect ();
		}
	}

	void SSUServer::CreateSessionThroughIntroducer (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest)
	{
		if (router && router->UsesIntroducer ())
		{
			auto address = router->GetSSUAddress (true); // v4 only for now
			if (address)
			{
				boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
				auto it = m_Sessions.find (remoteEndpoint);
				// check if session is presented already
				if (it != m_Sessions.end ())
				{
					auto session = it->second;
					if (peerTest && session->GetState () == eSessionStateEstablished)
						session->SendPeerTest ();
					return;
				}
				// create new session
				int numIntroducers = address->ssu->introducers.size ();
				if (numIntroducers > 0)
				{
					uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
					std::shared_ptr<SSUSession> introducerSession;
					const i2p::data::RouterInfo::Introducer * introducer = nullptr;
					// we might have a session to introducer already
					for (int i = 0; i < numIntroducers; i++)
					{
						auto intr = &(address->ssu->introducers[i]);
						if (intr->iExp > 0 && ts > intr->iExp) continue; // skip expired introducer
						boost::asio::ip::udp::endpoint ep (intr->iHost, intr->iPort);
						if (ep.address ().is_v4 ()) // ipv4 only
						{
							if (!introducer) introducer = intr; // we pick first one for now
							it = m_Sessions.find (ep);
							if (it != m_Sessions.end ())
							{
								introducerSession = it->second;
								break;
							}
						}
					}
					if (!introducer)
					{
						LogPrint (eLogWarning, "SSU: Can't connect to unreachable router and no ipv4 non-expired introducers presented");
						return;
					}

					if (introducerSession) // session found
						LogPrint (eLogWarning, "SSU: Session to introducer already exists");
					else // create new
					{
						LogPrint (eLogDebug, "SSU: Creating new session to introducer ", introducer->iHost);
						boost::asio::ip::udp::endpoint introducerEndpoint (introducer->iHost, introducer->iPort);
						introducerSession = std::make_shared<SSUSession> (*this, introducerEndpoint, router);
						m_Sessions[introducerEndpoint] = introducerSession;
					}
#if BOOST_VERSION >= 104900
					if (!address->host.is_unspecified () && address->port)
#endif
					{
						// create session
						auto session = std::make_shared<SSUSession> (*this, remoteEndpoint, router, peerTest);
						m_Sessions[remoteEndpoint] = session;

						// introduce
						LogPrint (eLogInfo, "SSU: Introduce new session to [", i2p::data::GetIdentHashAbbreviation (router->GetIdentHash ()),
								"] through introducer ", introducer->iHost, ":", introducer->iPort);
						session->WaitForIntroduction ();
						if (i2p::context.GetRouterInfo ().UsesIntroducer ()) // if we are unreachable
						{
							uint8_t buf[1];
							Send (buf, 0, remoteEndpoint); // send HolePunch
						}
					}
					introducerSession->Introduce (*introducer, router);
				}
				else
					LogPrint (eLogWarning, "SSU: Can't connect to unreachable router and no introducers present");
			}
			else
				LogPrint (eLogWarning, "SSU: Router ", i2p::data::GetIdentHashAbbreviation (router->GetIdentHash ()), " doesn't have SSU address");
		}
	}

	void SSUServer::DeleteSession (std::shared_ptr<SSUSession> session)
	{
		if (session)
		{
			session->Close ();
			auto& ep = session->GetRemoteEndpoint ();
			if (ep.address ().is_v6 ())
				m_SessionsV6.erase (ep);
			else
				m_Sessions.erase (ep);
		}
	}

	void SSUServer::DeleteAllSessions ()
	{
		for (auto& it: m_Sessions)
			it.second->Close ();
		m_Sessions.clear ();

		for (auto& it: m_SessionsV6)
			it.second->Close ();
		m_SessionsV6.clear ();
	}

	template<typename Filter>
	std::shared_ptr<SSUSession> SSUServer::GetRandomV4Session (Filter filter) // v4 only
	{
		std::vector<std::shared_ptr<SSUSession> > filteredSessions;
		for (const auto& s :m_Sessions)
			if (filter (s.second)) filteredSessions.push_back (s.second);
		if (filteredSessions.size () > 0)
		{
			auto ind = rand () % filteredSessions.size ();
			return filteredSessions[ind];
		}
		return nullptr;
	}

	std::shared_ptr<SSUSession> SSUServer::GetRandomEstablishedV4Session (std::shared_ptr<const SSUSession> excluded) // v4 only
	{
		return GetRandomV4Session (
			[excluded](std::shared_ptr<SSUSession> session)->bool
			{
				return session->GetState () == eSessionStateEstablished && session != excluded;
			}
								);
	}

	template<typename Filter>
	std::shared_ptr<SSUSession> SSUServer::GetRandomV6Session (Filter filter) // v6 only
	{
		std::vector<std::shared_ptr<SSUSession> > filteredSessions;
		for (const auto& s :m_SessionsV6)
			if (filter (s.second)) filteredSessions.push_back (s.second);
		if (filteredSessions.size () > 0)
		{
			auto ind = rand () % filteredSessions.size ();
			return filteredSessions[ind];
		}
		return nullptr;
	}

	std::shared_ptr<SSUSession> SSUServer::GetRandomEstablishedV6Session (std::shared_ptr<const SSUSession> excluded) // v6 only
	{
		return GetRandomV6Session (
			[excluded](std::shared_ptr<SSUSession> session)->bool
			{
				return session->GetState () == eSessionStateEstablished && session != excluded;
			}
								);
	}

	std::set<SSUSession *> SSUServer::FindIntroducers (int maxNumIntroducers)
	{
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		std::set<SSUSession *> ret;
		for (int i = 0; i < maxNumIntroducers; i++)
		{
			auto session = GetRandomV4Session (
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
			if (i2p::context.GetStatus () == eRouterStatusTesting)
			{
				// we still don't know if we need introducers
				ScheduleIntroducersUpdateTimer ();
				return;
			}
			if (i2p::context.GetStatus () == eRouterStatusOK) return; // we don't need introducers anymore
			// we are firewalled
			if (!i2p::context.IsUnreachable ()) i2p::context.SetUnreachable ();
			std::list<boost::asio::ip::udp::endpoint> newList;
			size_t numIntroducers = 0;
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			for (const auto& it : m_Introducers)
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
				for (const auto& it1: introducers)
				{
					const auto& ep = it1->GetRemoteEndpoint ();
					i2p::data::RouterInfo::Introducer introducer;
					introducer.iHost = ep.address ();
					introducer.iPort = ep.port ();
					introducer.iTag = it1->GetRelayTag ();
					introducer.iKey = it1->GetIntroKey ();
					if (i2p::context.AddIntroducer (introducer))
					{
						newList.push_back (ep);
						if (newList.size () >= SSU_MAX_NUM_INTRODUCERS) break;
					}
				}
			}
			m_Introducers = newList;
			if (m_Introducers.size () < SSU_MAX_NUM_INTRODUCERS)
			{
				auto introducer = i2p::data::netdb.GetRandomIntroducer ();
				if (introducer)
					CreateSession (introducer);
			}
			ScheduleIntroducersUpdateTimer ();
		}
	}

	void SSUServer::NewPeerTest (uint32_t nonce, PeerTestParticipant role, std::shared_ptr<SSUSession> session)
	{
		m_PeerTests[nonce] = { i2p::util::GetMillisecondsSinceEpoch (), role, session };
	}

	PeerTestParticipant SSUServer::GetPeerTestParticipant (uint32_t nonce)
	{
		auto it = m_PeerTests.find (nonce);
		if (it != m_PeerTests.end ())
			return it->second.role;
		else
			return ePeerTestParticipantUnknown;
	}

	std::shared_ptr<SSUSession> SSUServer::GetPeerTestSession (uint32_t nonce)
	{
		auto it = m_PeerTests.find (nonce);
		if (it != m_PeerTests.end ())
			return it->second.session;
		else
			return nullptr;
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
					++it;
			}
			if (numDeleted > 0)
				LogPrint (eLogDebug, "SSU: ", numDeleted, " peer tests have been expired");
			SchedulePeerTestsCleanupTimer ();
		}
	}

	void SSUServer::ScheduleTermination ()
	{
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(SSU_TERMINATION_CHECK_TIMEOUT));
		m_TerminationTimer.async_wait (std::bind (&SSUServer::HandleTerminationTimer,
			this, std::placeholders::_1));
	}

	void SSUServer::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto& it: m_Sessions)
				if (it.second->IsTerminationTimeoutExpired (ts))
				{
					auto session = it.second;
					if (it.first != session->GetRemoteEndpoint ())
						LogPrint (eLogWarning, "SSU: remote endpoint ", session->GetRemoteEndpoint (), " doesn't match key ", it.first, " adjusted");
					m_Service.post ([session]
						{
							LogPrint (eLogWarning, "SSU: no activity with ", session->GetRemoteEndpoint (), " for ", session->GetTerminationTimeout (), " seconds");
							session->Failed ();
						});
				}
			ScheduleTermination ();
		}
	}

	void SSUServer::ScheduleTerminationV6 ()
	{
		m_TerminationTimerV6.expires_from_now (boost::posix_time::seconds(SSU_TERMINATION_CHECK_TIMEOUT));
		m_TerminationTimerV6.async_wait (std::bind (&SSUServer::HandleTerminationTimerV6,
			this, std::placeholders::_1));
	}

	void SSUServer::HandleTerminationTimerV6 (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto& it: m_SessionsV6)
				if (it.second->IsTerminationTimeoutExpired (ts))
				{
					auto session = it.second;
					if (it.first != session->GetRemoteEndpoint ())
						LogPrint (eLogWarning, "SSU: remote endpoint ", session->GetRemoteEndpoint (), " doesn't match key ", it.first);
					m_ServiceV6.post ([session]
						{
							LogPrint (eLogWarning, "SSU: no activity with ", session->GetRemoteEndpoint (), " for ", session->GetTerminationTimeout (), " seconds");
							session->Failed ();
						});
				}
			ScheduleTerminationV6 ();
		}
	}
}
}

