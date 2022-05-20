/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "Log.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "NetDb.hpp"
#include "Config.h"
#include "util.h"
#include "SSU.h"

#if defined(__linux__) && !defined(_NETINET_IN_H)
	#include <linux/in6.h>
#endif

#ifdef _WIN32
#include <boost/winapi/error_codes.hpp>
#endif

namespace i2p
{
namespace transport
{
	SSUServer::SSUServer (int port):
		m_IsRunning(false), m_Thread (nullptr),
		m_ReceiversThread (nullptr), m_ReceiversThreadV6 (nullptr), m_Work (m_Service),
		m_ReceiversWork (m_ReceiversService), m_ReceiversWorkV6 (m_ReceiversServiceV6),
		m_Endpoint (boost::asio::ip::udp::v4 (), port), m_EndpointV6 (boost::asio::ip::udp::v6 (), port),
		m_Socket (m_ReceiversService), m_SocketV6 (m_ReceiversServiceV6),
		m_IntroducersUpdateTimer (m_Service), m_IntroducersUpdateTimerV6 (m_Service),
		m_PeerTestsCleanupTimer (m_Service), m_TerminationTimer (m_Service), m_TerminationTimerV6 (m_Service),
		m_IsSyncClockFromPeers (true)
	{
	}

	SSUServer::~SSUServer ()
	{
	}

	void SSUServer::OpenSocket ()
	{
		try
		{
			m_Socket.open (boost::asio::ip::udp::v4());
			m_Socket.set_option (boost::asio::socket_base::receive_buffer_size (SSU_SOCKET_RECEIVE_BUFFER_SIZE));
			m_Socket.set_option (boost::asio::socket_base::send_buffer_size (SSU_SOCKET_SEND_BUFFER_SIZE));
			m_Socket.bind (m_Endpoint);
			LogPrint (eLogInfo, "SSU: Start listening v4 port ", m_Endpoint.port());
		}
		catch ( std::exception & ex )
		{
			LogPrint (eLogError, "SSU: Failed to bind to v4 port ", m_Endpoint.port(), ": ", ex.what());
			ThrowFatal ("Unable to start IPv4 SSU transport at port ", m_Endpoint.port(), ": ", ex.what ());
		}
	}

	void SSUServer::OpenSocketV6 ()
	{
		try
		{
			m_SocketV6.open (boost::asio::ip::udp::v6());
			m_SocketV6.set_option (boost::asio::ip::v6_only (true));
			m_SocketV6.set_option (boost::asio::socket_base::receive_buffer_size (SSU_SOCKET_RECEIVE_BUFFER_SIZE));
			m_SocketV6.set_option (boost::asio::socket_base::send_buffer_size (SSU_SOCKET_SEND_BUFFER_SIZE));
#if defined(__linux__) && !defined(_NETINET_IN_H)
			if (m_EndpointV6.address() == boost::asio::ip::address().from_string("::")) // only if not binded to address
			{
				// Set preference to use public IPv6 address -- tested on linux, not works on windows, and not tested on others
#if (BOOST_VERSION >= 105500)
				typedef boost::asio::detail::socket_option::integer<BOOST_ASIO_OS_DEF(IPPROTO_IPV6), IPV6_ADDR_PREFERENCES> ipv6PreferAddr;
#else
				typedef boost::asio::detail::socket_option::integer<IPPROTO_IPV6, IPV6_ADDR_PREFERENCES> ipv6PreferAddr;
#endif
				m_SocketV6.set_option (ipv6PreferAddr(IPV6_PREFER_SRC_PUBLIC | IPV6_PREFER_SRC_HOME | IPV6_PREFER_SRC_NONCGA));
			}
#endif
			m_SocketV6.bind (m_EndpointV6);
			LogPrint (eLogInfo, "SSU: Start listening v6 port ", m_EndpointV6.port());
		}
		catch ( std::exception & ex )
		{
			LogPrint (eLogError, "SSU: Failed to bind to v6 port ", m_EndpointV6.port(), ": ", ex.what());
			ThrowFatal ("Unable to start IPv6 SSU transport at port ", m_Endpoint.port(), ": ", ex.what ());
		}
	}

	void SSUServer::Start ()
	{
		i2p::config::GetOption("nettime.frompeers", m_IsSyncClockFromPeers);
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&SSUServer::Run, this));
		if (context.SupportsV4 ())
		{
			OpenSocket ();
			m_ReceiversThread = new std::thread (std::bind (&SSUServer::RunReceivers, this));
			m_ReceiversService.post (std::bind (&SSUServer::Receive, this));
			ScheduleTermination ();
			ScheduleIntroducersUpdateTimer (); // wait for 30 seconds and decide if we need introducers
		}
		if (context.SupportsV6 ())
		{
			OpenSocketV6 ();
			m_ReceiversThreadV6 = new std::thread (std::bind (&SSUServer::RunReceiversV6, this));
			m_ReceiversServiceV6.post (std::bind (&SSUServer::ReceiveV6, this));
			ScheduleTerminationV6 ();
			ScheduleIntroducersUpdateTimerV6 (); // wait for 30 seconds and decide if we need introducers
		}
		SchedulePeerTestsCleanupTimer ();
	}

	void SSUServer::Stop ()
	{
		DeleteAllSessions ();
		m_IsRunning = false;
		m_TerminationTimer.cancel ();
		m_TerminationTimerV6.cancel ();
		m_IntroducersUpdateTimer.cancel ();
		m_IntroducersUpdateTimerV6.cancel ();
		m_Service.stop ();
		m_Socket.close ();
		m_SocketV6.close ();
		m_ReceiversService.stop ();
		m_ReceiversServiceV6.stop ();
		if (m_ReceiversThread)
		{
			m_ReceiversThread->join ();
			delete m_ReceiversThread;
			m_ReceiversThread = nullptr;
		}
		if (m_ReceiversThreadV6)
		{
			m_ReceiversThreadV6->join ();
			delete m_ReceiversThreadV6;
			m_ReceiversThreadV6 = nullptr;
		}
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = nullptr;
		}
	}

	void SSUServer::Run ()
	{
		i2p::util::SetThreadName("SSU");

		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU: Server runtime exception: ", ex.what ());
			}
		}
	}

	void SSUServer::RunReceivers ()
	{
		i2p::util::SetThreadName("SSUv4");

		while (m_IsRunning)
		{
			try
			{
				m_ReceiversService.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU: Receivers runtime exception: ", ex.what ());
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
		i2p::util::SetThreadName("SSUv6");

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

	void SSUServer::SetLocalAddress (const boost::asio::ip::address& localAddress)
	{
		if (localAddress.is_v6 ())
			m_EndpointV6.address (localAddress);
		else if (localAddress.is_v4 ())
			m_Endpoint.address (localAddress);
	}

	void SSUServer::AddRelay (uint32_t tag, std::shared_ptr<SSUSession> relay)
	{
		m_Relays.emplace (tag, relay);
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
		boost::system::error_code ec;
		if (to.protocol () == boost::asio::ip::udp::v4())
			m_Socket.send_to (boost::asio::buffer (buf, len), to, 0, ec);
		else
			m_SocketV6.send_to (boost::asio::buffer (buf, len), to, 0, ec);

		if (ec)
		{
			LogPrint (eLogError, "SSU: Send exception: ", ec.message (), " while trying to send data to ", to.address (), ":", to.port (), " (length: ", len, ")");
		}
	}

	void SSUServer::Receive ()
	{
		SSUPacket * packet = m_PacketsPool.AcquireMt ();
		m_Socket.async_receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V4), packet->from,
			std::bind (&SSUServer::HandleReceivedFrom, this, std::placeholders::_1, std::placeholders::_2, packet));
	}

	void SSUServer::ReceiveV6 ()
	{
		SSUPacket * packet = m_PacketsPool.AcquireMt ();
		m_SocketV6.async_receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V6), packet->from,
			std::bind (&SSUServer::HandleReceivedFromV6, this, std::placeholders::_1, std::placeholders::_2, packet));
	}

	void SSUServer::HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet)
	{
		if (!ecode
			|| ecode == boost::asio::error::connection_refused
			|| ecode == boost::asio::error::connection_reset
			|| ecode == boost::asio::error::network_unreachable
			|| ecode == boost::asio::error::host_unreachable
#ifdef _WIN32 // windows can throw WinAPI error, which is not handled by ASIO
			|| ecode.value() == boost::winapi::ERROR_CONNECTION_REFUSED_
			|| ecode.value() == boost::winapi::ERROR_NETWORK_UNREACHABLE_
			|| ecode.value() == boost::winapi::ERROR_HOST_UNREACHABLE_
#endif
		)
		// just try continue reading when received ICMP response otherwise socket can crash,
		// but better to find out which host were sent it and mark that router as unreachable
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
					packet = m_PacketsPool.AcquireMt ();
					packet->len = m_Socket.receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V4), packet->from, 0, ec);
					if (!ec)
					{
						packets.push_back (packet);
						moreBytes = m_Socket.available(ec);
						if (ec) break;
					}
					else
					{
						LogPrint (eLogError, "SSU: receive_from error: code ", ec.value(), ": ", ec.message ());
						m_PacketsPool.ReleaseMt (packet);
						break;
					}
				}
			}

			m_Service.post (std::bind (&SSUServer::HandleReceivedPackets, this, packets, &m_Sessions));
			Receive ();
		}
		else
		{
			m_PacketsPool.ReleaseMt (packet);
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU: Receive error: code ", ecode.value(), ": ", ecode.message ());
				m_Socket.close ();
				OpenSocket ();
				Receive ();
			}
		}
	}

	void SSUServer::HandleReceivedFromV6 (const boost::system::error_code& ecode, std::size_t bytes_transferred, SSUPacket * packet)
	{
		if (!ecode
			|| ecode == boost::asio::error::connection_refused
			|| ecode == boost::asio::error::connection_reset
			|| ecode == boost::asio::error::network_unreachable
			|| ecode == boost::asio::error::host_unreachable
#ifdef _WIN32 // windows can throw WinAPI error, which is not handled by ASIO
			|| ecode.value() == boost::winapi::ERROR_CONNECTION_REFUSED_
			|| ecode.value() == boost::winapi::ERROR_NETWORK_UNREACHABLE_
			|| ecode.value() == boost::winapi::ERROR_HOST_UNREACHABLE_
#endif
		)
		// just try continue reading when received ICMP response otherwise socket can crash,
		// but better to find out which host were sent it and mark that router as unreachable
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
					packet = m_PacketsPool.AcquireMt ();
					packet->len = m_SocketV6.receive_from (boost::asio::buffer (packet->buf, SSU_MTU_V6), packet->from, 0, ec);
					if (!ec)
					{
						packets.push_back (packet);
						moreBytes = m_SocketV6.available(ec);
						if (ec) break;
					}
					else
					{
						LogPrint (eLogError, "SSU: v6 receive_from error: code ", ec.value(), ": ", ec.message ());
						m_PacketsPool.ReleaseMt (packet);;
						break;
					}
				}
			}

			m_Service.post (std::bind (&SSUServer::HandleReceivedPackets, this, packets, &m_SessionsV6));
			ReceiveV6 ();
		}
		else
		{
			m_PacketsPool.ReleaseMt (packet);
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU: v6 receive error: code ", ecode.value(), ": ", ecode.message ());
				m_SocketV6.close ();
				OpenSocketV6 ();
				ReceiveV6 ();
			}
		}
	}

	void SSUServer::HandleReceivedPackets (std::vector<SSUPacket *> packets,
		std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSUSession> > * sessions)
	{
		if (!m_IsRunning) return;
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
					if (!session && packet->len > 0)
					{
						session = std::make_shared<SSUSession> (*this, packet->from);
						session->WaitForConnect ();
						(*sessions)[packet->from] = session;
						LogPrint (eLogDebug, "SSU: New session from ", packet->from.address ().to_string (), ":", packet->from.port (), " created");
					}
				}
				if (session)
					session->ProcessNextMessage (packet->buf, packet->len, packet->from);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "SSU: HandleReceivedPackets ", ex.what ());
				if (session) session->FlushData ();
				session = nullptr;
			}
		}
		m_PacketsPool.ReleaseMt (packets);
		if (session) session->FlushData ();
	}

	std::shared_ptr<SSUSession> SSUServer::FindSession (const boost::asio::ip::udp::endpoint& e) const
	{
		auto& sessions = e.address ().is_v6 () ? m_SessionsV6 : m_Sessions;
		auto it = sessions.find (e);
		if (it != sessions.end ())
			return it->second;
		else
			return nullptr;
	}

	bool SSUServer::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest, bool v4only)
	{
		auto address = router->GetSSUAddress (v4only || !context.SupportsV6 ());
		if (address)
			return CreateSession (router, address, peerTest);
		else
			LogPrint (eLogWarning, "SSU: Router ", i2p::data::GetIdentHashAbbreviation (router->GetIdentHash ()), " doesn't have SSU address");
		return false;
	}

	bool SSUServer::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address, bool peerTest)
	{
		if (router && address)
		{
			if (address->UsesIntroducer ())
				m_Service.post (std::bind (&SSUServer::CreateSessionThroughIntroducer, this, router, address, peerTest)); // always V4 thread
			else
			{
				if (address->host.is_unspecified () || !address->port) return false;
				boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
				m_Service.post (std::bind (&SSUServer::CreateDirectSession, this, router, remoteEndpoint, peerTest));
			}
		}
		else
			return false;
		return true;
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

	void SSUServer::CreateSessionThroughIntroducer (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address, bool peerTest)
	{
		if (router && address && address->UsesIntroducer ())
		{
			if (address->IsV4 () && !i2p::context.SupportsV4 ()) return;
			if (address->IsV6 () && !i2p::context.SupportsV6 ()) return;
			if (!address->host.is_unspecified () && address->port)
			{
				// we rarely come here
				auto& sessions = address->host.is_v6 () ? m_SessionsV6 : m_Sessions;
				boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
				auto it = sessions.find (remoteEndpoint);
				// check if session is presented already
				if (it != sessions.end ())
				{
					auto session = it->second;
					if (peerTest && session->GetState () == eSessionStateEstablished)
						session->SendPeerTest ();
					return;
				}
			}
			// create new session
			int numIntroducers = address->ssu->introducers.size ();
			if (numIntroducers > 0)
			{
				uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
				std::shared_ptr<SSUSession> introducerSession;
				const i2p::data::RouterInfo::Introducer * introducer = nullptr;
				// we might have a session to introducer already
				auto offset = rand ();
				for (int i = 0; i < numIntroducers; i++)
				{
					auto intr = &(address->ssu->introducers[(offset + i)%numIntroducers]);
					if (!intr->iPort) continue; // skip invalid introducer
					if (intr->iExp > 0 && ts > intr->iExp) continue; // skip expired introducer
					boost::asio::ip::udp::endpoint ep (intr->iHost, intr->iPort);
					if (ep.address ().is_v4 () && address->IsV4 ()) // ipv4
					{
						if (!introducer) introducer = intr;
						auto it = m_Sessions.find (ep);
						if (it != m_Sessions.end ())
						{
							introducerSession = it->second;
							break;
						}
					}
					if (ep.address ().is_v6 () && address->IsV6 ()) // ipv6
					{
						if (!introducer) introducer = intr;
						auto it = m_SessionsV6.find (ep);
						if (it != m_SessionsV6.end ())
						{
							introducerSession = it->second;
							break;
						}
					}
				}
				if (!introducer)
				{
					LogPrint (eLogWarning, "SSU: Can't connect to unreachable router and no compatibe non-expired introducers presented");
					return;
				}

				if (introducerSession) // session found
					LogPrint (eLogWarning, "SSU: Session to introducer already exists");
				else // create new
				{
					LogPrint (eLogDebug, "SSU: Creating new session to introducer ", introducer->iHost);
					boost::asio::ip::udp::endpoint introducerEndpoint (introducer->iHost, introducer->iPort);
					introducerSession = std::make_shared<SSUSession> (*this, introducerEndpoint, router);
					if (introducerEndpoint.address ().is_v4 ())
						m_Sessions[introducerEndpoint] = introducerSession;
					else if (introducerEndpoint.address ().is_v6 ())
						m_SessionsV6[introducerEndpoint] = introducerSession;
				}
				if (!address->host.is_unspecified () && address->port)
				{
					// create session
					boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
					auto session = std::make_shared<SSUSession> (*this, remoteEndpoint, router, peerTest);
					if (address->host.is_v4 ())
						m_Sessions[remoteEndpoint] = session;
					else if (address->host.is_v6 ())
						m_SessionsV6[remoteEndpoint] = session;

					// introduce
					LogPrint (eLogInfo, "SSU: Introduce new session to [", i2p::data::GetIdentHashAbbreviation (router->GetIdentHash ()),
							"] through introducer ", introducer->iHost, ":", introducer->iPort);
					session->WaitForIntroduction ();
					if ((address->host.is_v4 () && i2p::context.GetStatus () == eRouterStatusFirewalled) ||
						(address->host.is_v6 () && i2p::context.GetStatusV6 () == eRouterStatusFirewalled))
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

	std::list<std::shared_ptr<SSUSession> > SSUServer::FindIntroducers (int maxNumIntroducers,
		bool v4, std::set<i2p::data::IdentHash>& excluded)
	{
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		std::list<std::shared_ptr<SSUSession> > ret;
		const auto& sessions = v4 ? m_Sessions : m_SessionsV6;
		for (const auto& s : sessions)
		{
			if (s.second->GetRelayTag () && s.second->GetState () == eSessionStateEstablished &&
				ts < s.second->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_EXPIRATION)
				ret.push_back (s.second);
			else if (s.second->GetRemoteIdentity ())
				excluded.insert (s.second->GetRemoteIdentity ()->GetIdentHash ());
		}
		if ((int)ret.size () > maxNumIntroducers)
		{
			// shink ret randomly
			int sz = ret.size () - maxNumIntroducers;
			for (int i = 0; i < sz; i++)
			{
				auto ind = rand () % ret.size ();
				auto it = ret.begin ();
				std::advance (it, ind);
				ret.erase (it);
			}
		}
		return ret;
	}

	void SSUServer::RescheduleIntroducersUpdateTimer ()
	{
		m_IntroducersUpdateTimer.cancel ();
		m_IntroducersUpdateTimer.expires_from_now (boost::posix_time::seconds(SSU_KEEP_ALIVE_INTERVAL/2));
		m_IntroducersUpdateTimer.async_wait (std::bind (&SSUServer::HandleIntroducersUpdateTimer,
			this, std::placeholders::_1, true));
	}

	void SSUServer::ScheduleIntroducersUpdateTimer ()
	{
		m_IntroducersUpdateTimer.expires_from_now (boost::posix_time::seconds(SSU_KEEP_ALIVE_INTERVAL));
		m_IntroducersUpdateTimer.async_wait (std::bind (&SSUServer::HandleIntroducersUpdateTimer,
			this, std::placeholders::_1, true));
	}

	void SSUServer::RescheduleIntroducersUpdateTimerV6 ()
	{
		m_IntroducersUpdateTimerV6.cancel ();
		m_IntroducersUpdateTimerV6.expires_from_now (boost::posix_time::seconds(SSU_KEEP_ALIVE_INTERVAL/2));
		m_IntroducersUpdateTimerV6.async_wait (std::bind (&SSUServer::HandleIntroducersUpdateTimer,
			this, std::placeholders::_1, false));
	}

	void SSUServer::ScheduleIntroducersUpdateTimerV6 ()
	{
		m_IntroducersUpdateTimerV6.expires_from_now (boost::posix_time::seconds(SSU_KEEP_ALIVE_INTERVAL));
		m_IntroducersUpdateTimerV6.async_wait (std::bind (&SSUServer::HandleIntroducersUpdateTimer,
			this, std::placeholders::_1, false));
	}

	void SSUServer::HandleIntroducersUpdateTimer (const boost::system::error_code& ecode, bool v4)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			// timeout expired
			if (v4)
			{
				if (i2p::context.GetStatus () == eRouterStatusTesting)
				{
					// we still don't know if we need introducers
					ScheduleIntroducersUpdateTimer ();
					return;
				}
				if (i2p::context.GetStatus () != eRouterStatusFirewalled)
				{
					// we don't need introducers
					m_Introducers.clear ();
					return;
				}
				// we are firewalled
				if (!i2p::context.IsUnreachable ()) i2p::context.SetUnreachable (true, false); // v4
			}
			else
			{
				if (i2p::context.GetStatusV6 () == eRouterStatusTesting)
				{
					// we still don't know if we need introducers
					ScheduleIntroducersUpdateTimerV6 ();
					return;
				}
				if (i2p::context.GetStatusV6 () != eRouterStatusFirewalled)
				{
					// we don't need introducers
					m_IntroducersV6.clear ();
					return;
				}
				// we are firewalled
				auto addr = i2p::context.GetRouterInfo ().GetSSUV6Address ();
				if (addr && addr->ssu && addr->ssu->introducers.empty ())
					i2p::context.SetUnreachable (false, true); // v6
			}

			std::list<boost::asio::ip::udp::endpoint> newList;
			size_t numIntroducers = 0;
			uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
			std::set<i2p::data::IdentHash> excluded;
			auto& introducers = v4 ? m_Introducers : m_IntroducersV6;
			for (const auto& it : introducers)
			{
				auto session = FindSession (it);
				if (session)
				{
					if (ts < session->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_EXPIRATION)
						session->SendKeepAlive ();
					if (ts < session->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_DURATION)
					{
						newList.push_back (it);
						numIntroducers++;
						if (session->GetRemoteIdentity ())
							excluded.insert (session->GetRemoteIdentity ()->GetIdentHash ());
					}
					else
						session = nullptr;
				}
				if (!session)
					i2p::context.RemoveIntroducer (it);
			}
			if (numIntroducers < SSU_MAX_NUM_INTRODUCERS)
			{
				// create new
				auto sessions = FindIntroducers (SSU_MAX_NUM_INTRODUCERS, v4, excluded); // try to find if duplicates
				if (sessions.empty () && !introducers.empty ())
				{
					// bump creation time for previous introducers if no new sessions found
					LogPrint (eLogDebug, "SSU: No new introducers found. Trying to reuse existing");
					for (const auto& it : introducers)
					{
						auto session = FindSession (it);
						if (session)
							session->SetCreationTime (session->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_DURATION);
					}
					// try again
					excluded.clear ();
					sessions = FindIntroducers (SSU_MAX_NUM_INTRODUCERS, v4, excluded);
				}
				for (const auto& it1: sessions)
				{
					const auto& ep = it1->GetRemoteEndpoint ();
					i2p::data::RouterInfo::Introducer introducer;
					introducer.iHost = ep.address ();
					introducer.iPort = ep.port ();
					introducer.iTag = it1->GetRelayTag ();
					introducer.iKey = it1->GetIntroKey ();
					introducer.iExp = it1->GetCreationTime () + SSU_TO_INTRODUCER_SESSION_EXPIRATION;
					if (i2p::context.AddIntroducer (introducer))
					{
						newList.push_back (ep);
						if (newList.size () >= SSU_MAX_NUM_INTRODUCERS) break;
					}
					if (it1->GetRemoteIdentity ())
						excluded.insert (it1->GetRemoteIdentity ()->GetIdentHash ());
				}
			}
			introducers = newList;
			if (introducers.size () < SSU_MAX_NUM_INTRODUCERS)
			{
				for (auto i = introducers.size (); i < SSU_MAX_NUM_INTRODUCERS; i++)
				{
					auto introducer = i2p::data::netdb.GetRandomIntroducer (v4, excluded);
					if (introducer)
					{
						auto address = v4 ? introducer->GetSSUAddress (true) : introducer->GetSSUV6Address ();
						if (address && !address->host.is_unspecified () && address->port)
						{
							boost::asio::ip::udp::endpoint ep (address->host, address->port);
							if (std::find (introducers.begin (), introducers.end (), ep) == introducers.end ()) // not connected yet
							{
								CreateDirectSession (introducer, ep, false);
								excluded.insert (introducer->GetIdentHash ());
							}
						}
					}
					else
					{
						LogPrint (eLogDebug, "SSU: Can't find more introducers");
						break;
					}
				}
			}
			if (v4)
				ScheduleIntroducersUpdateTimer ();
			else
				ScheduleIntroducersUpdateTimerV6 ();
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
			// some cleaups. TODO: use separate timer
			m_FragmentsPool.CleanUp ();
			m_IncompleteMessagesPool.CleanUp ();
			m_SentMessagesPool.CleanUp ();

			SchedulePeerTestsCleanupTimer ();
		}
	}

	void SSUServer::ScheduleTermination ()
	{
		uint64_t timeout = SSU_TERMINATION_CHECK_TIMEOUT + (rand () % SSU_TERMINATION_CHECK_TIMEOUT)/5;
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(timeout));
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
						LogPrint (eLogWarning, "SSU: Remote endpoint ", session->GetRemoteEndpoint (), " doesn't match key ", it.first, " adjusted");
					m_Service.post ([session]
						{
							LogPrint (eLogWarning, "SSU: No activity with ", session->GetRemoteEndpoint (), " for ", session->GetTerminationTimeout (), " seconds");
							session->Failed ();
						});
				}
				else
					it.second->CleanUp (ts);
			ScheduleTermination ();
		}
	}

	void SSUServer::ScheduleTerminationV6 ()
	{
		uint64_t timeout = SSU_TERMINATION_CHECK_TIMEOUT + (rand () % SSU_TERMINATION_CHECK_TIMEOUT)/5;
		m_TerminationTimerV6.expires_from_now (boost::posix_time::seconds(timeout));
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
						LogPrint (eLogWarning, "SSU: Remote endpoint ", session->GetRemoteEndpoint (), " doesn't match key ", it.first);
					m_Service.post ([session]
						{
							LogPrint (eLogWarning, "SSU: No activity with ", session->GetRemoteEndpoint (), " for ", session->GetTerminationTimeout (), " seconds");
							session->Failed ();
						});
				}
				else
					it.second->CleanUp (ts);
			ScheduleTerminationV6 ();
		}
	}
}
}
