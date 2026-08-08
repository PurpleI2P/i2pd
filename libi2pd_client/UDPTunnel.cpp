/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string_view>
#include "Log.h"
#include "util.h"
#include "ClientContext.h"
#include "I2PTunnel.h" // for GetLoopbackAddressFor
#include "UDPTunnel.h"

namespace i2p
{
namespace client
{
	constexpr std::string_view UDP_SESSION_SEQN { "seqn" };
	constexpr std::string_view UDP_SESSION_ACKED { "acked" };
	constexpr std::string_view UDP_SESSION_FLAGS { "flags" };

	constexpr uint8_t UDP_SESSION_FLAG_RESET_PATH = 0x01;
	constexpr uint8_t UDP_SESSION_FLAG_ACK_REQUESTED = 0x02;
	constexpr uint8_t UDP_SESSION_FLAG_RESET_SEQN = 0x04;

	void I2PUDPServerTunnel::HandleRecvFromI2P(const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
		const uint8_t * buf, size_t len, const i2p::util::Mapping * options)
	{
		if (!m_LastSession || m_LastSession->Identity.GetLL()[0] != from.GetIdentHash ().GetLL()[0] || (fromPort && fromPort != m_LastSession->RemotePort))
			m_LastSession = ObtainUDPSession(from, toPort, fromPort);
		m_LastSession->m_LastReceivedTime = i2p::util::GetMillisecondsSinceEpoch ();
		boost::system::error_code ec;
		if (len > 0)
			m_LastSession->IPSocket.send_to(boost::asio::buffer(buf, len), m_RemoteEndpoint, 0, ec);
		if (!ec)
			m_LastSession->LastActivity = i2p::util::GetMillisecondsSinceEpoch();
		else
			LogPrint (eLogInfo, "UDP Server: Send exception: ", ec.message (), " to ", m_RemoteEndpoint);
		if (options)
		{
			uint32_t seqn = 0;
			if (options->Get (UDP_SESSION_SEQN, seqn) && seqn > m_LastSession->m_LastReceivedPacketNum)
				m_LastSession->m_LastReceivedPacketNum = seqn;
			uint8_t flags = 0;
			if (options->Get (UDP_SESSION_FLAGS, flags))
			{
				if (flags & UDP_SESSION_FLAG_RESET_PATH)
					m_LastSession->GetDatagramSession ()->DropSharedRoutingPath ();
				if ((flags & UDP_SESSION_FLAG_RESET_SEQN) && seqn)
					m_LastSession->m_LastReceivedPacketNum = seqn;
				if (flags & UDP_SESSION_FLAG_ACK_REQUESTED)
				{
					i2p::util::Mapping replyOptions;
					replyOptions.Put (UDP_SESSION_ACKED, m_LastSession->m_LastReceivedPacketNum);
					m_LastSession->m_Destination->SendDatagram(m_LastSession->GetDatagramSession (),
						nullptr, 0, m_LastSession->LocalPort, m_LastSession->RemotePort, &replyOptions); // Ack only, no payload
					m_LastSession->m_LastRepliableDatagramTime = i2p::util::GetMillisecondsSinceEpoch ();
				}
			}
			if (options->Get (UDP_SESSION_ACKED, seqn))
				m_LastSession->Acked (seqn);
		}
	}

	void I2PUDPServerTunnel::HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (m_LastSession && (fromPort != m_LastSession->RemotePort || toPort != m_LastSession->LocalPort))
		{
			std::lock_guard<std::mutex> lock(m_SessionsMutex);
			auto it = m_Sessions.find (GetSessionIndex (fromPort, toPort));
			if (it != m_Sessions.end ())
				m_LastSession = it->second;
			else
				m_LastSession = nullptr;
		}
		if (!m_LastSession)
		{
			m_NumRawNoSession++;
			LogPrint (eLogWarning, "UDP Server: No session for raw datagram from port ", fromPort, " to ", toPort,
				", dropped, ", m_NumRawNoSession, " total");
		}
		if (m_LastSession)
		{
			boost::system::error_code ec;
			m_LastSession->IPSocket.send_to(boost::asio::buffer(buf, len), m_RemoteEndpoint, 0, ec);
			if (!ec)
				m_LastSession->LastActivity = i2p::util::GetMillisecondsSinceEpoch();
			else
				LogPrint (eLogInfo, "UDP Server: Send exception: ", ec.message (), " to ", m_RemoteEndpoint);
		}
	}

	void I2PUDPServerTunnel::ExpireStale(const uint64_t delta)
	{
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		uint64_t now = i2p::util::GetMillisecondsSinceEpoch();
		auto itr = m_Sessions.begin();
		while(itr != m_Sessions.end())
		{
			if(now - itr->second->LastActivity >= delta )
				itr = m_Sessions.erase(itr);
			else
				itr++;
		}
	}

	void I2PUDPClientTunnel::ExpireStale(const uint64_t delta)
	{
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		uint64_t now = i2p::util::GetMillisecondsSinceEpoch();
		std::vector<uint16_t> removePorts;
		for (const auto & s : m_Sessions) {
			if (now - s.second->second >= delta)
				removePorts.push_back(s.first);
		}
		for(auto port : removePorts) {
			m_Sessions.erase(port);
		}
	}

	UDPSessionPtr I2PUDPServerTunnel::ObtainUDPSession(const i2p::data::IdentityEx& from, uint16_t localPort, uint16_t remotePort)
	{
		auto ih = from.GetIdentHash();
		auto idx = GetSessionIndex (remotePort, localPort);
		{
			std::lock_guard<std::mutex> lock(m_SessionsMutex);
			auto it = m_Sessions.find (idx);
			if (it != m_Sessions.end ())
			{
				if (it->second->Identity.GetLL()[0] == ih.GetLL()[0])
				{
					LogPrint(eLogDebug, "UDPServer: Found session ", it->second->IPSocket.local_endpoint(), " ", ih.ToBase32());
					return it->second;
				}
				else
				{
					LogPrint(eLogWarning, "UDPServer: Session with from ", remotePort, " and to ", localPort, " ports already exists. But from different address. Removed");
					m_Sessions.erase (it);
				}
			}
		}

		boost::asio::ip::address addr;
		/** create new udp session */
		if(m_IsUniqueLocal && m_LocalAddress.is_loopback())
		{
			auto ident = from.GetIdentHash();
			addr = GetLoopbackAddressFor(ident);
		}
		else
			addr = m_LocalAddress;

		auto s = std::make_shared<UDPSession>(boost::asio::ip::udp::endpoint(addr, 0),
			m_LocalDest, m_RemoteEndpoint, ih, localPort, remotePort);
		s->SetMaxWindow (m_MaxWindow);
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		m_Sessions.emplace (idx, s);
		return s;
	}

	void UDPConnection::Stop ()
	{
		m_AckTimer.cancel ();
	}

	void UDPConnection::Acked (uint32_t seqn)
	{
		m_IsFirstPacket = false;	// first packet confirmed
		if (m_AckTimerSeqn)
		{
			if (seqn >= m_AckTimerSeqn)
			{
				m_AckTimerSeqn = 0;
				m_NumAckTimeoutsInRow = 0;
				m_AckTimer.cancel ();
			}
		}
		else if (!m_UnackedDatagrams.empty ())
			seqn = m_UnackedDatagrams.back ().first;	// if we receive ack after path change, clear window and send new datagrams
		if (m_UnackedDatagrams.empty () || seqn < m_UnackedDatagrams.front ().first) return;
		bool acknowledged = false;
		auto it = m_UnackedDatagrams.begin ();
		while (it != m_UnackedDatagrams.end ())
		{
			if (it->first > seqn) break;
			 if (it->first == seqn && m_IsSendingAllowed) // ignore first ack after path change
			{
				auto ts = i2p::util::GetMillisecondsSinceEpoch ();
				UpdateRTT (ts - it->second, ts);
				m_NumAckTimeoutsInRow = 0;
				acknowledged = true;
			}
			it++;
		}
		m_UnackedDatagrams.erase (m_UnackedDatagrams.begin (), it);
		m_IsSendingAllowed = true; // if we recieve ack after path change, now can send new datagrams
		if (!m_UnackedDatagrams.empty ())
		{
			// keep armed while anything is unacked, otherwise a full window can't be unblocked
			if (acknowledged)
			{
				m_AckTimer.cancel ();
				m_AckTimerSeqn = 0;
			}
			ScheduleAckTimer (m_UnackedDatagrams.back ().first);
		}
	}

	void UDPConnection::UpdateRTT (uint64_t rtt, uint64_t ts)
	{
		if (m_RTT)
		{
			uint64_t diff = (rtt > m_RTT) ? rtt - m_RTT : m_RTT - rtt;
			m_RTTVar = ((I2P_UDP_RTT_VAR_BETA - 1)*m_RTTVar + diff)/I2P_UDP_RTT_VAR_BETA;
			m_RTT = ((I2P_UDP_RTT_ALPHA - 1)*m_RTT + rtt)/I2P_UDP_RTT_ALPHA;
		}
		else
		{
			m_RTT = rtt;
			m_RTTVar = rtt/2; // rfc 6298 for the first measurement
		}
		if (!m_MinRTT || rtt < m_MinRTT)
		{
			m_MinRTT = rtt;
			m_MinRTTCandidate = rtt;
			m_MinRTTUpdateTime = ts;
		}
		else
		{
			if (!m_MinRTTCandidate || rtt < m_MinRTTCandidate) m_MinRTTCandidate = rtt;
			// windowed minimum, so queueing delay is not taken for path delay
			if (ts > m_MinRTTUpdateTime + I2P_UDP_MIN_RTT_EXPIRATION_TIMEOUT)
			{
				m_MinRTT = m_MinRTTCandidate;
				m_MinRTTCandidate = 0;
				m_MinRTTUpdateTime = ts;
			}
		}
	}

	void UDPConnection::UpdateSendRate (uint32_t numDatagrams, uint64_t ts)
	{
		m_NumSentSinceRateUpdate += numDatagrams;
		if (!m_SendRateUpdateTime)
		{
			m_SendRateUpdateTime = ts;
			return;
		}
		uint64_t interval = ts - m_SendRateUpdateTime;
		if (interval < I2P_UDP_SEND_RATE_INTERVAL) return;
		uint32_t rate = m_NumSentSinceRateUpdate * 1000 / interval;
		m_NumSentSinceRateUpdate = 0;
		m_SendRateUpdateTime = ts;
		// best rate of the last few seconds, a rate following every dip would shrink the window
		if (rate >= m_SendRate || ts > m_SendRateMaxTime + I2P_UDP_SEND_RATE_EXPIRATION_TIMEOUT)
		{
			m_SendRate = rate;
			m_SendRateMaxTime = ts;
		}
	}

	size_t UDPConnection::GetMaxNumUnackedDatagrams () const
	{
		if (!m_MinRTT || !m_SendRate) return I2P_UDP_MIN_MAX_NUM_UNACKED_DATAGRAMS;
		// bandwidth-delay product for one path delay plus one repliable interval
		size_t w = I2P_UDP_WINDOW_GAIN * m_SendRate * (m_MinRTT + I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL) / 1000;
		if (w < I2P_UDP_MIN_MAX_NUM_UNACKED_DATAGRAMS) w = I2P_UDP_MIN_MAX_NUM_UNACKED_DATAGRAMS;
		if (w > m_MaxWindow) w = m_MaxWindow;
		return w;
	}

	bool UDPConnection::IsWindowFull () const
	{
		return !m_UnackedDatagrams.empty () &&
			m_NextSendPacketNum > m_UnackedDatagrams.front ().first + GetMaxNumUnackedDatagrams ();
	}

	void UDPConnection::ExpireUnackedDatagrams (uint64_t ts)
	{
		// such an ack is never coming and would keep the window blocked
		while (!m_UnackedDatagrams.empty () &&
			ts > m_UnackedDatagrams.front ().second + I2P_UDP_MAX_UNACKED_DATAGRAM_TIME)
			m_UnackedDatagrams.pop_front ();
	}

	uint64_t UDPConnection::GetRTO () const
	{
		if (!m_RTT) return I2P_UDP_MAX_UNACKED_DATAGRAM_TIME;
		uint64_t rto = m_RTT + I2P_UDP_RTO_K*m_RTTVar;
		if (rto < I2P_UDP_MIN_ACK_TIMEOUT) rto = I2P_UDP_MIN_ACK_TIMEOUT;
		if (rto > I2P_UDP_MAX_UNACKED_DATAGRAM_TIME) rto = I2P_UDP_MAX_UNACKED_DATAGRAM_TIME;
		return rto;
	}

	uint64_t UDPConnection::GetWindowProbeInterval () const
	{
		// an ack can't come back sooner than one rtt
		if (!m_RTT) return GetRTO ();
		return (m_RTT > I2P_UDP_MIN_WINDOW_PROBE_INTERVAL) ? m_RTT : I2P_UDP_MIN_WINDOW_PROBE_INTERVAL;
	}

	void UDPConnection::ScheduleAckTimer (uint32_t seqn)
	{
		if (!m_AckTimerSeqn)
		{
			m_AckTimerSeqn = seqn;
			uint32_t shift = m_NumAckTimeoutsInRow;
			if (shift > I2P_UDP_MAX_NUM_ACK_TIMEOUTS) shift = I2P_UDP_MAX_NUM_ACK_TIMEOUTS;
			uint64_t timeout = GetRTO () << shift;
			if (timeout > I2P_UDP_MAX_UNACKED_DATAGRAM_TIME) timeout = I2P_UDP_MAX_UNACKED_DATAGRAM_TIME;
			m_AckTimer.expires_after (std::chrono::milliseconds (timeout));
			m_AckTimer.async_wait ([this](const boost::system::error_code& ecode)
				{
					if (ecode != boost::asio::error::operation_aborted)
					{
						auto ts = i2p::util::GetMillisecondsSinceEpoch ();
						m_NumAckTimeouts++; m_NumAckTimeoutsInRow++;
						// timeouts happen under congestion, only silence means the path is dead
						bool resetPath = m_NumAckTimeoutsInRow >= I2P_UDP_MAX_NUM_ACK_TIMEOUTS &&
							ts > m_LastReceivedTime + I2P_UDP_MAX_UNACKED_DATAGRAM_TIME;
						bool resetPeerPath = resetPath && ts > m_LastReceivedTime + I2P_UDP_PEER_PATH_RESET_TIMEOUT;
						LogPrint (eLogWarning, "UDP Connection: Packet ", m_AckTimerSeqn, " was not acked, rtt ",
							m_RTT, "/", m_RTTVar, "ms, ", m_NumAckTimeoutsInRow, " in a row, ", m_NumAckTimeouts,
							" total", resetPath ? ", resetting path" : "");
						if (m_IsFirstPacket) m_IsSendingAllowed = false; // stop sending only if session is not established yet
						m_AckTimerSeqn = 0;
						// probe the peer, reset path only after several timeouts in a row
						uint8_t flags = UDP_SESSION_FLAG_ACK_REQUESTED;
						if (resetPeerPath) flags |= UDP_SESSION_FLAG_RESET_PATH | UDP_SESSION_FLAG_RESET_SEQN;
						i2p::util::Mapping options;
						options.Put (UDP_SESSION_FLAGS, flags);
						// without seqn the peer acks a stale one and a full window stays blocked
						options.Put (UDP_SESSION_SEQN, m_NextSendPacketNum);
						m_NextSendPacketNum++;
						// probe only while real data is outstanding, otherwise probes feed themselves
						if (!m_UnackedDatagrams.empty ()) ScheduleAckTimer (0);
						auto session = GetDatagramSession ();
						if (session)
						{
							if (resetPath)
							{
								session->DropSharedRoutingPath ();
								session->RequestUpdatedLeaseSet (); // in case current leases are dead
								m_NumAckTimeoutsInRow = 0;
							}
							m_Destination->SendDatagram (session, nullptr, 0, 0, 0, &options);
						}
					}
				});
		}
	}

	std::shared_ptr<i2p::datagram::DatagramSession> UDPConnection::GetDatagramSession ()
	{
		auto session = m_LastDatagramSession.lock ();
		if (!session && isIdentity)
		{
			session = m_Destination->GetSession (Identity);
			m_LastDatagramSession = session;
		}
		return session;
	}

	UDPSession::UDPSession(boost::asio::ip::udp::endpoint localEndpoint,
		const std::shared_ptr<i2p::client::ClientDestination> & localDestination,
		const boost::asio::ip::udp::endpoint& endpoint, const i2p::data::IdentHash& to,
		uint16_t ourPort, uint16_t theirPort) :
		UDPConnection (localDestination->GetService(), localDestination->GetDatagramDestination()),
		IPSocket(localDestination->GetService(), localEndpoint),
		SendEndpoint(endpoint), LastActivity(i2p::util::GetMillisecondsSinceEpoch()),
		LocalPort(ourPort), RemotePort(theirPort)
	{
		SetIdentity (to);
		Start ();
		IPSocket.set_option (boost::asio::socket_base::receive_buffer_size (I2P_UDP_SOCKET_BUFFER_SIZE));
		IPSocket.set_option (boost::asio::socket_base::send_buffer_size (I2P_UDP_SOCKET_BUFFER_SIZE));
		IPSocket.non_blocking (true);
		Receive();
	}

	void UDPSession::Receive()
	{
		LogPrint(eLogDebug, "UDPSession: Receive");
		IPSocket.async_receive_from(boost::asio::buffer(m_Buffer, I2P_UDP_MAX_MTU),
			FromEndpoint, std::bind(&UDPSession::HandleReceived, this, std::placeholders::_1, std::placeholders::_2));
	}

	void UDPSession::HandleReceived(const boost::system::error_code & ecode, std::size_t len)
	{
		if(!ecode)
		{
			ExpireUnackedDatagrams (i2p::util::GetMillisecondsSinceEpoch ());
			bool isWindowFull = IsWindowFull ();
			if (isWindowFull && i2p::util::GetMillisecondsSinceEpoch () < m_LastWindowProbeTime + GetWindowProbeInterval ())
			{
				// window is full, drop packet
				m_NumWindowDrops++;
				if (m_NumWindowDrops == 1 || !(m_NumWindowDrops % 100))
					LogPrint (eLogWarning, "UDP Server: Window full (front=", m_UnackedDatagrams.front ().first,
						" next=", m_NextSendPacketNum, "), dropped ", m_NumWindowDrops, " packets");
				Receive ();
				return;
			}
			LogPrint(eLogDebug, "UDPSession: Forward ", len, "B from ", FromEndpoint);
			auto ts = i2p::util::GetMillisecondsSinceEpoch();
			if (isWindowFull) m_LastWindowProbeTime = ts;
			auto session = GetDatagramSession ();
			uint64_t repliableDatagramInterval = I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL;
			if (m_RTT && m_RTT >= I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL && m_RTT < I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL*10) repliableDatagramInterval = m_RTT/10; // 10 - 100 ms
			if (isWindowFull || ts > m_LastRepliableDatagramTime + repliableDatagramInterval)
			{
				if (session->GetVersion () == i2p::datagram::eDatagramV3)
				{
					uint8_t flags = 0;
					if (isWindowFull || !m_RTT || !m_AckTimerSeqn || (!m_UnackedDatagrams.empty () &&
						ts > m_UnackedDatagrams.back ().second + repliableDatagramInterval)) // last ack request
					{
						flags |= UDP_SESSION_FLAG_ACK_REQUESTED;
						m_UnackedDatagrams.push_back ({ m_NextSendPacketNum, ts });
						ScheduleAckTimer (m_NextSendPacketNum);
					}
					if (m_IsFirstPacket)
						flags |= UDP_SESSION_FLAG_RESET_SEQN;
					i2p::util::Mapping options;
					options.Put (UDP_SESSION_SEQN, m_NextSendPacketNum);
					if (m_LastReceivedPacketNum > 0)
						options.Put (UDP_SESSION_ACKED, m_LastReceivedPacketNum);
					if (flags)
						options.Put (UDP_SESSION_FLAGS, flags);
					m_Destination->SendDatagram(session, m_Buffer, len, LocalPort, RemotePort, &options);
					ScheduleAckTimer (m_NextSendPacketNum);
				}
				else
					m_Destination->SendDatagram(session, m_Buffer, len, LocalPort, RemotePort);
				m_LastRepliableDatagramTime = ts;
			}
			else
				m_Destination->SendRawDatagram(session, m_Buffer, len, LocalPort, RemotePort);
			size_t numPackets = 0;
			while (numPackets < i2p::datagram::DATAGRAM_SEND_QUEUE_MAX_SIZE)
			{
				boost::system::error_code ec;
				size_t moreBytes = IPSocket.available(ec);
				if (ec || !moreBytes) break;
				len = IPSocket.receive_from (boost::asio::buffer (m_Buffer, I2P_UDP_MAX_MTU), FromEndpoint, 0, ec);
				m_Destination->SendRawDatagram (session, m_Buffer, len, LocalPort, RemotePort);
				numPackets++;
			}
			if (numPackets > 0)
				LogPrint(eLogDebug, "UDPSession: Forward more ", numPackets, "packets B from ", FromEndpoint);
			m_NextSendPacketNum += numPackets + 1;
			UpdateSendRate (numPackets + 1, ts);
			m_Destination->FlushSendQueue (session);
			LastActivity = ts;
			Receive();
		}
		else
			LogPrint(eLogError, "UDPSession: ", ecode.message());
	}

	I2PUDPServerTunnel::I2PUDPServerTunnel (const std::string & name, std::shared_ptr<i2p::client::ClientDestination> localDestination,
		const boost::asio::ip::address& localAddress, const boost::asio::ip::udp::endpoint& forwardTo, uint16_t inPort, bool gzip) :
		m_IsUniqueLocal (true), m_Name (name), m_LocalAddress (localAddress),
		m_RemoteEndpoint (forwardTo), m_LocalDest (localDestination), m_inPort(inPort), m_Gzip (gzip)
	{
	}

	I2PUDPServerTunnel::~I2PUDPServerTunnel ()
	{
		Stop ();
	}

	void I2PUDPServerTunnel::Start ()
	{
		m_LocalDest->Start ();

		auto dgram = m_LocalDest->CreateDatagramDestination (m_Gzip);
		dgram->SetReceiver (
			std::bind (&I2PUDPServerTunnel::HandleRecvFromI2P, this, std::placeholders::_1, std::placeholders::_2,
				std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6),
			m_inPort
		);
		dgram->SetRawReceiver (
			std::bind (&I2PUDPServerTunnel::HandleRecvFromI2PRaw, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
			m_inPort
		);
		m_StatsTimer.reset (new boost::asio::steady_timer (m_LocalDest->GetService ()));
		ScheduleStatsTimer ();
	}

	void I2PUDPServerTunnel::ScheduleStatsTimer ()
	{
		if (m_StatsTimer)
		{
			m_StatsTimer->expires_after (std::chrono::seconds (10));
			m_StatsTimer->async_wait (std::bind (&I2PUDPServerTunnel::HandleStatsTimer,
				this, std::placeholders::_1));
		}
	}

	void I2PUDPServerTunnel::HandleStatsTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			std::lock_guard<std::mutex> lock (m_SessionsMutex);
			for (const auto& it: m_Sessions)
			{
				auto& s = it.second;
				auto session = s->GetDatagramSession ();
				LogPrint (eLogDebug, "UDP Server: stats port=", s->RemotePort, " rtt=", s->m_RTT, "/",
					s->m_RTTVar, "/", s->m_MinRTT, "ms rto=", s->GetRTO (), "ms rate=", s->m_SendRate,
					"/s window=", s->GetMaxNumUnackedDatagrams (), " unacked=", s->m_UnackedDatagrams.size (),
					" nextSeqn=", s->m_NextSendPacketNum, " lastRecvSeqn=", s->m_LastReceivedPacketNum,
					" winDrops=", s->m_NumWindowDrops, " ackTimeouts=", s->m_NumAckTimeouts,
					" pathDrops=", session ? session->GetNumPathDrops () : 0,
					" noPathDrops=", session ? session->GetNumDroppedNoPath () : 0);
			}
			ScheduleStatsTimer ();
		}
	}

	void I2PUDPServerTunnel::Stop ()
	{
		if (m_StatsTimer) m_StatsTimer->cancel ();
		auto dgram = m_LocalDest->GetDatagramDestination ();
		if (dgram) {
			dgram->ResetReceiver (m_inPort);
			dgram->ResetRawReceiver (m_inPort);
		}
		{
			std::lock_guard<std::mutex> lock (m_SessionsMutex);
			m_Sessions.clear ();
		}
	}

	std::vector<std::shared_ptr<DatagramSessionInfo> > I2PUDPServerTunnel::GetSessions ()
	{
		std::vector<std::shared_ptr<DatagramSessionInfo> > sessions;
		std::lock_guard<std::mutex> lock (m_SessionsMutex);

        for (const auto &it: m_Sessions)
		{
			auto s = it.second;
			if (!s->m_Destination) continue;
			auto info = s->m_Destination->GetInfoForRemote (s->Identity);
			if (!info) continue;

			auto sinfo = std::make_shared<DatagramSessionInfo> ();
			sinfo->Name = m_Name;
			sinfo->LocalIdent = std::make_shared<i2p::data::IdentHash> (m_LocalDest->GetIdentHash ().data ());
			sinfo->RemoteIdent = std::make_shared<i2p::data::IdentHash> (s->Identity.data ());
			sinfo->CurrentIBGW = info->IBGW;
			sinfo->CurrentOBEP = info->OBEP;
			sessions.push_back (sinfo);
		}
		return sessions;
	}

	I2PUDPClientTunnel::I2PUDPClientTunnel (std::string_view name, std::string_view remoteDest,
		const boost::asio::ip::udp::endpoint& localEndpoint,
		std::shared_ptr<i2p::client::ClientDestination> localDestination,
		uint16_t remotePort, bool gzip, i2p::datagram::DatagramVersion datagramVersion) :
		UDPConnection (localDestination->GetService (), localDestination->GetDatagramDestination ()),
		m_Name (name), m_RemoteDest (remoteDest), m_LocalDest (localDestination), m_LocalEndpoint (localEndpoint),
		m_ResolveThread (nullptr), m_LocalSocket (nullptr), RemotePort (remotePort),
		m_LastPort (0), m_cancel_resolve (false), m_Gzip (gzip), m_DatagramVersion (datagramVersion)
	{
	}

	I2PUDPClientTunnel::~I2PUDPClientTunnel ()
	{
		Stop ();
	}

	void I2PUDPClientTunnel::Start ()
	{
		UDPConnection::Start ();
		// Reset flag in case of tunnel reload
		if (m_cancel_resolve) m_cancel_resolve = false;

		m_LocalSocket.reset (new boost::asio::ip::udp::socket (m_LocalDest->GetService (), m_LocalEndpoint));
		m_LocalSocket->set_option (boost::asio::socket_base::receive_buffer_size (I2P_UDP_SOCKET_BUFFER_SIZE));
		m_LocalSocket->set_option (boost::asio::socket_base::send_buffer_size (I2P_UDP_SOCKET_BUFFER_SIZE));
		m_LocalSocket->set_option (boost::asio::socket_base::reuse_address (true));
		m_LocalSocket->non_blocking (true);

		auto dgram = m_LocalDest->CreateDatagramDestination (m_Gzip, m_DatagramVersion);
		m_Destination = dgram;
		dgram->SetReceiver (std::bind (&I2PUDPClientTunnel::HandleRecvFromI2P, this,
			std::placeholders::_1, std::placeholders::_2,
			std::placeholders::_3, std::placeholders::_4,
			std::placeholders::_5, std::placeholders::_6));

		dgram->SetRawReceiver (std::bind (&I2PUDPClientTunnel::HandleRecvFromI2PRaw, this,
			std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));

		m_LocalDest->Start ();
		if (m_ResolveThread == nullptr)
			m_ResolveThread = new std::thread (std::bind (&I2PUDPClientTunnel::TryResolving, this));
		RecvFromLocal ();

		if (m_KeepAliveInterval)
			ScheduleKeepAliveTimer ();

		m_StatsTimer.reset (new boost::asio::steady_timer (m_LocalDest->GetService ()));
		ScheduleStatsTimer ();
	}

	void I2PUDPClientTunnel::Stop ()
	{
		if (m_KeepAliveTimer) m_KeepAliveTimer->cancel ();
		if (m_StatsTimer) m_StatsTimer->cancel ();

		auto dgram = m_LocalDest->GetDatagramDestination ();
		if (dgram)
		{
			dgram->ResetReceiver ();
			dgram->ResetRawReceiver ();
		}
		m_cancel_resolve = true;

		{
			std::lock_guard<std::mutex> lock (m_SessionsMutex);
			m_Sessions.clear();
		}

		if(m_LocalSocket && m_LocalSocket->is_open ())
			m_LocalSocket->close ();

		if(m_ResolveThread)
		{
			m_ResolveThread->join ();
			delete m_ResolveThread;
			m_ResolveThread = nullptr;
		}
		UDPConnection::Stop ();
	}

	void I2PUDPClientTunnel::RecvFromLocal ()
	{
		m_LocalSocket->async_receive_from (boost::asio::buffer (m_RecvBuff, I2P_UDP_MAX_MTU),
			m_RecvEndpoint, std::bind (&I2PUDPClientTunnel::HandleRecvFromLocal, this, std::placeholders::_1, std::placeholders::_2));
	}

	void I2PUDPClientTunnel::HandleRecvFromLocal (const boost::system::error_code & ec, std::size_t transferred)
	{
		if (m_cancel_resolve) {
			LogPrint (eLogDebug, "UDP Client: Ignoring incoming data: stopping");
			return;
		}
		if (ec) {
			LogPrint (eLogError, "UDP Client: Reading from socket error: ", ec.message (), ". Restarting listener...");
			RecvFromLocal (); // Restart listener and continue work
			return;
		}
		if (!isIdentity)
		{
			LogPrint (eLogWarning, "UDP Client: Remote endpoint not resolved yet");
			RecvFromLocal ();
			return; // drop, remote not resolved
		}
		if (!m_IsSendingAllowed)
		{
			const auto ts1 = i2p::util::GetMillisecondsSinceEpoch ();
			if (!m_IsFirstPacket && ts1 > m_LastRepliableDatagramTime + I2P_UDP_SESSION_TIMEOUT)
			{
				//  reset session
				m_IsFirstPacket = true;
				m_IsSendingAllowed = true;
				m_UnackedDatagrams.clear ();
				m_AckTimerSeqn = 0;
				m_RTT = 0;
			}
			if (!m_IsSendingAllowed)
			{
				if (!(m_IsFirstPacket && ts1 > m_LastRepliableDatagramTime + I2P_UDP_FIRST_PACKET_RESEND_INTERVAL))
				{
					RecvFromLocal ();
					return;
				}
				// else fall through and send new first packet, previous one wasn't acked in time
			}
		}
		ExpireUnackedDatagrams (i2p::util::GetMillisecondsSinceEpoch ());
		bool isWindowFull = IsWindowFull ();
		if (isWindowFull && i2p::util::GetMillisecondsSinceEpoch () < m_LastWindowProbeTime + GetWindowProbeInterval ())
		{
			// window is full, drop packet
			m_NumWindowDrops++;
			if (m_NumWindowDrops == 1 || !(m_NumWindowDrops % 100))
				LogPrint (eLogWarning, "UDP Client: Window full (front=", m_UnackedDatagrams.front ().first,
					" next=", m_NextSendPacketNum, "), dropped ", m_NumWindowDrops, " packets");
			RecvFromLocal ();
			return;
		}
		auto remotePort = m_RecvEndpoint.port ();
		if (!m_LastPort || m_LastPort != remotePort)
		{
			std::lock_guard<std::mutex> lock (m_SessionsMutex);
			auto itr = m_Sessions.find (remotePort);
			if (itr != m_Sessions.end ())
				m_LastSession = itr->second;
			else
			{
				m_LastSession = std::make_shared<UDPConvo> (boost::asio::ip::udp::endpoint (m_RecvEndpoint), 0);
				m_Sessions.emplace (remotePort, m_LastSession);
			}
			m_LastPort = remotePort;
		}
		// send off to remote i2p destination
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (isWindowFull) m_LastWindowProbeTime = ts;
		LogPrint (eLogDebug, "UDP Client: Send ", transferred, " to ", Identity.ToBase32 (), ":", RemotePort);
		auto session = GetDatagramSession ();
		uint64_t repliableDatagramInterval = I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL;
		if (m_RTT && m_RTT >= I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL && m_RTT < I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL*10) repliableDatagramInterval = m_RTT/10; // 10 - 100 ms
		if (isWindowFull || ts > m_LastRepliableDatagramTime + repliableDatagramInterval)
		{
			if (m_DatagramVersion == i2p::datagram::eDatagramV3)
			{
				uint8_t flags = 0;
				if (isWindowFull || !m_RTT || !m_AckTimerSeqn || (!m_UnackedDatagrams.empty () &&
					ts > m_UnackedDatagrams.back ().second + repliableDatagramInterval)) // last ack request
				{
					flags |= UDP_SESSION_FLAG_ACK_REQUESTED;
					m_UnackedDatagrams.push_back ({ m_NextSendPacketNum, ts });
					ScheduleAckTimer (m_NextSendPacketNum);
				}
				if (m_IsFirstPacket)
					flags |= UDP_SESSION_FLAG_RESET_SEQN;
				i2p::util::Mapping options;
				options.Put (UDP_SESSION_SEQN, m_NextSendPacketNum);
				if (m_LastReceivedPacketNum > 0)
					options.Put (UDP_SESSION_ACKED, m_LastReceivedPacketNum);
				if (flags)
					options.Put (UDP_SESSION_FLAGS, flags);
				m_Destination->SendDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort, &options);
				if (m_IsFirstPacket) m_IsSendingAllowed = false; // send only one packet at the start and wait ack
			}
			else
				m_Destination->SendDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort);
			m_LastRepliableDatagramTime = ts;
		}
		else
			m_Destination->SendRawDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort);
		size_t numPackets = 0;
		while (numPackets < i2p::datagram::DATAGRAM_SEND_QUEUE_MAX_SIZE)
		{
			boost::system::error_code ec;
			size_t moreBytes = m_LocalSocket->available (ec);
			if (ec || !moreBytes) break;
			transferred = m_LocalSocket->receive_from (boost::asio::buffer (m_RecvBuff, I2P_UDP_MAX_MTU), m_RecvEndpoint, 0, ec);
			remotePort = m_RecvEndpoint.port ();
			// TODO: check remotePort
			m_Destination->SendRawDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort);
			numPackets++;
		}
		if (numPackets)
			LogPrint (eLogDebug, "UDP Client: Sent ", numPackets, " more packets to ", Identity.ToBase32 ());
		m_NextSendPacketNum += numPackets + 1;
		UpdateSendRate (numPackets + 1, ts);
		m_Destination->FlushSendQueue (session);

		// mark convo as active
		if (m_LastSession)
			m_LastSession->second = ts;
		RecvFromLocal ();
	}

	std::vector<std::shared_ptr<DatagramSessionInfo> > I2PUDPClientTunnel::GetSessions ()
	{
		// TODO: implement
		std::vector<std::shared_ptr<DatagramSessionInfo> > infos;
		return infos;
	}

	void I2PUDPClientTunnel::TryResolving ()
	{
		i2p::util::SetThreadName ("UDP Resolver");
		LogPrint (eLogInfo, "UDP Tunnel: Trying to resolve ", m_RemoteDest);

		std::shared_ptr<const Address> remoteAddr;
		while (!(remoteAddr = context.GetAddressBook().GetAddress(m_RemoteDest)) && !m_cancel_resolve)
		{
			LogPrint (eLogWarning, "UDP Tunnel: Failed to lookup ", m_RemoteDest);
			std::this_thread::sleep_for (std::chrono::seconds (1));
		}
		if (m_cancel_resolve)
		{
			LogPrint(eLogError, "UDP Tunnel: Lookup of ", m_RemoteDest, " was cancelled");
			return;
		}
		if (!remoteAddr)
		{
			LogPrint (eLogError, "UDP Tunnel: ", m_RemoteDest, " not found");
			return;
		}
		if (!remoteAddr->IsIdentHash ()) // TODO: handle B33
		{
			LogPrint (eLogError, "UDP Tunnel: ", m_RemoteDest, " resolved to invalid address type");
			return;
		}
		LogPrint(eLogInfo, "UDP Tunnel: Resolved ", m_RemoteDest, " to ", remoteAddr->identHash.ToBase32 ());
		SetIdentity (remoteAddr->identHash);
	}

	void I2PUDPClientTunnel::HandleRecvFromI2P (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
		const uint8_t * buf, size_t len, const i2p::util::Mapping * options)
	{
		if (isIdentity && from.GetIdentHash() == Identity)
		{
			m_LastReceivedTime = i2p::util::GetMillisecondsSinceEpoch ();
			if (options)
			{
				uint32_t seqn = 0;
				if (options->Get (UDP_SESSION_SEQN, seqn) && seqn > m_LastReceivedPacketNum)
					m_LastReceivedPacketNum = seqn;
				uint8_t flags = 0;
				if (options->Get (UDP_SESSION_FLAGS, flags))
				{
					if ((flags & UDP_SESSION_FLAG_RESET_SEQN) && seqn)
						m_LastReceivedPacketNum = seqn;
					if (flags & UDP_SESSION_FLAG_ACK_REQUESTED)
					{
						i2p::util::Mapping replyOptions;
						replyOptions.Put (UDP_SESSION_ACKED, m_LastReceivedPacketNum);
						m_Destination->SendDatagram (GetDatagramSession (),
							nullptr, 0, m_LastPort, RemotePort, &replyOptions); // Ack only, no payload
						m_LastRepliableDatagramTime = i2p::util::GetMillisecondsSinceEpoch ();
					}
				}
				if (options->Get (UDP_SESSION_ACKED, seqn))
					Acked (seqn);
			}
			if (len > 0)
				HandleRecvFromI2PRaw (fromPort, toPort, buf, len);
		}
		else
			LogPrint(eLogWarning, "UDP Client: Unwarranted traffic from ", from.GetIdentHash().ToBase32 ());
	}

	void I2PUDPClientTunnel::HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		m_LastReceivedTime = i2p::util::GetMillisecondsSinceEpoch ();
		std::shared_ptr<UDPConvo> convo;
		{
			std::lock_guard<std::mutex> lock (m_SessionsMutex);
			auto itr = m_Sessions.find (toPort);
			// found convo ?
			if (itr != m_Sessions.end ())
				convo = itr->second;
		}
		if (convo)
		{
			// found convo
			if (len > 0)
			{
				LogPrint (eLogDebug, "UDP Client: Got ", len, "B from ", isIdentity ? Identity.ToBase32 () : "");
				boost::system::error_code ec;
				m_LocalSocket->send_to (boost::asio::buffer (buf, len), convo->first, 0, ec);
				if (!ec)
					// mark convo as active
					convo->second = i2p::util::GetMillisecondsSinceEpoch ();
				else
					LogPrint (eLogInfo, "UDP Client: Send exception: ", ec.message (), " to ", convo->first);
			}
		}
		else
			LogPrint (eLogWarning, "UDP Client: Not tracking udp session using port ", (int) toPort);
	}

	void I2PUDPClientTunnel::SetKeepAliveInterval (uint32_t keepAliveInterval)
	{
		m_KeepAliveInterval = keepAliveInterval;
		if (m_KeepAliveInterval)
			m_KeepAliveTimer.reset (new boost::asio::steady_timer (m_LocalDest->GetService ()));
	}

	void I2PUDPClientTunnel::ScheduleKeepAliveTimer ()
	{
		if (m_KeepAliveTimer)
		{
			m_KeepAliveTimer->expires_after (std::chrono::seconds (m_KeepAliveInterval));
			m_KeepAliveTimer->async_wait (std::bind (&I2PUDPClientTunnel::HandleKeepAliveTimer,
				this, std::placeholders::_1));
		}
	}

	void I2PUDPClientTunnel::HandleKeepAliveTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (i2p::util::GetMillisecondsSinceEpoch () > m_LastRepliableDatagramTime + m_KeepAliveInterval*1000)
				HandleRecvFromLocal (boost::system::error_code(), 0); // send empty packet like it was received from local
			ScheduleKeepAliveTimer ();
		}
	}

	void I2PUDPClientTunnel::ScheduleStatsTimer ()
	{
		if (m_StatsTimer)
		{
			m_StatsTimer->expires_after (std::chrono::seconds (10));
			m_StatsTimer->async_wait (std::bind (&I2PUDPClientTunnel::HandleStatsTimer,
				this, std::placeholders::_1));
		}
	}

	void I2PUDPClientTunnel::HandleStatsTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto session = GetDatagramSession ();
			LogPrint (eLogDebug, "UDP Client: stats rtt=", m_RTT, "/", m_RTTVar, "/", m_MinRTT, "ms rto=", GetRTO (),
				"ms rate=", m_SendRate, "/s window=", GetMaxNumUnackedDatagrams (),
				" unacked=", m_UnackedDatagrams.size (),
				" nextSeqn=", m_NextSendPacketNum, " winDrops=", m_NumWindowDrops,
				" ackTimeouts=", m_NumAckTimeouts,
				" pathDrops=", session ? session->GetNumPathDrops () : 0,
				" noPathDrops=", session ? session->GetNumDroppedNoPath () : 0);
			ScheduleStatsTimer ();
		}
	}
}
}
