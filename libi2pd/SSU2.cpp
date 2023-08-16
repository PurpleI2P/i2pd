/*
* Copyright (c) 2022-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <random>
#include "Log.h"
#include "RouterContext.h"
#include "Transports.h"
#include "NetDb.hpp"
#include "Config.h"
#include "SSU2.h"

namespace i2p
{
namespace transport
{
	SSU2Server::SSU2Server ():
		RunnableServiceWithWork ("SSU2"), m_ReceiveService ("SSU2r"),
		m_SocketV4 (m_ReceiveService.GetService ()), m_SocketV6 (m_ReceiveService.GetService ()),
		m_AddressV4 (boost::asio::ip::address_v4()), m_AddressV6 (boost::asio::ip::address_v6()),
		m_TerminationTimer (GetService ()), m_CleanupTimer (GetService ()), m_ResendTimer (GetService ()),
		m_IntroducersUpdateTimer (GetService ()), m_IntroducersUpdateTimerV6 (GetService ()),
		m_IsPublished (true), m_IsSyncClockFromPeers (true), m_IsThroughProxy (false)
	{
	}

	void SSU2Server::Start ()
	{
		if (!IsRunning ())
		{
			StartIOService ();
			i2p::config::GetOption ("ssu2.published", m_IsPublished);
			i2p::config::GetOption("nettime.frompeers", m_IsSyncClockFromPeers);
			bool found = false;
			auto addresses = i2p::context.GetRouterInfo ().GetAddresses ();
			if (!addresses) return;
			for (const auto& address: *addresses)
			{
				if (!address) continue;
				if (address->transportStyle == i2p::data::RouterInfo::eTransportSSU2)
				{
					if (m_IsThroughProxy)
					{
						found = true;
						if (address->IsV6 ())
						{
							uint16_t mtu; i2p::config::GetOption ("ssu2.mtu6", mtu);
							if (!mtu || mtu > SSU2_MAX_PACKET_SIZE - SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE)
								mtu = SSU2_MAX_PACKET_SIZE - SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE;
							i2p::context.SetMTU (mtu, false);
						}
						else
						{
							uint16_t mtu; i2p::config::GetOption ("ssu2.mtu4", mtu);
							if (!mtu || mtu > SSU2_MAX_PACKET_SIZE - SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE)
								mtu = SSU2_MAX_PACKET_SIZE - SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE;
							i2p::context.SetMTU (mtu, true);
						}
						continue; // we don't need port for proxy
					}
					auto port = address->port;
					if (!port)
					{
						uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
						if (ssu2Port) port = ssu2Port;
						else
						{
							uint16_t p; i2p::config::GetOption ("port", p);
							if (p) port = p;
						}
					}
					if (port)
					{
						if (address->IsV4 ())
						{
							found = true;
							LogPrint (eLogDebug, "SSU2: Opening IPv4 socket at Start");
							OpenSocket (boost::asio::ip::udp::endpoint (m_AddressV4, port));
							m_ReceiveService.GetService ().post(
								[this]()
								{
									Receive (m_SocketV4);
								});
							ScheduleIntroducersUpdateTimer (); // wait for 30 seconds and decide if we need introducers
						}
						if (address->IsV6 ())
						{
							found = true;
							LogPrint (eLogDebug, "SSU2: Opening IPv6 socket at Start");
							OpenSocket (boost::asio::ip::udp::endpoint (m_AddressV6, port));
							m_ReceiveService.GetService ().post(
							[this]()
								{
									Receive (m_SocketV6);
								});
							ScheduleIntroducersUpdateTimerV6 (); // wait for 30 seconds and decide if we need introducers
						}
					}
					else
						LogPrint (eLogCritical, "SSU2: Can't start server because port not specified");
				}
			}
			if (found)
			{
				if (m_IsThroughProxy)
					ConnectToProxy ();
				m_ReceiveService.Start ();
			}
			ScheduleTermination ();
			ScheduleCleanup ();
			ScheduleResend (false);
		}
	}

	void SSU2Server::Stop ()
	{
		if (IsRunning ())
		{
			m_TerminationTimer.cancel ();
			m_CleanupTimer.cancel ();
			m_ResendTimer.cancel ();
			m_IntroducersUpdateTimer.cancel ();
			m_IntroducersUpdateTimerV6.cancel ();
		}

		auto sessions = m_Sessions;
		for (auto& it: sessions)
		{
			it.second->RequestTermination (eSSU2TerminationReasonRouterShutdown);
			it.second->Done ();
		}

		if (context.SupportsV4 () || context.SupportsV6 ())
			m_ReceiveService.Stop ();
		m_SocketV4.close ();
		m_SocketV6.close ();

		if (m_UDPAssociateSocket)
		{
			m_UDPAssociateSocket->close ();
			m_UDPAssociateSocket.reset (nullptr);
		}

		StopIOService ();

		m_Sessions.clear ();
		m_SessionsByRouterHash.clear ();
		m_PendingOutgoingSessions.clear ();
		m_Relays.clear ();
		m_Introducers.clear ();
		m_IntroducersV6.clear ();
	}

	void SSU2Server::SetLocalAddress (const boost::asio::ip::address& localAddress)
	{
		if (localAddress.is_unspecified ()) return;
		if (localAddress.is_v4 ())
		{
			m_AddressV4 = localAddress;
			uint16_t mtu; i2p::config::GetOption ("ssu2.mtu4", mtu);
			if (!mtu) mtu = i2p::util::net::GetMTU (localAddress);
			if (mtu < (int)SSU2_MIN_PACKET_SIZE) mtu = SSU2_MIN_PACKET_SIZE;
			if (mtu > (int)SSU2_MAX_PACKET_SIZE) mtu = SSU2_MAX_PACKET_SIZE;
			i2p::context.SetMTU (mtu, true);
		}
		else if (localAddress.is_v6 ())
		{
			m_AddressV6 = localAddress;
			uint16_t mtu; i2p::config::GetOption ("ssu2.mtu6", mtu);
			if (!mtu)
			{
				int maxMTU = i2p::util::net::GetMaxMTU (localAddress.to_v6 ());
				mtu = i2p::util::net::GetMTU (localAddress);
				if (mtu > maxMTU) mtu = maxMTU;
			}
			else
				if (mtu > (int)SSU2_MAX_PACKET_SIZE) mtu = SSU2_MAX_PACKET_SIZE;
			if (mtu < (int)SSU2_MIN_PACKET_SIZE) mtu = SSU2_MIN_PACKET_SIZE;
			i2p::context.SetMTU (mtu, false);
		}
	}

	bool SSU2Server::IsSupported (const boost::asio::ip::address& addr) const
	{
		if (m_IsThroughProxy)
			return m_SocketV4.is_open ();
		if (addr.is_v4 ())
		{
			if (m_SocketV4.is_open ())
				return true;
		}
		else if (addr.is_v6 ())
		{
			if (m_SocketV6.is_open ())
				return true;
		}
		return false;
	}

	uint16_t SSU2Server::GetPort (bool v4) const
	{
		boost::system::error_code ec;
		boost::asio::ip::udp::endpoint ep = (v4 || m_IsThroughProxy) ? m_SocketV4.local_endpoint (ec) : m_SocketV6.local_endpoint (ec);
		if (ec) return 0;
		return ep.port ();
	}

	boost::asio::ip::udp::socket& SSU2Server::OpenSocket (const boost::asio::ip::udp::endpoint& localEndpoint)
	{
		boost::asio::ip::udp::socket& socket = localEndpoint.address ().is_v6 () ? m_SocketV6 : m_SocketV4;
		try
		{
			if (socket.is_open ())
				socket.close ();
			socket.open (localEndpoint.protocol ());
			if (localEndpoint.address ().is_v6 ())
				socket.set_option (boost::asio::ip::v6_only (true));
			socket.set_option (boost::asio::socket_base::receive_buffer_size (SSU2_SOCKET_RECEIVE_BUFFER_SIZE));
			socket.set_option (boost::asio::socket_base::send_buffer_size (SSU2_SOCKET_SEND_BUFFER_SIZE));
			socket.bind (localEndpoint);
			LogPrint (eLogInfo, "SSU2: Start listening on ", localEndpoint);
		}
		catch (std::exception& ex )
		{
			LogPrint (eLogCritical, "SSU2: Failed to bind to ", localEndpoint, ": ", ex.what());
			ThrowFatal ("Unable to start SSU2 transport on ", localEndpoint, ": ", ex.what ());
		}
		return socket;
	}

	void SSU2Server::Receive (boost::asio::ip::udp::socket& socket)
	{
		Packet * packet = m_PacketsPool.AcquireMt ();
		socket.async_receive_from (boost::asio::buffer (packet->buf, SSU2_MAX_PACKET_SIZE), packet->from,
			std::bind (&SSU2Server::HandleReceivedFrom, this, std::placeholders::_1, std::placeholders::_2, packet, std::ref (socket)));
	}

	void SSU2Server::HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred,
		Packet * packet, boost::asio::ip::udp::socket& socket)
	{
		if (!ecode
			|| ecode == boost::asio::error::connection_refused
			|| ecode == boost::asio::error::connection_reset
			|| ecode == boost::asio::error::network_reset
			|| ecode == boost::asio::error::network_unreachable
			|| ecode == boost::asio::error::host_unreachable
#ifdef _WIN32 // windows can throw WinAPI error, which is not handled by ASIO
			|| ecode.value() == boost::winapi::ERROR_CONNECTION_REFUSED_
			|| ecode.value() == boost::winapi::WSAENETRESET_ // 10052
			|| ecode.value() == boost::winapi::ERROR_NETWORK_UNREACHABLE_
			|| ecode.value() == boost::winapi::ERROR_HOST_UNREACHABLE_
#endif
		)
		// just try continue reading when received ICMP response otherwise socket can crash,
		// but better to find out which host were sent it and mark that router as unreachable
		{
			i2p::transport::transports.UpdateReceivedBytes (bytes_transferred);
			packet->len = bytes_transferred;

			boost::system::error_code ec;
			size_t moreBytes = socket.available (ec);
			if (!ec && moreBytes)
			{
				std::vector<Packet *> packets;
				packets.push_back (packet);
				while (moreBytes && packets.size () < 32)
				{
					packet = m_PacketsPool.AcquireMt ();
					packet->len = socket.receive_from (boost::asio::buffer (packet->buf, SSU2_MAX_PACKET_SIZE), packet->from, 0, ec);
					if (!ec)
					{
						i2p::transport::transports.UpdateReceivedBytes (packet->len);
						packets.push_back (packet);
						moreBytes = socket.available(ec);
						if (ec) break;
					}
					else
					{
						LogPrint (eLogError, "SSU2: receive_from error: code ", ec.value(), ": ", ec.message ());
						m_PacketsPool.ReleaseMt (packet);
						break;
					}
				}
				GetService ().post (std::bind (&SSU2Server::HandleReceivedPackets, this, packets));
			}
			else
				GetService ().post (std::bind (&SSU2Server::HandleReceivedPacket, this, packet));
			Receive (socket);
		}
		else
		{
			m_PacketsPool.ReleaseMt (packet);
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "SSU2: Receive error: code ", ecode.value(), ": ", ecode.message ());
				if (m_IsThroughProxy)
				{
					m_UDPAssociateSocket.reset (nullptr);
					m_ProxyRelayEndpoint.reset (nullptr);
					m_SocketV4.close ();
					ConnectToProxy ();
				}
				else
				{
					auto ep = socket.local_endpoint ();
					LogPrint (eLogCritical, "SSU2: Reopening socket in HandleReceivedFrom: code ", ecode.value(), ": ", ecode.message ());
					OpenSocket (ep);
					Receive (socket);
				}
			}
		}
	}

	void SSU2Server::HandleReceivedPacket (Packet * packet)
	{
		if (packet)
		{
			if (m_IsThroughProxy)
				ProcessNextPacketFromProxy (packet->buf, packet->len);
			else
				ProcessNextPacket (packet->buf, packet->len, packet->from);
			m_PacketsPool.ReleaseMt (packet);
			if (m_LastSession && m_LastSession->GetState () != eSSU2SessionStateTerminated)
				m_LastSession->FlushData ();
		}
	}

	void SSU2Server::HandleReceivedPackets (std::vector<Packet *> packets)
	{
		if (m_IsThroughProxy)
			for (auto& packet: packets)
				ProcessNextPacketFromProxy (packet->buf, packet->len);
		else
			for (auto& packet: packets)
				ProcessNextPacket (packet->buf, packet->len, packet->from);
		m_PacketsPool.ReleaseMt (packets);
		if (m_LastSession && m_LastSession->GetState () != eSSU2SessionStateTerminated)
			m_LastSession->FlushData ();
	}

	void SSU2Server::AddSession (std::shared_ptr<SSU2Session> session)
	{
		if (session)
		{
			m_Sessions.emplace (session->GetConnID (), session);
			AddSessionByRouterHash (session);
		}
	}

	void SSU2Server::RemoveSession (uint64_t connID)
	{
		auto it = m_Sessions.find (connID);
		if (it != m_Sessions.end ())
		{
			auto ident = it->second->GetRemoteIdentity ();
			if (ident)
				m_SessionsByRouterHash.erase (ident->GetIdentHash ());
			if (m_LastSession == it->second)
				m_LastSession = nullptr;
			m_Sessions.erase (it);
		}
	}

	void SSU2Server::AddSessionByRouterHash (std::shared_ptr<SSU2Session> session)
	{
		if (session)
		{
			auto ident = session->GetRemoteIdentity ();
			if (ident)
			{
				auto ret = m_SessionsByRouterHash.emplace (ident->GetIdentHash (), session);
				if (!ret.second)
				{
					// session already exists
					LogPrint (eLogWarning, "SSU2: Session to ", ident->GetIdentHash ().ToBase64 (), " already exists");
					// terminate existing
					GetService ().post (std::bind (&SSU2Session::RequestTermination, ret.first->second, eSSU2TerminationReasonReplacedByNewSession));
					// update session
					ret.first->second = session;
				}
			}
		}
	}

	bool SSU2Server::AddPendingOutgoingSession (std::shared_ptr<SSU2Session> session)
	{
		if (!session) return false;
		std::unique_lock<std::mutex> l(m_PendingOutgoingSessionsMutex);
		return m_PendingOutgoingSessions.emplace (session->GetRemoteEndpoint (), session).second;
	}

	std::shared_ptr<SSU2Session> SSU2Server::FindSession (const i2p::data::IdentHash& ident) const
	{
		auto it = m_SessionsByRouterHash.find (ident);
		if (it != m_SessionsByRouterHash.end ())
			return it->second;
		return nullptr;
	}

	std::shared_ptr<SSU2Session> SSU2Server::FindPendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep) const
	{
		std::unique_lock<std::mutex> l(m_PendingOutgoingSessionsMutex);
		auto it = m_PendingOutgoingSessions.find (ep);
		if (it != m_PendingOutgoingSessions.end ())
			return it->second;
		return nullptr;
	}

	void SSU2Server::RemovePendingOutgoingSession (const boost::asio::ip::udp::endpoint& ep)
	{
		std::unique_lock<std::mutex> l(m_PendingOutgoingSessionsMutex);
		m_PendingOutgoingSessions.erase (ep);
	}

	std::shared_ptr<SSU2Session> SSU2Server::GetRandomSession (
		i2p::data::RouterInfo::CompatibleTransports remoteTransports, const i2p::data::IdentHash& excluded) const
	{
		if (m_Sessions.empty ()) return nullptr;
		uint16_t ind;
		RAND_bytes ((uint8_t *)&ind, sizeof (ind));
		ind %= m_Sessions.size ();
		auto it = m_Sessions.begin ();
		std::advance (it, ind);
		while (it != m_Sessions.end ())
		{
			if ((it->second->GetRemoteTransports () & remoteTransports) &&
			    it->second->GetRemoteIdentity ()->GetIdentHash () != excluded)
				return it->second;
			it++;
		}
		// not found, try from beginning
		it = m_Sessions.begin ();
		while (it != m_Sessions.end () && ind)
		{
			if ((it->second->GetRemoteTransports () & remoteTransports) &&
			    it->second->GetRemoteIdentity ()->GetIdentHash () != excluded)
				return it->second;
			it++; ind--;
		}
		return nullptr;
	}

	void SSU2Server::AddRelay (uint32_t tag, std::shared_ptr<SSU2Session> relay)
	{
		m_Relays.emplace (tag, relay);
	}

	void SSU2Server::RemoveRelay (uint32_t tag)
	{
		m_Relays.erase (tag);
	}

	std::shared_ptr<SSU2Session> SSU2Server::FindRelaySession (uint32_t tag)
	{
		auto it = m_Relays.find (tag);
		if (it != m_Relays.end ())
		{
			if (it->second->IsEstablished ())
				return it->second;
			else
				m_Relays.erase (it);
		}
		return nullptr;
	}

	void SSU2Server::ProcessNextPacket (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint)
	{
		if (len < 24) return;
		uint64_t connID;
		memcpy (&connID, buf, 8);
		connID ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
		if (!m_LastSession || m_LastSession->GetConnID () != connID)
		{
			if (m_LastSession) m_LastSession->FlushData ();
			auto it = m_Sessions.find (connID);
			if (it != m_Sessions.end ())
				m_LastSession = it->second;
			else
				m_LastSession = nullptr;
		}
		if (m_LastSession)
		{
			switch (m_LastSession->GetState ())
			{
				case eSSU2SessionStateEstablished:
				case eSSU2SessionStateSessionConfirmedSent:
					m_LastSession->ProcessData (buf, len, senderEndpoint);
				break;
				case eSSU2SessionStateSessionCreatedSent:
					if (!m_LastSession->ProcessSessionConfirmed (buf, len))
					{
						m_LastSession->Done ();
						m_LastSession = nullptr;
					}
				break;
				case eSSU2SessionStateIntroduced:
					if (m_LastSession->GetRemoteEndpoint ().address ().is_unspecified ())
						m_LastSession->SetRemoteEndpoint (senderEndpoint);
					if (m_LastSession->GetRemoteEndpoint ().address () == senderEndpoint.address ()) // port might be different
						m_LastSession->ProcessHolePunch (buf, len);
					else
					{
						LogPrint (eLogWarning, "SSU2: HolePunch address ", senderEndpoint.address (),
							" doesn't match RelayResponse ", m_LastSession->GetRemoteEndpoint ().address ());
						m_LastSession->Done ();
						m_LastSession = nullptr;
					}
				break;
				case eSSU2SessionStatePeerTest:
					m_LastSession->SetRemoteEndpoint (senderEndpoint);
					m_LastSession->ProcessPeerTest (buf, len);
				break;
				case eSSU2SessionStateClosing:
					m_LastSession->ProcessData (buf, len, senderEndpoint); // we might receive termintaion block
					if (m_LastSession && m_LastSession->GetState () == eSSU2SessionStateClosing)
						m_LastSession->RequestTermination (eSSU2TerminationReasonIdleTimeout); // send termination again
				break;
				case eSSU2SessionStateClosingConfirmed:
				case eSSU2SessionStateTerminated:
					m_LastSession = nullptr;
				break;
				default:
					LogPrint (eLogWarning, "SSU2: Invalid session state ", (int)m_LastSession->GetState ());
			}
		}
		else
		{
			// check pending sessions if it's SessionCreated or Retry
			auto it1 = m_PendingOutgoingSessions.find (senderEndpoint);
			if (it1 != m_PendingOutgoingSessions.end ())
			{
				if (it1->second->GetState () == eSSU2SessionStateSessionRequestSent &&
					it1->second->ProcessSessionCreated (buf, len))
				{
					std::unique_lock<std::mutex> l(m_PendingOutgoingSessionsMutex);
					m_PendingOutgoingSessions.erase (it1); // we are done with that endpoint
				}
				else
					it1->second->ProcessRetry (buf, len);
			}
			else if (!i2p::util::net::IsInReservedRange(senderEndpoint.address ()) && senderEndpoint.port ())
			{
				// assume new incoming session
				auto session = std::make_shared<SSU2Session> (*this);
				session->SetRemoteEndpoint (senderEndpoint);
				session->ProcessFirstIncomingMessage (connID, buf, len);
			}
			else
				LogPrint (eLogError, "SSU2: Incoming packet received from invalid endpoint ", senderEndpoint);
		}
	}

	void SSU2Server::Send (const uint8_t * header, size_t headerLen, const uint8_t * payload, size_t payloadLen,
		const boost::asio::ip::udp::endpoint& to)
	{
		if (m_IsThroughProxy)
		{
			SendThroughProxy (header, headerLen, nullptr, 0, payload, payloadLen, to);
			return;
		}

		std::vector<boost::asio::const_buffer> bufs
		{
			boost::asio::buffer (header, headerLen),
			boost::asio::buffer (payload, payloadLen)
		};

		boost::system::error_code ec;
		if (to.address ().is_v6 ())
		{
			if (!m_SocketV6.is_open ()) return;
			m_SocketV6.send_to (bufs, to, 0, ec);
		}
		else
		{
			if (!m_SocketV4.is_open ()) return;
			m_SocketV4.send_to (bufs, to, 0, ec);
		}

		if (!ec)
			i2p::transport::transports.UpdateSentBytes (headerLen + payloadLen);
		else
			LogPrint (eLogError, "SSU2: Send exception: ", ec.message (), " to ", to);
	}

	void SSU2Server::Send (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen,
		const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to)
	{
		if (m_IsThroughProxy)
		{
			SendThroughProxy (header, headerLen, headerX, headerXLen, payload, payloadLen, to);
			return;
		}

		std::vector<boost::asio::const_buffer> bufs
		{
			boost::asio::buffer (header, headerLen),
			boost::asio::buffer (headerX, headerXLen),
			boost::asio::buffer (payload, payloadLen)
		};

		boost::system::error_code ec;
		if (to.address ().is_v6 ())
		{
			if (!m_SocketV6.is_open ()) return;
			m_SocketV6.send_to (bufs, to, 0, ec);
		}
		else
		{
			if (!m_SocketV4.is_open ()) return;
			m_SocketV4.send_to (bufs, to, 0, ec);
		}

		if (!ec)
			i2p::transport::transports.UpdateSentBytes (headerLen + headerXLen + payloadLen);
		else
			LogPrint (eLogError, "SSU2: Send exception: ", ec.message (), " to ", to);
	}

	bool SSU2Server::CreateSession (std::shared_ptr<const i2p::data::RouterInfo> router,
		std::shared_ptr<const i2p::data::RouterInfo::Address> address, bool peerTest)
	{
		if (router && address)
		{
			// check if no session
			auto it = m_SessionsByRouterHash.find (router->GetIdentHash ());
			if (it != m_SessionsByRouterHash.end ())
			{
				// session with router found, trying to send peer test if requested
				if (peerTest && it->second->IsEstablished ())
				{
					auto session = it->second;
					GetService ().post ([session]() { session->SendPeerTest (); });
				}
				return false;
			}
			// check is no pending session
			bool isValidEndpoint = !address->host.is_unspecified () && address->port;
			if (isValidEndpoint)
			{
				if (i2p::util::net::IsInReservedRange(address->host)) return false;
				auto s = FindPendingOutgoingSession (boost::asio::ip::udp::endpoint (address->host, address->port));
				if (s)
				{
					if (peerTest)
					{
						// if peer test requested add it to the list for pending session
						auto onEstablished = s->GetOnEstablished ();
						if (onEstablished)
							s->SetOnEstablished ([s, onEstablished]()
								{
									onEstablished ();
									s->SendPeerTest ();
								});
						else
							s->SetOnEstablished ([s]() { s->SendPeerTest (); });
					}
					return false;
				}
			}

			auto session = std::make_shared<SSU2Session> (*this, router, address);
			if (peerTest)
				session->SetOnEstablished ([session]() {session->SendPeerTest (); });

			if (address->UsesIntroducer ())
				GetService ().post (std::bind (&SSU2Server::ConnectThroughIntroducer, this, session));
			else if (isValidEndpoint) // we can't connect without endpoint
				GetService ().post ([session]() { session->Connect (); });
			else
				return false;
		}
		else
			return false;
		return true;
	}

	void SSU2Server::ConnectThroughIntroducer (std::shared_ptr<SSU2Session> session)
	{
		if (!session) return;
		auto address = session->GetAddress ();
		if (!address) return;
		session->WaitForIntroduction ();
		// try to find existing session first
		for (auto& it: address->ssu->introducers)
		{
			auto it1 = m_SessionsByRouterHash.find (it.iH);
			if (it1 != m_SessionsByRouterHash.end ())
			{
				it1->second->Introduce (session, it.iTag);
				return;
			}
		}
		// we have to start a new session to an introducer
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		std::shared_ptr<i2p::data::RouterInfo> r;
		uint32_t relayTag = 0;
		if (!address->ssu->introducers.empty ())
		{
			std::vector<int> indices;
			for (int i = 0; i < (int)address->ssu->introducers.size (); i++) indices.push_back(i);
			if (indices.size () > 1)
				std::shuffle (indices.begin(), indices.end(), std::mt19937(std::random_device()()));

			for (auto i: indices)
			{
				const auto& introducer = address->ssu->introducers[indices[i]];
				if (introducer.iTag && ts < introducer.iExp)
				{
					r = i2p::data::netdb.FindRouter (introducer.iH);
					if (r && r->IsReachableFrom (i2p::context.GetRouterInfo ()))
					{
						relayTag = introducer.iTag;
						if (relayTag) break;
					}
				}
			}
		}
		if (r)
		{
			if (relayTag)
			{
				// introducer and tag found connect to it through SSU2
				auto addr = address->IsV6 () ? r->GetSSU2V6Address () : r->GetSSU2V4Address ();
				if (addr)
				{
					bool isValidEndpoint = !addr->host.is_unspecified () && addr->port &&
						!i2p::util::net::IsInReservedRange(addr->host);
					if (isValidEndpoint)
					{
						auto s = FindPendingOutgoingSession (boost::asio::ip::udp::endpoint (addr->host, addr->port));
						if (!s)
						{
							s = std::make_shared<SSU2Session> (*this, r, addr);
							s->SetOnEstablished ([session, s, relayTag]() { s->Introduce (session, relayTag); });
							s->Connect ();
						}
						else
						{
							auto onEstablished = s->GetOnEstablished ();
							if (onEstablished)
								s->SetOnEstablished ([session, s, relayTag, onEstablished]()
									{
										onEstablished ();
										s->Introduce (session, relayTag);
									});
							else
								s->SetOnEstablished ([session, s, relayTag]() {s->Introduce (session, relayTag); });
						}
					}
				}
			}
		}
		else
		{
			// introducers not found, try to request them
			for (auto& it: address->ssu->introducers)
				if (it.iTag && ts < it.iExp)
					i2p::data::netdb.RequestDestination (it.iH);
		}
	}

	bool SSU2Server::StartPeerTest (std::shared_ptr<const i2p::data::RouterInfo> router, bool v4)
	{
		if (!router) return false;
		auto addr = v4 ? router->GetSSU2V4Address () : router->GetSSU2V6Address ();
		if (!addr) return false;
		auto it = m_SessionsByRouterHash.find (router->GetIdentHash ());
		if (it != m_SessionsByRouterHash.end ())
		{
			auto s = it->second;
			if (it->second->IsEstablished ())
				GetService ().post ([s]() { s->SendPeerTest (); });
			else
				s->SetOnEstablished ([s]() { s->SendPeerTest (); });
			return true;
		}
		else
			CreateSession (router, addr, true);
		return true;
	}

	void SSU2Server::ScheduleTermination ()
	{
		m_TerminationTimer.expires_from_now (boost::posix_time::seconds(SSU2_TERMINATION_CHECK_TIMEOUT));
		m_TerminationTimer.async_wait (std::bind (&SSU2Server::HandleTerminationTimer,
			this, std::placeholders::_1));
	}

	void SSU2Server::HandleTerminationTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_PendingOutgoingSessions.begin (); it != m_PendingOutgoingSessions.end ();)
			{
				if (it->second->IsTerminationTimeoutExpired (ts))
				{
					//it->second->Terminate ();
					std::unique_lock<std::mutex> l(m_PendingOutgoingSessionsMutex);
					it = m_PendingOutgoingSessions.erase (it);
				}
				else
					it++;
			}

			for (auto it: m_Sessions)
			{
				auto state = it.second->GetState ();
				if (state == eSSU2SessionStateTerminated || state == eSSU2SessionStateClosing)
					it.second->Done ();
				else if (it.second->IsTerminationTimeoutExpired (ts))
				{
					if (it.second->IsEstablished ())
						it.second->RequestTermination (eSSU2TerminationReasonIdleTimeout);
					else
						it.second->Done ();
				}
				else
					it.second->CleanUp (ts);
			}

			for (auto it = m_SessionsByRouterHash.begin (); it != m_SessionsByRouterHash.begin ();)
			{
				if (it->second && it->second->GetState () == eSSU2SessionStateTerminated)
					it = m_SessionsByRouterHash.erase (it);
				else
					it++;
			}

			ScheduleTermination ();
		}
	}

	void SSU2Server::ScheduleCleanup ()
	{
		m_CleanupTimer.expires_from_now (boost::posix_time::seconds(SSU2_CLEANUP_INTERVAL));
		m_CleanupTimer.async_wait (std::bind (&SSU2Server::HandleCleanupTimer,
			this, std::placeholders::_1));
	}

	void SSU2Server::HandleCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_Relays.begin (); it != m_Relays.begin ();)
			{
				if (it->second && it->second->GetState () == eSSU2SessionStateTerminated)
					it = m_Relays.erase (it);
				else
					it++;
			}

			for (auto it = m_IncomingTokens.begin (); it != m_IncomingTokens.end (); )
			{
				if (ts > it->second.second)
					it = m_IncomingTokens.erase (it);
				else
					it++;
			}

			for (auto it = m_OutgoingTokens.begin (); it != m_OutgoingTokens.end (); )
			{
				if (ts > it->second.second)
					it = m_OutgoingTokens.erase (it);
				else
					it++;
			}

			m_PacketsPool.CleanUpMt ();
			m_SentPacketsPool.CleanUp ();
			m_IncompleteMessagesPool.CleanUp ();
			m_FragmentsPool.CleanUp ();
			ScheduleCleanup ();
		}
	}

	void SSU2Server::ScheduleResend (bool more)
	{
		m_ResendTimer.expires_from_now (boost::posix_time::milliseconds (more ? SSU2_RESEND_CHECK_MORE_TIMEOUT :
			(SSU2_RESEND_CHECK_TIMEOUT + rand () % SSU2_RESEND_CHECK_TIMEOUT_VARIANCE)));
		m_ResendTimer.async_wait (std::bind (&SSU2Server::HandleResendTimer,
			this, std::placeholders::_1));
	}

	void SSU2Server::HandleResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			size_t resentPacketsNum = 0;
			auto ts = i2p::util::GetMillisecondsSinceEpoch ();
			for (auto it: m_Sessions)
			{
				resentPacketsNum += it.second->Resend (ts);
				if (resentPacketsNum > SSU2_MAX_RESEND_PACKETS) break;
			}
			for (auto it: m_PendingOutgoingSessions)
				it.second->Resend (ts);
			ScheduleResend (resentPacketsNum > SSU2_MAX_RESEND_PACKETS);
		}
	}

	void SSU2Server::UpdateOutgoingToken (const boost::asio::ip::udp::endpoint& ep, uint64_t token, uint32_t exp)
	{
		m_OutgoingTokens[ep] = {token, exp};
	}

	uint64_t SSU2Server::FindOutgoingToken (const boost::asio::ip::udp::endpoint& ep)
	{
		auto it = m_OutgoingTokens.find (ep);
		if (it != m_OutgoingTokens.end ())
		{
			if (i2p::util::GetSecondsSinceEpoch () + SSU2_TOKEN_EXPIRATION_THRESHOLD > it->second.second)
			{
				// token expired
				m_OutgoingTokens.erase (it);
				return 0;
			}
			return it->second.first;
		}
		return 0;
	}

	uint64_t SSU2Server::GetIncomingToken (const boost::asio::ip::udp::endpoint& ep)
	{
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		auto it = m_IncomingTokens.find (ep);
		if (it != m_IncomingTokens.end ())
		{
			if (ts + SSU2_TOKEN_EXPIRATION_THRESHOLD <= it->second.second)
				return it->second.first;
			else // token expired
				m_IncomingTokens.erase (it);
		}
		uint64_t token;
		RAND_bytes ((uint8_t *)&token, 8);
		m_IncomingTokens.emplace (ep, std::make_pair (token, uint32_t(ts + SSU2_TOKEN_EXPIRATION_TIMEOUT)));
		return token;
	}

	std::pair<uint64_t, uint32_t> SSU2Server::NewIncomingToken (const boost::asio::ip::udp::endpoint& ep)
	{
		m_IncomingTokens.erase (ep); // drop previous
		uint64_t token;
		RAND_bytes ((uint8_t *)&token, 8);
		auto ret = std::make_pair (token, uint32_t(i2p::util::GetSecondsSinceEpoch () + SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT));
		m_IncomingTokens.emplace (ep, ret);
		return ret;
	}

	std::list<std::shared_ptr<SSU2Session> > SSU2Server::FindIntroducers (int maxNumIntroducers,
		bool v4, const std::set<i2p::data::IdentHash>& excluded) const
	{
		std::list<std::shared_ptr<SSU2Session> > ret;
		for (const auto& s : m_Sessions)
		{
			if (s.second->IsEstablished () && (s.second->GetRelayTag () && s.second->IsOutgoing ()) &&
			    !excluded.count (s.second->GetRemoteIdentity ()->GetIdentHash ()) &&
			    ((v4 && (s.second->GetRemoteTransports () & i2p::data::RouterInfo::eSSU2V4)) ||
			    (!v4 && (s.second->GetRemoteTransports () & i2p::data::RouterInfo::eSSU2V6))))
				ret.push_back (s.second);
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

	void SSU2Server::UpdateIntroducers (bool v4)
	{
		uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
		std::list<i2p::data::IdentHash> newList, impliedList;
		auto& introducers = v4 ? m_Introducers : m_IntroducersV6;
		std::set<i2p::data::IdentHash> excluded;
		for (const auto& it : introducers)
		{
			std::shared_ptr<SSU2Session> session;
			auto it1 = m_SessionsByRouterHash.find (it);
			if (it1 != m_SessionsByRouterHash.end ())
			{
				session = it1->second;
				excluded.insert (it);
			}
			if (session && session->IsEstablished () && session->GetRelayTag () && session->IsOutgoing ()) // still session with introducer?
			{
				if (ts < session->GetCreationTime () + SSU2_TO_INTRODUCER_SESSION_EXPIRATION)
				{	
					session->SendKeepAlive ();
					if (ts < session->GetCreationTime () + SSU2_TO_INTRODUCER_SESSION_DURATION)	
						newList.push_back (it);
					else	
					{	
						impliedList.push_back (it); // keep in introducers list, but not publish
						session = nullptr;	
					}		
				}	
				else
					session = nullptr;
			}
			if (!session)
				i2p::context.RemoveSSU2Introducer (it, v4);
		}
		if (newList.size () < SSU2_MAX_NUM_INTRODUCERS)
		{
			auto sessions = FindIntroducers (SSU2_MAX_NUM_INTRODUCERS - newList.size (), v4, excluded);
			if (sessions.empty () && !introducers.empty ())
			{
				// bump creation time for previous introducers if no new sessions found
				LogPrint (eLogDebug, "SSU2: No new introducers found. Trying to reuse existing");
				impliedList.clear ();
				for (auto& it : introducers)
				{
					auto it1 = m_SessionsByRouterHash.find (it);
					if (it1 != m_SessionsByRouterHash.end ())
					{
						auto session = it1->second;
						if (session->IsEstablished () && session->GetRelayTag () && session->IsOutgoing ())
						{
							session->SetCreationTime (session->GetCreationTime () + SSU2_TO_INTRODUCER_SESSION_DURATION);
							if (std::find (newList.begin (), newList.end (), it) == newList.end ())
								sessions.push_back (session);
						}
					}
				}
			}

			for (const auto& it : sessions)
			{
				uint32_t tag = it->GetRelayTag ();
				uint32_t exp = it->GetCreationTime () + SSU2_TO_INTRODUCER_SESSION_EXPIRATION;
				if (!tag || ts + SSU2_TO_INTRODUCER_SESSION_DURATION/2 > exp)
					continue; // don't pick too old session for introducer	
				i2p::data::RouterInfo::Introducer introducer;
				introducer.iTag = tag;
				introducer.iH = it->GetRemoteIdentity ()->GetIdentHash ();
				introducer.iExp = exp;
				excluded.insert (it->GetRemoteIdentity ()->GetIdentHash ());
				if (i2p::context.AddSSU2Introducer (introducer, v4))
				{
					LogPrint (eLogDebug, "SSU2: Introducer added ", it->GetRelayTag (), " at ",
						i2p::data::GetIdentHashAbbreviation (it->GetRemoteIdentity ()->GetIdentHash ()));
					newList.push_back (it->GetRemoteIdentity ()->GetIdentHash ());
					if (newList.size () >= SSU2_MAX_NUM_INTRODUCERS) break;
				}
			}
		}
		introducers = newList;

		if (introducers.size () < SSU2_MAX_NUM_INTRODUCERS)
		{
			for (auto i = introducers.size (); i < SSU2_MAX_NUM_INTRODUCERS; i++)
			{
				auto introducer = i2p::data::netdb.GetRandomSSU2Introducer (v4, excluded);
				if (introducer)
				{
					auto address = v4 ? introducer->GetSSU2V4Address () : introducer->GetSSU2V6Address ();
					if (address)
					{
						CreateSession (introducer, address);
						excluded.insert (introducer->GetIdentHash ());
					}
				}
				else
				{
					LogPrint (eLogDebug, "SSU2: Can't find more introducers");
					break;
				}
			}
		}
		introducers.splice (introducers.end (), impliedList);  // insert non-published, but non-expired introducers back
	}

	void SSU2Server::ScheduleIntroducersUpdateTimer ()
	{
		if (m_IsPublished)
		{
			m_IntroducersUpdateTimer.expires_from_now (boost::posix_time::seconds(
				SSU2_KEEP_ALIVE_INTERVAL + rand () % SSU2_KEEP_ALIVE_INTERVAL_VARIANCE));
			m_IntroducersUpdateTimer.async_wait (std::bind (&SSU2Server::HandleIntroducersUpdateTimer,
				this, std::placeholders::_1, true));
		}
	}

	void SSU2Server::RescheduleIntroducersUpdateTimer ()
	{
		if (m_IsPublished)
		{
			m_IntroducersUpdateTimer.cancel ();
			i2p::context.ClearSSU2Introducers (true);
			m_Introducers.clear ();
			m_IntroducersUpdateTimer.expires_from_now (boost::posix_time::seconds(
				(SSU2_KEEP_ALIVE_INTERVAL + rand () % SSU2_KEEP_ALIVE_INTERVAL_VARIANCE)/2));
			m_IntroducersUpdateTimer.async_wait (std::bind (&SSU2Server::HandleIntroducersUpdateTimer,
				this, std::placeholders::_1, true));
		}
	}

	void SSU2Server::ScheduleIntroducersUpdateTimerV6 ()
	{
		if (m_IsPublished)
		{
			m_IntroducersUpdateTimerV6.expires_from_now (boost::posix_time::seconds(
				SSU2_KEEP_ALIVE_INTERVAL + rand () % SSU2_KEEP_ALIVE_INTERVAL_VARIANCE));
			m_IntroducersUpdateTimerV6.async_wait (std::bind (&SSU2Server::HandleIntroducersUpdateTimer,
				this, std::placeholders::_1, false));
		}
	}

	void SSU2Server::RescheduleIntroducersUpdateTimerV6 ()
	{
		if (m_IsPublished)
		{
			m_IntroducersUpdateTimerV6.cancel ();
			i2p::context.ClearSSU2Introducers (false);
			m_IntroducersV6.clear ();
			m_IntroducersUpdateTimerV6.expires_from_now (boost::posix_time::seconds(
				(SSU2_KEEP_ALIVE_INTERVAL + rand () % SSU2_KEEP_ALIVE_INTERVAL_VARIANCE)/2));
			m_IntroducersUpdateTimerV6.async_wait (std::bind (&SSU2Server::HandleIntroducersUpdateTimer,
				this, std::placeholders::_1, false));
		}
	}

	void SSU2Server::HandleIntroducersUpdateTimer (const boost::system::error_code& ecode, bool v4)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			// timeout expired
			if (v4)
			{
				if (i2p::context.GetTesting ())
				{
					// we still don't know if we need introducers
					ScheduleIntroducersUpdateTimer ();
					return;
				}
				if (i2p::context.GetStatus () != eRouterStatusFirewalled)
				{
					// we don't need introducers
					i2p::context.ClearSSU2Introducers (true);
					m_Introducers.clear ();
					return;
				}
				// we are firewalled
				auto addr = i2p::context.GetRouterInfo ().GetSSU2V4Address ();
				if (addr && addr->ssu && addr->ssu->introducers.empty ())
					i2p::context.SetUnreachable (true, false); // v4

				UpdateIntroducers (true);
				ScheduleIntroducersUpdateTimer ();
			}
			else
			{
				if (i2p::context.GetTestingV6 ())
				{
					// we still don't know if we need introducers
					ScheduleIntroducersUpdateTimerV6 ();
					return;
				}
				if (i2p::context.GetStatusV6 () != eRouterStatusFirewalled)
				{
					// we don't need introducers
					i2p::context.ClearSSU2Introducers (false);
					m_IntroducersV6.clear ();
					return;
				}
				// we are firewalled
				auto addr = i2p::context.GetRouterInfo ().GetSSU2V6Address ();
				if (addr && addr->ssu && addr->ssu->introducers.empty ())
					i2p::context.SetUnreachable (false, true); // v6

				UpdateIntroducers (false);
				ScheduleIntroducersUpdateTimerV6 ();
			}
		}
	}

	void SSU2Server::SendThroughProxy (const uint8_t * header, size_t headerLen, const uint8_t * headerX, size_t headerXLen,
		const uint8_t * payload, size_t payloadLen, const boost::asio::ip::udp::endpoint& to)
	{
		if (!m_ProxyRelayEndpoint) return;
		size_t requestHeaderSize = 0;
		memset (m_UDPRequestHeader, 0, 3);
		if (to.address ().is_v6 ())
		{
			m_UDPRequestHeader[3] = SOCKS5_ATYP_IPV6;
			memcpy (m_UDPRequestHeader + 4, to.address ().to_v6().to_bytes().data(), 16);
			requestHeaderSize = SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE;
		}
		else
		{
			m_UDPRequestHeader[3] = SOCKS5_ATYP_IPV4;
			memcpy (m_UDPRequestHeader + 4, to.address ().to_v4().to_bytes().data(), 4);
			requestHeaderSize = SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE;
		}
		htobe16buf (m_UDPRequestHeader + requestHeaderSize - 2, to.port ());

		std::vector<boost::asio::const_buffer> bufs;
		bufs.push_back (boost::asio::buffer (m_UDPRequestHeader, requestHeaderSize));
		bufs.push_back (boost::asio::buffer (header, headerLen));
		if (headerX) bufs.push_back (boost::asio::buffer (headerX, headerXLen));
		bufs.push_back (boost::asio::buffer (payload, payloadLen));

		boost::system::error_code ec;
		m_SocketV4.send_to (bufs, *m_ProxyRelayEndpoint, 0, ec); // TODO: implement ipv6 proxy
		if (!ec)
			i2p::transport::transports.UpdateSentBytes (headerLen + payloadLen);
		else
			LogPrint (eLogError, "SSU2: Send exception: ", ec.message (), " to ", to);
	}

	void SSU2Server::ProcessNextPacketFromProxy (uint8_t * buf, size_t len)
	{
		if (buf[2]) // FRAG
		{
			LogPrint (eLogWarning, "SSU2: Proxy packet fragmentation is not supported");
			return;
		}
		size_t offset = 0;
		boost::asio::ip::udp::endpoint ep;
		switch (buf[3]) // ATYP
		{
			case SOCKS5_ATYP_IPV4:
			{
				offset = SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE;
				if (offset > len) return;
				boost::asio::ip::address_v4::bytes_type bytes;
				memcpy (bytes.data (), buf + 4, 4);
				uint16_t port = bufbe16toh (buf + 8);
				ep = boost::asio::ip::udp::endpoint (boost::asio::ip::address_v4 (bytes), port);
				break;
			}
			case SOCKS5_ATYP_IPV6:
			{
				offset = SOCKS5_UDP_IPV6_REQUEST_HEADER_SIZE;
				if (offset > len) return;
				boost::asio::ip::address_v6::bytes_type bytes;
				memcpy (bytes.data (), buf + 4, 16);
				uint16_t port = bufbe16toh (buf + 20);
				ep = boost::asio::ip::udp::endpoint (boost::asio::ip::address_v6 (bytes), port);
				break;
			}
			default:
			{
				LogPrint (eLogWarning, "SSU2: Unknown ATYP ", (int)buf[3], " from proxy relay");
				return;
			}
		}
		ProcessNextPacket (buf + offset, len - offset, ep);
	}

	void SSU2Server::ConnectToProxy ()
	{
		if (!m_ProxyEndpoint) return;
		m_UDPAssociateSocket.reset (new boost::asio::ip::tcp::socket (m_ReceiveService.GetService ()));
		m_UDPAssociateSocket->async_connect (*m_ProxyEndpoint,
		    [this] (const boost::system::error_code& ecode)
			{
				if (ecode)
				{
					LogPrint (eLogError, "SSU2: Can't connect to proxy ", *m_ProxyEndpoint, " ", ecode.message ());
					m_UDPAssociateSocket.reset (nullptr);
					ReconnectToProxy ();
				}
				else
					HandshakeWithProxy ();
			});
	}

	void SSU2Server::HandshakeWithProxy ()
	{
		if (!m_UDPAssociateSocket) return;
		m_UDPRequestHeader[0] = SOCKS5_VER;
		m_UDPRequestHeader[1] = 1; // 1 method
		m_UDPRequestHeader[2] = 0; // no authentication
		boost::asio::async_write (*m_UDPAssociateSocket, boost::asio::buffer (m_UDPRequestHeader, 3), boost::asio::transfer_all(),
			[this] (const boost::system::error_code& ecode, std::size_t bytes_transferred)
			{
				(void) bytes_transferred;
				if (ecode)
				{
					LogPrint(eLogError, "SSU2: Proxy write error ", ecode.message());
					m_UDPAssociateSocket.reset (nullptr);
					ReconnectToProxy ();
				}
				else
					ReadHandshakeWithProxyReply ();
			});
	}

	void SSU2Server::ReadHandshakeWithProxyReply ()
	{
		if (!m_UDPAssociateSocket) return;
		boost::asio::async_read (*m_UDPAssociateSocket, boost::asio::buffer (m_UDPRequestHeader, 2), boost::asio::transfer_all(),
			[this] (const boost::system::error_code& ecode, std::size_t bytes_transferred)
			{
				(void) bytes_transferred;
				if (ecode)
				{
					LogPrint(eLogError, "SSU2: Proxy read error ", ecode.message());
					m_UDPAssociateSocket.reset (nullptr);
					ReconnectToProxy ();
				}
				else
				{
					if (m_UDPRequestHeader[0] == SOCKS5_VER && !m_UDPRequestHeader[1])
						SendUDPAssociateRequest ();
					else
					{
						LogPrint(eLogError, "SSU2: Invalid proxy reply");
						m_UDPAssociateSocket.reset (nullptr);
					}
				}
			});
	}

	void SSU2Server::SendUDPAssociateRequest ()
	{
		if (!m_UDPAssociateSocket) return;
		m_UDPRequestHeader[0] = SOCKS5_VER;
		m_UDPRequestHeader[1] = SOCKS5_CMD_UDP_ASSOCIATE;
		m_UDPRequestHeader[2] = 0; // RSV
		m_UDPRequestHeader[3] = SOCKS5_ATYP_IPV4; // TODO: implement ipv6 proxy
		memset (m_UDPRequestHeader + 4, 0, 6); // address and port all zeros
		boost::asio::async_write (*m_UDPAssociateSocket, boost::asio::buffer (m_UDPRequestHeader, SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE), boost::asio::transfer_all(),
			[this] (const boost::system::error_code& ecode, std::size_t bytes_transferred)
			{
				(void) bytes_transferred;
				if (ecode)
				{
					LogPrint(eLogError, "SSU2: Proxy write error ", ecode.message());
					m_UDPAssociateSocket.reset (nullptr);
					ReconnectToProxy ();
				}
				else
					ReadUDPAssociateReply ();
			});
	}

	void SSU2Server::ReadUDPAssociateReply ()
	{
		if (!m_UDPAssociateSocket) return;
		boost::asio::async_read (*m_UDPAssociateSocket, boost::asio::buffer (m_UDPRequestHeader, SOCKS5_UDP_IPV4_REQUEST_HEADER_SIZE), boost::asio::transfer_all(),
			[this] (const boost::system::error_code& ecode, std::size_t bytes_transferred)
			{
				(void) bytes_transferred;
				if (ecode)
				{
					LogPrint(eLogError, "SSU2: Proxy read error ", ecode.message());
					m_UDPAssociateSocket.reset (nullptr);
					ReconnectToProxy ();
				}
				else
				{
					if (m_UDPRequestHeader[0] == SOCKS5_VER && !m_UDPRequestHeader[1])
					{
						if (m_UDPRequestHeader[3] == SOCKS5_ATYP_IPV4)
						{
							boost::asio::ip::address_v4::bytes_type bytes;
							memcpy (bytes.data (), m_UDPRequestHeader + 4, 4);
							uint16_t port = bufbe16toh (m_UDPRequestHeader + 8);
							m_ProxyRelayEndpoint.reset (new boost::asio::ip::udp::endpoint (boost::asio::ip::address_v4 (bytes), port));
							m_SocketV4.open (boost::asio::ip::udp::v4 ());
							Receive (m_SocketV4);
							ReadUDPAssociateSocket ();
						}
						else
						{
							LogPrint(eLogError, "SSU2: Proxy UDP associate unsupported ATYP ", (int)m_UDPRequestHeader[3]);
							m_UDPAssociateSocket.reset (nullptr);
						}
					}
					else
					{
						LogPrint(eLogError, "SSU2: Proxy UDP associate error ", (int)m_UDPRequestHeader[1]);
						m_UDPAssociateSocket.reset (nullptr);
					}
				}
			});
	}

	void SSU2Server::ReadUDPAssociateSocket ()
	{
		if (!m_UDPAssociateSocket) return;
		m_UDPAssociateSocket->async_read_some (boost::asio::buffer (m_UDPRequestHeader, 1),
			[this] (const boost::system::error_code& ecode, std::size_t bytes_transferred)
			{
				(void) bytes_transferred;
				if (ecode)
				{
					LogPrint(eLogWarning, "SSU2: Proxy UDP Associate socket error ", ecode.message());
					m_UDPAssociateSocket.reset (nullptr);
					m_ProxyRelayEndpoint.reset (nullptr);
					m_SocketV4.close ();
					ConnectToProxy (); // try to reconnect immediately
				}
				else
					ReadUDPAssociateSocket ();
			});
	}

	void SSU2Server::ReconnectToProxy ()
	{
		LogPrint(eLogInfo, "SSU2: Reconnect to proxy after ", SSU2_PROXY_CONNECT_RETRY_TIMEOUT, " seconds");
		if (m_ProxyConnectRetryTimer)
			m_ProxyConnectRetryTimer->cancel ();
		else
			m_ProxyConnectRetryTimer.reset (new boost::asio::deadline_timer (m_ReceiveService.GetService ()));
		m_ProxyConnectRetryTimer->expires_from_now (boost::posix_time::seconds (SSU2_PROXY_CONNECT_RETRY_TIMEOUT));
		m_ProxyConnectRetryTimer->async_wait (
			[this](const boost::system::error_code& ecode)
			{
				if (ecode != boost::asio::error::operation_aborted)
				{
					m_UDPAssociateSocket.reset (nullptr);
					m_ProxyRelayEndpoint.reset (nullptr);
					LogPrint(eLogInfo, "SSU2: Reconnecting to proxy");
					ConnectToProxy ();
				}
			});
	}

	bool SSU2Server::SetProxy (const std::string& address, uint16_t port)
	{
		boost::system::error_code ecode;
		auto addr = boost::asio::ip::address::from_string (address, ecode);
		if (!ecode && !addr.is_unspecified () && port)
		{
			m_IsThroughProxy = true;
			m_ProxyEndpoint.reset (new boost::asio::ip::tcp::endpoint (addr, port));
		}
		else
		{
			if (ecode)
				LogPrint (eLogError, "SSU2: Invalid proxy address ", address, " ", ecode.message());
			return false;
		}
		return true;
	}
}
}
