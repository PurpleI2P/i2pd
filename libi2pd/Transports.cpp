/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "Crypto.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "NetDb.hpp"
#include "Transports.h"
#include "Config.h"
#include "HTTP.h"
#include "util.h"

using namespace i2p::data;

namespace i2p
{
namespace transport
{
	template<typename Keys>
	EphemeralKeysSupplier<Keys>::EphemeralKeysSupplier (int size):
		m_QueueSize (size), m_IsRunning (false), m_Thread (nullptr)
	{
	}

	template<typename Keys>
	EphemeralKeysSupplier<Keys>::~EphemeralKeysSupplier ()
	{
		Stop ();
	}

	template<typename Keys>
	void EphemeralKeysSupplier<Keys>::Start ()
	{
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&EphemeralKeysSupplier<Keys>::Run, this));
	}

	template<typename Keys>
	void EphemeralKeysSupplier<Keys>::Stop ()
	{
		{
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			m_IsRunning = false;
			m_Acquired.notify_one ();
		}
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = 0;
		}
	}

	template<typename Keys>
	void EphemeralKeysSupplier<Keys>::Run ()
	{
		i2p::util::SetThreadName("Ephemerals");

		while (m_IsRunning)
		{
			int num, total = 0;
			while ((num = m_QueueSize - (int)m_Queue.size ()) > 0 && total < 10)
			{
				CreateEphemeralKeys (num);
				total += num;
			}
			if (total >= 10)
			{
				LogPrint (eLogWarning, "Transports: ", total, " ephemeral keys generated at the time");
				std::this_thread::sleep_for (std::chrono::seconds(1)); // take a break
			}
			else
			{
				std::unique_lock<std::mutex> l(m_AcquiredMutex);
				if (!m_IsRunning) break;
				m_Acquired.wait (l); // wait for element gets acquired
			}
		}
	}

	template<typename Keys>
	void EphemeralKeysSupplier<Keys>::CreateEphemeralKeys (int num)
	{
		if (num > 0)
		{
			for (int i = 0; i < num; i++)
			{
				auto pair = std::make_shared<Keys> ();
				pair->GenerateKeys ();
				std::unique_lock<std::mutex> l(m_AcquiredMutex);
				m_Queue.push (pair);
			}
		}
	}

	template<typename Keys>
	std::shared_ptr<Keys> EphemeralKeysSupplier<Keys>::Acquire ()
	{
		{
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			if (!m_Queue.empty ())
			{
				auto pair = m_Queue.front ();
				m_Queue.pop ();
				m_Acquired.notify_one ();
				return pair;
			}
		}
		// queue is empty, create new
		auto pair = std::make_shared<Keys> ();
		pair->GenerateKeys ();
		return pair;
	}

	template<typename Keys>
	void EphemeralKeysSupplier<Keys>::Return (std::shared_ptr<Keys> pair)
	{
		if (pair)
		{
			std::unique_lock<std::mutex>l(m_AcquiredMutex);
			if ((int)m_Queue.size () < 2*m_QueueSize)
				m_Queue.push (pair);
		}
		else
			LogPrint(eLogError, "Transports: Return null DHKeys");
	}

	Transports transports;

	Transports::Transports ():
		m_IsOnline (true), m_IsRunning (false), m_IsNAT (true), m_CheckReserved(true), m_Thread (nullptr),
		m_Service (nullptr), m_Work (nullptr), m_PeerCleanupTimer (nullptr), m_PeerTestTimer (nullptr),
		m_UpdateBandwidthTimer (nullptr), m_SSU2Server (nullptr), m_NTCP2Server (nullptr),
		m_X25519KeysPairSupplier (15), // 15 pre-generated keys
		m_TotalSentBytes (0), m_TotalReceivedBytes (0), m_TotalTransitTransmittedBytes (0),
		m_InBandwidth (0), m_OutBandwidth (0), m_TransitBandwidth (0),
		m_LastInBandwidthUpdateBytes (0), m_LastOutBandwidthUpdateBytes (0), m_LastTransitBandwidthUpdateBytes (0),
		m_InBandwidth15s (0), m_OutBandwidth15s (0), m_TransitBandwidth15s (0),
		m_LastInBandwidth15sUpdateBytes (0), m_LastOutBandwidth15sUpdateBytes (0), m_LastTransitBandwidth15sUpdateBytes (0),
		m_LastBandwidth15sUpdateTime (0)
	{
	}

	Transports::~Transports ()
	{
		Stop ();
		if (m_Service)
		{
			delete m_PeerCleanupTimer; m_PeerCleanupTimer = nullptr;
			delete m_PeerTestTimer; m_PeerTestTimer = nullptr;
			delete m_UpdateBandwidthTimer; m_UpdateBandwidthTimer = nullptr;
			delete m_Work; m_Work = nullptr;
			delete m_Service; m_Service = nullptr;
		}
	}

	void Transports::Start (bool enableNTCP2, bool enableSSU2)
	{
		if (!m_Service)
		{
			m_Service = new boost::asio::io_service ();
			m_Work = new boost::asio::io_service::work (*m_Service);
			m_PeerCleanupTimer = new boost::asio::deadline_timer (*m_Service);
			m_PeerTestTimer = new boost::asio::deadline_timer (*m_Service);
			m_UpdateBandwidthTimer = new boost::asio::deadline_timer (*m_Service);
		}

		bool ipv4; i2p::config::GetOption("ipv4", ipv4);
		bool ipv6; i2p::config::GetOption("ipv6", ipv6);
		i2p::config::GetOption("nat", m_IsNAT);
		m_X25519KeysPairSupplier.Start ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&Transports::Run, this));
		std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
		i2p::http::URL proxyurl;
		// create NTCP2. TODO: move to acceptor
		if (enableNTCP2 || i2p::context.SupportsMesh ())
		{
			if(!ntcp2proxy.empty() && enableNTCP2)
			{
				if(proxyurl.parse(ntcp2proxy))
				{
					if(proxyurl.schema == "socks" || proxyurl.schema == "http")
					{
						m_NTCP2Server = new NTCP2Server ();
						NTCP2Server::ProxyType proxytype = NTCP2Server::eSocksProxy;

						if (proxyurl.schema == "http")
							proxytype = NTCP2Server::eHTTPProxy;

						m_NTCP2Server->UseProxy(proxytype, proxyurl.host, proxyurl.port, proxyurl.user, proxyurl.pass);
						i2p::context.SetStatus (eRouterStatusProxy);
						if (ipv6)
							i2p::context.SetStatusV6 (eRouterStatusProxy);
					}
					else
						LogPrint(eLogCritical, "Transports: Unsupported NTCP2 proxy URL ", ntcp2proxy);
				}
				else
					LogPrint(eLogCritical, "Transports: Invalid NTCP2 proxy URL ", ntcp2proxy);
			}
			else
				m_NTCP2Server = new NTCP2Server ();
		}

		// create SSU2 server
		if (enableSSU2)
		{
			m_SSU2Server = new SSU2Server ();
			std::string ssu2proxy; i2p::config::GetOption("ssu2.proxy", ssu2proxy);
			if (!ssu2proxy.empty())
			{
				if (proxyurl.parse (ssu2proxy) && proxyurl.schema == "socks")
				{
					if (m_SSU2Server->SetProxy (proxyurl.host, proxyurl.port))
					{
						i2p::context.SetStatus (eRouterStatusProxy);
						if (ipv6)
							i2p::context.SetStatusV6 (eRouterStatusProxy);
					}
					else
						LogPrint(eLogCritical, "Transports: Can't set SSU2 proxy ", ssu2proxy);
				}
				else
					LogPrint(eLogCritical, "Transports: Invalid SSU2 proxy URL ", ssu2proxy);
			}
		}

		// bind to interfaces
		if (ipv4)
		{
			std::string address; i2p::config::GetOption("address4", address);
			if (!address.empty ())
			{
				boost::system::error_code ec;
				auto addr = boost::asio::ip::address::from_string (address, ec);
				if (!ec)
				{
					if (m_NTCP2Server) m_NTCP2Server->SetLocalAddress (addr);
					if (m_SSU2Server) m_SSU2Server->SetLocalAddress (addr);
				}
			}

			if (enableSSU2)
			{
				uint16_t mtu; i2p::config::GetOption ("ssu2.mtu4", mtu);
				if (mtu)
				{
					if (mtu < (int)SSU2_MIN_PACKET_SIZE) mtu = SSU2_MIN_PACKET_SIZE;
					if (mtu > (int)SSU2_MAX_PACKET_SIZE) mtu = SSU2_MAX_PACKET_SIZE;
					i2p::context.SetMTU (mtu, true);
				}
			}
		}

		if (ipv6)
		{
			std::string address; i2p::config::GetOption("address6", address);
			if (!address.empty ())
			{
				boost::system::error_code ec;
				auto addr = boost::asio::ip::address::from_string (address, ec);
				if (!ec)
				{
					if (m_NTCP2Server) m_NTCP2Server->SetLocalAddress (addr);
					if (m_SSU2Server) m_SSU2Server->SetLocalAddress (addr);
				}
			}

			if (enableSSU2)
			{
				uint16_t mtu; i2p::config::GetOption ("ssu2.mtu6", mtu);
				if (mtu)
				{
					if (mtu < (int)SSU2_MIN_PACKET_SIZE) mtu = SSU2_MIN_PACKET_SIZE;
					if (mtu > (int)SSU2_MAX_PACKET_SIZE) mtu = SSU2_MAX_PACKET_SIZE;
					i2p::context.SetMTU (mtu, false);
				}
			}
		}

		bool ygg; i2p::config::GetOption("meshnets.yggdrasil", ygg);
		if (ygg)
		{
			std::string address; i2p::config::GetOption("meshnets.yggaddress", address);
			if (!address.empty ())
			{
				boost::system::error_code ec;
				auto addr = boost::asio::ip::address::from_string (address, ec);
				if (!ec && m_NTCP2Server && i2p::util::net::IsYggdrasilAddress (addr))
					m_NTCP2Server->SetLocalAddress (addr);
			}
		}

		// start servers
		if (m_NTCP2Server) m_NTCP2Server->Start ();
		if (m_SSU2Server) m_SSU2Server->Start ();
		if (m_SSU2Server) DetectExternalIP ();

		m_PeerCleanupTimer->expires_from_now (boost::posix_time::seconds(5 * SESSION_CREATION_TIMEOUT));
		m_PeerCleanupTimer->async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));

		m_UpdateBandwidthTimer->expires_from_now (boost::posix_time::seconds(1));
		m_UpdateBandwidthTimer->async_wait (std::bind (&Transports::HandleUpdateBandwidthTimer, this, std::placeholders::_1));

		if (m_IsNAT)
		{
			m_PeerTestTimer->expires_from_now (boost::posix_time::minutes(PEER_TEST_INTERVAL));
			m_PeerTestTimer->async_wait (std::bind (&Transports::HandlePeerTestTimer, this, std::placeholders::_1));
		}
	}

	void Transports::Stop ()
	{
		if (m_PeerCleanupTimer) m_PeerCleanupTimer->cancel ();
		if (m_PeerTestTimer) m_PeerTestTimer->cancel ();
		m_Peers.clear ();

		if (m_SSU2Server)
		{
			m_SSU2Server->Stop ();
			delete m_SSU2Server;
			m_SSU2Server = nullptr;
		}

		if (m_NTCP2Server)
		{
			m_NTCP2Server->Stop ();
			delete m_NTCP2Server;
			m_NTCP2Server = nullptr;
		}

		m_X25519KeysPairSupplier.Stop ();
		m_IsRunning = false;
		if (m_Service) m_Service->stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = nullptr;
		}
	}

	void Transports::Run ()
	{
		i2p::util::SetThreadName("Transports");

		while (m_IsRunning && m_Service)
		{
			try
			{
				m_Service->run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Transports: Runtime exception: ", ex.what ());
			}
		}
	}

	void Transports::HandleUpdateBandwidthTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();

			// updated every second
			m_InBandwidth = m_TotalReceivedBytes - m_LastInBandwidthUpdateBytes;
			m_OutBandwidth = m_TotalSentBytes - m_LastOutBandwidthUpdateBytes;
			m_TransitBandwidth = m_TotalTransitTransmittedBytes - m_LastTransitBandwidthUpdateBytes;

			m_LastInBandwidthUpdateBytes = m_TotalReceivedBytes;
			m_LastOutBandwidthUpdateBytes = m_TotalSentBytes;
			m_LastTransitBandwidthUpdateBytes = m_TotalTransitTransmittedBytes;

			// updated every 15 seconds
			auto delta = ts - m_LastBandwidth15sUpdateTime;
			if (delta > 15 * 1000)
			{
				m_InBandwidth15s = (m_TotalReceivedBytes - m_LastInBandwidth15sUpdateBytes) * 1000 / delta;
				m_OutBandwidth15s = (m_TotalSentBytes - m_LastOutBandwidth15sUpdateBytes) * 1000 / delta;
				m_TransitBandwidth15s = (m_TotalTransitTransmittedBytes - m_LastTransitBandwidth15sUpdateBytes) * 1000 / delta;

				m_LastBandwidth15sUpdateTime = ts;
				m_LastInBandwidth15sUpdateBytes = m_TotalReceivedBytes;
				m_LastOutBandwidth15sUpdateBytes = m_TotalSentBytes;
				m_LastTransitBandwidth15sUpdateBytes = m_TotalTransitTransmittedBytes;
			}

			m_UpdateBandwidthTimer->expires_from_now (boost::posix_time::seconds(1));
			m_UpdateBandwidthTimer->async_wait (std::bind (&Transports::HandleUpdateBandwidthTimer, this, std::placeholders::_1));
		}
	}

	bool Transports::IsBandwidthExceeded () const
	{
		auto limit = i2p::context.GetBandwidthLimit() * 1024; // convert to bytes
		auto bw = std::max (m_InBandwidth15s, m_OutBandwidth15s);
		return bw > limit;
	}

	bool Transports::IsTransitBandwidthExceeded () const
	{
		auto limit = i2p::context.GetTransitBandwidthLimit() * 1024; // convert to bytes
		return m_TransitBandwidth > limit;
	}

	void Transports::SendMessage (const i2p::data::IdentHash& ident, std::shared_ptr<i2p::I2NPMessage> msg)
	{
		if (m_IsOnline)
			SendMessages (ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > {msg });
	}

	void Transports::SendMessages (const i2p::data::IdentHash& ident, const std::vector<std::shared_ptr<i2p::I2NPMessage> >& msgs)
	{
		m_Service->post (std::bind (&Transports::PostMessages, this, ident, msgs));
	}

	void Transports::PostMessages (i2p::data::IdentHash ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > msgs)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
		{
			// we send it to ourself
			for (auto& it: msgs)
				m_LoopbackHandler.PutNextMessage (std::move (it));
			m_LoopbackHandler.Flush ();
			return;
		}
		if(RoutesRestricted() && !IsRestrictedPeer(ident)) return;
		auto it = m_Peers.find (ident);
		if (it == m_Peers.end ())
		{
			bool connected = false;
			try
			{
				auto r = netdb.FindRouter (ident);
				if (r && (r->IsUnreachable () || !r->IsReachableFrom (i2p::context.GetRouterInfo ()))) return; // router found but non-reachable
				{
					auto ts = i2p::util::GetSecondsSinceEpoch ();
					std::unique_lock<std::mutex> l(m_PeersMutex);
					it = m_Peers.insert (std::pair<i2p::data::IdentHash, Peer>(ident, {r, ts})).first;
				}
				connected = ConnectToPeer (ident, it->second);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Transports: PostMessages exception:", ex.what ());
			}
			if (!connected) return;
		}
		if (!it->second.sessions.empty ())
			it->second.sessions.front ()->SendI2NPMessages (msgs);
		else
		{
			auto sz = it->second.delayedMessages.size (); 	
			if (sz < MAX_NUM_DELAYED_MESSAGES)
			{
				if (sz < CHECK_PROFILE_NUM_DELAYED_MESSAGES && sz + msgs.size () >= CHECK_PROFILE_NUM_DELAYED_MESSAGES)
				{
					auto profile = i2p::data::GetRouterProfile (ident);
					if (profile && profile->IsUnreachable ())
					{
						LogPrint (eLogWarning, "Transports: Peer profile for ", ident.ToBase64 (), " reports unreachable. Dropped");
						std::unique_lock<std::mutex> l(m_PeersMutex);
						m_Peers.erase (it);
						return;
					}	
				}	
				for (auto& it1: msgs)
					it->second.delayedMessages.push_back (it1);
			}
			else
			{
				LogPrint (eLogWarning, "Transports: Delayed messages queue size to ",
					ident.ToBase64 (), " exceeds ", MAX_NUM_DELAYED_MESSAGES);
				std::unique_lock<std::mutex> l(m_PeersMutex);
				m_Peers.erase (it);
			}
		}
	}

	bool Transports::ConnectToPeer (const i2p::data::IdentHash& ident, Peer& peer)
	{
		if (!peer.router) // reconnect
			peer.SetRouter (netdb.FindRouter (ident)); // try to get new one from netdb
		if (peer.router) // we have RI already
		{
			if (peer.priority.empty ())
				SetPriority (peer);
			while (peer.numAttempts < (int)peer.priority.size ())
			{
				auto tr = peer.priority[peer.numAttempts];
				peer.numAttempts++;
				switch (tr)
				{
					case i2p::data::RouterInfo::eNTCP2V4:
					case i2p::data::RouterInfo::eNTCP2V6:
					{
						if (!m_NTCP2Server) continue;
						std::shared_ptr<const RouterInfo::Address> address = (tr == i2p::data::RouterInfo::eNTCP2V6) ?
							peer.router->GetPublishedNTCP2V6Address () : peer.router->GetPublishedNTCP2V4Address ();
						if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
							address = nullptr;
						if (address)
						{
							auto s = std::make_shared<NTCP2Session> (*m_NTCP2Server, peer.router, address);
							if( m_NTCP2Server->UsingProxy())
								m_NTCP2Server->ConnectWithProxy(s);
							else
								m_NTCP2Server->Connect (s);
							return true;
						}
						break;
					}
					case i2p::data::RouterInfo::eSSU2V4:
					case i2p::data::RouterInfo::eSSU2V6:
					{
						if (!m_SSU2Server) continue;
						std::shared_ptr<const RouterInfo::Address> address = (tr == i2p::data::RouterInfo::eSSU2V6) ?
							peer.router->GetSSU2V6Address () : peer.router->GetSSU2V4Address ();
						if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
							address = nullptr;
						if (address && address->IsReachableSSU ())
						{
							if (m_SSU2Server->CreateSession (peer.router, address))
								return true;
						}
						break;
					}
					case i2p::data::RouterInfo::eNTCP2V6Mesh:
					{
						if (!m_NTCP2Server) continue;
						auto address = peer.router->GetYggdrasilAddress ();
						if (address)
						{
							auto s = std::make_shared<NTCP2Session> (*m_NTCP2Server, peer.router, address);
							m_NTCP2Server->Connect (s);
							return true;
						}
						break;
					}
					default:
						LogPrint (eLogError, "Transports: Unknown transport ", (int)tr);
				}
			}

			LogPrint (eLogInfo, "Transports: No compatible addresses available");
			if (peer.router->IsReachableFrom (i2p::context.GetRouterInfo ()))
				i2p::data::netdb.SetUnreachable (ident, true); // we are here because all connection attempts failed but router claimed them
			peer.Done ();
			std::unique_lock<std::mutex> l(m_PeersMutex);
			m_Peers.erase (ident);
			return false;
		}
		else // otherwise request RI
		{
			LogPrint (eLogInfo, "Transports: RouterInfo for ", ident.ToBase64 (), " not found, requested");
			i2p::data::netdb.RequestDestination (ident, std::bind (
				&Transports::RequestComplete, this, std::placeholders::_1, ident));
		}
		return true;
	}

	void Transports::SetPriority (Peer& peer) const
	{
		static const std::vector<i2p::data::RouterInfo::SupportedTransports>
			ntcp2Priority =
		{
			i2p::data::RouterInfo::eNTCP2V6,
			i2p::data::RouterInfo::eNTCP2V4,
			i2p::data::RouterInfo::eSSU2V6,
			i2p::data::RouterInfo::eSSU2V4,
			i2p::data::RouterInfo::eNTCP2V6Mesh
		},
			ssu2Priority =
		{
			i2p::data::RouterInfo::eSSU2V6,
			i2p::data::RouterInfo::eSSU2V4,
			i2p::data::RouterInfo::eNTCP2V6,
			i2p::data::RouterInfo::eNTCP2V4,
			i2p::data::RouterInfo::eNTCP2V6Mesh
		};
		if (!peer.router) return;
		auto compatibleTransports = context.GetRouterInfo ().GetCompatibleTransports (false) &
			peer.router->GetCompatibleTransports (true);
		peer.numAttempts = 0;
		peer.priority.clear ();
		bool ssu2 = peer.router->GetProfile ()->IsReal () ? (rand () & 1) : false; // try NTCP2 if router is not confirmed real
		const auto& priority = ssu2 ? ssu2Priority : ntcp2Priority;
		for (auto transport: priority)
			if (transport & compatibleTransports)
				peer.priority.push_back (transport);
	}

	void Transports::RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident)
	{
		m_Service->post (std::bind (&Transports::HandleRequestComplete, this, r, ident));
	}

	void Transports::HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, i2p::data::IdentHash ident)
	{
		auto it = m_Peers.find (ident);
		if (it != m_Peers.end ())
		{
			if (r)
			{
				LogPrint (eLogDebug, "Transports: RouterInfo for ", ident.ToBase64 (), " found, trying to connect");
				it->second.SetRouter (r);
				ConnectToPeer (ident, it->second);
			}
			else
			{
				LogPrint (eLogWarning, "Transports: RouterInfo not found, failed to send messages");
				std::unique_lock<std::mutex> l(m_PeersMutex);
				m_Peers.erase (it);
			}
		}
	}

	void Transports::DetectExternalIP ()
	{
		if (RoutesRestricted())
		{
			LogPrint(eLogInfo, "Transports: Restricted routes enabled, not detecting IP");
			i2p::context.SetStatus (eRouterStatusOK);
			return;
		}
		if (m_SSU2Server)
			PeerTest ();
		else
			LogPrint (eLogWarning, "Transports: Can't detect external IP. SSU or SSU2 is not available");
	}

	void Transports::PeerTest (bool ipv4, bool ipv6)
	{
		if (RoutesRestricted() || !m_SSU2Server || m_SSU2Server->UsesProxy ()) return;
		if (ipv4 && i2p::context.SupportsV4 ())
		{
			LogPrint (eLogInfo, "Transports: Started peer test IPv4");
			std::set<i2p::data::IdentHash> excluded;
			excluded.insert (i2p::context.GetIdentHash ()); // don't pick own router
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomSSU2PeerTestRouter (true, excluded); // v4
				if (router)
				{
					if (!i2p::context.GetTesting ())
						i2p::context.SetTesting (true);
					m_SSU2Server->StartPeerTest (router, true);
					excluded.insert (router->GetIdentHash ());
				}
			}
			if (excluded.size () <= 1)
				LogPrint (eLogWarning, "Transports: Can't find routers for peer test IPv4");
		}
		if (ipv6 && i2p::context.SupportsV6 ())
		{
			LogPrint (eLogInfo, "Transports: Started peer test IPv6");
			std::set<i2p::data::IdentHash> excluded;
			excluded.insert (i2p::context.GetIdentHash ()); // don't pick own router
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomSSU2PeerTestRouter (false, excluded); // v6
				if (router)
				{
					if (!i2p::context.GetTestingV6 ())
						i2p::context.SetTestingV6 (true);
					m_SSU2Server->StartPeerTest (router, false);
					excluded.insert (router->GetIdentHash ());
				}
			}
			if (excluded.size () <= 1)
				LogPrint (eLogWarning, "Transports: Can't find routers for peer test IPv6");
		}
	}

	std::shared_ptr<i2p::crypto::X25519Keys> Transports::GetNextX25519KeysPair ()
	{
		return m_X25519KeysPairSupplier.Acquire ();
	}

	void Transports::ReuseX25519KeysPair (std::shared_ptr<i2p::crypto::X25519Keys> pair)
	{
		m_X25519KeysPairSupplier.Return (pair);
	}

	void Transports::PeerConnected (std::shared_ptr<TransportSession> session)
	{
		m_Service->post([session, this]()
		{
			auto remoteIdentity = session->GetRemoteIdentity ();
			if (!remoteIdentity) return;
			auto ident = remoteIdentity->GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				if (it->second.numAttempts > 1)
				{
					// exclude failed transports
					i2p::data::RouterInfo::CompatibleTransports transports = 0;
					int numExcluded = it->second.numAttempts - 1;
					if (numExcluded > (int)it->second.priority.size ()) numExcluded = it->second.priority.size ();
					for (int i = 0; i < numExcluded; i++)
						transports |= it->second.priority[i];
					i2p::data::netdb.ExcludeReachableTransports (ident, transports);
				}	
				if (it->second.router && it->second.numAttempts)
				{	
					auto transport = it->second.priority[it->second.numAttempts-1];
					if (transport == i2p::data::RouterInfo::eNTCP2V4 || 
						transport == i2p::data::RouterInfo::eNTCP2V6 || transport == i2p::data::RouterInfo::eNTCP2V6Mesh)
						it->second.router->GetProfile ()->Connected (); // outgoing NTCP2 connection if always real
					i2p::data::netdb.SetUnreachable (ident, false); // clear unreachable 
				}		
				it->second.numAttempts = 0;
				it->second.router = nullptr; // we don't need RouterInfo after successive connect
				bool sendDatabaseStore = true;
				if (it->second.delayedMessages.size () > 0)
				{
					// check if first message is our DatabaseStore (publishing)
					auto firstMsg = it->second.delayedMessages[0];
					if (firstMsg && firstMsg->GetTypeID () == eI2NPDatabaseStore &&
							i2p::data::IdentHash(firstMsg->GetPayload () + DATABASE_STORE_KEY_OFFSET) == i2p::context.GetIdentHash ())
						sendDatabaseStore = false; // we have it in the list already
				}
				if (sendDatabaseStore)
					session->SendLocalRouterInfo ();
				else
					session->SetTerminationTimeout (10); // most likely it's publishing, no follow-up messages expected, set timeout to 10 seconds
				it->second.sessions.push_back (session);
				session->SendI2NPMessages (it->second.delayedMessages);
				it->second.delayedMessages.clear ();
			}
			else // incoming connection or peer test
			{
				if(RoutesRestricted() && ! IsRestrictedPeer(ident)) {
					// not trusted
					LogPrint(eLogWarning, "Transports: Closing untrusted inbound connection from ", ident.ToBase64());
					session->Done();
					return;
				}
				if (!session->IsOutgoing ()) // incoming
					session->SendI2NPMessages ({ CreateDatabaseStoreMsg () }); // send DatabaseStore
				auto r = i2p::data::netdb.FindRouter (ident); // router should be in netdb after SessionConfirmed
				if (r) r->GetProfile ()->Connected ();
				auto ts = i2p::util::GetSecondsSinceEpoch ();
				std::unique_lock<std::mutex> l(m_PeersMutex);
				auto it = m_Peers.insert (std::make_pair (ident, Peer{ r, ts })).first;
				it->second.sessions.push_back (session);
				it->second.router = nullptr;
			}
		});
	}

	void Transports::PeerDisconnected (std::shared_ptr<TransportSession> session)
	{
		m_Service->post([session, this]()
		{
			auto remoteIdentity = session->GetRemoteIdentity ();
			if (!remoteIdentity) return;
			auto ident = remoteIdentity->GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				auto before = it->second.sessions.size ();
				it->second.sessions.remove (session);
				if (it->second.sessions.empty ())
				{
					if (it->second.delayedMessages.size () > 0)
					{
						if (before > 0) // we had an active session before
							it->second.numAttempts = 0; // start over
						ConnectToPeer (ident, it->second);
					}
					else
					{
						std::unique_lock<std::mutex> l(m_PeersMutex);
						m_Peers.erase (it);
					}
				}
			}
		});
	}

	bool Transports::IsConnected (const i2p::data::IdentHash& ident) const
	{
		std::unique_lock<std::mutex> l(m_PeersMutex);
		auto it = m_Peers.find (ident);
		return it != m_Peers.end ();
	}

	void Transports::HandlePeerCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_Peers.begin (); it != m_Peers.end (); )
			{
				it->second.sessions.remove_if (
					[](std::shared_ptr<TransportSession> session)->bool
					{
						return !session || !session->IsEstablished ();
					});
 				if (it->second.sessions.empty () && ts > it->second.creationTime + SESSION_CREATION_TIMEOUT)
				{
					LogPrint (eLogWarning, "Transports: Session to peer ", it->first.ToBase64 (), " has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
				/*	if (!it->second.router) 
					{	 
						// if router for ident not found mark it unreachable
						auto profile = i2p::data::GetRouterProfile (it->first);
						if (profile) profile->Unreachable ();
					}	*/
					std::unique_lock<std::mutex> l(m_PeersMutex);
					it = m_Peers.erase (it);
				}
				else
				{
					if (ts > it->second.nextRouterInfoUpdateTime)
					{
						auto session = it->second.sessions.front ();
						if (session)
							session->SendLocalRouterInfo (true);
						it->second.nextRouterInfoUpdateTime = ts + PEER_ROUTER_INFO_UPDATE_INTERVAL +
							rand () % PEER_ROUTER_INFO_UPDATE_INTERVAL_VARIANCE;
					}
					++it;
				}
			}
			bool ipv4Testing = i2p::context.GetTesting ();
			bool ipv6Testing = i2p::context.GetTestingV6 ();
			// if still testing, repeat peer test
			if (ipv4Testing || ipv6Testing)
				PeerTest (ipv4Testing, ipv6Testing);
			m_PeerCleanupTimer->expires_from_now (boost::posix_time::seconds(3 * SESSION_CREATION_TIMEOUT));
			m_PeerCleanupTimer->async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));
		}
	}

	void Transports::HandlePeerTestTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			PeerTest ();
			m_PeerTestTimer->expires_from_now (boost::posix_time::minutes(PEER_TEST_INTERVAL));
			m_PeerTestTimer->async_wait (std::bind (&Transports::HandlePeerTestTimer, this, std::placeholders::_1));
		}
	}

	template<typename Filter>
	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer (Filter filter) const
	{
		if (m_Peers.empty()) return nullptr;
		bool found = false;
		i2p::data::IdentHash ident;
		{
			uint16_t inds[3];
			RAND_bytes ((uint8_t *)inds, sizeof (inds));
			std::unique_lock<std::mutex> l(m_PeersMutex);
			auto count = m_Peers.size ();
			if(count == 0) return nullptr;
			inds[0] %= count;
			auto it = m_Peers.begin ();
			std::advance (it, inds[0]);
			// try random peer
			if (it != m_Peers.end () && filter (it->second))
			{
				ident = it->first;
				found = true;
			}
			else
			{
				// try some peers around
				auto it1 = m_Peers.begin ();
				if (inds[0])
				{
					// before
					inds[1] %= inds[0];
					std::advance (it1, (inds[1] + inds[0])/2);
				}
				else
					it1 = it;
				auto it2 = it;
				if (inds[0] < m_Peers.size () - 1)
				{
					// after
					inds[2] %= (m_Peers.size () - 1 - inds[0]); inds[2] /= 2;
					std::advance (it2, inds[2]);
				}
				// it1 - from, it2 - to
				it = it1;
				while (it != it2 && it != m_Peers.end ())
				{
					if (filter (it->second))
					{
						ident = it->first;
						found = true;
						break;
					}
					it++;
				}
				if (!found)
				{
					// still not found, try from the beginning
					it = m_Peers.begin ();
					while (it != it1 && it != m_Peers.end ())
					{
						if (filter (it->second))
						{
							ident = it->first;
							found = true;
							break;
						}
						it++;
					}
					if (!found)
					{
						// still not found, try to the beginning
						it = it2;
						while (it != m_Peers.end ())
						{
							if (filter (it->second))
							{
								ident = it->first;
								found = true;
								break;
							}
							it++;
						}
					}
				}
			}
		}
		return found ? i2p::data::netdb.FindRouter (ident) : nullptr;
	}

	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer (bool isHighBandwidth) const
	{
		return GetRandomPeer (
			[isHighBandwidth](const Peer& peer)->bool
			{
				// connected, not overloaded and not slow
				return !peer.router && !peer.sessions.empty () && peer.isReachable &&
					peer.sessions.front ()->GetSendQueueSize () <= PEER_ROUTER_INFO_OVERLOAD_QUEUE_SIZE &&
					!peer.sessions.front ()->IsSlow () &&
					(!isHighBandwidth || peer.isHighBandwidth);
			});
	}

	void Transports::RestrictRoutesToFamilies(const std::set<std::string>& families)
	{
		std::lock_guard<std::mutex> lock(m_FamilyMutex);
		m_TrustedFamilies.clear();
		for (auto fam : families)
		{
			boost::to_lower (fam);
			auto id = i2p::data::netdb.GetFamilies ().GetFamilyID (fam);
			if (id)
				m_TrustedFamilies.push_back (id);
		}
	}

	void Transports::RestrictRoutesToRouters(std::set<i2p::data::IdentHash> routers)
	{
		std::unique_lock<std::mutex> lock(m_TrustedRoutersMutex);
		m_TrustedRouters.clear();
		for (const auto & ri : routers )
			m_TrustedRouters.push_back(ri);
	}

	bool Transports::RoutesRestricted() const {
		std::unique_lock<std::mutex> famlock(m_FamilyMutex);
		std::unique_lock<std::mutex> routerslock(m_TrustedRoutersMutex);
		return m_TrustedFamilies.size() > 0 || m_TrustedRouters.size() > 0;
	}

	/** XXX: if routes are not restricted this dies */
	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRestrictedPeer() const
	{
		{
			std::lock_guard<std::mutex> l(m_FamilyMutex);
			i2p::data::FamilyID fam = 0;
			auto sz = m_TrustedFamilies.size();
			if(sz > 1)
			{
				auto it = m_TrustedFamilies.begin ();
				std::advance(it, rand() % sz);
				fam = *it;
			}
			else if (sz == 1)
			{
				fam = m_TrustedFamilies[0];
			}
			if (fam)
				return i2p::data::netdb.GetRandomRouterInFamily(fam);
		}
		{
			std::unique_lock<std::mutex> l(m_TrustedRoutersMutex);
			auto sz = m_TrustedRouters.size();
			if (sz)
			{
				if(sz == 1)
					return i2p::data::netdb.FindRouter(m_TrustedRouters[0]);
				auto it = m_TrustedRouters.begin();
				std::advance(it, rand() % sz);
				return i2p::data::netdb.FindRouter(*it);
			}
		}
		return nullptr;
	}

	bool Transports::IsRestrictedPeer(const i2p::data::IdentHash & ih) const
	{
		{
			std::unique_lock<std::mutex> l(m_TrustedRoutersMutex);
			for (const auto & r : m_TrustedRouters )
				if ( r == ih ) return true;
		}
		{
			std::unique_lock<std::mutex> l(m_FamilyMutex);
			auto ri = i2p::data::netdb.FindRouter(ih);
			for (const auto & fam : m_TrustedFamilies)
				if(ri->IsFamily(fam)) return true;
		}
		return false;
	}

	void Transports::SetOnline (bool online)
	{
		if (m_IsOnline != online)
		{
			m_IsOnline = online;
			if (online)
				PeerTest ();
			else
				i2p::context.SetError (eRouterErrorOffline);
		}
	}

	void InitAddressFromIface ()
	{
		bool ipv6; i2p::config::GetOption("ipv6", ipv6);
		bool ipv4; i2p::config::GetOption("ipv4", ipv4);

		// ifname -> address
		std::string ifname; i2p::config::GetOption("ifname", ifname);
		if (ipv4 && i2p::config::IsDefault ("address4"))
		{
			std::string ifname4; i2p::config::GetOption("ifname4", ifname4);
			if (!ifname4.empty ())
				i2p::config::SetOption ("address4", i2p::util::net::GetInterfaceAddress(ifname4, false).to_string ()); // v4
			else if (!ifname.empty ())
				i2p::config::SetOption ("address4", i2p::util::net::GetInterfaceAddress(ifname, false).to_string ()); // v4
		}
		if (ipv6 && i2p::config::IsDefault ("address6"))
		{
			std::string ifname6; i2p::config::GetOption("ifname6", ifname6);
			if (!ifname6.empty ())
				i2p::config::SetOption ("address6", i2p::util::net::GetInterfaceAddress(ifname6, true).to_string ()); // v6
			else if (!ifname.empty ())
				i2p::config::SetOption ("address6", i2p::util::net::GetInterfaceAddress(ifname, true).to_string ()); // v6
		}
	}

	void InitTransports ()
	{
		bool ipv6;     i2p::config::GetOption("ipv6", ipv6);
		bool ipv4;     i2p::config::GetOption("ipv4", ipv4);
		bool ygg;      i2p::config::GetOption("meshnets.yggdrasil", ygg);
		uint16_t port; i2p::config::GetOption("port", port);

		boost::asio::ip::address_v6 yggaddr;
		if (ygg)
		{
			std::string yggaddress; i2p::config::GetOption ("meshnets.yggaddress", yggaddress);
			if (!yggaddress.empty ())
			{
				yggaddr = boost::asio::ip::address_v6::from_string (yggaddress);
				if (yggaddr.is_unspecified () || !i2p::util::net::IsYggdrasilAddress (yggaddr) ||
					!i2p::util::net::IsLocalAddress (yggaddr))
				{
					LogPrint(eLogWarning, "Transports: Can't find Yggdrasil address ", yggaddress);
					ygg = false;
				}
			}
			else
			{
				yggaddr = i2p::util::net::GetYggdrasilAddress ();
				if (yggaddr.is_unspecified ())
				{
					LogPrint(eLogWarning, "Transports: Yggdrasil is not running. Disabled");
					ygg = false;
				}
			}
		}

		if (!i2p::config::IsDefault("port"))
		{
			LogPrint(eLogInfo, "Transports: Accepting incoming connections at port ", port);
			i2p::context.UpdatePort (port);
		}
		i2p::context.SetSupportsV6 (ipv6);
		i2p::context.SetSupportsV4 (ipv4);
		i2p::context.SetSupportsMesh (ygg, yggaddr);

		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
		{
			bool published; i2p::config::GetOption("ntcp2.published", published);
			if (published)
			{
				std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
				if (!ntcp2proxy.empty ()) published = false;
			}
			if (published)
			{
				uint16_t ntcp2port; i2p::config::GetOption("ntcp2.port", ntcp2port);
				if (!ntcp2port) ntcp2port = port; // use standard port
				i2p::context.PublishNTCP2Address (ntcp2port, true, ipv4, ipv6, false); // publish
				if (ipv6)
				{
					std::string ipv6Addr; i2p::config::GetOption("ntcp2.addressv6", ipv6Addr);
					auto addr = boost::asio::ip::address_v6::from_string (ipv6Addr);
					if (!addr.is_unspecified () && addr != boost::asio::ip::address_v6::any ())
						i2p::context.UpdateNTCP2V6Address (addr); // set ipv6 address if configured
				}
			}
			else
				i2p::context.PublishNTCP2Address (port, false, ipv4, ipv6, false); // unpublish
		}
		if (ygg)
		{
			i2p::context.PublishNTCP2Address (port, true, false, false, true);
			i2p::context.UpdateNTCP2V6Address (yggaddr);
			if (!ipv4 && !ipv6)
				i2p::context.SetStatus (eRouterStatusMesh);
		}
		bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
		if (ssu2 && i2p::config::IsDefault ("ssu2.enabled") && !ipv4 && !ipv6)
			ssu2 = false; // don't enable ssu2 for yggdrasil only router
		if (ssu2)
		{
			uint16_t ssu2port; i2p::config::GetOption("ssu2.port", ssu2port);
			if (!ssu2port && port) ssu2port = port;
			bool published; i2p::config::GetOption("ssu2.published", published);
			if (published)
				i2p::context.PublishSSU2Address (ssu2port, true, ipv4, ipv6); // publish
			else
				i2p::context.PublishSSU2Address (ssu2port, false, ipv4, ipv6); // unpublish
		}

	}
}
}
