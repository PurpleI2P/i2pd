/*
* Copyright (c) 2013-2022, The PurpleI2P Project
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
		m_SSUServer (nullptr), m_SSU2Server (nullptr), m_NTCP2Server (nullptr),
		m_X25519KeysPairSupplier (15), // 15 pre-generated keys
		m_TotalSentBytes(0), m_TotalReceivedBytes(0), m_TotalTransitTransmittedBytes (0),
		m_InBandwidth (0), m_OutBandwidth (0), m_TransitBandwidth(0),
		m_LastInBandwidthUpdateBytes (0), m_LastOutBandwidthUpdateBytes (0),
		m_LastTransitBandwidthUpdateBytes (0), m_LastBandwidthUpdateTime (0)
	{
	}

	Transports::~Transports ()
	{
		Stop ();
		if (m_Service)
		{
			delete m_PeerCleanupTimer; m_PeerCleanupTimer = nullptr;
			delete m_PeerTestTimer; m_PeerTestTimer = nullptr;
			delete m_Work; m_Work = nullptr;
			delete m_Service; m_Service = nullptr;
		}
	}

	void Transports::Start (bool enableNTCP2, bool enableSSU, bool enableSSU2)
	{
		if (!m_Service)
		{
			m_Service = new boost::asio::io_service ();
			m_Work = new boost::asio::io_service::work (*m_Service);
			m_PeerCleanupTimer = new boost::asio::deadline_timer (*m_Service);
			m_PeerTestTimer = new boost::asio::deadline_timer (*m_Service);
		}

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
					}
					else
						LogPrint(eLogError, "Transports: Unsupported NTCP2 proxy URL ", ntcp2proxy);
				}
				else
					LogPrint(eLogError, "Transports: Invalid NTCP2 proxy URL ", ntcp2proxy);
			}
			else
				m_NTCP2Server = new NTCP2Server ();
		}

		// create SSU server
		int ssuPort = 0;
		if (enableSSU)
		{
			auto& addresses = context.GetRouterInfo ().GetAddresses ();
			for (const auto& address: addresses)
			{
				if (!address) continue;
				if (address->transportStyle == RouterInfo::eTransportSSU)
				{
					ssuPort = address->port;
					m_SSUServer = new SSUServer (address->port);
					break;
				}
			}
		}
		// create SSU2 server
		if (enableSSU2) m_SSU2Server = new SSU2Server ();

		// bind to interfaces
		bool ipv4; i2p::config::GetOption("ipv4", ipv4);
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
					if (m_SSUServer) m_SSUServer->SetLocalAddress (addr);
				}
			}
		}

		bool ipv6; i2p::config::GetOption("ipv6", ipv6);
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
					if (m_SSUServer) m_SSUServer->SetLocalAddress (addr);
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
		if (m_SSUServer)
		{
			LogPrint (eLogInfo, "Transports: Start listening UDP port ", ssuPort);
			try
			{
				m_SSUServer->Start ();
			}
			catch (std::exception& ex )
			{
				LogPrint(eLogError, "Transports: Failed to bind to UDP port", ssuPort);
				m_SSUServer->Stop ();
				delete m_SSUServer;
				m_SSUServer = nullptr;
			}
			if (m_SSUServer) DetectExternalIP ();
		}
		if (m_SSU2Server) m_SSU2Server->Start ();

		m_PeerCleanupTimer->expires_from_now (boost::posix_time::seconds(5*SESSION_CREATION_TIMEOUT));
		m_PeerCleanupTimer->async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));

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
		if (m_SSUServer)
		{
			m_SSUServer->Stop ();
			delete m_SSUServer;
			m_SSUServer = nullptr;
		}

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

	void Transports::UpdateBandwidth ()
	{
		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (m_LastBandwidthUpdateTime > 0)
		{
			auto delta = ts - m_LastBandwidthUpdateTime;
			if (delta > 0)
			{
				m_InBandwidth = (m_TotalReceivedBytes - m_LastInBandwidthUpdateBytes)*1000/delta; // per second
				m_OutBandwidth = (m_TotalSentBytes - m_LastOutBandwidthUpdateBytes)*1000/delta; // per second
				m_TransitBandwidth = (m_TotalTransitTransmittedBytes - m_LastTransitBandwidthUpdateBytes)*1000/delta;
			}
		}
		m_LastBandwidthUpdateTime = ts;
		m_LastInBandwidthUpdateBytes = m_TotalReceivedBytes;
		m_LastOutBandwidthUpdateBytes = m_TotalSentBytes;
		m_LastTransitBandwidthUpdateBytes = m_TotalTransitTransmittedBytes;
	}

	bool Transports::IsBandwidthExceeded () const
	{
		auto limit = i2p::context.GetBandwidthLimit() * 1024; // convert to bytes
		auto bw = std::max (m_InBandwidth, m_OutBandwidth);
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
					std::unique_lock<std::mutex> l(m_PeersMutex);
					it = m_Peers.insert (std::pair<i2p::data::IdentHash, Peer>(ident, { 0, r, {},
						i2p::util::GetSecondsSinceEpoch (), {} })).first;
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
			if (it->second.delayedMessages.size () < MAX_NUM_DELAYED_MESSAGES)
			{
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
			peer.router = netdb.FindRouter (ident); // try to get new one from netdb
		if (peer.router) // we have RI already
		{
			if (peer.numAttempts < 2) // NTCP2, 0 - ipv6, 1- ipv4
			{
				if (m_NTCP2Server) // we support NTCP2
				{
					std::shared_ptr<const RouterInfo::Address> address;
					if (!peer.numAttempts) // NTCP2 ipv6
					{
						if (context.GetRouterInfo ().IsNTCP2V6 () && peer.router->IsReachableBy (RouterInfo::eNTCP2V6))
						{
							address = peer.router->GetPublishedNTCP2V6Address ();
							if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
								address = nullptr;
						}
						peer.numAttempts++;
					}
					if (!address && peer.numAttempts == 1) // NTCP2 ipv4
					{
						if (context.GetRouterInfo ().IsNTCP2 (true) && peer.router->IsReachableBy (RouterInfo::eNTCP2V4))
						{
							address = peer.router->GetPublishedNTCP2V4Address ();
							if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
								address = nullptr;
						}
						peer.numAttempts++;
					}
					if (address)
					{
						auto s = std::make_shared<NTCP2Session> (*m_NTCP2Server, peer.router, address);
						if( m_NTCP2Server->UsingProxy())
							m_NTCP2Server->ConnectWithProxy(s);
						else
							m_NTCP2Server->Connect (s);
						return true;
					}
				}
				else
					peer.numAttempts = 2; // switch to SSU
			}
			if (peer.numAttempts == 2 || peer.numAttempts == 3) // SSU
			{
				if (m_SSUServer)
				{
					std::shared_ptr<const RouterInfo::Address> address;
					if (peer.numAttempts == 2) // SSU ipv6
					{
						if (context.GetRouterInfo ().IsSSUV6 () && peer.router->IsReachableBy (RouterInfo::eSSUV6))
						{
							address = peer.router->GetSSUV6Address ();
							if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
								address = nullptr;
						}
						peer.numAttempts++;
					}
					if (!address && peer.numAttempts == 3) // SSU ipv4
					{
						if (context.GetRouterInfo ().IsSSU (true) && peer.router->IsReachableBy (RouterInfo::eSSUV4))
						{
							address = peer.router->GetSSUAddress (true);
							if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
								address = nullptr;
						}
						peer.numAttempts++;
					}
					if (address && address->IsReachableSSU ())
					{
						if (m_SSUServer->CreateSession (peer.router, address))
							return true;
					}
				}
				else
					peer.numAttempts += 2; // switch to Mesh
			}
			if (peer.numAttempts == 4) // Mesh
			{
				peer.numAttempts++;
				if (m_NTCP2Server && context.GetRouterInfo ().IsMesh () && peer.router->IsMesh ())
				{
					auto address = peer.router->GetYggdrasilAddress ();
					if (address)
					{
						auto s = std::make_shared<NTCP2Session> (*m_NTCP2Server, peer.router, address);
						m_NTCP2Server->Connect (s);
						return true;
					}
				}
			}
			if (peer.numAttempts == 5 || peer.numAttempts == 6) // SSU2
			{
				if (m_SSU2Server)
				{
					std::shared_ptr<const RouterInfo::Address> address;
					if (peer.numAttempts == 5) // SSU2 ipv6
					{
						if (context.GetRouterInfo ().IsSSU2V6 () && peer.router->IsReachableBy (RouterInfo::eSSU2V6))
						{
							address = peer.router->GetSSU2V6Address ();
							if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
								address = nullptr;
						}
						peer.numAttempts++;
					}
					if (!address && peer.numAttempts == 6) // SSU2 ipv4
					{
						if (context.GetRouterInfo ().IsSSU2V4 () && peer.router->IsReachableBy (RouterInfo::eSSU2V4))
						{
							address = peer.router->GetSSU2V4Address ();
							if (address && m_CheckReserved && i2p::util::net::IsInReservedRange(address->host))
								address = nullptr;
						}
						peer.numAttempts++;
					}
					if (address && address->IsReachableSSU ())
					{
						if (m_SSU2Server->CreateSession (peer.router, address))
							return true;
					}
				}
				else
					peer.numAttempts += 2;
			}
			LogPrint (eLogInfo, "Transports: No compatble NTCP2 or SSU addresses available");
			i2p::data::netdb.SetUnreachable (ident, true); // we are here because all connection attempts failed
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
				it->second.router = r;
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
		if (m_SSUServer)
			PeerTest ();
		else
			LogPrint (eLogError, "Transports: Can't detect external IP. SSU is not available");
	}

	void Transports::PeerTest (bool ipv4, bool ipv6)
	{
		if (RoutesRestricted() || !m_SSUServer) return;
		if (ipv4 && i2p::context.SupportsV4 ())
		{
			LogPrint (eLogInfo, "Transports: Started peer test IPv4");
			std::set<i2p::data::IdentHash> excluded;
			excluded.insert (i2p::context.GetIdentHash ()); // don't pick own router
			bool statusChanged = false;
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomPeerTestRouter (true, excluded); // v4
				if (router)
				{
					auto addr = router->GetSSUAddress (true); // ipv4
					if (addr && !i2p::util::net::IsInReservedRange(addr->host))
					{
						if (!statusChanged)
						{
							statusChanged = true;
							i2p::context.SetStatus (eRouterStatusTesting); // first time only
						}
						m_SSUServer->CreateSession (router, addr, true); // peer test v4
					}
					excluded.insert (router->GetIdentHash ());
				}
			}
			if (!statusChanged)
				LogPrint (eLogWarning, "Transports: Can't find routers for peer test IPv4");
		}
		if (ipv6 && i2p::context.SupportsV6 ())
		{
			LogPrint (eLogInfo, "Transports: Started peer test IPv6");
			std::set<i2p::data::IdentHash> excluded;
			excluded.insert (i2p::context.GetIdentHash ()); // don't pick own router
			bool statusChanged = false;
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomPeerTestRouter (false, excluded); // v6
				if (router)
				{
					auto addr = router->GetSSUV6Address ();
					if (addr && !i2p::util::net::IsInReservedRange(addr->host))
					{
						if (!statusChanged)
						{
							statusChanged = true;
							i2p::context.SetStatusV6 (eRouterStatusTesting); // first time only
						}
						m_SSUServer->CreateSession (router, addr, true); // peer test v6
					}
					excluded.insert (router->GetIdentHash ());
				}
			}
			if (!statusChanged)
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
			else // incoming connection
			{
				if(RoutesRestricted() && ! IsRestrictedPeer(ident)) {
					// not trusted
					LogPrint(eLogWarning, "Transports: Closing untrusted inbound connection from ", ident.ToBase64());
					session->Done();
					return;
				}
				session->SendI2NPMessages ({ CreateDatabaseStoreMsg () }); // send DatabaseStore
				std::unique_lock<std::mutex>	l(m_PeersMutex);
				m_Peers.insert (std::make_pair (ident, Peer{ 0, nullptr, { session }, i2p::util::GetSecondsSinceEpoch (), {} }));
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
				if (it->second.sessions.empty () && ts > it->second.creationTime + SESSION_CREATION_TIMEOUT)
				{
					LogPrint (eLogWarning, "Transports: Session to peer ", it->first.ToBase64 (), " has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
					auto profile = i2p::data::GetRouterProfile(it->first);
					if (profile)
					{
						profile->TunnelNonReplied();
					}
					std::unique_lock<std::mutex> l(m_PeersMutex);
					it = m_Peers.erase (it);
				}
				else
					++it;
			}
			UpdateBandwidth (); // TODO: use separate timer(s) for it
			bool ipv4Testing = i2p::context.GetStatus () == eRouterStatusTesting;
			bool ipv6Testing = i2p::context.GetStatusV6 () == eRouterStatusTesting;
			// if still testing, repeat peer test
			if (ipv4Testing || ipv6Testing)
				PeerTest (ipv4Testing, ipv6Testing);
			m_PeerCleanupTimer->expires_from_now (boost::posix_time::seconds(3*SESSION_CREATION_TIMEOUT));
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

	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer () const
	{
		if (m_Peers.empty ()) return nullptr;
		i2p::data::IdentHash ident;
		{
			std::unique_lock<std::mutex> l(m_PeersMutex);
			auto it = m_Peers.begin ();
			std::advance (it, rand () % m_Peers.size ());
			if (it == m_Peers.end () || it->second.router) return nullptr; // not connected
			ident = it->first;
		}
		return i2p::data::netdb.FindRouter (ident);
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
}
}
