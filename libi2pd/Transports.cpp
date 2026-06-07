/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <boost/algorithm/string.hpp> // for boost::to_lower
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
	X25519KeysPairSupplier::X25519KeysPairSupplier (int size):
		m_QueueSize (size), m_IsRunning (false)
	{
	}

	X25519KeysPairSupplier::~X25519KeysPairSupplier ()
	{
		Stop ();
	}

	void X25519KeysPairSupplier::Start ()
	{
		m_IsRunning = true;
		m_Thread.reset (new std::thread (std::bind (&X25519KeysPairSupplier::Run, this)));
	}

	void X25519KeysPairSupplier::Stop ()
	{
		{
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			m_IsRunning = false;
		}
		m_Acquired.notify_one ();

		if (m_Thread)
		{
			m_Thread->join ();
			m_Thread = nullptr;
		}
		if (!m_Queue.empty ())
		{
			// clean up queue
			std::list<std::shared_ptr<i2p::crypto::X25519Keys> > tmp;
	   		std::swap (m_Queue, tmp);
		}
		m_KeysPool.CleanUpMt ();
	}

	void X25519KeysPairSupplier::Run ()
	{
		i2p::util::SetThreadName("Ephemerals");

		int num = 0;
		while (m_IsRunning)
		{
			if (num <= 0)
			{
				std::unique_lock<std::mutex> l(m_AcquiredMutex);
				num = m_QueueSize - (int)m_Queue.size ();
			}
			int total = 0;
			while (num > 0 && total < m_QueueSize)
			{
				auto queueSize = CreateEphemeralKeys (num);
				total += num;
				num = m_QueueSize - (int)queueSize;
			}
			if (total > m_QueueSize)
			{
				LogPrint (eLogWarning, "Transports: ", total, " ephemeral keys generated at the time");
				std::this_thread::sleep_for (std::chrono::seconds(1)); // take a break
				num = 0;
			}
			else
			{
				m_KeysPool.CleanUpMt ();
				std::unique_lock<std::mutex> l(m_AcquiredMutex);
				if (!m_IsRunning) break;
				m_Acquired.wait (l); // wait for element gets acquired
				num = m_QueueSize - (int)m_Queue.size ();
			}
		}
	}

	size_t X25519KeysPairSupplier::CreateEphemeralKeys (int num)
	{
		if (num > 0)
		{
			std::list<std::shared_ptr<i2p::crypto::X25519Keys> > newKeys;
			for (int i = 0; i < num; i++)
			{
				auto pair = m_KeysPool.AcquireSharedMt ();
				pair->GenerateKeys ();
				newKeys.emplace_back (pair);
			}
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			m_Queue.splice (m_Queue.end (), newKeys);
			return m_Queue.size ();
		}
		else
		{
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			return m_Queue.size ();
		}
	}

	std::shared_ptr<i2p::crypto::X25519Keys> X25519KeysPairSupplier::Acquire ()
	{
		std::shared_ptr<i2p::crypto::X25519Keys> pair;
		{
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			if (!m_Queue.empty ())
			{
				pair = m_Queue.front ();
				m_Queue.pop_front ();
			}
		}
		if (pair)
		{
			m_Acquired.notify_one ();
			return pair;
		}
		// queue is empty, create new
		pair = m_KeysPool.AcquireSharedMt ();
		pair->GenerateKeys ();
		return pair;
	}

	void X25519KeysPairSupplier::Return (std::shared_ptr<i2p::crypto::X25519Keys> pair)
	{
		if (pair)
		{
			std::unique_lock<std::mutex> l(m_AcquiredMutex);
			if ((int)m_Queue.size () < 2*m_QueueSize)
				m_Queue.emplace_back (pair);
		}
		else
			LogPrint(eLogError, "Transports: Return null keys");
	}

	void Peer::UpdateParams (std::shared_ptr<const i2p::data::RouterInfo> router)
	{
		if (router)
		{
			isHighBandwidth = router->IsHighBandwidth ();
			isEligible =(bool)router->GetCompatibleTransports (true) && // reachable
				router->GetCongestion () < i2p::data::RouterInfo::eHighCongestion && // accepts tunnel and not overloaded
				router->IsECIES () && router->GetVersion () >= NETDB_MIN_HIGHBANDWIDTH_VERSION; // not too old
		}
	}

	Transports transports;

	Transports::Transports ():
		m_IsOnline (true), m_IsRunning (false), m_IsNAT (true), m_CheckReserved(true), m_Thread (nullptr),
		m_Service (nullptr), m_Work (nullptr), m_PeerCleanupTimer (nullptr), m_PeerTestTimer (nullptr),
		m_UpdateBandwidthTimer (nullptr), m_SSU2Server (nullptr), m_NTCP2Server (nullptr),
		m_X25519KeysPairSupplier (NUM_X25519_PRE_GENERATED_KEYS),
		m_TotalSentBytes (0), m_TotalReceivedBytes (0), m_TotalTransitTransmittedBytes (0),
		m_InBandwidth (0), m_OutBandwidth (0), m_TransitBandwidth (0),
		m_InBandwidth15s (0), m_OutBandwidth15s (0), m_TransitBandwidth15s (0),
		m_InBandwidth5m (0), m_OutBandwidth5m (0), m_TransitBandwidth5m (0),
		m_Rng(i2p::util::GetMonotonicMicroseconds () % 1000000LL)
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
			m_Service = new boost::asio::io_context ();
			m_Work = new boost::asio::executor_work_guard<boost::asio::io_context::executor_type> (m_Service->get_executor ());
			m_PeerCleanupTimer = new boost::asio::steady_timer (*m_Service);
			m_PeerTestTimer = new boost::asio::steady_timer (*m_Service);
			m_UpdateBandwidthTimer = new boost::asio::steady_timer (*m_Service);
			m_BanListCleanupTimer = std::make_unique<boost::asio::steady_timer>(*m_Service);
		}

		bool ipv4; i2p::config::GetOption("ipv4", ipv4);
		bool ipv6; i2p::config::GetOption("ipv6", ipv6);
		i2p::config::GetOption("nat", m_IsNAT);
		m_X25519KeysPairSupplier.Start ();
		m_IsRunning = true;
		m_Thread = new std::thread (std::bind (&Transports::Run, this));
		std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
        int ntcp2version = 2, ssu2version = 2;
#if OPENSSL_MLKEM
        i2p::config::GetOption("ntcp2.version", ntcp2version);
        i2p::config::GetOption("ssu2.version", ssu2version);
#endif
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
			m_NTCP2Server->SetVersion (ntcp2version);
		}

		// create SSU2 server
		if (enableSSU2)
		{
			m_SSU2Server = new SSU2Server ();
			m_SSU2Server->SetVersion (ssu2version);
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
				auto addr = boost::asio::ip::make_address (address, ec);
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
				auto addr = boost::asio::ip::make_address (address, ec);
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
				auto addr = boost::asio::ip::make_address (address, ec);
				if (!ec && m_NTCP2Server && i2p::util::net::IsYggdrasilAddress (addr))
					m_NTCP2Server->SetLocalAddress (addr);
			}
		}

		// start servers
		if (m_NTCP2Server) m_NTCP2Server->Start ();
		if (m_SSU2Server) m_SSU2Server->Start ();
		if (m_SSU2Server) DetectExternalIP ();

		m_PeerCleanupTimer->expires_after (std::chrono::seconds(5 * SESSION_CREATION_TIMEOUT));
		m_PeerCleanupTimer->async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));

		uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
		for (int i = 0; i < TRAFFIC_SAMPLE_COUNT; i++)
		{
			m_TrafficSamples[i].Timestamp = ts - (TRAFFIC_SAMPLE_COUNT - i - 1) * 1000;
			m_TrafficSamples[i].TotalReceivedBytes = 0;
			m_TrafficSamples[i].TotalSentBytes = 0;
			m_TrafficSamples[i].TotalTransitTransmittedBytes = 0;
		}
		m_TrafficSamplePtr = TRAFFIC_SAMPLE_COUNT - 1;

		m_UpdateBandwidthTimer->expires_after (std::chrono::seconds(1));
		m_UpdateBandwidthTimer->async_wait (std::bind (&Transports::HandleUpdateBandwidthTimer, this, std::placeholders::_1));

		if (m_IsNAT)
		{
			m_PeerTestTimer->expires_after (std::chrono::seconds(PEER_TEST_INTERVAL + m_Rng() % PEER_TEST_INTERVAL_VARIANCE));
			m_PeerTestTimer->async_wait (std::bind (&Transports::HandlePeerTestTimer, this, std::placeholders::_1));
		}
		m_BanListCleanupTimer->expires_after (std::chrono::seconds(BAN_LIST_CLEANUP_INTERVAL + m_Rng () % BAN_LIST_CLEANUP_INTERVAL_VARIANCE));
		m_BanListCleanupTimer->async_wait (std::bind (&Transports::HandleBanListCleanupTimer, this, std::placeholders::_1));
	}

	void Transports::Stop ()
	{
		if (m_PeerCleanupTimer) m_PeerCleanupTimer->cancel ();
		if (m_PeerTestTimer) m_PeerTestTimer->cancel ();
		if (m_BanListCleanupTimer) m_BanListCleanupTimer->cancel ();

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
		m_Peers.clear ();
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

	void Transports::UpdateBandwidthValues(int interval, uint32_t& in, uint32_t& out, uint32_t& transit)
	{
		TrafficSample& sample1 = m_TrafficSamples[m_TrafficSamplePtr];
		TrafficSample& sample2 = m_TrafficSamples[(TRAFFIC_SAMPLE_COUNT + m_TrafficSamplePtr - interval) % TRAFFIC_SAMPLE_COUNT];
		auto delta = (int64_t)sample1.Timestamp - (int64_t)sample2.Timestamp;
		if (delta <= 0)
		{
			LogPrint (eLogError, "Transports: Backward clock jump detected, got ", delta, " instead of ", interval * 1000);
			return;
		}
		in = (sample1.TotalReceivedBytes - sample2.TotalReceivedBytes) * 1000 / delta;
		out = (sample1.TotalSentBytes - sample2.TotalSentBytes) * 1000 / delta;
		transit = (sample1.TotalTransitTransmittedBytes - sample2.TotalTransitTransmittedBytes) * 1000 / delta;
	}

	void Transports::HandleUpdateBandwidthTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			m_TrafficSamplePtr++;
			if (m_TrafficSamplePtr == TRAFFIC_SAMPLE_COUNT)
				m_TrafficSamplePtr = 0;

			TrafficSample& sample = m_TrafficSamples[m_TrafficSamplePtr];
			sample.Timestamp = i2p::util::GetMillisecondsSinceEpoch();
			sample.TotalReceivedBytes = m_TotalReceivedBytes;
			sample.TotalSentBytes = m_TotalSentBytes;
			sample.TotalTransitTransmittedBytes = m_TotalTransitTransmittedBytes;

			UpdateBandwidthValues (1, m_InBandwidth, m_OutBandwidth, m_TransitBandwidth);
			UpdateBandwidthValues (15, m_InBandwidth15s, m_OutBandwidth15s, m_TransitBandwidth15s);
			UpdateBandwidthValues (300, m_InBandwidth5m, m_OutBandwidth5m, m_TransitBandwidth5m);

			m_UpdateBandwidthTimer->expires_after (std::chrono::seconds(1));
			m_UpdateBandwidthTimer->async_wait (std::bind (&Transports::HandleUpdateBandwidthTimer, this, std::placeholders::_1));
		}
	}

	int Transports::GetCongestionLevel (bool longTerm) const
	{
		auto bwLimit = i2p::context.GetBandwidthLimit () * 1024; // convert to bytes
		auto tbwLimit = i2p::context.GetTransitBandwidthLimit () * 1024; // convert to bytes

		if (tbwLimit == 0 || bwLimit == 0)
			return CONGESTION_LEVEL_FULL;

		uint32_t bw;
		uint32_t tbw;
		if (longTerm)
		{
			bw = std::max (m_InBandwidth5m, m_OutBandwidth5m);
			tbw = m_TransitBandwidth5m;
		}
		else
		{
			bw = std::max (m_InBandwidth15s, m_OutBandwidth15s);
			tbw = m_TransitBandwidth;
		}
		auto bwCongestionLevel = CONGESTION_LEVEL_FULL * bw / bwLimit;
		auto tbwCongestionLevel = CONGESTION_LEVEL_FULL * tbw / tbwLimit;
		return std::max (bwCongestionLevel, tbwCongestionLevel);
	}

	std::future<std::shared_ptr<TransportSession> > Transports::SendMessage (const i2p::data::IdentHash& ident, std::shared_ptr<i2p::I2NPMessage> msg)
	{
		if (m_IsOnline)
			return SendMessages (ident, { msg });
		return {}; // invalid future
	}

	std::future<std::shared_ptr<TransportSession> > Transports::SendMessages (const i2p::data::IdentHash& ident, std::list<std::shared_ptr<i2p::I2NPMessage> >&& msgs)
	{
		return boost::asio::post (*m_Service, boost::asio::use_future ([this, ident, msgs = std::move(msgs)] () mutable
			{
				return PostMessages (ident, msgs);
			}));
	}

	std::shared_ptr<TransportSession> Transports::PostMessages (const i2p::data::IdentHash& ident, std::list<std::shared_ptr<i2p::I2NPMessage> >& msgs)
	{
		if (ident == i2p::context.GetRouterInfo ().GetIdentHash ())
		{
			// we send it to ourself
			for (auto& it: msgs)
				m_LoopbackHandler.PutNextMessage (std::move (it));
			m_LoopbackHandler.Flush ();
			return nullptr;
		}
		if(RoutesRestricted() && !IsRestrictedPeer(ident)) return nullptr;
		std::shared_ptr<Peer> peer;
		{
			std::lock_guard<std::mutex> l(m_PeersMutex);
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
				peer = it->second;
		}
		if (!peer)
		{
			// check if not banned
			if (i2p::data::IsRouterBanned (ident)) return nullptr; // don't create peer to unreachable router
			// try to connect
			bool connected = false;
			try
			{
				auto r = netdb.FindRouter (ident);
				if (r && (r->IsUnreachable () || !r->IsReachableFrom (i2p::context.GetRouterInfo ()) ||
					(r->GetVersion () < i2p::data::NETDB_MIN_ALLOWED_VERSION && !r->IsHighBandwidth ())))
					return nullptr; // router found but non-reachable or too old

				peer = std::make_shared<Peer>(r, i2p::util::GetSecondsSinceEpoch ());
				{
					std::lock_guard<std::mutex> l(m_PeersMutex);
					peer = m_Peers.emplace (ident, peer).first->second;
				}
				if (peer)
					connected = ConnectToPeer (ident, peer);
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Transports: PostMessages exception:", ex.what ());
			}
			if (!connected) return nullptr;
		}

		if (!peer) return nullptr;
		if (peer->IsConnected ())
		{
			auto session = peer->sessions.front ();
			if (session) session->SendI2NPMessages (msgs);
			return session;
		}
		else
		{
			auto sz = peer->delayedMessages.size ();
			if (sz < MAX_NUM_DELAYED_MESSAGES)
			{
				if (sz < CHECK_PROFILE_NUM_DELAYED_MESSAGES && sz + msgs.size () >= CHECK_PROFILE_NUM_DELAYED_MESSAGES)
				{
					if (i2p::data::IsRouterBanned (ident))
					{
						LogPrint (eLogWarning, "Transports: Router ", ident.ToBase64 (), " is banned. Peer dropped");
						std::lock_guard<std::mutex> l(m_PeersMutex);
						m_Peers.erase (ident);
						return nullptr;
					}
				}
				if (sz > MAX_NUM_DELAYED_MESSAGES/2)
				{
					for (auto& it1: msgs)
						if (it1->onDrop)
							it1->Drop (); // drop earlier because we can handle it
						else
							peer->delayedMessages.push_back (it1);
				}
				else
					peer->delayedMessages.splice (peer->delayedMessages.end (), msgs);
			}
			else
			{
				LogPrint (eLogWarning, "Transports: Delayed messages queue size to ",
					ident.ToBase64 (), " exceeds ", MAX_NUM_DELAYED_MESSAGES);
				std::lock_guard<std::mutex> l(m_PeersMutex);
				m_Peers.erase (ident);
			}
		}
		return nullptr;
	}

	bool Transports::ConnectToPeer (const i2p::data::IdentHash& ident, std::shared_ptr<Peer> peer)
	{
		if (!peer->router) // reconnect
		{
			auto r = netdb.FindRouter (ident); // try to get new one from netdb
			if (r)
			{
				peer->SetRouter (r);
				r->CancelBufferToDelete ();
			}
		}
		if (peer->router) // we have RI already
		{
			if (peer->priority.empty ())
				SetPriority (peer);
			while (peer->numAttempts < (int)peer->priority.size ())
			{
				auto tr = peer->priority[peer->numAttempts];
				peer->numAttempts++;
				switch (tr)
				{
					case i2p::data::RouterInfo::eNTCP2V4:
					case i2p::data::RouterInfo::eNTCP2V6:
					{
						if (!m_NTCP2Server) continue;
						std::shared_ptr<const RouterInfo::Address> address = (tr == i2p::data::RouterInfo::eNTCP2V6) ?
							peer->router->GetPublishedNTCP2V6Address () : peer->router->GetPublishedNTCP2V4Address ();
						if (address && IsInReservedRange(address->host))
							address = nullptr;
						if (address)
						{
							auto s = std::make_shared<NTCP2Session> (*m_NTCP2Server, peer->router, address);
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
							peer->router->GetSSU2V6Address () : peer->router->GetSSU2V4Address ();
						if (address && IsInReservedRange(address->host))
							address = nullptr;
						if (address && address->IsReachableSSU ())
						{
							if (m_SSU2Server->CreateSession (peer->router, address))
								return true;
						}
						break;
					}
					case i2p::data::RouterInfo::eNTCP2V6Mesh:
					{
						if (!m_NTCP2Server) continue;
						auto address = peer->router->GetYggdrasilAddress ();
						if (address)
						{
							auto s = std::make_shared<NTCP2Session> (*m_NTCP2Server, peer->router, address);
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
			if (!i2p::context.IsLimitedConnectivity () && peer->router->IsReachableFrom (i2p::context.GetRouterInfo ()))
				i2p::data::netdb.SetUnreachable (ident, true); // we are here because all connection attempts failed but router claimed them
			peer->Done ();
			std::lock_guard<std::mutex> l(m_PeersMutex);
			m_Peers.erase (ident);
			return false;
		}
		else if (i2p::data::IsRouterBanned (ident))
		{
			LogPrint (eLogWarning, "Transports: Router ", ident.ToBase64 (), " is banned. Peer dropped");
			peer->Done ();
			std::lock_guard<std::mutex> l(m_PeersMutex);
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

	void Transports::SetPriority (std::shared_ptr<Peer> peer)
	{
		static constexpr std::array
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
		if (!peer || !peer->router) return;
		auto compatibleTransports = context.GetRouterInfo ().GetCompatibleTransports (false) &
			peer->router->GetCompatibleTransports (true);
		auto directTransports = compatibleTransports & peer->router->GetPublishedTransports ();
		peer->numAttempts = 0;
		peer->priority.clear ();

		std::shared_ptr<RouterProfile> profile;
		if (peer->router->HasProfile ()) profile = peer->router->GetProfile (); // only if in memory
		bool ssu2 = false; // NTCP2 by default
		bool isReal = profile ? profile->IsReal () : true;
		if (isReal)
		{
			ssu2 = m_Rng () & 1; // 1/2
			if (ssu2 && (compatibleTransports & (i2p::data::RouterInfo::eSSU2V4 | i2p::data::RouterInfo::eSSU2V6)))
			{
				bool isSSU2PQ = false;
#if OPENSSL_MLKEM
				if (m_SSU2Server && m_SSU2Server->GetVersion () > 2)
				{
					isSSU2PQ = true;
					// both ipv4 and ipv6 must be post-quantum if presented
					auto addr = peer->router->GetSSU2V4Address ();
					if (addr && addr->v == 2) isSSU2PQ = false;
					if (isSSU2PQ)
					{
						auto addr = peer->router->GetSSU2V6Address ();
						if (addr && addr->v == 2) isSSU2PQ = false;
					}
				}
#endif
				if (!isSSU2PQ && !profile) // check profile only if SSU2 is not post-quantum
				{
					profile = peer->router->GetProfile (); // load profile if necessary
					isReal = profile->IsReal ();
					if (!isReal) ssu2 = false; // try NTCP2 if router is not confirmed real
				}
			}
			else
				ssu2 = false;
		}
		const auto& priority = ssu2 ? ssu2Priority : ntcp2Priority;
		if (directTransports)
		{
			// direct connections have higher priority
			if (!isReal && (directTransports & (i2p::data::RouterInfo::eNTCP2V4 | i2p::data::RouterInfo::eNTCP2V6)))
			{
				// Non-confirmed router and a NTCP2 direct connection is presented
				compatibleTransports &= ~directTransports; // exclude SSU2 direct connections
				directTransports &= ~(i2p::data::RouterInfo::eSSU2V4 | i2p::data::RouterInfo::eSSU2V6);
			}
			for (auto transport: priority)
				if (transport & directTransports)
					peer->priority.push_back (transport);
			compatibleTransports &= ~directTransports;
		}
		if (compatibleTransports)
		{
			// then remaining
			for (auto transport: priority)
				if (transport & compatibleTransports)
					peer->priority.push_back (transport);
		}
		if (peer->priority.empty ())
		{
			// try recently connected SSU2 if any
			auto supportedTransports = context.GetRouterInfo ().GetCompatibleTransports (false) &
				peer->router->GetCompatibleTransports (false);
			if ((supportedTransports & (i2p::data::RouterInfo::eSSU2V4 | i2p::data::RouterInfo::eSSU2V6)) &&
			    peer->router->HasProfile ())
			{
				auto ep = peer->router->GetProfile ()->GetLastEndpoint ();
				if (!ep.address ().is_unspecified () && ep.port ())
				{
					if (ep.address ().is_v4 ())
					{
						if ((supportedTransports & i2p::data::RouterInfo::eSSU2V4) &&
							m_SSU2Server->IsConnectedRecently (ep, false))
							peer->priority.push_back (i2p::data::RouterInfo::eSSU2V4);
					}
					else if (ep.address ().is_v6 ())
					{
						if ((supportedTransports & i2p::data::RouterInfo::eSSU2V6) &&
							m_SSU2Server->IsConnectedRecently (ep))
							peer->priority.push_back (i2p::data::RouterInfo::eSSU2V6);
					}
				}
			}
		}
	}

	void Transports::RequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, const i2p::data::IdentHash& ident)
	{
		boost::asio::post (*m_Service, std::bind (&Transports::HandleRequestComplete, this, r, ident));
	}

	void Transports::HandleRequestComplete (std::shared_ptr<const i2p::data::RouterInfo> r, i2p::data::IdentHash ident)
	{
		std::shared_ptr<Peer> peer;
		{
			std::lock_guard<std::mutex> l(m_PeersMutex);
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				if (r)
					peer = it->second;
				else
					m_Peers.erase (it);
			}
		}

		if (peer && !peer->router && r)
		{
			LogPrint (eLogDebug, "Transports: RouterInfo for ", ident.ToBase64 (), " found, trying to connect");
			peer->SetRouter (r);
			if (!peer->IsConnected ())
				ConnectToPeer (ident, peer);
		}
		else if (!r)
			LogPrint (eLogInfo, "Transports: RouterInfo not found, failed to send messages");

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
		if (RoutesRestricted() || i2p::context.IsLimitedConnectivity () ||
		    !m_SSU2Server || m_SSU2Server->UsesProxy ()) return;
		if (ipv4 && i2p::context.SupportsV4 ())
		{
			LogPrint (eLogInfo, "Transports: Started peer test IPv4");
			std::unordered_set<i2p::data::IdentHash> excluded;
			excluded.insert (i2p::context.GetIdentHash ()); // don't pick own router
			int testDelay = 0;
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomSSU2PeerTestRouter (true, excluded); // v4
				if (router)
				{
					if (!i2p::context.GetTesting ())
					{
						i2p::context.SetTesting (true);
						// send first peer test immediately
						m_SSU2Server->StartPeerTest (router, true);
					}
					else
					{
						testDelay += PEER_TEST_DELAY_INTERVAL + m_Rng() % PEER_TEST_DELAY_INTERVAL_VARIANCE;
						if (m_Service)
						{
							auto delayTimer = std::make_shared<boost::asio::steady_timer>(*m_Service);
							delayTimer->expires_after (std::chrono::milliseconds (testDelay));
							delayTimer->async_wait (
								[this, router, delayTimer](const boost::system::error_code& ecode)
								{
									if (ecode != boost::asio::error::operation_aborted)
										m_SSU2Server->StartPeerTest (router, true);
								});
						}
					}
					excluded.insert (router->GetIdentHash ());
				}
			}
			if (excluded.size () <= 1)
				LogPrint (eLogWarning, "Transports: Can't find routers for peer test IPv4");
		}
		if (ipv6 && i2p::context.SupportsV6 ())
		{
			LogPrint (eLogInfo, "Transports: Started peer test IPv6");
			std::unordered_set<i2p::data::IdentHash> excluded;
			excluded.insert (i2p::context.GetIdentHash ()); // don't pick own router
			int testDelay = 0;
			for (int i = 0; i < 5; i++)
			{
				auto router = i2p::data::netdb.GetRandomSSU2PeerTestRouter (false, excluded); // v6
				if (router)
				{
					if (!i2p::context.GetTestingV6 ())
					{
						i2p::context.SetTestingV6 (true);
						// send first peer test immediately
						m_SSU2Server->StartPeerTest (router, false);
					}
					else
					{
						testDelay += PEER_TEST_DELAY_INTERVAL + m_Rng() % PEER_TEST_DELAY_INTERVAL_VARIANCE;
						if (m_Service)
						{
							auto delayTimer = std::make_shared<boost::asio::steady_timer>(*m_Service);
							delayTimer->expires_after (std::chrono::milliseconds (testDelay));
							delayTimer->async_wait (
								[this, router, delayTimer](const boost::system::error_code& ecode)
								{
									if (ecode != boost::asio::error::operation_aborted)
										m_SSU2Server->StartPeerTest (router, false);
								});
						}
					}
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

	void Transports::PeerConnected (std::weak_ptr<TransportSession> session)
	{
		boost::asio::post (*m_Service, [weakSession = std::move(session), this]()
		{
			auto session = weakSession.lock();
			if (!session) return;
			auto remoteIdentity = session->GetRemoteIdentity ();
			if (!remoteIdentity) return;
			auto ident = remoteIdentity->GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				auto peer = it->second;
				if (peer->numAttempts > 1)
				{
					// exclude failed transports
					i2p::data::RouterInfo::CompatibleTransports transports = 0;
					int numExcluded = peer->numAttempts - 1;
					if (numExcluded > (int)peer->priority.size ()) numExcluded = peer->priority.size ();
					for (int i = 0; i < numExcluded; i++)
						transports |= peer->priority[i];
					i2p::data::netdb.ExcludeReachableTransports (ident, transports);
				}
				if (peer->router && peer->numAttempts)
				{
					auto transport = peer->priority[peer->numAttempts-1];
					if (transport == i2p::data::RouterInfo::eNTCP2V4 ||
						transport == i2p::data::RouterInfo::eNTCP2V6 || transport == i2p::data::RouterInfo::eNTCP2V6Mesh)
							i2p::data::UpdateRouterProfile (ident,
								[](std::shared_ptr<i2p::data::RouterProfile> profile)
								{
									if (profile) profile->Connected (); // outgoing NTCP2 connection if always real
								});
					i2p::data::netdb.SetUnreachable (ident, false); // clear unreachable
				}
				peer->numAttempts = 0;
				peer->router = nullptr; // we don't need RouterInfo after successive connect
				bool sendDatabaseStore = true;
				if (it->second->delayedMessages.size () > 0)
				{
					// check if first message is our DatabaseStore (publishing)
					auto firstMsg = peer->delayedMessages.front ();
					if (firstMsg && firstMsg->GetTypeID () == eI2NPDatabaseStore &&
							i2p::data::IdentHash(firstMsg->GetPayload () + DATABASE_STORE_KEY_OFFSET) == i2p::context.GetIdentHash ())
						sendDatabaseStore = false; // we have it in the list already
				}
				if (sendDatabaseStore)
					session->SendLocalRouterInfo ();
				else
					session->SetTerminationTimeout (10); // most likely it's publishing, no follow-up messages expected, set timeout to 10 seconds
				peer->sessions.push_back (session);
				session->SendI2NPMessages (peer->delayedMessages); // send and clear
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
					session->SendLocalRouterInfo (); // send DatabaseStore
				auto r = i2p::data::netdb.FindRouter (ident); // router should be in netdb after SessionConfirmed
				i2p::data::UpdateRouterProfile (ident,
					[](std::shared_ptr<i2p::data::RouterProfile> profile)
					{
						if (profile) profile->Connected ();
					});
				auto ts = i2p::util::GetSecondsSinceEpoch ();
				auto peer = std::make_shared<Peer>(r, ts);
				peer->sessions.push_back (session);
				peer->router = nullptr;
				std::lock_guard<std::mutex> l(m_PeersMutex);
				m_Peers.emplace (ident, peer);
			}
			if (IsCheckReserved ())
			{
				auto addr = GetNetworkAddress (session);
				if (!addr.is_unspecified ())
				{
					std::lock_guard<std::mutex> l( m_ConnectedNetworksMutex);
					auto [it1, inserted] = m_ConnectedNetworks.try_emplace (addr, 0);
					it1->second++;
				}
			}
		});
	}

	void Transports::PeerDisconnected (std::weak_ptr<TransportSession> session)
	{
		boost::asio::post (*m_Service, [weakSession = std::move(session), this]()
		{
			auto session = weakSession.lock();
			if (!session) return;
			auto remoteIdentity = session->GetRemoteIdentity ();
			if (!remoteIdentity) return;
			auto ident = remoteIdentity->GetIdentHash ();
			auto it = m_Peers.find (ident);
			if (it != m_Peers.end ())
			{
				auto peer = it->second;
				bool wasConnected = peer->IsConnected ();
				peer->sessions.remove (session);
				if (!peer->IsConnected ())
				{
					if (peer->delayedMessages.size () > 0)
					{
						if (wasConnected) // we had an active session before
							peer->numAttempts = 0; // start over
						ConnectToPeer (ident, peer);
					}
					else
					{
						{
							std::lock_guard<std::mutex> l(m_PeersMutex);
							m_Peers.erase (it);
						}
						// delete buffer of just disconnected router
						auto r = i2p::data::netdb.FindRouter (ident);
						if (r && !r->IsUpdated ()) r->ScheduleBufferToDelete ();
					}
				}
			}
			if (IsCheckReserved ())
			{
				auto addr = GetNetworkAddress (session);
				if (!addr.is_unspecified ())
				{
					std::lock_guard<std::mutex> l( m_ConnectedNetworksMutex);
					auto it1 = m_ConnectedNetworks.find (addr);
					if (it1 != m_ConnectedNetworks.end ())
					{
						it1->second--;
						if (it1->second <= 0)
							m_ConnectedNetworks.erase (it1);
					}
				}
			}
		});
	}

	bool Transports::IsConnected (const i2p::data::IdentHash& ident) const
	{
		std::lock_guard<std::mutex> l(m_PeersMutex);
#if __cplusplus >= 202002L // C++20
		return m_Peers.contains (ident);
#else
		auto it = m_Peers.find (ident);
		return it != m_Peers.end ();
#endif
	}

	void Transports::UpdatePeerParams (std::shared_ptr<const i2p::data::RouterInfo> r)
	{
		if (!r) return;
		std::shared_ptr<Peer> peer;
		{
			std::lock_guard<std::mutex> l(m_PeersMutex);
			auto it = m_Peers.find (r->GetIdentHash ());
			if (it != m_Peers.end ())
				peer = it->second;
		}
		if (peer)
			peer->UpdateParams (r);
	}

	void Transports::HandlePeerCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			std::list<std::shared_ptr<TransportSession> > sessionsToRemove;
			std::list<std::shared_ptr<Peer> > peersToRemove;

			{
				std::lock_guard<std::mutex> l(m_PeersMutex);
				for (auto it = m_Peers.begin (); it != m_Peers.end (); )
				{
					auto peer = it->second;
					peer->sessions.remove_if (
						[&sessionsToRemove](std::shared_ptr<TransportSession> session)->bool
						{
							bool remove = false;
							if (session)
							{
								if (!session->IsEstablished ())
								{
									sessionsToRemove.emplace_back (session); // defer session destructor call after the loop
									remove = true;
								}
							}
							else
								remove = true;
							return remove;
						});
					if (!peer->IsConnected () && ts > peer->creationTime + SESSION_CREATION_TIMEOUT)
					{
						LogPrint (eLogWarning, "Transports: Session to peer ", it->first.ToBase64 (), " has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
					/*	if (!it->second.router)
						{
							// if router for ident not found mark it unreachable
							auto profile = i2p::data::GetRouterProfile (it->first);
							if (profile) profile->Unreachable ();
						}	*/
						peersToRemove.emplace_back (peer); // defer peer destructor call after the loop
						it = m_Peers.erase (it);
					}
					else
					{
						if (ts > peer->nextRouterInfoUpdateTime)
						{
							auto session = (!peer->sessions.empty ()) ? peer->sessions.front () : nullptr;
							if (session)
								session->SendLocalRouterInfo (true);
							peer->nextRouterInfoUpdateTime = ts + PEER_ROUTER_INFO_UPDATE_INTERVAL +
								m_Rng() % PEER_ROUTER_INFO_UPDATE_INTERVAL_VARIANCE;
						}
						++it;
					}
				}
			}

			bool ipv4Testing = i2p::context.GetTesting ();
			if (!ipv4Testing)
				ipv4Testing = i2p::context.GetRouterInfo ().IsSSU2V4 () && (i2p::context.GetStatus() == eRouterStatusUnknown);
			bool ipv6Testing = i2p::context.GetTestingV6 ();
			if (!ipv6Testing)
				ipv6Testing = i2p::context.GetRouterInfo ().IsSSU2V6 () && (i2p::context.GetStatusV6() == eRouterStatusUnknown);
			// if still testing or unknown, repeat peer test
			if (ipv4Testing || ipv6Testing)
				PeerTest (ipv4Testing, ipv6Testing);
			m_PeerCleanupTimer->expires_after (std::chrono::seconds(2 * SESSION_CREATION_TIMEOUT + m_Rng() % SESSION_CREATION_TIMEOUT));
			m_PeerCleanupTimer->async_wait (std::bind (&Transports::HandlePeerCleanupTimer, this, std::placeholders::_1));
			// cleanup and delete sessionsToRemove and peersToRemove here
		}
	}

	void Transports::HandlePeerTestTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			PeerTest ();
			m_PeerTestTimer->expires_after (std::chrono::seconds(PEER_TEST_INTERVAL + m_Rng() % PEER_TEST_INTERVAL_VARIANCE));
			m_PeerTestTimer->async_wait (std::bind (&Transports::HandlePeerTestTimer, this, std::placeholders::_1));
		}
	}

	void Transports::HandleBanListCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (!m_BanList.empty ())
			{
				auto ts = i2p::util::GetMonotonicSeconds ();
				{
					std::lock_guard<std::mutex> l(m_BanListMutex);
					for (auto it = m_BanList.begin (); it != m_BanList.end (); )
					{
						if (ts < it->second)
							it++;
						else
							it = m_BanList.erase (it);
					}
				}
			}
			m_BanListCleanupTimer->expires_after (std::chrono::seconds(BAN_LIST_CLEANUP_INTERVAL + m_Rng () % BAN_LIST_CLEANUP_INTERVAL_VARIANCE));
			m_BanListCleanupTimer->async_wait (std::bind (&Transports::HandleBanListCleanupTimer, this, std::placeholders::_1));
		}
	}

	template<typename Filter>
	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer (Filter filter, i2p::data::PeerOrdering * peerOrdering) const
	{
		std::vector<std::pair<i2p::data::IdentHash, std::shared_ptr<Peer> > > peers;
		{
			// copy peers to temporary vector
			std::lock_guard<std::mutex> l(m_PeersMutex);
			if (m_Peers.empty()) return nullptr;
			peers.reserve (m_Peers.size ());
			peers.assign (m_Peers.begin(), m_Peers.end());
		}
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		bool found = false;
		i2p::data::IdentHash foundIdent;
		uint16_t inds[3];
		RAND_bytes ((uint8_t *)inds, sizeof (inds));
		auto count = peers.size ();
		if (!count) return nullptr;
		inds[0] %= count;
		auto& [ident, peer] = peers[inds[0]];
		// try random peer
		if (ts > peer->lastSelectionTime + PEER_SELECTION_MIN_INTERVAL)
		{
			bool eligibleForFirstHop = peerOrdering ? peerOrdering->IsFirstHop (ident) : true;
			if (eligibleForFirstHop && filter (peer))
			{
				foundIdent = ident;
				peer->lastSelectionTime = ts;
				found = true;
			}
		}
		if (!found)
		{
			// try some peers around
			if (inds[0])
			{
				// before
				inds[1] %= inds[0];
				inds[1] = (inds[1] + inds[0])/2;
			}
			else
				inds[1] = 0;
			if (inds[0] < peers.size () - 1)
			{
				// after
				inds[2] %= (peers.size () - 1 - inds[0]);
				inds[2] /= 2;
				inds[2] += inds[0];
			}
			else
				inds[2] = inds[0];
			// from inds[1] to inds[2]
			for (auto i = inds[1]; i < inds[2]; i++)
			{
				auto& [ident, peer] = peers[i];
				if (ts > peer->lastSelectionTime + PEER_SELECTION_MIN_INTERVAL)
				{
					bool eligibleForFirstHop = peerOrdering ? peerOrdering->IsFirstHop (ident) : true;
					if (eligibleForFirstHop && filter (peer))
					{
						foundIdent = ident;
						peer->lastSelectionTime = ts;
						found = true;
						break;
					}
				}
			}

			if (!found)
			{
				// still not found, try from the beginning to inds[1]
				for (auto i = 0; i < inds[1]; i++)
				{
					auto& [ident, peer] = peers[i];
					if (ts > peer->lastSelectionTime + PEER_SELECTION_MIN_INTERVAL)
					{
						bool eligibleForFirstHop = peerOrdering ? peerOrdering->IsFirstHop (ident) : true;
						if (eligibleForFirstHop && filter (peer))
						{
							foundIdent = ident;
							peer->lastSelectionTime = ts;
							found = true;
							break;
						}
					}
				}

				if (!found)
				{
					// still not found, try from inds[2] to the end
					for (auto i = inds[2]; i < peers.size (); i++)
					{
						auto& [ident, peer] = peers[i];
						if (ts > peer->lastSelectionTime + PEER_SELECTION_MIN_INTERVAL)
						{
							bool eligibleForFirstHop = peerOrdering ? peerOrdering->IsFirstHop (ident) : true;
							if (eligibleForFirstHop && filter (peer))
							{
								foundIdent = ident;
								peer->lastSelectionTime = ts;
								found = true;
								break;
							}
						}
					}
				}
			}
		}
		return found ? i2p::data::netdb.FindRouter (foundIdent) : nullptr;
	}

	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer (bool isHighBandwidth, i2p::data::PeerOrdering * peerOrdering) const
	{
		return GetRandomPeer (
			[isHighBandwidth, this](std::shared_ptr<const Peer> peer)->bool
			{
				// check if connected and high bandwidth if required
				if (peer->router || !peer->IsConnected () || !peer->isEligible ||
					peer->sessions.empty () || (isHighBandwidth && !peer->isHighBandwidth)) return false;
				auto session = peer->sessions.front ();
				// check if session not overloaded, slow or bandwidth exceeded
				if (session->GetSendQueueSize () > PEER_ROUTER_INFO_OVERLOAD_QUEUE_SIZE ||
					session->IsSlow () || session->IsBandwidthExceeded (peer->isHighBandwidth)) return false;
				if (IsCheckReserved ())
				{
					// check if max num connections from subnet is not exceeded
					auto addr = GetNetworkAddress (session);
					if (!addr.is_unspecified ())
					{
						std::lock_guard<std::mutex> l( m_ConnectedNetworksMutex);
						auto it = m_ConnectedNetworks.find (addr);
						if (it != m_ConnectedNetworks.end () && it->second > MAX_NUM_CONNECTIONS_FROM_SUBNET_FOR_PEER) return false;
					}
				}
				return true;
			},
			i2p::context.IsLimitedConnectivity () ? nullptr : peerOrdering);
	}

	void Transports::RestrictRoutesToFamilies(const std::vector<std::string_view>& families)
	{
		std::lock_guard<std::mutex> lock(m_FamilyMutex);
		m_TrustedFamilies.clear();
		for (auto f: families)
		{
            std::string fam(f); boost::to_lower (fam);
			auto id = i2p::data::netdb.GetFamilies ().GetFamilyID (fam);
			if (id)
				m_TrustedFamilies.push_back (id);
		}
	}

	void Transports::RestrictRoutesToRouters(const std::vector<i2p::data::IdentHash>& routers)
	{
		std::lock_guard<std::mutex> lock(m_TrustedRoutersMutex);
		m_TrustedRouters.clear();
		for (const auto & ri : routers )
			m_TrustedRouters.insert(ri);
	}

	bool Transports::RoutesRestricted() const
	{
		{
			std::lock_guard<std::mutex> routerslock(m_TrustedRoutersMutex);
			if (!m_TrustedRouters.empty ()) return true;
		}
		{
			std::lock_guard<std::mutex> famlock(m_FamilyMutex);
			if (!m_TrustedFamilies.empty ()) return true;
		}
		return false;
	}

	/** XXX: if routes are not restricted this dies */
	std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRestrictedPeer()
	{
		{
			std::lock_guard<std::mutex> l(m_FamilyMutex);
			i2p::data::FamilyID fam = 0;
			auto sz = m_TrustedFamilies.size();
			if(sz > 1)
			{
				auto it = m_TrustedFamilies.begin ();
				std::advance(it, m_Rng() % sz);
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
			std::lock_guard<std::mutex> l(m_TrustedRoutersMutex);
			auto sz = m_TrustedRouters.size();
			if (sz)
			{
				auto it = m_TrustedRouters.begin();
				if(sz > 1)
					std::advance(it, m_Rng() % sz);
				return i2p::data::netdb.FindRouter(*it);
			}
		}
		return nullptr;
	}

	bool Transports::IsTrustedRouter (const i2p::data::IdentHash& ih) const
	{
		if (m_TrustedRouters.empty ()) return false;
		std::lock_guard<std::mutex> l(m_TrustedRoutersMutex);
#if __cplusplus >= 202002L // C++20
		if (m_TrustedRouters.contains (ih))
#else
		if (m_TrustedRouters.count (ih) > 0)
#endif
			return true;
		return false;
	}

	bool Transports::IsRestrictedPeer(const i2p::data::IdentHash& ih) const
	{
		if (IsTrustedRouter (ih)) return true;

		{
			std::lock_guard<std::mutex> l(m_FamilyMutex);
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

	int Transports::GetLocalDelay () const
	{
		return (i2p::context.GetStatus () == eRouterStatusProxy) ? 1000 : 0; // 1 sec for proxy. TODO: implement param
	}

	bool Transports::IsInReservedRange (const boost::asio::ip::address& host) const
	{
		return IsCheckReserved () && i2p::util::net::IsInReservedRange (host);
	}

	bool Transports::IsBanned (const boost::asio::ip::address& addr)
	{
		std::lock_guard<std::mutex> l(m_BanListMutex);
		auto it = m_BanList.find (addr);
		if (it != m_BanList.end ())
		{
			if (it->second > i2p::util::GetMonotonicSeconds ())
				return true;
			else
				m_BanList.erase (it);
		}
		return false;
	}

	bool Transports::AddBan (const boost::asio::ip::address& addr)
	{
		auto ts = i2p::util::GetMonotonicSeconds () + IP_BAN_TIME + m_Rng () % IP_BAN_TIME_VARIANCE;
		std::lock_guard<std::mutex> l(m_BanListMutex);
		return m_BanList.emplace (addr, ts).second;
	}

	boost::asio::ip::address Transports::GetNetworkAddress (const boost::asio::ip::address& addr) const
	{
		if (!addr.is_unspecified ())
		{
			if (addr.is_v4 ())
				return boost::asio::ip::network_v4 (addr.to_v4 (), 24).network (); // /24
			else
			{
				if (i2p::util::net::IsYggdrasilAddress (addr))
				{
					// change to 2xx range
					auto bytes = addr.to_v6 ().to_bytes ();
					bytes[0] = 0x02;
					return  boost::asio::ip::network_v6 (boost::asio::ip::address_v6 (bytes), 64).network (); // /64
				}
				return boost::asio::ip::network_v6 (addr.to_v6 (), 56).network (); // /56
			}
		}
		return boost::asio::ip::address ();
	}

	boost::asio::ip::address Transports::GetNetworkAddress (std::shared_ptr<TransportSession> session) const
	{
		if (session)
			return GetNetworkAddress (session->GetRemoteAddress ());
		return boost::asio::ip::address ();
	}

	bool Transports::IsTooManyConnectionsFromSubnet (std::shared_ptr<const i2p::data::RouterInfo> r) const
	{
		if (!r || !IsCheckReserved ()) return false;
		auto addresses = r->GetAddresses ();
		if (!addresses) return false;
		for (auto& address : *addresses)
			if (address && !address->host.is_unspecified ())
			{
				auto networkAddr = GetNetworkAddress (address->host);
				if (!networkAddr.is_unspecified ())
				{
					std::lock_guard<std::mutex> l( m_ConnectedNetworksMutex);
					auto it = m_ConnectedNetworks.find (networkAddr);
					if (it != m_ConnectedNetworks.end () && it->second > MAX_NUM_CONNECTIONS_FROM_SUBNET_FOR_PEER) return true;
				}
			}
		return false;
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
		bool stan;	   i2p::config::GetOption("stan", stan);

		boost::asio::ip::address_v6 yggaddr;
		if (ygg)
		{
			std::string yggaddress; i2p::config::GetOption ("meshnets.yggaddress", yggaddress);
			if (!yggaddress.empty ())
			{
				yggaddr = boost::asio::ip::make_address (yggaddress).to_v6 ();
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

		if (ipv6 &&	i2p::util::net::GetClearnetIPV6Address ().is_unspecified ())
		{
			std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
			std::string ssu2proxy; i2p::config::GetOption("ssu2.proxy", ssu2proxy);
			if (ntcp2proxy.empty () && ssu2proxy.empty ())
			{
				LogPrint(eLogWarning, "Transports: Clearnet ipv6 not found. Disabled");
				ipv6 = false;
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
			bool published = false;
			if (!stan) i2p::config::GetOption("ntcp2.published", published);
			if (published)
			{
				std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
				if (!ntcp2proxy.empty ()) published = false;
			}
			int ntcp2version = 2;
#if OPENSSL_MLKEM
			i2p::config::GetOption("ntcp2.version", ntcp2version);
#endif
			if (published)
			{
				uint16_t ntcp2port; i2p::config::GetOption("ntcp2.port", ntcp2port);
				if (!ntcp2port) ntcp2port = port; // use standard port
				i2p::context.PublishNTCP2Address (ntcp2port, true, ipv4, ipv6, false, ntcp2version); // publish
				if (ipv6)
				{
					std::string ipv6Addr; i2p::config::GetOption("ntcp2.addressv6", ipv6Addr);
					auto addr = boost::asio::ip::make_address (ipv6Addr).to_v6 ();
					if (!addr.is_unspecified () && addr != boost::asio::ip::address_v6::any ())
						i2p::context.UpdateNTCP2V6Address (addr); // set ipv6 address if configured
				}
			}
			else
				i2p::context.PublishNTCP2Address (port, false, ipv4, ipv6, false, ntcp2version); // unpublish
		}
		if (ygg)
		{
			i2p::context.PublishNTCP2Address (port, true, false, false, true, 2);
			i2p::context.UpdateNTCP2V6Address (yggaddr);
			if (!ipv4 && !ipv6)
				i2p::context.SetStatus (eRouterStatusMesh);
		}
		bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
		if (ssu2 && i2p::config::IsDefault ("ssu2.enabled") && !ipv4 && !ipv6)
			ssu2 = false; // don't enable ssu2 for yggdrasil only router
		if (ssu2)
		{
			int ssu2version = 2;
#if OPENSSL_MLKEM
			i2p::config::GetOption("ssu2.version", ssu2version);
#endif
			uint16_t ssu2port; i2p::config::GetOption("ssu2.port", ssu2port);
			if (!ssu2port && port) ssu2port = port;
			bool published = false;
			if (!stan) i2p::config::GetOption("ssu2.published", published);
			if (published)
				i2p::context.PublishSSU2Address (ssu2port, true, ipv4, ipv6, ssu2version); // publish
			else
				i2p::context.PublishSSU2Address (ssu2port, false, ipv4, ipv6, ssu2version); // unpublish
		}
		if (stan)
			i2p::context.SetStatus (eRouterStatusStan);
	}
}
}
