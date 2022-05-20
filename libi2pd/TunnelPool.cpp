/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>
#include <random>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Tunnel.h"
#include "NetDb.hpp"
#include "Timestamp.h"
#include "Garlic.h"
#include "Transports.h"
#include "Log.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "Destination.h"

namespace i2p
{
namespace tunnel
{
	void Path::Add (std::shared_ptr<const i2p::data::RouterInfo> r)
	{
		if (r)
		{
			peers.push_back (r->GetRouterIdentity ());
			if (r->GetVersion () < i2p::data::NETDB_MIN_SHORT_TUNNEL_BUILD_VERSION ||
				r->GetRouterIdentity ()->GetCryptoKeyType () != i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
				isShort = false;
		}
	}

	void Path::Reverse ()
	{
		std::reverse (peers.begin (), peers.end ());
	}

	TunnelPool::TunnelPool (int numInboundHops, int numOutboundHops, int numInboundTunnels,
		int numOutboundTunnels, int inboundVariance, int outboundVariance):
		m_NumInboundHops (numInboundHops), m_NumOutboundHops (numOutboundHops),
		m_NumInboundTunnels (numInboundTunnels), m_NumOutboundTunnels (numOutboundTunnels),
		m_InboundVariance (inboundVariance), m_OutboundVariance (outboundVariance),
		m_IsActive (true), m_CustomPeerSelector(nullptr)
	{
		if (m_NumInboundTunnels > TUNNEL_POOL_MAX_INBOUND_TUNNELS_QUANTITY)
			m_NumInboundTunnels = TUNNEL_POOL_MAX_INBOUND_TUNNELS_QUANTITY;
		if (m_NumOutboundTunnels > TUNNEL_POOL_MAX_OUTBOUND_TUNNELS_QUANTITY)
			m_NumOutboundTunnels = TUNNEL_POOL_MAX_OUTBOUND_TUNNELS_QUANTITY;
		if (m_InboundVariance < 0 && m_NumInboundHops + m_InboundVariance <= 0)
			m_InboundVariance = m_NumInboundHops ? -m_NumInboundHops + 1 : 0;
		if (m_OutboundVariance < 0 && m_NumOutboundHops + m_OutboundVariance <= 0)
			m_OutboundVariance = m_NumOutboundHops ? -m_NumOutboundHops + 1 : 0;
		if (m_InboundVariance > 0 && m_NumInboundHops + m_InboundVariance > STANDARD_NUM_RECORDS)
			m_InboundVariance = (m_NumInboundHops < STANDARD_NUM_RECORDS) ? STANDARD_NUM_RECORDS - m_NumInboundHops : 0;
		if (m_OutboundVariance > 0 && m_NumOutboundHops + m_OutboundVariance > STANDARD_NUM_RECORDS)
			m_OutboundVariance = (m_NumOutboundHops < STANDARD_NUM_RECORDS) ? STANDARD_NUM_RECORDS - m_NumOutboundHops : 0;
		m_NextManageTime = i2p::util::GetSecondsSinceEpoch () + rand () % TUNNEL_POOL_MANAGE_INTERVAL;
	}

	TunnelPool::~TunnelPool ()
	{
		DetachTunnels ();
	}

	void TunnelPool::SetExplicitPeers (std::shared_ptr<std::vector<i2p::data::IdentHash> > explicitPeers)
	{
		m_ExplicitPeers = explicitPeers;
		if (m_ExplicitPeers)
		{
			int size = m_ExplicitPeers->size ();
			if (m_NumInboundHops > size)
			{
				m_NumInboundHops = size;
				LogPrint (eLogInfo, "Tunnels: Inbound tunnel length has beed adjusted to ", size, " for explicit peers");
			}
			if (m_NumOutboundHops > size)
			{
				m_NumOutboundHops = size;
				LogPrint (eLogInfo, "Tunnels: Outbound tunnel length has beed adjusted to ", size, " for explicit peers");
			}
			m_NumInboundTunnels = 1;
			m_NumOutboundTunnels = 1;
		}
	}

	void TunnelPool::DetachTunnels ()
	{
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (auto& it: m_InboundTunnels)
				it->SetTunnelPool (nullptr);
			m_InboundTunnels.clear ();
		}
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (auto& it: m_OutboundTunnels)
				it->SetTunnelPool (nullptr);
			m_OutboundTunnels.clear ();
		}
		m_Tests.clear ();
	}

	bool TunnelPool::Reconfigure(int inHops, int outHops, int inQuant, int outQuant)
	{
		if( inHops >= 0 && outHops >= 0 && inQuant > 0 && outQuant > 0)
		{
			m_NumInboundHops = inHops;
			m_NumOutboundHops = outHops;
			m_NumInboundTunnels = inQuant;
			m_NumOutboundTunnels = outQuant;
			return true;
		}
		return false;
	}

	void TunnelPool::TunnelCreated (std::shared_ptr<InboundTunnel> createdTunnel)
	{
		if (!m_IsActive) return;
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			if (createdTunnel->IsRecreated ())
			{
				// find and mark old tunnel as expired
				createdTunnel->SetRecreated (false);
				for (auto& it: m_InboundTunnels)
					if (it->IsRecreated () && it->GetNextIdentHash () == createdTunnel->GetNextIdentHash ())
					{
						it->SetState (eTunnelStateExpiring);
						break;
					}
			}
			m_InboundTunnels.insert (createdTunnel);
		}
		if (m_LocalDestination)
			m_LocalDestination->SetLeaseSetUpdated ();
	}

	void TunnelPool::TunnelExpired (std::shared_ptr<InboundTunnel> expiredTunnel)
	{
		if (expiredTunnel)
		{
			expiredTunnel->SetTunnelPool (nullptr);
			for (auto& it: m_Tests)
				if (it.second.second == expiredTunnel) it.second.second = nullptr;

			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			m_InboundTunnels.erase (expiredTunnel);
		}
	}

	void TunnelPool::TunnelCreated (std::shared_ptr<OutboundTunnel> createdTunnel)
	{
		if (!m_IsActive) return;
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			m_OutboundTunnels.insert (createdTunnel);
		}
	}

	void TunnelPool::TunnelExpired (std::shared_ptr<OutboundTunnel> expiredTunnel)
	{
		if (expiredTunnel)
		{
			expiredTunnel->SetTunnelPool (nullptr);
			for (auto& it: m_Tests)
				if (it.second.first == expiredTunnel) it.second.first = nullptr;

			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			m_OutboundTunnels.erase (expiredTunnel);
		}
	}

	std::vector<std::shared_ptr<InboundTunnel> > TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<std::shared_ptr<InboundTunnel> > v;
		int i = 0;
		std::shared_ptr<InboundTunnel> slowTunnel;
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		for (const auto& it : m_InboundTunnels)
		{
			if (i >= num) break;
			if (it->IsEstablished ())
			{
				if (it->IsSlow () && !slowTunnel)
					slowTunnel = it;
				else
				{
					v.push_back (it);
					i++;
				}
			}
		}
		if (slowTunnel && (int)v.size () < (num/2+1))
			v.push_back (slowTunnel);
		return v;
	}

	std::shared_ptr<OutboundTunnel> TunnelPool::GetNextOutboundTunnel (std::shared_ptr<OutboundTunnel> excluded,
		i2p::data::RouterInfo::CompatibleTransports compatible) const
	{
		std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
		return GetNextTunnel (m_OutboundTunnels, excluded, compatible);
	}

	std::shared_ptr<InboundTunnel> TunnelPool::GetNextInboundTunnel (std::shared_ptr<InboundTunnel> excluded,
		i2p::data::RouterInfo::CompatibleTransports compatible) const
	{
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		return GetNextTunnel (m_InboundTunnels, excluded, compatible);
	}

	template<class TTunnels>
	typename TTunnels::value_type TunnelPool::GetNextTunnel (TTunnels& tunnels,
		typename TTunnels::value_type excluded, i2p::data::RouterInfo::CompatibleTransports compatible) const
	{
		if (tunnels.empty ()) return nullptr;
		uint32_t ind = rand () % (tunnels.size ()/2 + 1), i = 0;
		bool skipped = false;
		typename TTunnels::value_type tunnel = nullptr;
		for (const auto& it: tunnels)
		{
			if (it->IsEstablished () && it != excluded && (compatible & it->GetFarEndTransports ()))
			{
				if (it->IsSlow () || (HasLatencyRequirement() && it->LatencyIsKnown() &&
					!it->LatencyFitsRange(m_MinLatency, m_MaxLatency)))
				{
					i++; skipped = true;
					continue;
				}
				tunnel = it;
				i++;
			}
			if (i > ind && tunnel) break;
		}
		if (!tunnel && skipped)
		{
			ind = rand () % (tunnels.size ()/2 + 1), i = 0;
			for (const auto& it: tunnels)
			{
				if (it->IsEstablished () && it != excluded)
				{
					tunnel = it;
					i++;
				}
				if (i > ind && tunnel) break;
			}
		}
		if (!tunnel && excluded && excluded->IsEstablished ()) tunnel = excluded;
		return tunnel;
	}

	std::shared_ptr<OutboundTunnel> TunnelPool::GetNewOutboundTunnel (std::shared_ptr<OutboundTunnel> old) const
	{
		if (old && old->IsEstablished ()) return old;
		std::shared_ptr<OutboundTunnel> tunnel;
		if (old)
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (const auto& it: m_OutboundTunnels)
				if (it->IsEstablished () && old->GetEndpointIdentHash () == it->GetEndpointIdentHash ())
				{
					tunnel = it;
					break;
				}
		}

		if (!tunnel)
			tunnel = GetNextOutboundTunnel ();
		return tunnel;
	}

	void TunnelPool::CreateTunnels ()
	{
		int num = 0;
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (const auto& it : m_OutboundTunnels)
				if (it->IsEstablished ()) num++;
		}
		for (int i = num; i < m_NumOutboundTunnels; i++)
			CreateOutboundTunnel ();

		num = 0;
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (const auto& it : m_InboundTunnels)
				if (it->IsEstablished ()) num++;
		}
		if (!num && !m_OutboundTunnels.empty () && m_NumOutboundHops > 0)
		{
			for (auto it: m_OutboundTunnels)
			{
				CreatePairedInboundTunnel (it);
				num++;
				if (num >= m_NumInboundTunnels) break;
			}
		}
		for (int i = num; i < m_NumInboundTunnels; i++)
			CreateInboundTunnel ();

		if (num < m_NumInboundTunnels && m_NumInboundHops <= 0 && m_LocalDestination) // zero hops IB
			m_LocalDestination->SetLeaseSetUpdated (); // update LeaseSet immediately
	}

	void TunnelPool::TestTunnels ()
	{
		decltype(m_Tests) tests;
		{
			std::unique_lock<std::mutex> l(m_TestsMutex);
			tests.swap(m_Tests);
		}

		for (auto& it: tests)
		{
			LogPrint (eLogWarning, "Tunnels: Test of tunnel ", it.first, " failed");
			// if test failed again with another tunnel we consider it failed
			if (it.second.first)
			{
				if (it.second.first->GetState () == eTunnelStateTestFailed)
				{
					it.second.first->SetState (eTunnelStateFailed);
					std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
					m_OutboundTunnels.erase (it.second.first);
				}
				else
					it.second.first->SetState (eTunnelStateTestFailed);
			}
			if (it.second.second)
			{
				if (it.second.second->GetState () == eTunnelStateTestFailed)
				{
					it.second.second->SetState (eTunnelStateFailed);
					{
						std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
						m_InboundTunnels.erase (it.second.second);
					}
					if (m_LocalDestination)
						m_LocalDestination->SetLeaseSetUpdated ();
				}
				else
					it.second.second->SetState (eTunnelStateTestFailed);
			}
		}

		// new tests
		std::unique_lock<std::mutex> l1(m_OutboundTunnelsMutex);
		auto it1 = m_OutboundTunnels.begin ();
		std::unique_lock<std::mutex> l2(m_InboundTunnelsMutex);
		auto it2 = m_InboundTunnels.begin ();
		while (it1 != m_OutboundTunnels.end () && it2 != m_InboundTunnels.end ())
		{
			bool failed = false;
			if ((*it1)->IsFailed ())
			{
				failed = true;
				++it1;
			}
			if ((*it2)->IsFailed ())
			{
				failed = true;
				++it2;
			}
			if (!failed)
			{
				uint32_t msgID;
				RAND_bytes ((uint8_t *)&msgID, 4);
				{
					std::unique_lock<std::mutex> l(m_TestsMutex);
					m_Tests[msgID] = std::make_pair (*it1, *it2);
				}
				(*it1)->SendTunnelDataMsg ((*it2)->GetNextIdentHash (), (*it2)->GetNextTunnelID (),
					CreateDeliveryStatusMsg (msgID));
				++it1; ++it2;
			}
		}
	}

	void TunnelPool::ManageTunnels (uint64_t ts)
	{
		if (ts > m_NextManageTime || ts + 2*TUNNEL_POOL_MANAGE_INTERVAL < m_NextManageTime) // in case if clock was adjusted
		{
			CreateTunnels ();
			TestTunnels ();
			m_NextManageTime = ts + TUNNEL_POOL_MANAGE_INTERVAL + (rand () % TUNNEL_POOL_MANAGE_INTERVAL)/2;
		}
	}

	void TunnelPool::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_LocalDestination)
			m_LocalDestination->ProcessGarlicMessage (msg);
		else
			LogPrint (eLogWarning, "Tunnels: Local destination doesn't exist, dropped");
	}

	void TunnelPool::ProcessDeliveryStatus (std::shared_ptr<I2NPMessage> msg)
	{
		const uint8_t * buf = msg->GetPayload ();
		uint32_t msgID = bufbe32toh (buf);
		buf += 4;
		uint64_t timestamp = bufbe64toh (buf);

		decltype(m_Tests)::mapped_type test;
		bool found = false;
		{
			std::unique_lock<std::mutex> l(m_TestsMutex);
			auto it = m_Tests.find (msgID);
			if (it != m_Tests.end ())
			{
				found = true;
				test = it->second;
				m_Tests.erase (it);
			}
		}
		if (found)
		{
			uint64_t dlt = i2p::util::GetMillisecondsSinceEpoch () - timestamp;
			LogPrint (eLogDebug, "Tunnels: Test of ", msgID, " successful. ", dlt, " milliseconds");
			int numHops = 0;
			if (test.first) numHops += test.first->GetNumHops ();
			if (test.second) numHops += test.second->GetNumHops ();
			// restore from test failed state if any
			if (test.first)
			{
				if (test.first->GetState () == eTunnelStateTestFailed)
					test.first->SetState (eTunnelStateEstablished);
				// update latency
				uint64_t latency = 0;
				if (numHops) latency = dlt*test.first->GetNumHops ()/numHops;
				if (!latency) latency = dlt/2;
				test.first->AddLatencySample(latency);
			}
			if (test.second)
			{
				if (test.second->GetState () == eTunnelStateTestFailed)
					test.second->SetState (eTunnelStateEstablished);
				// update latency
				uint64_t latency = 0;
				if (numHops) latency = dlt*test.second->GetNumHops ()/numHops;
				if (!latency) latency = dlt/2;
				test.second->AddLatencySample(latency);
			}
		}
		else
		{
			if (m_LocalDestination)
				m_LocalDestination->ProcessDeliveryStatusMessage (msg);
			else
				LogPrint (eLogWarning, "Tunnels: Local destination doesn't exist, dropped");
		}
	}

	bool TunnelPool::IsExploratory () const
	{
		return i2p::tunnel::tunnels.GetExploratoryPool () == shared_from_this ();
	}

	std::shared_ptr<const i2p::data::RouterInfo> TunnelPool::SelectNextHop (std::shared_ptr<const i2p::data::RouterInfo> prevHop, bool reverse) const
	{
		auto hop = IsExploratory () ? i2p::data::netdb.GetRandomRouter (prevHop, reverse):
			i2p::data::netdb.GetHighBandwidthRandomRouter (prevHop, reverse);

		if (!hop || hop->GetProfile ()->IsBad ())
			hop = i2p::data::netdb.GetRandomRouter (prevHop, reverse);
		return hop;
	}

	bool StandardSelectPeers(Path & path, int numHops, bool inbound, SelectHopFunc nextHop)
	{
		int start = 0;
		std::shared_ptr<const i2p::data::RouterInfo> prevHop = i2p::context.GetSharedRouterInfo ();
		if(i2p::transport::transports.RoutesRestricted())
		{
			/** if routes are restricted prepend trusted first hop */
			auto hop = i2p::transport::transports.GetRestrictedPeer();
			if(!hop) return false;
			path.Add (hop);
			prevHop = hop;
			start++;
		}
		else if (i2p::transport::transports.GetNumPeers () > 100 ||
			(inbound && i2p::transport::transports.GetNumPeers () > 25))
		{
			auto r = i2p::transport::transports.GetRandomPeer ();
			if (r && r->IsECIES () && !r->GetProfile ()->IsBad () &&
				(numHops > 1 || (r->IsV4 () && (!inbound || r->IsReachable ())))) // first inbound must be reachable
			{
				prevHop = r;
				path.Add (r);
				start++;
			}
		}

		for(int i = start; i < numHops; i++ )
		{
			auto hop = nextHop (prevHop, inbound);
			if (!hop && !i) // if no suitable peer found for first hop, try already connected
			{
				LogPrint (eLogInfo, "Tunnels: Can't select first hop for a tunnel. Trying already connected");
				hop = i2p::transport::transports.GetRandomPeer ();
				if (hop && !hop->IsECIES ()) hop = nullptr;
			}
			if (!hop)
			{
				LogPrint (eLogError, "Tunnels: Can't select next hop for ", prevHop->GetIdentHashBase64 ());
				return false;
			}
			if ((i == numHops - 1) && (!hop->IsV4 () || // doesn't support ipv4
				(inbound && !hop->IsReachable ()))) // IBGW is not reachable
			{
				auto hop1 = nextHop (prevHop, true);
				if (hop1) hop = hop1;
			}
			prevHop = hop;
			path.Add (hop);
		}
		path.farEndTransports = prevHop->GetCompatibleTransports (inbound); // last hop
		return true;
	}

	bool TunnelPool::SelectPeers (Path& path, bool isInbound)
	{
		// explicit peers in use
		if (m_ExplicitPeers) return SelectExplicitPeers (path, isInbound);
		// calculate num hops
		int numHops;
		if (isInbound)
		{
			numHops = m_NumInboundHops;
			if (m_InboundVariance)
			{
				int offset = rand () % (std::abs (m_InboundVariance) + 1);
				if (m_InboundVariance < 0) offset = -offset;
				numHops += offset;
			}
		}
		else
		{
			numHops = m_NumOutboundHops;
			if (m_OutboundVariance)
			{
				int offset = rand () % (std::abs (m_OutboundVariance) + 1);
				if (m_OutboundVariance < 0) offset = -offset;
				numHops += offset;
			}
		}
		// peers is empty
		if (numHops <= 0) return true;
		// custom peer selector in use ?
		{
			std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
			if (m_CustomPeerSelector)
				return m_CustomPeerSelector->SelectPeers(path, numHops, isInbound);
		}
		return StandardSelectPeers(path, numHops, isInbound, std::bind(&TunnelPool::SelectNextHop, this, std::placeholders::_1, std::placeholders::_2));
	}

	bool TunnelPool::SelectExplicitPeers (Path& path, bool isInbound)
	{
		int numHops = isInbound ? m_NumInboundHops : m_NumOutboundHops;
		if (numHops > (int)m_ExplicitPeers->size ()) numHops = m_ExplicitPeers->size ();
		if (!numHops) return false;
		for (int i = 0; i < numHops; i++)
		{
			auto& ident = (*m_ExplicitPeers)[i];
			auto r = i2p::data::netdb.FindRouter (ident);
			if (r)
			{
				if (r->IsECIES ())
				{
					path.Add (r);
					if (i == numHops - 1)
						path.farEndTransports = r->GetCompatibleTransports (isInbound);
				}
				else
				{
					LogPrint (eLogError, "Tunnels: ElGamal router ", ident.ToBase64 (), " is not supported");
					return false;
				}
			}
			else
			{
				LogPrint (eLogInfo, "Tunnels: Can't find router for ", ident.ToBase64 ());
				i2p::data::netdb.RequestDestination (ident);
				return false;
			}
		}
		return true;
	}

	void TunnelPool::CreateInboundTunnel ()
	{
		LogPrint (eLogDebug, "Tunnels: Creating destination inbound tunnel...");
		Path path;
		if (SelectPeers (path, true))
		{
			auto outboundTunnel = GetNextOutboundTunnel (nullptr, path.farEndTransports);
			if (!outboundTunnel)
				outboundTunnel = tunnels.GetNextOutboundTunnel ();
			std::shared_ptr<TunnelConfig> config;
			if (m_NumInboundHops > 0)
			{
				path.Reverse ();
				config = std::make_shared<TunnelConfig> (path.peers, path.isShort, path.farEndTransports);
			}
			auto tunnel = tunnels.CreateInboundTunnel (config, shared_from_this (), outboundTunnel);
			if (tunnel->IsEstablished ()) // zero hops
				TunnelCreated (tunnel);
		}
		else
			LogPrint (eLogError, "Tunnels: Can't create inbound tunnel, no peers available");
	}

	void TunnelPool::RecreateInboundTunnel (std::shared_ptr<InboundTunnel> tunnel)
	{
		if (IsExploratory () || tunnel->IsSlow ()) // always create new exploratory tunnel or if slow
		{
			CreateInboundTunnel ();
			return;
		}
		auto outboundTunnel = GetNextOutboundTunnel (nullptr, tunnel->GetFarEndTransports ());
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint (eLogDebug, "Tunnels: Re-creating destination inbound tunnel...");
		std::shared_ptr<TunnelConfig> config;
		if (m_NumInboundHops > 0 && tunnel->GetPeers().size())
			config = std::make_shared<TunnelConfig>(tunnel->GetPeers (), tunnel->IsShortBuildMessage (), tunnel->GetFarEndTransports ());
		if (!m_NumInboundHops || config)
		{
			auto newTunnel = tunnels.CreateInboundTunnel (config, shared_from_this(), outboundTunnel);
			if (newTunnel->IsEstablished ()) // zero hops
				TunnelCreated (newTunnel);
			else
				newTunnel->SetRecreated (true);
		}
	}

	void TunnelPool::CreateOutboundTunnel ()
	{
		LogPrint (eLogDebug, "Tunnels: Creating destination outbound tunnel...");
		Path path;
		if (SelectPeers (path, false))
		{
			auto inboundTunnel = GetNextInboundTunnel (nullptr, path.farEndTransports);
			if (!inboundTunnel)
				inboundTunnel = tunnels.GetNextInboundTunnel ();
			if (!inboundTunnel)
			{
				LogPrint (eLogError, "Tunnels: Can't create outbound tunnel, no inbound tunnels found");
				return;
			}

			if (m_LocalDestination && !m_LocalDestination->SupportsEncryptionType (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD))
				path.isShort = false; // because can't handle ECIES encrypted reply

			std::shared_ptr<TunnelConfig> config;
			if (m_NumOutboundHops > 0)
				config = std::make_shared<TunnelConfig>(path.peers, inboundTunnel->GetNextTunnelID (),
					inboundTunnel->GetNextIdentHash (), path.isShort, path.farEndTransports);

			std::shared_ptr<OutboundTunnel> tunnel;
			if (path.isShort)
			{
				// TODO: implement it better
				tunnel = tunnels.CreateOutboundTunnel (config, inboundTunnel->GetTunnelPool ());
				tunnel->SetTunnelPool (shared_from_this ());
			}
			else
				tunnel = tunnels.CreateOutboundTunnel (config, shared_from_this ());
			if (tunnel && tunnel->IsEstablished ()) // zero hops
				TunnelCreated (tunnel);
		}
		else
			LogPrint (eLogError, "Tunnels: Can't create outbound tunnel, no peers available");
	}

	void TunnelPool::RecreateOutboundTunnel (std::shared_ptr<OutboundTunnel> tunnel)
	{
		if (IsExploratory () || tunnel->IsSlow ()) // always create new exploratory tunnel or if slow
		{
			CreateOutboundTunnel ();
			return;
		}
		auto inboundTunnel = GetNextInboundTunnel (nullptr, tunnel->GetFarEndTransports ());
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{
			LogPrint (eLogDebug, "Tunnels: Re-creating destination outbound tunnel...");
			std::shared_ptr<TunnelConfig> config;
			if (m_NumOutboundHops > 0 && tunnel->GetPeers().size())
			{
				config = std::make_shared<TunnelConfig>(tunnel->GetPeers (), inboundTunnel->GetNextTunnelID (),
					inboundTunnel->GetNextIdentHash (), inboundTunnel->IsShortBuildMessage (), tunnel->GetFarEndTransports ());
			}
			if (!m_NumOutboundHops || config)
			{
				auto newTunnel = tunnels.CreateOutboundTunnel (config, shared_from_this ());
				if (newTunnel->IsEstablished ()) // zero hops
					TunnelCreated (newTunnel);
			}
		}
		else
			LogPrint (eLogDebug, "Tunnels: Can't re-create outbound tunnel, no inbound tunnels found");
	}

	void TunnelPool::CreatePairedInboundTunnel (std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		LogPrint (eLogDebug, "Tunnels: Creating paired inbound tunnel...");
		auto tunnel = tunnels.CreateInboundTunnel (
			m_NumOutboundHops > 0 ? std::make_shared<TunnelConfig>(outboundTunnel->GetInvertedPeers (),
				outboundTunnel->IsShortBuildMessage ()) : nullptr,
				shared_from_this (), outboundTunnel);
		if (tunnel->IsEstablished ()) // zero hops
			TunnelCreated (tunnel);
	}

	void TunnelPool::SetCustomPeerSelector(ITunnelPeerSelector * selector)
	{
		std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
		m_CustomPeerSelector = selector;
	}

	void TunnelPool::UnsetCustomPeerSelector()
	{
		SetCustomPeerSelector(nullptr);
	}

	bool TunnelPool::HasCustomPeerSelector()
	{
		std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
		return m_CustomPeerSelector != nullptr;
	}

	std::shared_ptr<InboundTunnel> TunnelPool::GetLowestLatencyInboundTunnel(std::shared_ptr<InboundTunnel> exclude) const
	{
		std::shared_ptr<InboundTunnel> tun = nullptr;
		std::unique_lock<std::mutex> lock(m_InboundTunnelsMutex);
		uint64_t min = 1000000;
		for (const auto & itr : m_InboundTunnels) {
			if(!itr->LatencyIsKnown()) continue;
			auto l = itr->GetMeanLatency();
			if (l >= min) continue;
			tun = itr;
			if(tun == exclude) continue;
			min = l;
		}
		return tun;
	}

	std::shared_ptr<OutboundTunnel> TunnelPool::GetLowestLatencyOutboundTunnel(std::shared_ptr<OutboundTunnel> exclude) const
	{
		std::shared_ptr<OutboundTunnel> tun = nullptr;
		std::unique_lock<std::mutex> lock(m_OutboundTunnelsMutex);
		uint64_t min = 1000000;
		for (const auto & itr : m_OutboundTunnels) {
			if(!itr->LatencyIsKnown()) continue;
			auto l = itr->GetMeanLatency();
			if (l >= min) continue;
			tun = itr;
			if(tun == exclude) continue;
			min = l;
		}
		return tun;
	}
}
}
