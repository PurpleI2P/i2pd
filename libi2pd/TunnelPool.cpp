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

	TunnelPool::TunnelPool (int numInboundHops, int numOutboundHops, int numInboundTunnels, int numOutboundTunnels):
		m_NumInboundHops (numInboundHops), m_NumOutboundHops (numOutboundHops),
		m_NumInboundTunnels (numInboundTunnels), m_NumOutboundTunnels (numOutboundTunnels), m_IsActive (true),
		m_CustomPeerSelector(nullptr)
	{
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

	bool TunnelPool::Reconfigure(int inHops, int outHops, int inQuant, int outQuant)	{
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
		//CreatePairedInboundTunnel (createdTunnel);
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
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		for (const auto& it : m_InboundTunnels)
		{
			if (i >= num) break;
			if (it->IsEstablished ())
			{
				v.push_back (it);
				i++;
			}
		}
		return v;
	}

	std::shared_ptr<OutboundTunnel> TunnelPool::GetNextOutboundTunnel (std::shared_ptr<OutboundTunnel> excluded) const
	{
		std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
		return GetNextTunnel (m_OutboundTunnels, excluded);
	}

	std::shared_ptr<InboundTunnel> TunnelPool::GetNextInboundTunnel (std::shared_ptr<InboundTunnel> excluded) const
	{
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		return GetNextTunnel (m_InboundTunnels, excluded);
	}

	template<class TTunnels>
	typename TTunnels::value_type TunnelPool::GetNextTunnel (TTunnels& tunnels, typename TTunnels::value_type excluded) const
	{
		if (tunnels.empty ()) return nullptr;
		uint32_t ind = rand () % (tunnels.size ()/2 + 1), i = 0;
		typename TTunnels::value_type tunnel = nullptr;
		for (const auto& it: tunnels)
		{
			if (it->IsEstablished () && it != excluded)
			{
				if(HasLatencyRequirement() && it->LatencyIsKnown() && !it->LatencyFitsRange(m_MinLatency, m_MaxLatency)) {
					i ++;
					continue;
				}
				tunnel = it;
				i++;
			}
			if (i > ind && tunnel) break;
		}
		if(HasLatencyRequirement() && !tunnel) {
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
			LogPrint (eLogWarning, "Tunnels: test of tunnel ", it.first, " failed");
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
		auto it1 = m_OutboundTunnels.begin ();
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

	void TunnelPool::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_LocalDestination)
			m_LocalDestination->ProcessGarlicMessage (msg);
		else
			LogPrint (eLogWarning, "Tunnels: local destination doesn't exist, dropped");
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
			// restore from test failed state if any
			if (test.first->GetState () == eTunnelStateTestFailed)
				test.first->SetState (eTunnelStateEstablished);
			if (test.second->GetState () == eTunnelStateTestFailed)
				test.second->SetState (eTunnelStateEstablished);
			uint64_t dlt = i2p::util::GetMillisecondsSinceEpoch () - timestamp;
			LogPrint (eLogDebug, "Tunnels: test of ", msgID, " successful. ", dlt, " milliseconds");
			// update latency
			uint64_t latency = dlt / 2;
			test.first->AddLatencySample(latency);
			test.second->AddLatencySample(latency);
		}
		else
		{
			if (m_LocalDestination)
				m_LocalDestination->ProcessDeliveryStatusMessage (msg);
			else
				LogPrint (eLogWarning, "Tunnels: Local destination doesn't exist, dropped");
		}
	}

	std::shared_ptr<const i2p::data::RouterInfo> TunnelPool::SelectNextHop (std::shared_ptr<const i2p::data::RouterInfo> prevHop) const
	{
		bool isExploratory = (i2p::tunnel::tunnels.GetExploratoryPool () == shared_from_this ());
		auto hop = isExploratory ? i2p::data::netdb.GetRandomRouter (prevHop):
			i2p::data::netdb.GetHighBandwidthRandomRouter (prevHop);

		if (!hop || hop->GetProfile ()->IsBad ())
			hop = i2p::data::netdb.GetRandomRouter (prevHop);
		return hop;
	}

	bool StandardSelectPeers(Path & peers, int numHops, bool inbound, SelectHopFunc nextHop)
	{
		auto prevHop = i2p::context.GetSharedRouterInfo ();
		if(i2p::transport::transports.RoutesRestricted())
		{
			/** if routes are restricted prepend trusted first hop */
			auto hop = i2p::transport::transports.GetRestrictedPeer();
			if(!hop) return false;
			peers.push_back(hop->GetRouterIdentity());
			prevHop = hop;
		}
		else if (i2p::transport::transports.GetNumPeers () > 25)
		{
			auto r = i2p::transport::transports.GetRandomPeer ();
			if (r && !r->GetProfile ()->IsBad ())
			{
				prevHop = r;
				peers.push_back (r->GetRouterIdentity ());
				numHops--;
			}
		}

		for(int i = 0; i < numHops; i++ )
		{
			auto hop = nextHop (prevHop);
			if (!hop)
			{
				LogPrint (eLogError, "Tunnels: Can't select next hop for ", prevHop->GetIdentHashBase64 ());
				return false;
			}
			prevHop = hop;
			peers.push_back (hop->GetRouterIdentity ());
		}
		return true;
	}

	bool TunnelPool::SelectPeers (std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers, bool isInbound)
	{
		int numHops = isInbound ? m_NumInboundHops : m_NumOutboundHops;
		// peers is empty
		if (numHops <= 0) return true;
		// custom peer selector in use ?
		{
			std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
			if (m_CustomPeerSelector)
					return m_CustomPeerSelector->SelectPeers(peers, numHops, isInbound);
		}
		// explicit peers in use
		if (m_ExplicitPeers) return SelectExplicitPeers (peers, isInbound);
		return StandardSelectPeers(peers, numHops, isInbound, std::bind(&TunnelPool::SelectNextHop, this, std::placeholders::_1));
	}

	bool TunnelPool::SelectExplicitPeers (std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers, bool isInbound)
	{
		int size = m_ExplicitPeers->size ();
		std::vector<int> peerIndicies;
		for (int i = 0; i < size; i++) peerIndicies.push_back(i);
		std::shuffle (peerIndicies.begin(), peerIndicies.end(), std::mt19937(std::random_device()()));

		int numHops = isInbound ? m_NumInboundHops : m_NumOutboundHops;
		for (int i = 0; i < numHops; i++)
		{
			auto& ident = (*m_ExplicitPeers)[peerIndicies[i]];
			auto r = i2p::data::netdb.FindRouter (ident);
			if (r)
				peers.push_back (r->GetRouterIdentity ());
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
		auto outboundTunnel = GetNextOutboundTunnel ();
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint (eLogDebug, "Tunnels: Creating destination inbound tunnel...");
		std::vector<std::shared_ptr<const i2p::data::IdentityEx> > peers;
		if (SelectPeers (peers, true))
		{
			std::shared_ptr<TunnelConfig> config;
			if (m_NumInboundHops > 0)
			{
				std::reverse (peers.begin (), peers.end ());
				config = std::make_shared<TunnelConfig> (peers);
			}
			auto tunnel = tunnels.CreateInboundTunnel (config, outboundTunnel);
			tunnel->SetTunnelPool (shared_from_this ());
			if (tunnel->IsEstablished ()) // zero hops
				TunnelCreated (tunnel);
		}
		else
			LogPrint (eLogError, "Tunnels: Can't create inbound tunnel, no peers available");
	}

	void TunnelPool::RecreateInboundTunnel (std::shared_ptr<InboundTunnel> tunnel)
	{
		auto outboundTunnel = GetNextOutboundTunnel ();
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint (eLogDebug, "Tunnels: Re-creating destination inbound tunnel...");
		std::shared_ptr<TunnelConfig> config;
		if (m_NumInboundHops > 0 && tunnel->GetPeers().size())
		{
			config = std::make_shared<TunnelConfig>(tunnel->GetPeers ());
		}
		if (m_NumInboundHops == 0 || config)
		{
			auto newTunnel = tunnels.CreateInboundTunnel (config, outboundTunnel);
			newTunnel->SetTunnelPool (shared_from_this());
			if (newTunnel->IsEstablished ()) // zero hops
				TunnelCreated (newTunnel);
		}
	}

	void TunnelPool::CreateOutboundTunnel ()
	{
		auto inboundTunnel = GetNextInboundTunnel ();
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{
			LogPrint (eLogDebug, "Tunnels: Creating destination outbound tunnel...");
			std::vector<std::shared_ptr<const i2p::data::IdentityEx> > peers;
			if (SelectPeers (peers, false))
			{
				std::shared_ptr<TunnelConfig> config;
				if (m_NumOutboundHops > 0)
					config = std::make_shared<TunnelConfig>(peers, inboundTunnel->GetNextTunnelID (), inboundTunnel->GetNextIdentHash ());
				auto tunnel = tunnels.CreateOutboundTunnel (config);
				tunnel->SetTunnelPool (shared_from_this ());
				if (tunnel->IsEstablished ()) // zero hops
					TunnelCreated (tunnel);
			}
			else
				LogPrint (eLogError, "Tunnels: Can't create outbound tunnel, no peers available");
		}
		else
			LogPrint (eLogError, "Tunnels: Can't create outbound tunnel, no inbound tunnels found");
	}

	void TunnelPool::RecreateOutboundTunnel (std::shared_ptr<OutboundTunnel> tunnel)
	{
		auto inboundTunnel = GetNextInboundTunnel ();
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{
			LogPrint (eLogDebug, "Tunnels: Re-creating destination outbound tunnel...");
			std::shared_ptr<TunnelConfig> config;
			if (m_NumOutboundHops > 0 && tunnel->GetPeers().size())
			{
				config = std::make_shared<TunnelConfig>(tunnel->GetPeers (), inboundTunnel->GetNextTunnelID (), inboundTunnel->GetNextIdentHash ());
			}
			if(m_NumOutboundHops == 0 || config)
			{
				auto newTunnel = tunnels.CreateOutboundTunnel (config);
				newTunnel->SetTunnelPool (shared_from_this ());
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
		auto tunnel = tunnels.CreateInboundTunnel (std::make_shared<TunnelConfig>(outboundTunnel->GetInvertedPeers ()), outboundTunnel);
		tunnel->SetTunnelPool (shared_from_this ());
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
