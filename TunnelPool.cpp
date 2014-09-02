#include "I2PEndian.h"
#include "CryptoConst.h"
#include "Tunnel.h"
#include "NetDb.h"
#include "Timestamp.h"
#include "Garlic.h"
#include "TunnelPool.h"

namespace i2p
{
namespace tunnel
{
	TunnelPool::TunnelPool (i2p::data::LocalDestination& localDestination, int numHops, int numTunnels):
		m_LocalDestination (localDestination), m_NumHops (numHops), m_NumTunnels (numTunnels)
	{
	}

	TunnelPool::~TunnelPool ()
	{
		for (auto it: m_InboundTunnels)
			it->SetTunnelPool (nullptr);
		for (auto it: m_OutboundTunnels)
			it->SetTunnelPool (nullptr);
	}

	void TunnelPool::TunnelCreated (InboundTunnel * createdTunnel)
	{
		m_InboundTunnels.insert (createdTunnel);
		m_LocalDestination.SetLeaseSetUpdated ();
	}

	void TunnelPool::TunnelExpired (InboundTunnel * expiredTunnel)
	{
		if (expiredTunnel)
		{	
			expiredTunnel->SetTunnelPool (nullptr);
			m_InboundTunnels.erase (expiredTunnel);
			for (auto it: m_Tests)
				if (it.second.second == expiredTunnel) it.second.second = nullptr;
			RecreateInboundTunnel (expiredTunnel);	
		}	
	}	

	void TunnelPool::TunnelCreated (OutboundTunnel * createdTunnel)
	{
		m_OutboundTunnels.insert (createdTunnel);
	}

	void TunnelPool::TunnelExpired (OutboundTunnel * expiredTunnel)
	{
		if (expiredTunnel)
		{
			expiredTunnel->SetTunnelPool (nullptr);
			m_OutboundTunnels.erase (expiredTunnel);
			for (auto it: m_Tests)
				if (it.second.first == expiredTunnel) it.second.first = nullptr;
			RecreateOutboundTunnel (expiredTunnel);
		}
	}
		
	std::vector<InboundTunnel *> TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<InboundTunnel *> v;
		int i = 0;
		for (auto it : m_InboundTunnels)
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

	OutboundTunnel * TunnelPool::GetNextOutboundTunnel (OutboundTunnel * suggested) 
	{
		return GetNextTunnel (m_OutboundTunnels, suggested);
	}	

	InboundTunnel * TunnelPool::GetNextInboundTunnel (InboundTunnel * suggested)
	{
		return GetNextTunnel (m_InboundTunnels, suggested);
	}

	template<class TTunnels>
	typename TTunnels::value_type TunnelPool::GetNextTunnel (TTunnels& tunnels, 
		typename TTunnels::value_type suggested)
	{
		if (tunnels.empty ()) return nullptr;
		if (suggested && tunnels.count (suggested) > 0 && suggested->IsEstablished ())
				return suggested;
		
		CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
		uint32_t ind = rnd.GenerateWord32 (0, tunnels.size ()/2), i = 0;
		typename TTunnels::value_type tunnel = nullptr;
		for (auto it: tunnels)
		{	
			if (it->IsEstablished ())
			{
				tunnel = it;
				i++;
			}
			if (i > ind && tunnel) break;
		}	
		return tunnel;
	}

	void TunnelPool::CreateTunnels ()
	{
		int num = 0;
		for (auto it : m_InboundTunnels)
			if (it->IsEstablished ()) num++;
		for (int i = num; i < m_NumTunnels; i++)
			CreateInboundTunnel ();	
		
		num = 0;
		for (auto it : m_OutboundTunnels)
			if (it->IsEstablished ()) num++;
		for (int i = num; i < m_NumTunnels; i++)
			CreateOutboundTunnel ();	
	}

	void TunnelPool::TestTunnels ()
	{
		auto& rnd = i2p::context.GetRandomNumberGenerator ();
		for (auto it: m_Tests)
		{
			LogPrint ("Tunnel test ", (int)it.first, " failed"); 
			// if test failed again with another tunnel we consider it failed
			if (it.second.first)
			{	
				if (it.second.first->GetState () == eTunnelStateTestFailed)
				{	
					it.second.first->SetState (eTunnelStateFailed);
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
					m_InboundTunnels.erase (it.second.second);
					m_LocalDestination.SetLeaseSetUpdated ();
				}	
				else
					it.second.second->SetState (eTunnelStateTestFailed);
			}	
		}
		m_Tests.clear ();	
		auto it1 = m_OutboundTunnels.begin ();
		auto it2 = m_InboundTunnels.begin ();
		while (it1 != m_OutboundTunnels.end () && it2 != m_InboundTunnels.end ())
		{
			bool failed = false;
			if ((*it1)->IsFailed ())
			{	
				failed = true;
				it1++;
			}
			if ((*it2)->IsFailed ())
			{	
				failed = true;
				it2++;
			}
			if (!failed)
			{
				uint32_t msgID = rnd.GenerateWord32 ();
				m_Tests[msgID] = std::make_pair (*it1, *it2);
				(*it1)->SendTunnelDataMsg ((*it2)->GetNextIdentHash (), (*it2)->GetNextTunnelID (),
					CreateDeliveryStatusMsg (msgID));
				it1++; it2++;
			}	
		}
	}

	void TunnelPool::ProcessDeliveryStatus (I2NPMessage * msg)
	{
		I2NPDeliveryStatusMsg * deliveryStatus = (I2NPDeliveryStatusMsg *)msg->GetPayload ();
		auto it = m_Tests.find (be32toh (deliveryStatus->msgID));
		if (it != m_Tests.end ())
		{
			// restore from test failed state if any
			if (it->second.first->GetState () == eTunnelStateTestFailed)
				it->second.first->SetState (eTunnelStateEstablished);
			if (it->second.second->GetState () == eTunnelStateTestFailed)
				it->second.second->SetState (eTunnelStateEstablished);
			LogPrint ("Tunnel test ", it->first, " successive. ", i2p::util::GetMillisecondsSinceEpoch () - be64toh (deliveryStatus->timestamp), " milliseconds");
			m_Tests.erase (it);
			DeleteI2NPMessage (msg);
		}
		else
			i2p::garlic::routing.PostI2NPMsg (msg);
	}

	void TunnelPool::CreateInboundTunnel ()
	{
		OutboundTunnel * outboundTunnel = GetNextOutboundTunnel ();
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint ("Creating destination inbound tunnel...");
		const i2p::data::RouterInfo * prevHop = &i2p::context.GetRouterInfo ();	
		std::vector<const i2p::data::RouterInfo *> hops;
		int numHops = m_NumHops;
		if (outboundTunnel)
		{	
			// last hop
			auto hop = outboundTunnel->GetTunnelConfig ()->GetFirstHop ()->router;
			if (hop->GetIdentHash () != i2p::context.GetRouterIdentHash ()) // outbound shouldn't be zero-hop tunnel
			{	
				prevHop = hop;
				hops.push_back (prevHop);
				numHops--;
			}
		}
		for (int i = 0; i < numHops; i++)
		{
			auto hop = i2p::data::netdb.GetRandomRouter (prevHop);
			prevHop = hop;
			hops.push_back (hop);
		}		
		std::reverse (hops.begin (), hops.end ());	
		auto * tunnel = tunnels.CreateTunnel<InboundTunnel> (new TunnelConfig (hops), outboundTunnel);
		tunnel->SetTunnelPool (this);
	}

	void TunnelPool::RecreateInboundTunnel (InboundTunnel * tunnel)
	{
		OutboundTunnel * outboundTunnel = GetNextOutboundTunnel ();
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint ("Re-creating destination inbound tunnel...");
		auto * newTunnel = tunnels.CreateTunnel<InboundTunnel> (tunnel->GetTunnelConfig ()->Clone (), outboundTunnel);
		newTunnel->SetTunnelPool (this);
	}	
		
	void TunnelPool::CreateOutboundTunnel ()
	{
		InboundTunnel * inboundTunnel = GetNextInboundTunnel ();
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{	
			LogPrint ("Creating destination outbound tunnel...");

			const i2p::data::RouterInfo * prevHop = &i2p::context.GetRouterInfo ();
			std::vector<const i2p::data::RouterInfo *> hops;
			for (int i = 0; i < m_NumHops; i++)
			{
				auto hop = i2p::data::netdb.GetRandomRouter (prevHop);
				prevHop = hop;
				hops.push_back (hop);
			}	
				
			auto * tunnel = tunnels.CreateTunnel<OutboundTunnel> (
				new TunnelConfig (hops, inboundTunnel->GetTunnelConfig ()));
			tunnel->SetTunnelPool (this);
		}	
	}	

	void TunnelPool::RecreateOutboundTunnel (OutboundTunnel * tunnel)
	{
		InboundTunnel * inboundTunnel = GetNextInboundTunnel ();
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		LogPrint ("Re-creating destination outbound tunnel...");
		auto * newTunnel = tunnels.CreateTunnel<OutboundTunnel> (
			tunnel->GetTunnelConfig ()->Clone (inboundTunnel->GetTunnelConfig ()));
		newTunnel->SetTunnelPool (this);
	}			
}
}
