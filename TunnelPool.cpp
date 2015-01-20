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
	TunnelPool::TunnelPool (i2p::garlic::GarlicDestination * localDestination, int numInboundHops, int numOutboundHops, int numTunnels):
		m_LocalDestination (localDestination), m_NumInboundHops (numInboundHops), m_NumOutboundHops (numOutboundHops),
		m_NumTunnels (numTunnels), m_IsActive (true)
	{
	}

	TunnelPool::~TunnelPool ()
	{
		DetachTunnels ();
	}

	void TunnelPool::DetachTunnels ()
	{
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);	
			for (auto it: m_InboundTunnels)
				it->SetTunnelPool (nullptr);
			m_InboundTunnels.clear ();
		}
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (auto it: m_OutboundTunnels)
				it->SetTunnelPool (nullptr);
			m_OutboundTunnels.clear ();
		}
		m_Tests.clear ();
	}	
		
	void TunnelPool::TunnelCreated (InboundTunnel * createdTunnel)
	{
		if (!m_IsActive) return;
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			m_InboundTunnels.insert (createdTunnel);
		}
		if (m_LocalDestination)
			m_LocalDestination->SetLeaseSetUpdated ();
	}

	void TunnelPool::TunnelExpired (InboundTunnel * expiredTunnel)
	{
		if (expiredTunnel)
		{	
			expiredTunnel->SetTunnelPool (nullptr);
			for (auto it: m_Tests)
				if (it.second.second == expiredTunnel) it.second.second = nullptr;
			RecreateInboundTunnel (expiredTunnel);	

			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			m_InboundTunnels.erase (expiredTunnel);
		}	
	}	

	void TunnelPool::TunnelCreated (OutboundTunnel * createdTunnel)
	{
		if (!m_IsActive) return;
		std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
		m_OutboundTunnels.insert (createdTunnel);
	}

	void TunnelPool::TunnelExpired (OutboundTunnel * expiredTunnel)
	{
		if (expiredTunnel)
		{
			expiredTunnel->SetTunnelPool (nullptr);
			for (auto it: m_Tests)
				if (it.second.first == expiredTunnel) it.second.first = nullptr;
			RecreateOutboundTunnel (expiredTunnel);

			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			m_OutboundTunnels.erase (expiredTunnel);
		}
	}
		
	std::vector<InboundTunnel *> TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<InboundTunnel *> v;
		int i = 0;
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
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

	OutboundTunnel * TunnelPool::GetNextOutboundTunnel (OutboundTunnel * suggested) const
	{
		std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);	
		return GetNextTunnel (m_OutboundTunnels, suggested);
	}	

	InboundTunnel * TunnelPool::GetNextInboundTunnel (InboundTunnel * suggested) const
	{
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);	
		return GetNextTunnel (m_InboundTunnels, suggested);
	}

	template<class TTunnels>
	typename TTunnels::value_type TunnelPool::GetNextTunnel (TTunnels& tunnels, 
		typename TTunnels::value_type suggested) const
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
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (auto it : m_InboundTunnels)
				if (it->IsEstablished ()) num++;
		}
		for (int i = num; i < m_NumTunnels; i++)
			CreateInboundTunnel ();	
		
		num = 0;
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);	
			for (auto it : m_OutboundTunnels)
				if (it->IsEstablished ()) num++;
		}
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
		m_Tests.clear ();
		// new tests	
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

	void TunnelPool::ProcessGarlicMessage (I2NPMessage * msg)
	{
		if (m_LocalDestination)
			m_LocalDestination->ProcessGarlicMessage (msg);
		else
		{
			LogPrint (eLogWarning, "Local destination doesn't exist. Dropped");
			DeleteI2NPMessage (msg);
		}	
	}	
		
	void TunnelPool::ProcessDeliveryStatus (I2NPMessage * msg)
	{
		const uint8_t * buf = msg->GetPayload ();
		uint32_t msgID = bufbe32toh (buf);
		buf += 4;	
		uint64_t timestamp = bufbe64toh (buf);

		auto it = m_Tests.find (msgID);
		if (it != m_Tests.end ())
		{
			// restore from test failed state if any
			if (it->second.first->GetState () == eTunnelStateTestFailed)
				it->second.first->SetState (eTunnelStateEstablished);
			if (it->second.second->GetState () == eTunnelStateTestFailed)
				it->second.second->SetState (eTunnelStateEstablished);
			LogPrint ("Tunnel test ", it->first, " successive. ", i2p::util::GetMillisecondsSinceEpoch () - timestamp, " milliseconds");
			m_Tests.erase (it);
			DeleteI2NPMessage (msg);
		}
		else
		{
			if (m_LocalDestination)
				m_LocalDestination->ProcessDeliveryStatusMessage (msg);
			else
			{	
				LogPrint (eLogWarning, "Local destination doesn't exist. Dropped");
				DeleteI2NPMessage (msg);
			}	
		}	
	}

	std::shared_ptr<const i2p::data::RouterInfo> TunnelPool::SelectNextHop (std::shared_ptr<const i2p::data::RouterInfo> prevHop) const
	{
		bool isExploratory = (m_LocalDestination == &i2p::context); // TODO: implement it better
		auto hop =  isExploratory ? i2p::data::netdb.GetRandomRouter (prevHop): 
			i2p::data::netdb.GetHighBandwidthRandomRouter (prevHop);
			
		if (!hop)
			hop = i2p::data::netdb.GetRandomRouter ();
		return hop;	
	}	
		
	void TunnelPool::CreateInboundTunnel ()
	{
		OutboundTunnel * outboundTunnel = GetNextOutboundTunnel ();
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint ("Creating destination inbound tunnel...");
		auto prevHop = i2p::context.GetSharedRouterInfo ();	
		std::vector<std::shared_ptr<const i2p::data::RouterInfo> > hops;
		int numHops = m_NumInboundHops;
		if (outboundTunnel)
		{	
			// last hop
			auto hop = outboundTunnel->GetTunnelConfig ()->GetFirstHop ()->router;
			if (hop->GetIdentHash () != i2p::context.GetIdentHash ()) // outbound shouldn't be zero-hop tunnel
			{	
				prevHop = hop;
				hops.push_back (prevHop);
				numHops--;
			}
		}
		for (int i = 0; i < numHops; i++)
		{
			auto hop = SelectNextHop (prevHop);
			prevHop = hop;
			hops.push_back (hop);
		}		
		std::reverse (hops.begin (), hops.end ());	
		auto * tunnel = tunnels.CreateTunnel<InboundTunnel> (new TunnelConfig (hops), outboundTunnel);
		tunnel->SetTunnelPool (shared_from_this ());
	}

	void TunnelPool::RecreateInboundTunnel (InboundTunnel * tunnel)
	{
		OutboundTunnel * outboundTunnel = GetNextOutboundTunnel ();
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint ("Re-creating destination inbound tunnel...");
		auto * newTunnel = tunnels.CreateTunnel<InboundTunnel> (tunnel->GetTunnelConfig ()->Clone (), outboundTunnel);
		newTunnel->SetTunnelPool (shared_from_this());
	}	
		
	void TunnelPool::CreateOutboundTunnel ()
	{
		InboundTunnel * inboundTunnel = GetNextInboundTunnel ();
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{	
			LogPrint ("Creating destination outbound tunnel...");

			auto prevHop = i2p::context.GetSharedRouterInfo ();
			std::vector<std::shared_ptr<const i2p::data::RouterInfo> > hops;
			for (int i = 0; i < m_NumOutboundHops; i++)
			{
				auto hop = SelectNextHop (prevHop);
				prevHop = hop;
				hops.push_back (hop);
			}	
				
			auto * tunnel = tunnels.CreateTunnel<OutboundTunnel> (
				new TunnelConfig (hops, inboundTunnel->GetTunnelConfig ()));
			tunnel->SetTunnelPool (shared_from_this ());
		}	
		else
			LogPrint ("Can't create outbound tunnel. No inbound tunnels found");
	}	
		
	void TunnelPool::RecreateOutboundTunnel (OutboundTunnel * tunnel)
	{
		InboundTunnel * inboundTunnel = GetNextInboundTunnel ();
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{	
			LogPrint ("Re-creating destination outbound tunnel...");
			auto * newTunnel = tunnels.CreateTunnel<OutboundTunnel> (
				tunnel->GetTunnelConfig ()->Clone (inboundTunnel->GetTunnelConfig ()));
			newTunnel->SetTunnelPool (shared_from_this ());
		}	
		else
			LogPrint ("Can't re-create outbound tunnel. No inbound tunnels found");
	}			
}
}
