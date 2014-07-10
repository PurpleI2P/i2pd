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
	}

	void TunnelPool::TunnelExpired (InboundTunnel * expiredTunnel)
	{
		if (expiredTunnel)
		{	
			expiredTunnel->SetTunnelPool (nullptr);
			m_InboundTunnels.erase (expiredTunnel);
			for (auto it: m_Tests)
				if (it.second.second == expiredTunnel) it.second.second = nullptr;
				
		}	
		m_LocalDestination.UpdateLeaseSet ();
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
		}
	}
		
	std::vector<InboundTunnel *> TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<InboundTunnel *> v;
		int i = 0;
		for (auto it : m_InboundTunnels)
		{
			if (i >= num) break;
			if (!it->IsFailed ())
			{
				v.push_back (it);
				i++;
			}	
		}	
		return v;
	}

	OutboundTunnel * TunnelPool::GetNextOutboundTunnel () 
	{
		return GetNextTunnel (m_OutboundTunnels);
	}	

	InboundTunnel * TunnelPool::GetNextInboundTunnel ()
	{
		return GetNextTunnel (m_InboundTunnels);
	}

	template<class TTunnels>
	typename TTunnels::value_type TunnelPool::GetNextTunnel (TTunnels& tunnels)
	{
		if (tunnels.empty ()) return nullptr;
		for (auto it: tunnels)
			if (!it->IsFailed ())
				return it;
		return nullptr;
	}

	void TunnelPool::CreateTunnels ()
	{
		int num = m_InboundTunnels.size ();
		for (int i = num; i < m_NumTunnels; i++)
			CreateInboundTunnel ();	
		num = m_OutboundTunnels.size ();
		for (int i = num; i < m_NumTunnels; i++)
			CreateOutboundTunnel ();	
	}

	void TunnelPool::TestTunnels ()
	{
		auto& rnd = i2p::context.GetRandomNumberGenerator ();
		for (auto it: m_Tests)
		{
			LogPrint ("Tunnel test ", (int)it.first, " failed"); 
			// both outbound and inbound tunnels considered as invalid
			if (it.second.first)
			{	
				it.second.first->SetFailed (true);
				m_OutboundTunnels.erase (it.second.first);
			}	
			if (it.second.second)
			{
				it.second.second->SetFailed (true);
				m_InboundTunnels.erase (it.second.second);
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
			LogPrint ("Tunnel test ", it->first, " successive. ", i2p::util::GetMillisecondsSinceEpoch () - be64toh (deliveryStatus->timestamp), " milliseconds");
			m_Tests.erase (it);
		}
		else
			i2p::garlic::routing.HandleDeliveryStatusMessage (msg->GetPayload (), msg->GetLength ()); // TODO:
		DeleteI2NPMessage (msg);
	}

	void TunnelPool::CreateInboundTunnel ()
	{
		OutboundTunnel * outboundTunnel = m_OutboundTunnels.size () > 0 ? 
			*m_OutboundTunnels.begin () : tunnels.GetNextOutboundTunnel ();
		LogPrint ("Creating destination inbound tunnel...");
		auto firstHop = i2p::data::netdb.GetRandomRouter (outboundTunnel ? outboundTunnel->GetEndpointRouter () : nullptr); 
		auto secondHop = outboundTunnel ? outboundTunnel->GetTunnelConfig ()->GetFirstHop ()->router : nullptr;
		if (!secondHop || secondHop->GetIdentHash () == i2p::context.GetIdentHash ())
			secondHop = i2p::data::netdb.GetRandomRouter (firstHop);	
		auto * tunnel = tunnels.CreateTunnel<InboundTunnel> (
			new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
				{                
			        firstHop, 
					secondHop
	            }),                 
			outboundTunnel);
		tunnel->SetTunnelPool (this);
	}

	void TunnelPool::CreateOutboundTunnel ()
	{
		InboundTunnel * inboundTunnel = m_InboundTunnels.size () > 0 ? 
			*m_InboundTunnels.begin () : tunnels.GetNextInboundTunnel ();
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
}
}
