#include "Tunnel.h"
#include "NetDb.h"
#include "Timestamp.h"
#include "TunnelPool.h"

namespace i2p
{
namespace tunnel
{
	TunnelPool::TunnelPool (i2p::data::LocalDestination * owner, int numTunnels):
		m_Owner (owner), m_NumTunnels (numTunnels)
	{
	}

	TunnelPool::~TunnelPool ()
	{
		for (auto it: m_InboundTunnels)
			it->SetTunnelPool (nullptr);
	}

	void TunnelPool::TunnelCreated (InboundTunnel * createdTunnel)
	{
		m_InboundTunnels.insert (createdTunnel);
	}

	void TunnelPool::TunnelExpired (InboundTunnel * expiredTunnel)
	{
		m_InboundTunnels.erase (expiredTunnel);
		if (m_Owner)
			m_Owner->UpdateLeaseSet ();
	}	
		
	std::vector<InboundTunnel *> TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<InboundTunnel *> v;
		int i = 0;
		for (auto it : m_InboundTunnels)
		{
			if (i >= num) break;
			v.push_back (it);
			i++;	
		}	
		return v;
	}

	void TunnelPool::CreateTunnels ()
	{
		int num = m_InboundTunnels.size ();
		for (int i = num; i < m_NumTunnels; i++)
			CreateInboundTunnel ();	
	}

	void TunnelPool::CreateInboundTunnel ()
	{
		OutboundTunnel * outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint ("Creating destination inbound tunnel...");
		auto firstHop = i2p::data::netdb.GetRandomRouter (outboundTunnel ? outboundTunnel->GetEndpointRouter () : nullptr); 
		auto secondHop = i2p::data::netdb.GetRandomRouter (firstHop);	
		auto * tunnel = tunnels.CreateTunnel<InboundTunnel> (
			new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
				{                
			        firstHop, 
					secondHop,
					i2p::data::netdb.GetRandomRouter (secondHop) 
	            }),                 
			outboundTunnel);
		tunnel->SetTunnelPool (this);
	}
}
}
