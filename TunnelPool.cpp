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
		auto * tunnel = tunnels.CreateTunnel<InboundTunnel> (
			new TunnelConfig (std::vector<const i2p::data::RouterInfo *>
				{                
			        firstHop, 
					i2p::data::netdb.GetRandomRouter (firstHop) 
	            }),                 
			outboundTunnel);
		tunnel->SetTunnelPool (this);
	}

	void TunnelPool::ManageTunnels ()
	{
		uint64_t ts = i2p::util::GetSecondsSinceEpoch ();
		bool isLeaseSetUpdated = false;
		for (auto it = m_InboundTunnels.begin (); it != m_InboundTunnels.end ();)
		{
			if (ts > (*it)->GetCreationTime () + TUNNEL_EXPIRATION_TIMEOUT)
			{
				LogPrint ("Destination tunnel ", (*it)->GetTunnelID (), " expired");
				m_InboundTunnels.erase (it++);
				isLeaseSetUpdated = true;
			}	
			else 
				++it;
		}
		CreateTunnels ();
		if (isLeaseSetUpdated && m_Owner)
			m_Owner->UpdateLeaseSet ();
	}	
}
}
