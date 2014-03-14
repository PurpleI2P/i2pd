#include "Tunnel.h"
#include "TunnelPool.h"

namespace i2p
{
namespace tunnel
{
	TunnelPool::TunnelPool ()
	{
	}

	TunnelPool::~TunnelPool ()
	{
		for (auto it: m_InboundTunnels)
			it->SetTunnelPool (nullptr);
	}

	void TunnelPool::TunnelCreationFailed (Tunnel * failedTunnel)
	{
	}	

	void TunnelPool::TunnelExpired (InboundTunnel * expiredTunnel)
	{
	}
}
}
