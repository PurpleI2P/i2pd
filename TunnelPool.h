#ifndef TUNNEL_POOL__
#define TUNNEL_POOL__

#include <set>
#include <vector>
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "TunnelBase.h"

namespace i2p
{
namespace tunnel
{
	class Tunnel;
	class InboundTunnel;
	class OutboundTunnel;

	class TunnelPool // per local destination
	{
		public:

			TunnelPool (i2p::data::LocalDestination * owner, int numTunnels = 5);
			~TunnelPool ();

			void CreateTunnels ();
			void TunnelCreated (InboundTunnel * createdTunnel);
			std::vector<InboundTunnel *> GetInboundTunnels (int num) const;
			void ManageTunnels ();
	
		private:

			void CreateInboundTunnel ();	

		private:

			i2p::data::LocalDestination * m_Owner;
			int m_NumTunnels;
			std::set<InboundTunnel *, TunnelCreationTimeCmp> m_InboundTunnels; // recent tunnel appears first

	};	
}
}

#endif

