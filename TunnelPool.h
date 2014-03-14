#ifndef TUNNEL_POOL__
#define TUNNEL_POOL__

#include <list>
#include "LeaseSet.h"

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

			TunnelPool ();
			~TunnelPool ();

			void TunnelCreationFailed (Tunnel * failedTunnel);
			void TunnelExpired (InboundTunnel * expiredTunnel);

		private:

			std::list<InboundTunnel *> m_InboundTunnels;	
	};	
}
}

#endif

