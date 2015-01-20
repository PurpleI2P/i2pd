#ifndef TUNNEL_POOL__
#define TUNNEL_POOL__

#include <inttypes.h>
#include <set>
#include <vector>
#include <utility>
#include <mutex>
#include <memory>
#include "Identity.h"
#include "LeaseSet.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "TunnelBase.h"
#include "RouterContext.h"
#include "Garlic.h"

namespace i2p
{
namespace tunnel
{
	class Tunnel;
	class InboundTunnel;
	class OutboundTunnel;

	class TunnelPool: public std::enable_shared_from_this<TunnelPool> // per local destination
	{
		public:

			TunnelPool (i2p::garlic::GarlicDestination * localDestination, int numInboundHops, int numOutboundHops, int numTunnels = 5);
			~TunnelPool ();
		
			i2p::garlic::GarlicDestination * GetLocalDestination () const { return m_LocalDestination; };
			void SetLocalDestination (i2p::garlic::GarlicDestination * destination) { m_LocalDestination = destination; };

			void CreateTunnels ();
			void TunnelCreated (InboundTunnel * createdTunnel);
			void TunnelExpired (InboundTunnel * expiredTunnel);
			void TunnelCreated (OutboundTunnel * createdTunnel);
			void TunnelExpired (OutboundTunnel * expiredTunnel);
			std::vector<InboundTunnel *> GetInboundTunnels (int num) const;
			OutboundTunnel * GetNextOutboundTunnel (OutboundTunnel * suggested = nullptr) const;
			InboundTunnel * GetNextInboundTunnel (InboundTunnel * suggested = nullptr) const;		

			void TestTunnels ();
			void ProcessGarlicMessage (I2NPMessage * msg);
			void ProcessDeliveryStatus (I2NPMessage * msg);

			bool IsActive () const { return m_IsActive; };
			void SetActive (bool isActive) { m_IsActive = isActive; };
			void DetachTunnels ();
			
		private:

			void CreateInboundTunnel ();	
			void CreateOutboundTunnel ();
			void RecreateInboundTunnel (InboundTunnel * tunnel);
			void RecreateOutboundTunnel (OutboundTunnel * tunnel);
			template<class TTunnels>
			typename TTunnels::value_type GetNextTunnel (TTunnels& tunnels, 
				typename TTunnels::value_type suggested = nullptr) const;
			std::shared_ptr<const i2p::data::RouterInfo> SelectNextHop (std::shared_ptr<const i2p::data::RouterInfo> prevHop) const;
			
		private:

			i2p::garlic::GarlicDestination * m_LocalDestination;
			int m_NumInboundHops, m_NumOutboundHops, m_NumTunnels;
			mutable std::mutex m_InboundTunnelsMutex;
			std::set<InboundTunnel *, TunnelCreationTimeCmp> m_InboundTunnels; // recent tunnel appears first
			mutable std::mutex m_OutboundTunnelsMutex;
			std::set<OutboundTunnel *, TunnelCreationTimeCmp> m_OutboundTunnels;
			std::map<uint32_t, std::pair<OutboundTunnel *, InboundTunnel *> > m_Tests;
			bool m_IsActive;

		public:

			// for HTTP only
			const decltype(m_OutboundTunnels)& GetOutboundTunnels () const { return m_OutboundTunnels; };
			const decltype(m_InboundTunnels)& GetInboundTunnels () const { return m_InboundTunnels; };

	};	
}
}

#endif

