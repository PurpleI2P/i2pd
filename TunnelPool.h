#ifndef TUNNEL_POOL__
#define TUNNEL_POOL__

#include <inttypes.h>
#include <set>
#include <vector>
#include <utility>
#include <mutex>
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

	class TunnelPool // per local destination
	{
		public:

			TunnelPool (i2p::garlic::GarlicDestination& localDestination, int numHops, int numTunnels = 5);
			~TunnelPool ();

			const uint8_t * GetEncryptionPrivateKey () const { return m_LocalDestination.GetEncryptionPrivateKey (); };
			const uint8_t * GetEncryptionPublicKey () const { return m_LocalDestination.GetEncryptionPublicKey (); };
			const i2p::data::LocalDestination& GetLocalDestination () const { return m_LocalDestination; };			
			i2p::garlic::GarlicDestination& GetGarlicDestination () const { return m_LocalDestination; };	
			bool IsExploratory () const { return GetIdentHash () == i2p::context.GetIdentHash (); };		

			void CreateTunnels ();
			void TunnelCreated (InboundTunnel * createdTunnel);
			void TunnelExpired (InboundTunnel * expiredTunnel);
			void TunnelCreated (OutboundTunnel * createdTunnel);
			void TunnelExpired (OutboundTunnel * expiredTunnel);
			std::vector<InboundTunnel *> GetInboundTunnels (int num) const;
			OutboundTunnel * GetNextOutboundTunnel (OutboundTunnel * suggested = nullptr) const;
			InboundTunnel * GetNextInboundTunnel (InboundTunnel * suggested = nullptr) const;
			const i2p::data::IdentHash& GetIdentHash () const { return m_LocalDestination.GetIdentHash (); };			

			void TestTunnels ();
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

			i2p::garlic::GarlicDestination& m_LocalDestination;
			int m_NumHops, m_NumTunnels;
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

