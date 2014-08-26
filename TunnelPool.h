#ifndef TUNNEL_POOL__
#define TUNNEL_POOL__

#include <inttypes.h>
#include <set>
#include <vector>
#include <utility>
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "TunnelBase.h"
#include "RouterContext.h"

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

			TunnelPool (i2p::data::LocalDestination& localDestination, int numHops, int numTunnels = 5);
			~TunnelPool ();

			const uint8_t * GetEncryptionPrivateKey () const { return m_LocalDestination.GetEncryptionPrivateKey (); };
			const uint8_t * GetEncryptionPublicKey () const { return m_LocalDestination.GetEncryptionPublicKey (); };
			const i2p::data::LocalDestination& GetLocalDestination () const { return m_LocalDestination; };
			bool IsExploratory () const { return GetIdentHash () == i2p::context.GetRouterIdentHash (); };		

			void CreateTunnels ();
			void TunnelCreated (InboundTunnel * createdTunnel);
			void TunnelExpired (InboundTunnel * expiredTunnel);
			void TunnelCreated (OutboundTunnel * createdTunnel);
			void TunnelExpired (OutboundTunnel * expiredTunnel);
			std::vector<InboundTunnel *> GetInboundTunnels (int num) const;
			OutboundTunnel * GetNextOutboundTunnel (OutboundTunnel * suggested = nullptr);
			InboundTunnel * GetNextInboundTunnel (InboundTunnel * suggested = nullptr);
			const i2p::data::IdentHash& GetIdentHash () const { return m_LocalDestination.GetIdentHash (); };			

			void TestTunnels ();
			void ProcessDeliveryStatus (I2NPMessage * msg);

		private:

			void CreateInboundTunnel ();	
			void CreateOutboundTunnel ();
			void RecreateInboundTunnel (InboundTunnel * tunnel);
			void RecreateOutboundTunnel (OutboundTunnel * tunnel);
			template<class TTunnels>
			typename TTunnels::value_type GetNextTunnel (TTunnels& tunnels, 
				typename TTunnels::value_type suggested = nullptr);
			
		private:

			i2p::data::LocalDestination& m_LocalDestination;
			int m_NumHops, m_NumTunnels;
			std::set<InboundTunnel *, TunnelCreationTimeCmp> m_InboundTunnels; // recent tunnel appears first
			std::set<OutboundTunnel *, TunnelCreationTimeCmp> m_OutboundTunnels;
			std::map<uint32_t, std::pair<OutboundTunnel *, InboundTunnel *> > m_Tests;
	};	
}
}

#endif

