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

			TunnelPool (i2p::data::LocalDestination * localDestination, int numTunnels = 5);
			~TunnelPool ();

			const uint8_t * GetEncryptionPrivateKey () const { return m_EncryptionPrivateKey; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionPublicKey; };
			
			void CreateTunnels ();
			void TunnelCreated (InboundTunnel * createdTunnel);
			void TunnelExpired (InboundTunnel * expiredTunnel);
			void TunnelCreated (OutboundTunnel * createdTunnel);
			void TunnelExpired (OutboundTunnel * expiredTunnel);
			std::vector<InboundTunnel *> GetInboundTunnels (int num) const;
			OutboundTunnel * GetNextOutboundTunnel ();
			
		private:

			void CreateInboundTunnel ();	
			void CreateOutboundTunnel ();
			
		private:

			uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];
			i2p::data::LocalDestination * m_LocalDestination;
			int m_NumTunnels;
			std::set<InboundTunnel *, TunnelCreationTimeCmp> m_InboundTunnels; // recent tunnel appears first
			std::set<OutboundTunnel *, TunnelCreationTimeCmp> m_OutboundTunnels;
			OutboundTunnel * m_LastOutboundTunnel;
	};	
}
}

#endif

