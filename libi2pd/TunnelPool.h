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

	typedef std::shared_ptr<const i2p::data::IdentityEx> Peer;
	typedef std::vector<Peer> Path;

	/** interface for custom tunnel peer selection algorithm */
	struct ITunnelPeerSelector
	{
		virtual ~ITunnelPeerSelector() {};
		virtual bool SelectPeers(Path & peers, int hops, bool isInbound) = 0;
	};


	typedef std::function<std::shared_ptr<const i2p::data::RouterInfo>(std::shared_ptr<const i2p::data::RouterInfo>)> SelectHopFunc;
	// standard peer selection algorithm
	bool StandardSelectPeers(Path & path, int hops, bool inbound, SelectHopFunc nextHop);

	class TunnelPool: public std::enable_shared_from_this<TunnelPool> // per local destination
	{
		public:

			TunnelPool (int numInboundHops, int numOutboundHops, int numInboundTunnels, int numOutboundTunnels);
			~TunnelPool ();

			std::shared_ptr<i2p::garlic::GarlicDestination> GetLocalDestination () const { return m_LocalDestination; };
			void SetLocalDestination (std::shared_ptr<i2p::garlic::GarlicDestination> destination) { m_LocalDestination = destination; };
			void SetExplicitPeers (std::shared_ptr<std::vector<i2p::data::IdentHash> > explicitPeers);

			void CreateTunnels ();
			void TunnelCreated (std::shared_ptr<InboundTunnel> createdTunnel);
			void TunnelExpired (std::shared_ptr<InboundTunnel> expiredTunnel);
			void TunnelCreated (std::shared_ptr<OutboundTunnel> createdTunnel);
			void TunnelExpired (std::shared_ptr<OutboundTunnel> expiredTunnel);
			void RecreateInboundTunnel (std::shared_ptr<InboundTunnel> tunnel);
			void RecreateOutboundTunnel (std::shared_ptr<OutboundTunnel> tunnel);
			std::vector<std::shared_ptr<InboundTunnel> > GetInboundTunnels (int num) const;
			std::shared_ptr<OutboundTunnel> GetNextOutboundTunnel (std::shared_ptr<OutboundTunnel> excluded = nullptr) const;
			std::shared_ptr<InboundTunnel> GetNextInboundTunnel (std::shared_ptr<InboundTunnel> excluded = nullptr) const;
			std::shared_ptr<OutboundTunnel> GetNewOutboundTunnel (std::shared_ptr<OutboundTunnel> old) const;
			void TestTunnels ();
			void ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			void ProcessDeliveryStatus (std::shared_ptr<I2NPMessage> msg);

			bool IsActive () const { return m_IsActive; };
			void SetActive (bool isActive) { m_IsActive = isActive; };
			void DetachTunnels ();

			int GetNumInboundTunnels () const { return m_NumInboundTunnels; };
			int GetNumOutboundTunnels () const { return m_NumOutboundTunnels; };
			int GetNumInboundHops() const { return m_NumInboundHops; };
			int GetNumOutboundHops() const { return m_NumOutboundHops; };

			/** i2cp reconfigure */
			bool Reconfigure(int inboundHops, int outboundHops, int inboundQuant, int outboundQuant);
    
			void SetCustomPeerSelector(ITunnelPeerSelector * selector);
			void UnsetCustomPeerSelector();
			bool HasCustomPeerSelector();

		/** @brief make this tunnel pool yield tunnels that fit latency range [min, max] */
		void RequireLatency(uint64_t min, uint64_t max) { m_MinLatency = min; m_MaxLatency = max; }

		/** @brief return true if this tunnel pool has a latency requirement */
		bool HasLatencyRequirement() const { return m_MinLatency > 0 && m_MaxLatency > 0; }

		/** @brief get the lowest latency tunnel in this tunnel pool regardless of latency requirements */
		std::shared_ptr<InboundTunnel> GetLowestLatencyInboundTunnel(std::shared_ptr<InboundTunnel> exclude=nullptr) const;
		std::shared_ptr<OutboundTunnel> GetLowestLatencyOutboundTunnel(std::shared_ptr<OutboundTunnel> exclude=nullptr) const;

		// for overriding tunnel peer selection
		std::shared_ptr<const i2p::data::RouterInfo> SelectNextHop (std::shared_ptr<const i2p::data::RouterInfo> prevHop) const;

		private:

			void CreateInboundTunnel ();
			void CreateOutboundTunnel ();
			void CreatePairedInboundTunnel (std::shared_ptr<OutboundTunnel> outboundTunnel);
			template<class TTunnels>
			typename TTunnels::value_type GetNextTunnel (TTunnels& tunnels, typename TTunnels::value_type excluded) const;
			bool SelectPeers (std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& hops, bool isInbound);
			bool SelectExplicitPeers (std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& hops, bool isInbound);

		private:

			std::shared_ptr<i2p::garlic::GarlicDestination> m_LocalDestination;
			int m_NumInboundHops, m_NumOutboundHops, m_NumInboundTunnels, m_NumOutboundTunnels;
			std::shared_ptr<std::vector<i2p::data::IdentHash> > m_ExplicitPeers;
			mutable std::mutex m_InboundTunnelsMutex;
			std::set<std::shared_ptr<InboundTunnel>, TunnelCreationTimeCmp> m_InboundTunnels; // recent tunnel appears first
			mutable std::mutex m_OutboundTunnelsMutex;
			std::set<std::shared_ptr<OutboundTunnel>, TunnelCreationTimeCmp> m_OutboundTunnels;
			mutable std::mutex m_TestsMutex;
			std::map<uint32_t, std::pair<std::shared_ptr<OutboundTunnel>, std::shared_ptr<InboundTunnel> > > m_Tests;
			bool m_IsActive;
			std::mutex m_CustomPeerSelectorMutex;
			ITunnelPeerSelector * m_CustomPeerSelector;

		uint64_t m_MinLatency=0; // if > 0 this tunnel pool will try building tunnels with minimum latency by ms
		uint64_t m_MaxLatency=0; // if > 0 this tunnel pool will try building tunnels with maximum latency by ms

		public:

			// for HTTP only
			const decltype(m_OutboundTunnels)& GetOutboundTunnels () const { return m_OutboundTunnels; };
			const decltype(m_InboundTunnels)& GetInboundTunnels () const { return m_InboundTunnels; };

	};
}
}

#endif
