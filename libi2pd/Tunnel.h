/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TUNNEL_H__
#define TUNNEL_H__

#include <inttypes.h>
#include <map>
#include <unordered_map>
#include <list>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include "util.h"
#include "Queue.h"
#include "Crypto.h"
#include "TunnelConfig.h"
#include "TunnelPool.h"
#include "TransitTunnel.h"
#include "TunnelEndpoint.h"
#include "TunnelGateway.h"
#include "TunnelBase.h"
#include "I2NPProtocol.h"

namespace i2p
{
namespace tunnel
{
	const int TUNNEL_EXPIRATION_TIMEOUT = 660; // 11 minutes
	const int TUNNEL_EXPIRATION_THRESHOLD = 60; // 1 minute
	const int TUNNEL_RECREATION_THRESHOLD = 90; // 1.5 minutes
	const int TUNNEL_CREATION_TIMEOUT = 30; // 30 seconds
	const int STANDARD_NUM_RECORDS = 4; // in VariableTunnelBuild message
	const int MAX_NUM_RECORDS = 8;
	const int HIGH_LATENCY_PER_HOP = 250; // in milliseconds

	const size_t I2NP_TUNNEL_MESSAGE_SIZE = TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE + 34; // reserved for alignment and NTCP 16 + 6 + 12
	const size_t I2NP_TUNNEL_ENPOINT_MESSAGE_SIZE = 2*TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE + 28; // reserved for alignment and NTCP 16 + 6 + 6

	enum TunnelState
	{
		eTunnelStatePending,
		eTunnelStateBuildReplyReceived,
		eTunnelStateBuildFailed,
		eTunnelStateEstablished,
		eTunnelStateTestFailed,
		eTunnelStateFailed,
		eTunnelStateExpiring
	};

	class OutboundTunnel;
	class InboundTunnel;
	class Tunnel: public TunnelBase
	{
		struct TunnelHop
		{
			std::shared_ptr<const i2p::data::IdentityEx> ident;
			i2p::crypto::TunnelDecryption decryption;
		};

		public:

			/** function for visiting a hops stored in a tunnel */
			typedef std::function<void(std::shared_ptr<const i2p::data::IdentityEx>)> TunnelHopVisitor;

			Tunnel (std::shared_ptr<const TunnelConfig> config);
			~Tunnel ();

			void Build (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);

			std::shared_ptr<const TunnelConfig> GetTunnelConfig () const { return m_Config; }
			std::vector<std::shared_ptr<const i2p::data::IdentityEx> > GetPeers () const;
			std::vector<std::shared_ptr<const i2p::data::IdentityEx> > GetInvertedPeers () const;
			bool IsShortBuildMessage () const { return m_IsShortBuildMessage; };
			i2p::data::RouterInfo::CompatibleTransports GetFarEndTransports () const { return m_FarEndTransports; };
			TunnelState GetState () const { return m_State; };
			void SetState (TunnelState state);
			bool IsEstablished () const { return m_State == eTunnelStateEstablished; };
			bool IsFailed () const { return m_State == eTunnelStateFailed; };
			bool IsRecreated () const { return m_IsRecreated; };
			void SetRecreated (bool recreated) { m_IsRecreated = recreated; };
			int GetNumHops () const { return m_Hops.size (); };
			virtual bool IsInbound() const = 0;

			std::shared_ptr<TunnelPool> GetTunnelPool () const { return m_Pool; };
			void SetTunnelPool (std::shared_ptr<TunnelPool> pool) { m_Pool = pool; };

			bool HandleTunnelBuildResponse (uint8_t * msg, size_t len);

			// implements TunnelBase
			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg);
			void EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out);

			/** @brief add latency sample */
			void AddLatencySample(const uint64_t ms) { m_Latency = (m_Latency + ms) >> 1; }
			/** @brief get this tunnel's estimated latency */
			uint64_t GetMeanLatency() const { return m_Latency; }
			/** @brief return true if this tunnel's latency fits in range [lowerbound, upperbound] */
			bool LatencyFitsRange(uint64_t lowerbound, uint64_t upperbound) const;

			bool LatencyIsKnown() const { return m_Latency > 0; }
			bool IsSlow () const { return LatencyIsKnown() && (int)m_Latency > HIGH_LATENCY_PER_HOP*GetNumHops (); }

			/** visit all hops we currently store */
			void VisitTunnelHops(TunnelHopVisitor v);

		private:

			std::shared_ptr<const TunnelConfig> m_Config;
			std::vector<TunnelHop> m_Hops;
			bool m_IsShortBuildMessage;
			std::shared_ptr<TunnelPool> m_Pool; // pool, tunnel belongs to, or null
			TunnelState m_State;
			i2p::data::RouterInfo::CompatibleTransports m_FarEndTransports;
			bool m_IsRecreated; // if tunnel is replaced by new, or new tunnel requested to replace
			uint64_t m_Latency; // in milliseconds
	};

	class OutboundTunnel: public Tunnel
	{
		public:

			OutboundTunnel (std::shared_ptr<const TunnelConfig> config):
				Tunnel (config), m_Gateway (this), m_EndpointIdentHash (config->GetLastIdentHash ()) {};

			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, std::shared_ptr<i2p::I2NPMessage> msg);
			virtual void SendTunnelDataMsg (const std::vector<TunnelMessageBlock>& msgs); // multiple messages
			const i2p::data::IdentHash& GetEndpointIdentHash () const { return m_EndpointIdentHash; };
			virtual size_t GetNumSentBytes () const { return m_Gateway.GetNumSentBytes (); };

			// implements TunnelBase
			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg);

			bool IsInbound() const { return false; }

		private:

			std::mutex m_SendMutex;
			TunnelGateway m_Gateway;
			i2p::data::IdentHash m_EndpointIdentHash;
	};

	class InboundTunnel: public Tunnel, public std::enable_shared_from_this<InboundTunnel>
	{
		public:

			InboundTunnel (std::shared_ptr<const TunnelConfig> config): Tunnel (config), m_Endpoint (true) {};
			void HandleTunnelDataMsg (std::shared_ptr<I2NPMessage>&& msg);
			virtual size_t GetNumReceivedBytes () const { return m_Endpoint.GetNumReceivedBytes (); };
			bool IsInbound() const { return true; }

			// override TunnelBase
			void Cleanup () { m_Endpoint.Cleanup (); };

		private:

			TunnelEndpoint m_Endpoint;
	};

	class ZeroHopsInboundTunnel: public InboundTunnel
	{
		public:

			ZeroHopsInboundTunnel ();
			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg);
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };

		private:

			size_t m_NumReceivedBytes;
	};

	class ZeroHopsOutboundTunnel: public OutboundTunnel
	{
		public:

			ZeroHopsOutboundTunnel ();
			void SendTunnelDataMsg (const std::vector<TunnelMessageBlock>& msgs);
			size_t GetNumSentBytes () const { return m_NumSentBytes; };

		private:

			size_t m_NumSentBytes;
	};

	class Tunnels
	{
		public:

			Tunnels ();
			~Tunnels ();
			void Start ();
			void Stop ();

			std::shared_ptr<InboundTunnel> GetPendingInboundTunnel (uint32_t replyMsgID);
			std::shared_ptr<OutboundTunnel> GetPendingOutboundTunnel (uint32_t replyMsgID);
			std::shared_ptr<InboundTunnel> GetNextInboundTunnel ();
			std::shared_ptr<OutboundTunnel> GetNextOutboundTunnel ();
			std::shared_ptr<TunnelPool> GetExploratoryPool () const { return m_ExploratoryPool; };
			std::shared_ptr<TunnelBase> GetTunnel (uint32_t tunnelID);
			int GetTransitTunnelsExpirationTimeout ();
			void AddTransitTunnel (std::shared_ptr<TransitTunnel> tunnel);
			void AddOutboundTunnel (std::shared_ptr<OutboundTunnel> newTunnel);
			void AddInboundTunnel (std::shared_ptr<InboundTunnel> newTunnel);
			std::shared_ptr<InboundTunnel> CreateInboundTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<TunnelPool> pool, std::shared_ptr<OutboundTunnel> outboundTunnel);
			std::shared_ptr<OutboundTunnel> CreateOutboundTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<TunnelPool> pool);
			void PostTunnelData (std::shared_ptr<I2NPMessage> msg);
			void PostTunnelData (const std::vector<std::shared_ptr<I2NPMessage> >& msgs);
			void AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<InboundTunnel> tunnel);
			void AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> tunnel);
			std::shared_ptr<TunnelPool> CreateTunnelPool (int numInboundHops, int numOuboundHops,
				int numInboundTunnels, int numOutboundTunnels, int inboundVariance, int outboundVariance);
			void DeleteTunnelPool (std::shared_ptr<TunnelPool> pool);
			void StopTunnelPool (std::shared_ptr<TunnelPool> pool);

			std::shared_ptr<I2NPMessage> NewI2NPTunnelMessage (bool endpoint);

		private:

			template<class TTunnel>
			std::shared_ptr<TTunnel> CreateTunnel (std::shared_ptr<TunnelConfig> config,
				std::shared_ptr<TunnelPool> pool, std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);

			template<class TTunnel>
			std::shared_ptr<TTunnel> GetPendingTunnel (uint32_t replyMsgID, const std::map<uint32_t, std::shared_ptr<TTunnel> >& pendingTunnels);

			void HandleTunnelGatewayMsg (std::shared_ptr<TunnelBase> tunnel, std::shared_ptr<I2NPMessage> msg);

			void Run ();
			void ManageTunnels ();
			void ManageOutboundTunnels ();
			void ManageInboundTunnels ();
			void ManageTransitTunnels ();
			void ManagePendingTunnels ();
			template<class PendingTunnels>
			void ManagePendingTunnels (PendingTunnels& pendingTunnels);
			void ManageTunnelPools (uint64_t ts);

			std::shared_ptr<ZeroHopsInboundTunnel> CreateZeroHopsInboundTunnel (std::shared_ptr<TunnelPool> pool);
			std::shared_ptr<ZeroHopsOutboundTunnel> CreateZeroHopsOutboundTunnel (std::shared_ptr<TunnelPool> pool);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;
			std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_PendingInboundTunnels; // by replyMsgID
			std::map<uint32_t, std::shared_ptr<OutboundTunnel> > m_PendingOutboundTunnels; // by replyMsgID
			std::list<std::shared_ptr<InboundTunnel> > m_InboundTunnels;
			std::list<std::shared_ptr<OutboundTunnel> > m_OutboundTunnels;
			std::list<std::shared_ptr<TransitTunnel> > m_TransitTunnels;
			std::unordered_map<uint32_t, std::shared_ptr<TunnelBase> > m_Tunnels; // tunnelID->tunnel known by this id
			std::mutex m_PoolsMutex;
			std::list<std::shared_ptr<TunnelPool>> m_Pools;
			std::shared_ptr<TunnelPool> m_ExploratoryPool;
			i2p::util::Queue<std::shared_ptr<I2NPMessage> > m_Queue;
			i2p::util::MemoryPoolMt<I2NPMessageBuffer<I2NP_TUNNEL_ENPOINT_MESSAGE_SIZE> > m_I2NPTunnelEndpointMessagesMemoryPool;
			i2p::util::MemoryPoolMt<I2NPMessageBuffer<I2NP_TUNNEL_MESSAGE_SIZE> > m_I2NPTunnelMessagesMemoryPool;

			// some stats
			int m_NumSuccesiveTunnelCreations, m_NumFailedTunnelCreations;

		public:

			// for HTTP only
			const decltype(m_OutboundTunnels)& GetOutboundTunnels () const { return m_OutboundTunnels; };
			const decltype(m_InboundTunnels)& GetInboundTunnels () const { return m_InboundTunnels; };
			const decltype(m_TransitTunnels)& GetTransitTunnels () const { return m_TransitTunnels; };

			size_t CountTransitTunnels() const;
			size_t CountInboundTunnels() const;
			size_t CountOutboundTunnels() const;

			int GetQueueSize () { return m_Queue.GetSize (); };
			int GetTunnelCreationSuccessRate () const // in percents
			{
				int totalNum = m_NumSuccesiveTunnelCreations + m_NumFailedTunnelCreations;
				return totalNum ? m_NumSuccesiveTunnelCreations*100/totalNum : 0;
			}
	};

	extern Tunnels tunnels;
}
}

#endif
