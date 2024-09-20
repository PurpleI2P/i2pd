/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
	const int UNKNOWN_LATENCY = -1;
	const int HIGH_LATENCY_PER_HOP = 250000; // in microseconds
	const int MAX_TUNNEL_MSGS_BATCH_SIZE = 100; // handle messages without interrupt
	const uint16_t DEFAULT_MAX_NUM_TRANSIT_TUNNELS = 5000;
	const int TUNNEL_MANAGE_INTERVAL = 15; // in seconds
	const int TUNNEL_POOLS_MANAGE_INTERVAL = 5; // in seconds
	const int TUNNEL_MEMORY_POOL_MANAGE_INTERVAL = 120; // in seconds

	const size_t I2NP_TUNNEL_MESSAGE_SIZE = TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE + 34; // reserved for alignment and NTCP 16 + 6 + 12
	const size_t I2NP_TUNNEL_ENPOINT_MESSAGE_SIZE = 2*TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE + 28; // reserved for alignment and NTCP 16 + 6 + 6

	const double TCSR_SMOOTHING_CONSTANT = 0.0005; // smoothing constant in exponentially weighted moving average
	const double TCSR_START_VALUE = 0.1; // start value of tunnel creation success rate

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
	class Tunnel: public TunnelBase,
		 public std::enable_shared_from_this<Tunnel>
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
			bool IsEstablished () const { return m_State == eTunnelStateEstablished || m_State == eTunnelStateTestFailed; };
			bool IsFailed () const { return m_State == eTunnelStateFailed; };
			bool IsRecreated () const { return m_IsRecreated; };
			void SetRecreated (bool recreated) { m_IsRecreated = recreated; };
			int GetNumHops () const { return m_Hops.size (); };
			virtual bool IsInbound() const = 0;

			std::shared_ptr<TunnelPool> GetTunnelPool () const { return m_Pool; };
			void SetTunnelPool (std::shared_ptr<TunnelPool> pool) { m_Pool = pool; };

			bool HandleTunnelBuildResponse (uint8_t * msg, size_t len);

			// implements TunnelBase
			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg) override;
			void EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out) override;

			/** @brief add latency sample */
			void AddLatencySample(const int us) { m_Latency = LatencyIsKnown() ? (m_Latency + us) >> 1 : us; }
			/** @brief get this tunnel's estimated latency */
			int GetMeanLatency() const { return (m_Latency + 500) / 1000; }
			/** @brief return true if this tunnel's latency fits in range [lowerbound, upperbound] */
			bool LatencyFitsRange(int lowerbound, int upperbound) const;

			bool LatencyIsKnown() const { return m_Latency != UNKNOWN_LATENCY; }
			bool IsSlow () const { return LatencyIsKnown() && m_Latency > HIGH_LATENCY_PER_HOP*GetNumHops (); }

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
			int m_Latency; // in microseconds
	};

	class OutboundTunnel: public Tunnel
	{
		public:

			OutboundTunnel (std::shared_ptr<const TunnelConfig> config):
				Tunnel (config), m_Gateway (this), m_EndpointIdentHash (config->GetLastIdentHash ()) {};

			void SendTunnelDataMsgTo (const uint8_t * gwHash, uint32_t gwTunnel, std::shared_ptr<i2p::I2NPMessage> msg);
			virtual void SendTunnelDataMsgs (const std::vector<TunnelMessageBlock>& msgs); // multiple messages
			const i2p::data::IdentHash& GetEndpointIdentHash () const { return m_EndpointIdentHash; };
			virtual size_t GetNumSentBytes () const { return m_Gateway.GetNumSentBytes (); };

			// implements TunnelBase
			void HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg) override;

			bool IsInbound() const override { return false; }

		private:

			std::mutex m_SendMutex;
			TunnelGateway m_Gateway;
			i2p::data::IdentHash m_EndpointIdentHash;
	};

	class InboundTunnel: public Tunnel
	{
		public:

			InboundTunnel (std::shared_ptr<const TunnelConfig> config): Tunnel (config), m_Endpoint (true) {};
			void HandleTunnelDataMsg (std::shared_ptr<I2NPMessage>&& msg) override;
			virtual size_t GetNumReceivedBytes () const { return m_Endpoint.GetNumReceivedBytes (); };
			bool IsInbound() const override { return true; }

			// override TunnelBase
			void Cleanup () override { m_Endpoint.Cleanup (); };

		protected:

			std::shared_ptr<InboundTunnel> GetSharedFromThis () 
			{
				return std::static_pointer_cast<InboundTunnel>(shared_from_this ());
			}
			
		private:

			TunnelEndpoint m_Endpoint;
	};

	class ZeroHopsInboundTunnel: public InboundTunnel
	{
		public:

			ZeroHopsInboundTunnel ();
			void SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg) override;
			size_t GetNumReceivedBytes () const override { return m_NumReceivedBytes; };

		private:

			size_t m_NumReceivedBytes;
	};

	class ZeroHopsOutboundTunnel: public OutboundTunnel
	{
		public:

			ZeroHopsOutboundTunnel ();
			void SendTunnelDataMsgs (const std::vector<TunnelMessageBlock>& msgs) override;
			size_t GetNumSentBytes () const override { return m_NumSentBytes; };

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
			bool AddTransitTunnel (std::shared_ptr<TransitTunnel> tunnel);
			void AddOutboundTunnel (std::shared_ptr<OutboundTunnel> newTunnel);
			void AddInboundTunnel (std::shared_ptr<InboundTunnel> newTunnel);
			std::shared_ptr<InboundTunnel> CreateInboundTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<TunnelPool> pool, std::shared_ptr<OutboundTunnel> outboundTunnel);
			std::shared_ptr<OutboundTunnel> CreateOutboundTunnel (std::shared_ptr<TunnelConfig> config, std::shared_ptr<TunnelPool> pool);
			void PostTunnelData (std::shared_ptr<I2NPMessage> msg);
			void PostTunnelData (const std::vector<std::shared_ptr<I2NPMessage> >& msgs);
			void AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<InboundTunnel> tunnel);
			void AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> tunnel);
			std::shared_ptr<TunnelPool> CreateTunnelPool (int numInboundHops, 
			    int numOuboundHops, int numInboundTunnels, int numOutboundTunnels, 
			    int inboundVariance, int outboundVariance,  bool isHighBandwidth);
			void DeleteTunnelPool (std::shared_ptr<TunnelPool> pool);
			void StopTunnelPool (std::shared_ptr<TunnelPool> pool);

			std::shared_ptr<I2NPMessage> NewI2NPTunnelMessage (bool endpoint);

			void SetMaxNumTransitTunnels (uint32_t maxNumTransitTunnels);
			uint32_t GetMaxNumTransitTunnels () const { return m_MaxNumTransitTunnels; };
			int GetCongestionLevel() const { return m_MaxNumTransitTunnels ? CONGESTION_LEVEL_FULL * m_TransitTunnels.size() / m_MaxNumTransitTunnels : CONGESTION_LEVEL_FULL; }

		private:

			template<class TTunnel>
			std::shared_ptr<TTunnel> CreateTunnel (std::shared_ptr<TunnelConfig> config,
				std::shared_ptr<TunnelPool> pool, std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);

			template<class TTunnel>
			std::shared_ptr<TTunnel> GetPendingTunnel (uint32_t replyMsgID, const std::map<uint32_t, std::shared_ptr<TTunnel> >& pendingTunnels);

			void HandleTunnelGatewayMsg (std::shared_ptr<TunnelBase> tunnel, std::shared_ptr<I2NPMessage> msg);

			void Run ();
			void ManageTunnels (uint64_t ts);
			void ManageOutboundTunnels (uint64_t ts);
			void ManageInboundTunnels (uint64_t ts);
			void ManageTransitTunnels (uint64_t ts);
			void ManagePendingTunnels (uint64_t ts);
			template<class PendingTunnels>
			void ManagePendingTunnels (PendingTunnels& pendingTunnels, uint64_t ts);
			void ManageTunnelPools (uint64_t ts);

			std::shared_ptr<ZeroHopsInboundTunnel> CreateZeroHopsInboundTunnel (std::shared_ptr<TunnelPool> pool);
			std::shared_ptr<ZeroHopsOutboundTunnel> CreateZeroHopsOutboundTunnel (std::shared_ptr<TunnelPool> pool);

			// Calculating of tunnel creation success rate
			void SuccesiveTunnelCreation()
			{
				// total TCSR
				m_TotalNumSuccesiveTunnelCreations++;
				// A modified version of the EWMA algorithm, where alpha is increased at the beginning to accelerate similarity
				double alpha = TCSR_SMOOTHING_CONSTANT + (1 - TCSR_SMOOTHING_CONSTANT)/++m_TunnelCreationAttemptsNum;
				m_TunnelCreationSuccessRate = alpha * 1 + (1 - alpha) * m_TunnelCreationSuccessRate;

			}
			void FailedTunnelCreation()
			{
				m_TotalNumFailedTunnelCreations++;

				double alpha = TCSR_SMOOTHING_CONSTANT + (1 - TCSR_SMOOTHING_CONSTANT)/++m_TunnelCreationAttemptsNum;
				m_TunnelCreationSuccessRate = alpha * 0 + (1 - alpha) * m_TunnelCreationSuccessRate;
			}

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
			uint32_t m_MaxNumTransitTunnels;
			// count of tunnels for total TCSR algorithm
			int m_TotalNumSuccesiveTunnelCreations, m_TotalNumFailedTunnelCreations;
			double m_TunnelCreationSuccessRate;
			int m_TunnelCreationAttemptsNum;

		public:

			// for HTTP only
			const decltype(m_OutboundTunnels)& GetOutboundTunnels () const { return m_OutboundTunnels; };
			const decltype(m_InboundTunnels)& GetInboundTunnels () const { return m_InboundTunnels; };
			const decltype(m_TransitTunnels)& GetTransitTunnels () const { return m_TransitTunnels; };

			size_t CountTransitTunnels() const;
			size_t CountInboundTunnels() const;
			size_t CountOutboundTunnels() const;

			int GetQueueSize () { return m_Queue.GetSize (); };
			int GetTunnelCreationSuccessRate () const { return std::round(m_TunnelCreationSuccessRate * 100); } // in percents
			double GetPreciseTunnelCreationSuccessRate () const { return m_TunnelCreationSuccessRate * 100; } // in percents
			int GetTotalTunnelCreationSuccessRate () const // in percents
			{
				int totalNum = m_TotalNumSuccesiveTunnelCreations + m_TotalNumFailedTunnelCreations;
				return totalNum ? m_TotalNumSuccesiveTunnelCreations*100/totalNum : 0;
			}
	};

	extern Tunnels tunnels;
}
}

#endif
