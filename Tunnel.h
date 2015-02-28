#ifndef TUNNEL_H__
#define TUNNEL_H__

#include <inttypes.h>
#include <map>
#include <list>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include "Queue.h"
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
	const int TUNNEL_CREATION_TIMEOUT = 30; // 30 seconds
	const int STANDARD_NUM_RECORDS = 5; // in VariableTunnelBuild message

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
		public:

			Tunnel (TunnelConfig * config);
			~Tunnel ();

			void Build (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);
			
			TunnelConfig * GetTunnelConfig () const { return m_Config; }
			TunnelState GetState () const { return m_State; };
			void SetState (TunnelState state)  { m_State = state; };
			bool IsEstablished () const { return m_State == eTunnelStateEstablished; };
			bool IsFailed () const { return m_State == eTunnelStateFailed; };

			std::shared_ptr<TunnelPool> GetTunnelPool () const { return m_Pool; };
			void SetTunnelPool (std::shared_ptr<TunnelPool> pool) { m_Pool = pool; };			
			
			bool HandleTunnelBuildResponse (uint8_t * msg, size_t len);
			
			// implements TunnelBase
			void SendTunnelDataMsg (i2p::I2NPMessage * msg);
			void EncryptTunnelMsg (I2NPMessage * tunnelMsg); 
			uint32_t GetNextTunnelID () const { return m_Config->GetFirstHop ()->tunnelID; };
			const i2p::data::IdentHash& GetNextIdentHash () const { return m_Config->GetFirstHop ()->router->GetIdentHash (); };
			
		private:

			TunnelConfig * m_Config;
			std::shared_ptr<TunnelPool> m_Pool; // pool, tunnel belongs to, or null
			TunnelState m_State;
	};	

	class OutboundTunnel: public Tunnel 
	{
		public:

			OutboundTunnel (TunnelConfig * config): Tunnel (config), m_Gateway (this) {};

			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			void SendTunnelDataMsg (const std::vector<TunnelMessageBlock>& msgs); // multiple messages
			std::shared_ptr<const i2p::data::RouterInfo> GetEndpointRouter () const 
				{ return GetTunnelConfig ()->GetLastHop ()->router; }; 
			size_t GetNumSentBytes () const { return m_Gateway.GetNumSentBytes (); };

			// implements TunnelBase
			void HandleTunnelDataMsg (i2p::I2NPMessage * tunnelMsg);
			uint32_t GetTunnelID () const { return GetNextTunnelID (); };
			
		private:

			std::mutex m_SendMutex;
			TunnelGateway m_Gateway; 
	};
	
	class InboundTunnel: public Tunnel, public std::enable_shared_from_this<InboundTunnel>
	{
		public:

			InboundTunnel (TunnelConfig * config): Tunnel (config), m_Endpoint (true) {};
			void HandleTunnelDataMsg (I2NPMessage * msg);
			size_t GetNumReceivedBytes () const { return m_Endpoint.GetNumReceivedBytes (); };

			// implements TunnelBase
			uint32_t GetTunnelID () const { return GetTunnelConfig ()->GetLastHop ()->nextTunnelID; };
		private:

			TunnelEndpoint m_Endpoint; 
	};	

	
	class Tunnels
	{	
		public:

			Tunnels ();
			~Tunnels ();
			void Start ();
			void Stop ();		
			
			std::shared_ptr<InboundTunnel> GetInboundTunnel (uint32_t tunnelID);
			std::shared_ptr<InboundTunnel> GetPendingInboundTunnel (uint32_t replyMsgID);	
			std::shared_ptr<OutboundTunnel> GetPendingOutboundTunnel (uint32_t replyMsgID);			
			std::shared_ptr<InboundTunnel> GetNextInboundTunnel ();
			std::shared_ptr<OutboundTunnel> GetNextOutboundTunnel ();
			std::shared_ptr<TunnelPool> GetExploratoryPool () const { return m_ExploratoryPool; };
			TransitTunnel * GetTransitTunnel (uint32_t tunnelID);
			int GetTransitTunnelsExpirationTimeout ();
			void AddTransitTunnel (TransitTunnel * tunnel);
			void AddOutboundTunnel (std::shared_ptr<OutboundTunnel> newTunnel);
			void AddInboundTunnel (std::shared_ptr<InboundTunnel> newTunnel);
			void PostTunnelData (I2NPMessage * msg);
			void PostTunnelData (const std::vector<I2NPMessage *>& msgs);
			template<class TTunnel>
			std::shared_ptr<TTunnel> CreateTunnel (TunnelConfig * config, std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);
			void AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<InboundTunnel> tunnel);
			void AddPendingTunnel (uint32_t replyMsgID, std::shared_ptr<OutboundTunnel> tunnel);
			std::shared_ptr<TunnelPool> CreateTunnelPool (i2p::garlic::GarlicDestination * localDestination, int numInboundHops, int numOuboundHops);
			void DeleteTunnelPool (std::shared_ptr<TunnelPool> pool);
			void StopTunnelPool (std::shared_ptr<TunnelPool> pool);
			
		private:
		
			template<class TTunnel>
			std::shared_ptr<TTunnel> GetPendingTunnel (uint32_t replyMsgID, const std::map<uint32_t, std::shared_ptr<TTunnel> >& pendingTunnels);			

			void HandleTunnelGatewayMsg (TunnelBase * tunnel, I2NPMessage * msg);

			void Run ();	
			void ManageTunnels ();
			void ManageOutboundTunnels ();
			void ManageInboundTunnels ();
			void ManageTransitTunnels ();
			void ManagePendingTunnels ();
			template<class PendingTunnels>
			void ManagePendingTunnels (PendingTunnels& pendingTunnels);
			void ManageTunnelPools ();
			
			void CreateZeroHopsInboundTunnel ();
			
		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_PendingInboundTunnels; // by replyMsgID
			std::map<uint32_t, std::shared_ptr<OutboundTunnel> > m_PendingOutboundTunnels; // by replyMsgID
			std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_InboundTunnels;
			std::list<std::shared_ptr<OutboundTunnel> > m_OutboundTunnels;
			std::mutex m_TransitTunnelsMutex;
			std::map<uint32_t, TransitTunnel *> m_TransitTunnels;
			std::mutex m_PoolsMutex;
			std::list<std::shared_ptr<TunnelPool>> m_Pools;
			std::shared_ptr<TunnelPool> m_ExploratoryPool;
			i2p::util::Queue<I2NPMessage> m_Queue;

			// some stats
			int m_NumSuccesiveTunnelCreations, m_NumFailedTunnelCreations;

		public:

			// for HTTP only
			const decltype(m_OutboundTunnels)& GetOutboundTunnels () const { return m_OutboundTunnels; };
			const decltype(m_InboundTunnels)& GetInboundTunnels () const { return m_InboundTunnels; };
			const decltype(m_TransitTunnels)& GetTransitTunnels () const { return m_TransitTunnels; };
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
