#ifndef TUNNEL_H__
#define TUNNEL_H__

#include <inttypes.h>
#include <map>
#include <list>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
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
	
	class OutboundTunnel;
	class InboundTunnel;
	class Tunnel: public TunnelBase
	{
		public:

			Tunnel (TunnelConfig * config);
			~Tunnel ();

			void Build (uint32_t replyMsgID, OutboundTunnel * outboundTunnel = 0);
			
			TunnelConfig * GetTunnelConfig () const { return m_Config; }
			bool IsEstablished () const { return m_IsEstablished; };
			bool IsFailed () const { return m_IsFailed; };
			void SetFailed (bool failed) { m_IsFailed = failed; } 

			TunnelPool * GetTunnelPool () const { return m_Pool; };
			void SetTunnelPool (TunnelPool * pool) { m_Pool = pool; };			
			
			bool HandleTunnelBuildResponse (uint8_t * msg, size_t len);
			
			// implements TunnelBase
			void EncryptTunnelMsg (I2NPMessage * tunnelMsg); 
			uint32_t GetNextTunnelID () const { return m_Config->GetFirstHop ()->tunnelID; };
			const i2p::data::IdentHash& GetNextIdentHash () const { return m_Config->GetFirstHop ()->router->GetIdentHash (); };
			
		private:

			void LayerDecrypt (const uint8_t * in, size_t len, const uint8_t * layerKey, 
				const uint8_t * iv, uint8_t * out);
			void IVDecrypt (const uint8_t * in, const uint8_t * ivKey, uint8_t * out);	
			
		private:

			TunnelConfig * m_Config;
			TunnelPool * m_Pool; // pool, tunnel belongs to, or null
			bool m_IsEstablished, m_IsFailed; 

			CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption m_ECBDecryption;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_CBCDecryption;
	};	

	class OutboundTunnel: public Tunnel 
	{
		public:

			OutboundTunnel (TunnelConfig * config): Tunnel (config), m_Gateway (this) {};

			void SendTunnelDataMsg (const uint8_t * gwHash, uint32_t gwTunnel, i2p::I2NPMessage * msg);
			void SendTunnelDataMsg (std::vector<TunnelMessageBlock> msgs); // multiple messages
			const i2p::data::RouterInfo * GetEndpointRouter () const 
				{ return GetTunnelConfig ()->GetLastHop ()->router; }; 
			size_t GetNumSentBytes () const { return m_Gateway.GetNumSentBytes (); };

			// implements TunnelBase
			uint32_t GetTunnelID () const { return GetNextTunnelID (); };
			
		private:

			std::mutex m_SendMutex;
			TunnelGateway m_Gateway; 
	};
	
	class InboundTunnel: public Tunnel 
	{
		public:

			InboundTunnel (TunnelConfig * config): Tunnel (config) {};
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
			
			InboundTunnel * GetInboundTunnel (uint32_t tunnelID);
			Tunnel * GetPendingTunnel (uint32_t replyMsgID);
			InboundTunnel * GetNextInboundTunnel ();
			OutboundTunnel * GetNextOutboundTunnel ();
			TransitTunnel * GetTransitTunnel (uint32_t tunnelID);
			void AddTransitTunnel (TransitTunnel * tunnel);
			void AddOutboundTunnel (OutboundTunnel * newTunnel);
			void AddInboundTunnel (InboundTunnel * newTunnel);
			void PostTunnelData (I2NPMessage * msg);
			template<class TTunnel>
			TTunnel * CreateTunnel (TunnelConfig * config, OutboundTunnel * outboundTunnel = 0);
			TunnelPool * CreateTunnelPool (i2p::data::LocalDestination& localDestination);
			void DeleteTunnelPool (TunnelPool * pool);
			
		private:
			
			void Run ();	
			void ManageTunnels ();
			void ManageOutboundTunnels ();
			void ManageInboundTunnels ();
			void ManageTransitTunnels ();
			void ManageTunnelPools ();
			
			void CreateZeroHopsInboundTunnel ();
			
		private:

			bool m_IsRunning;
			bool m_IsTunnelCreated; // TODO: temporary
			uint32_t m_NextReplyMsgID; // TODO: make it random later
			std::thread * m_Thread;	
			std::map<uint32_t, Tunnel *> m_PendingTunnels; // by replyMsgID
			std::map<uint32_t, InboundTunnel *> m_InboundTunnels;
			std::list<OutboundTunnel *> m_OutboundTunnels;
			std::map<uint32_t, TransitTunnel *> m_TransitTunnels;
			std::map<i2p::data::IdentHash, TunnelPool *> m_Pools;
			TunnelPool * m_ExploratoryPool;
			i2p::util::Queue<I2NPMessage> m_Queue;

		public:

			// for HTTP only
			const decltype(m_OutboundTunnels)& GetOutboundTunnels () const { return m_OutboundTunnels; };
			const decltype(m_InboundTunnels)& GetInboundTunnels () const { return m_InboundTunnels; };
			const decltype(m_TransitTunnels)& GetTransitTunnels () const { return m_TransitTunnels; };
	};	

	extern Tunnels tunnels;
}	
}

#endif
