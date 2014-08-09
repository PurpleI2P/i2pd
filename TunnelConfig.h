#ifndef TUNNEL_CONFIG_H__
#define TUNNEL_CONFIG_H__

#include <inttypes.h>
#include <sstream>
#include <vector>
#include "aes.h"
#include "RouterInfo.h"
#include "RouterContext.h"

namespace i2p
{
namespace tunnel
{
	struct TunnelHopConfig
	{
		const i2p::data::RouterInfo * router, * nextRouter;
		uint32_t tunnelID, nextTunnelID;
		uint8_t layerKey[32];
		uint8_t ivKey[32];
		uint8_t replyKey[32];
		uint8_t replyIV[16];
		bool isGateway, isEndpoint;	
		
		TunnelHopConfig * next, * prev;
		i2p::crypto::TunnelDecryption decryption;	
		int recordIndex; // record # in tunnel build message
		
		TunnelHopConfig (const i2p::data::RouterInfo * r)
		{
			CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
			rnd.GenerateBlock (layerKey, 32);
			rnd.GenerateBlock (ivKey, 32);
			rnd.GenerateBlock (replyIV, 16);
			tunnelID = rnd.GenerateWord32 ();
			isGateway = true;
			isEndpoint = true;
			router = r; 
			nextRouter = 0;
			nextTunnelID = 0;

			next = 0;
			prev = 0;
		}	

		void SetNextRouter (const i2p::data::RouterInfo * r)
		{
			nextRouter = r;
			isEndpoint = false;
			CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
			nextTunnelID = rnd.GenerateWord32 ();
		}	

		void SetReplyHop (const TunnelHopConfig * replyFirstHop)
		{
			nextRouter = replyFirstHop->router;
			nextTunnelID = replyFirstHop->tunnelID;
			isEndpoint = true;
		}
		
		void SetNext (TunnelHopConfig * n)
		{
			next = n;
			if (next)
			{	
				next->prev = this;
				next->isGateway = false;
				isEndpoint = false;
				nextRouter = next->router;
				nextTunnelID = next->tunnelID;
			}	
		}

		void SetPrev (TunnelHopConfig * p)
		{
			prev = p;
			if (prev) 
			{	
				prev->next = this;
				prev->isEndpoint = false;
				isGateway = false;
			}	
		}
	};	

	class TunnelConfig
	{
		public:			
			

			TunnelConfig (std::vector<const i2p::data::RouterInfo *> peers, 
				const TunnelConfig * replyTunnelConfig = nullptr) // replyTunnelConfig=nullptr means inbound
			{
				TunnelHopConfig * prev = nullptr;
				for (auto it: peers)
				{
					auto hop = new TunnelHopConfig (it);
					if (prev)
						prev->SetNext (hop);
					else	
						m_FirstHop = hop;
					prev = hop;
				}	
				m_LastHop = prev;
				
				if (replyTunnelConfig) // outbound
				{
					m_FirstHop->isGateway = false;
					m_LastHop->SetReplyHop (replyTunnelConfig->GetFirstHop ());
				}	
				else // inbound
					m_LastHop->SetNextRouter (&i2p::context.GetRouterInfo ());
			}
			
			~TunnelConfig ()
			{
				TunnelHopConfig * hop = m_FirstHop;
				
				while (hop)
				{
					auto tmp = hop;
					hop = hop->next;
					delete tmp;
				}	
			}
			
			TunnelHopConfig * GetFirstHop () const
			{
				return m_FirstHop;
			}

			TunnelHopConfig * GetLastHop () const
			{
				return m_LastHop;
			}

			int GetNumHops () const
			{
				int num = 0;
				TunnelHopConfig * hop = m_FirstHop;		
				while (hop)
				{
					num++;
					hop = hop->next;
				}	
				return num;
			}

			void Print (std::stringstream& s) const
			{
				TunnelHopConfig * hop = m_FirstHop;
				if (!m_FirstHop->isGateway)
					s << "me";
				s << "-->" << m_FirstHop->tunnelID;
				while (hop)
				{
					s << ":" << hop->router->GetIdentHashAbbreviation () << "-->"; 
					if (!hop->isEndpoint)
						s << hop->nextTunnelID;
					else
						return;
					hop = hop->next;
				}	
				// we didn't reach enpoint that mean we are last hop
				s << ":me";	
			}

			TunnelConfig * Invert () const
			{
				TunnelConfig * newConfig = new TunnelConfig ();
				TunnelHopConfig * hop = m_FirstHop, * nextNewHop = nullptr;
				while (hop)
				{
					TunnelHopConfig * newHop = new TunnelHopConfig (hop->router);
					if (nextNewHop)
						newHop->SetNext (nextNewHop);
					nextNewHop = newHop;
					newHop->isEndpoint = hop->isGateway;
					newHop->isGateway = hop->isEndpoint;
					
					if (!hop->prev) // first hop
					{	
						newConfig->m_LastHop = newHop; 
						if (hop->isGateway) // inbound tunnel
							newHop->SetReplyHop (m_FirstHop); // use it as reply tunnel
						else
							newHop->SetNextRouter (&i2p::context.GetRouterInfo ());
					}	
					if (!hop->next) newConfig->m_FirstHop = newHop; // last hop
									
					hop = hop->next;
				}	
				return newConfig;
			}

			TunnelConfig * Clone (const TunnelConfig * replyTunnelConfig = nullptr) const
			{
				std::vector<const i2p::data::RouterInfo *> peers;
				TunnelHopConfig * hop = m_FirstHop;
				while (hop)
				{
					peers.push_back (hop->router);
					hop = hop->next;
				}	
				return new TunnelConfig (peers, replyTunnelConfig);
			}	
			
		private:

			// this constructor can't be called from outside
			TunnelConfig (): m_FirstHop (nullptr), m_LastHop (nullptr)
			{
			}
			
		private:

			TunnelHopConfig * m_FirstHop, * m_LastHop;
	};	
}		
}	

#endif
