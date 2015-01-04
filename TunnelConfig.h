#ifndef TUNNEL_CONFIG_H__
#define TUNNEL_CONFIG_H__

#include <inttypes.h>
#include <sstream>
#include <vector>
#include <memory>
#include "aes.h"
#include "RouterInfo.h"
#include "RouterContext.h"
#include "Timestamp.h"

namespace i2p
{
namespace tunnel
{
	struct TunnelHopConfig
	{
		std::shared_ptr<const i2p::data::RouterInfo> router, nextRouter;
		uint32_t tunnelID, nextTunnelID;
		uint8_t layerKey[32];
		uint8_t ivKey[32];
		uint8_t replyKey[32];
		uint8_t replyIV[16];
		bool isGateway, isEndpoint;	
		
		TunnelHopConfig * next, * prev;
		i2p::crypto::TunnelDecryption decryption;	
		int recordIndex; // record # in tunnel build message
		
		TunnelHopConfig (std::shared_ptr<const i2p::data::RouterInfo> r)
		{
			CryptoPP::RandomNumberGenerator& rnd = i2p::context.GetRandomNumberGenerator ();
			rnd.GenerateBlock (layerKey, 32);
			rnd.GenerateBlock (ivKey, 32);
			rnd.GenerateBlock (replyIV, 16);
			tunnelID = rnd.GenerateWord32 ();
			isGateway = true;
			isEndpoint = true;
			router = r; 
			//nextRouter = nullptr; 
			nextTunnelID = 0;

			next = nullptr;
			prev = nullptr;
		}	

		void SetNextRouter (std::shared_ptr<const i2p::data::RouterInfo> r)
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

		void CreateBuildRequestRecord (uint8_t * record, uint32_t replyMsgID)
		{
			uint8_t clearText[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
			htobe32buf (clearText + BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET, tunnelID); 
			memcpy (clearText + BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET, router->GetIdentHash (), 32);
			htobe32buf (clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET, nextTunnelID);
			memcpy (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET, nextRouter->GetIdentHash (), 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET, layerKey, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_IV_KEY_OFFSET, ivKey, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET, replyKey, 32);
			memcpy (clearText + BUILD_REQUEST_RECORD_REPLY_IV_OFFSET, replyIV, 16);
			uint8_t flag = 0;
			if (isGateway) flag |= 0x80;
			if (isEndpoint) flag |= 0x40;
			clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] = flag;
			htobe32buf (clearText + BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET, i2p::util::GetHoursSinceEpoch ()); 
			htobe32buf (clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET, replyMsgID); 
			// TODO: fill padding
			router->GetElGamalEncryption ()->Encrypt (clearText, BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET);
			memcpy (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)router->GetIdentHash (), 16);
		}	
	};	

	class TunnelConfig
	{
		public:			
			

			TunnelConfig (std::vector<std::shared_ptr<const i2p::data::RouterInfo> > peers, 
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
					m_LastHop->SetNextRouter (i2p::context.GetSharedRouterInfo ());
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
							newHop->SetNextRouter (i2p::context.GetSharedRouterInfo ());
					}	
					if (!hop->next) newConfig->m_FirstHop = newHop; // last hop
									
					hop = hop->next;
				}	
				return newConfig;
			}

			TunnelConfig * Clone (const TunnelConfig * replyTunnelConfig = nullptr) const
			{
				std::vector<std::shared_ptr<const i2p::data::RouterInfo> > peers;
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
