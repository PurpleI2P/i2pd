#ifndef TUNNEL_CONFIG_H__
#define TUNNEL_CONFIG_H__

#include <inttypes.h>
#include <sstream>
#include <vector>
#include <memory>
#include "Crypto.h"
#include "Identity.h"
#include "RouterContext.h"
#include "Timestamp.h"

namespace i2p
{
namespace tunnel
{
	struct TunnelHopConfig
	{
		std::shared_ptr<const i2p::data::IdentityEx> ident;
		i2p::data::IdentHash nextIdent;
		uint32_t tunnelID, nextTunnelID;
		uint8_t layerKey[32];
		uint8_t ivKey[32];
		uint8_t replyKey[32];
		uint8_t replyIV[16];
		bool isGateway, isEndpoint;	
		
		TunnelHopConfig * next, * prev;
		int recordIndex; // record # in tunnel build message
		
		TunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r)
		{
			RAND_bytes (layerKey, 32);
			RAND_bytes (ivKey, 32);
			RAND_bytes (replyKey, 32);
			RAND_bytes (replyIV, 16);
			RAND_bytes ((uint8_t *)&tunnelID, 4);
			isGateway = true;
			isEndpoint = true;
			ident = r; 
			//nextRouter = nullptr; 
			nextTunnelID = 0;

			next = nullptr;
			prev = nullptr;
		}	

		void SetNextIdent (const i2p::data::IdentHash& ident)
		{
			nextIdent = ident;
			isEndpoint = false;
			RAND_bytes ((uint8_t *)&nextTunnelID, 4);
		}	

		void SetReplyHop (uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent)
		{
			nextIdent = replyIdent;
			nextTunnelID = replyTunnelID;
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
				nextIdent = next->ident->GetIdentHash ();
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

		void CreateBuildRequestRecord (uint8_t * record, uint32_t replyMsgID, BN_CTX * ctx) const
		{
			uint8_t clearText[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
			htobe32buf (clearText + BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET, tunnelID); 
			memcpy (clearText + BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET, ident->GetIdentHash (), 32);
			htobe32buf (clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET, nextTunnelID);
			memcpy (clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET, nextIdent, 32);
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
			RAND_bytes (clearText + BUILD_REQUEST_RECORD_PADDING_OFFSET, BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE - BUILD_REQUEST_RECORD_PADDING_OFFSET);
			i2p::crypto::ElGamalEncrypt (ident->GetEncryptionPublicKey (), clearText, record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, ctx);
			memcpy (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)ident->GetIdentHash (), 16);
		}	
	};	

	class TunnelConfig
	{
		public:			
			
			TunnelConfig (std::vector<std::shared_ptr<const i2p::data::IdentityEx> > peers) // inbound
			{
				CreatePeers (peers);
				m_LastHop->SetNextIdent (i2p::context.GetIdentHash ());
			}

			TunnelConfig (std::vector<std::shared_ptr<const i2p::data::IdentityEx> > peers, 
				uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent) // outbound
			{
				CreatePeers (peers);
				m_FirstHop->isGateway = false;
				m_LastHop->SetReplyHop (replyTunnelID, replyIdent);
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

			bool IsEmpty () const
			{
				return !m_FirstHop;
			}			

			virtual bool IsInbound () const { return m_FirstHop->isGateway; }

			virtual uint32_t GetTunnelID () const 
			{	
				if (!m_FirstHop) return 0;
				return IsInbound () ? m_LastHop->nextTunnelID : m_FirstHop->tunnelID; 
			}

			virtual uint32_t GetNextTunnelID () const 
			{	
				if (!m_FirstHop) return 0;
				return m_FirstHop->tunnelID; 
			}

			virtual const i2p::data::IdentHash& GetNextIdentHash () const 
			{ 
				return m_FirstHop->ident->GetIdentHash (); 
			}	

			virtual const i2p::data::IdentHash& GetLastIdentHash () const 
			{ 
				return m_LastHop->ident->GetIdentHash (); 
			}	
			
			std::vector<std::shared_ptr<const i2p::data::IdentityEx> > GetPeers () const
			{
				std::vector<std::shared_ptr<const i2p::data::IdentityEx> > peers;
				TunnelHopConfig * hop = m_FirstHop;		
				while (hop)
				{
					peers.push_back (hop->ident);
					hop = hop->next;
				}	
				return peers;
			}
			
		protected:

			// this constructor can't be called from outside
			TunnelConfig (): m_FirstHop (nullptr), m_LastHop (nullptr)
			{
			}
	
		private:

			template<class Peers>
			void CreatePeers (const Peers& peers)
			{
				TunnelHopConfig * prev = nullptr;
				for (const auto& it: peers)
				{
					auto hop = new TunnelHopConfig (it);
					if (prev)
						prev->SetNext (hop);
					else	
						m_FirstHop = hop;
					prev = hop;
				}	
				m_LastHop = prev;
			}
			
		private:

			TunnelHopConfig * m_FirstHop, * m_LastHop;
	};

	class ZeroHopsTunnelConfig: public TunnelConfig
	{
		public:

			ZeroHopsTunnelConfig () { RAND_bytes ((uint8_t *)&m_TunnelID, 4);};

			bool IsInbound () const { return true; }; // TODO:		
			uint32_t GetTunnelID () const { return m_TunnelID; };
			uint32_t GetNextTunnelID () const { return m_TunnelID; };
			const i2p::data::IdentHash& GetNextIdentHash () const { return i2p::context.GetIdentHash (); };
			const i2p::data::IdentHash& GetLastIdentHash () const { return i2p::context.GetIdentHash (); };


		private:
		
			uint32_t m_TunnelID;	
	};	
}		
}	

#endif
