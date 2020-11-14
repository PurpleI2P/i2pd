/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TUNNEL_CONFIG_H__
#define TUNNEL_CONFIG_H__

#include <vector>
#include "Identity.h"
#include "RouterContext.h"
#include "Crypto.h"

namespace i2p
{
namespace tunnel
{
	struct TunnelHopConfig: public i2p::crypto::NoiseSymmetricState
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
	
		TunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r);
	
		void SetNextIdent (const i2p::data::IdentHash& ident);
		void SetReplyHop (uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent);
		void SetNext (TunnelHopConfig * n);
		void SetPrev (TunnelHopConfig * p);		

		bool IsECIES () const { return ident->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD; };
		void CreateBuildRequestRecord (uint8_t * record, uint32_t replyMsgID, BN_CTX * ctx);
		void EncryptECIES (std::shared_ptr<i2p::crypto::CryptoKeyEncryptor>& encryptor, 
			const uint8_t * clearText, uint8_t * encrypted, BN_CTX * ctx);
	};

	void InitBuildRequestRecordNoiseState (i2p::crypto::NoiseSymmetricState& state);	
	
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
