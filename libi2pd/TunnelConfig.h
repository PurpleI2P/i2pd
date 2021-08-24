/*
* Copyright (c) 2013-2021, The PurpleI2P Project
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

		TunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r);
		virtual ~TunnelHopConfig () {};

		void SetNextIdent (const i2p::data::IdentHash& ident);
		void SetReplyHop (uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent);
		void SetNext (TunnelHopConfig * n);
		void SetPrev (TunnelHopConfig * p);

		virtual uint8_t GetRetCode (const uint8_t * records) const = 0;
		virtual void CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID) = 0;
		virtual bool DecryptBuildResponseRecord (uint8_t * records) const = 0;
		virtual void DecryptRecord (uint8_t * records, int index) const; // AES
		virtual uint64_t GetGarlicKey (uint8_t * key) const { return 0; }; // return tag
	};

	struct ElGamalTunnelHopConfig: public TunnelHopConfig
	{
		ElGamalTunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r):
			TunnelHopConfig (r) {};
		uint8_t GetRetCode (const uint8_t * records) const
		{ return (records + recordIndex*TUNNEL_BUILD_RECORD_SIZE)[BUILD_RESPONSE_RECORD_RET_OFFSET]; };
		void CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID);
		bool DecryptBuildResponseRecord (uint8_t * records) const;
	};

	struct ECIESTunnelHopConfig: public TunnelHopConfig, public i2p::crypto::NoiseSymmetricState
	{
		ECIESTunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r):
			TunnelHopConfig (r) {};
		void EncryptECIES (const uint8_t * clearText, size_t len, uint8_t * encrypted);
		bool DecryptECIES (const uint8_t * key, const uint8_t * nonce, const uint8_t * encrypted, size_t len, uint8_t * clearText) const;
	};

	struct LongECIESTunnelHopConfig: public ECIESTunnelHopConfig
	{
		LongECIESTunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r):
			ECIESTunnelHopConfig (r) {};
		uint8_t GetRetCode (const uint8_t * records) const override
		{ return (records + recordIndex*TUNNEL_BUILD_RECORD_SIZE)[ECIES_BUILD_RESPONSE_RECORD_RET_OFFSET]; };
		void CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID) override;
		bool DecryptBuildResponseRecord (uint8_t * records) const override;
	};

	struct ShortECIESTunnelHopConfig: public ECIESTunnelHopConfig
	{
		ShortECIESTunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r):
			ECIESTunnelHopConfig (r) {};
		uint8_t GetRetCode (const uint8_t * records) const override
		{ return (records + recordIndex*SHORT_TUNNEL_BUILD_RECORD_SIZE)[SHORT_RESPONSE_RECORD_RET_OFFSET]; };
		void CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID) override;
		bool DecryptBuildResponseRecord (uint8_t * records) const override;
		void DecryptRecord (uint8_t * records, int index) const override; // Chacha20
		uint64_t GetGarlicKey (uint8_t * key) const override;
	};

	class TunnelConfig
	{
		public:

			TunnelConfig (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers,
				bool isShort = false): // inbound
				m_IsShort (isShort)
			{
				CreatePeers (peers);
				m_LastHop->SetNextIdent (i2p::context.GetIdentHash ());
			}

			TunnelConfig (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers,
				uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent, bool isShort = false): // outbound
				m_IsShort (isShort)
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

			bool IsShort () const { return m_IsShort; }

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
			TunnelConfig (): m_FirstHop (nullptr), m_LastHop (nullptr), m_IsShort (false)
			{
			}

		private:

			void CreatePeers (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers)
			{
				TunnelHopConfig * prev = nullptr;
				for (const auto& it: peers)
				{
					TunnelHopConfig * hop;
					if (m_IsShort)
						hop = new ShortECIESTunnelHopConfig (it);
					else
					{
						if (it->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
							hop = new LongECIESTunnelHopConfig (it);
						else
							hop = new ElGamalTunnelHopConfig (it);
					}
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
			bool m_IsShort;
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
