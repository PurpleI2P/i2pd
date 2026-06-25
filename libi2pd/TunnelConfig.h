/*
* Copyright (c) 2013-2026, The PurpleI2P Project
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
		virtual void DecryptRecord (uint8_t * records, int index) const = 0;
		virtual std::pair<const uint8_t *, uint64_t> GetGarlicKey () const { return { nullptr, 0}; }; // return [key,tag]
	};

	struct ShortECIESTunnelHopConfig: public TunnelHopConfig, public i2p::crypto::NoiseSymmetricState
	{
		ShortECIESTunnelHopConfig (std::shared_ptr<const i2p::data::IdentityEx> r):
			TunnelHopConfig (r) {};

		void EncryptECIES (const uint8_t * clearText, uint8_t * encrypted);

		uint8_t GetRetCode (const uint8_t * records) const override
		{ return (records + recordIndex*SHORT_TUNNEL_BUILD_RECORD_SIZE)[SHORT_RESPONSE_RECORD_RET_OFFSET]; };
		void CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID) override;
		bool DecryptBuildResponseRecord (uint8_t * records) const override;
		void DecryptRecord (uint8_t * records, int index) const override; // Chacha20
		std::pair<const uint8_t *, uint64_t> GetGarlicKey () const override;
	};

	struct ShortPhonyTunnelHopConfig: public TunnelHopConfig
	{
		ShortPhonyTunnelHopConfig (): TunnelHopConfig (nullptr) {}
		uint8_t GetRetCode (const uint8_t * records) const override { return 0; }
		bool DecryptBuildResponseRecord (uint8_t * records) const override { return true; }
		void DecryptRecord (uint8_t * records, int index) const override {} // do nothing
		void CreateBuildRequestRecord (uint8_t * records, uint32_t replyMsgID) override;
	};

	class TunnelConfig
	{
		public:

			TunnelConfig (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers,
				i2p::data::RouterInfo::CompatibleTransports farEndTransports = i2p::data::RouterInfo::eAllTransports); // inbound

			TunnelConfig (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers,
				uint32_t replyTunnelID, const i2p::data::IdentHash& replyIdent,
				i2p::data::RouterInfo::CompatibleTransports farEndTransports = i2p::data::RouterInfo::eAllTransports); // outbound

			virtual ~TunnelConfig ()
			{
				TunnelHopConfig * hop = m_FirstHop;

				while (hop)
				{
					auto tmp = hop;
					hop = hop->next;
					delete tmp;
				}
			}

			i2p::data::RouterInfo::CompatibleTransports GetFarEndTransports () const
			{
				return m_FarEndTransports;
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

			size_t GetRecordSize () const { return SHORT_TUNNEL_BUILD_RECORD_SIZE; };

			void CreatePhonyHop ();
			void DeletePhonyHop ();

		protected:

			// this constructor can't be called from outside
			TunnelConfig (): m_FirstHop (nullptr), m_LastHop (nullptr),
				m_FarEndTransports (i2p::data::RouterInfo::eAllTransports)
			{
			}

		private:

			void CreatePeers (const std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers);

		private:

			TunnelHopConfig * m_FirstHop, * m_LastHop;
			i2p::data::RouterInfo::CompatibleTransports m_FarEndTransports;
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
