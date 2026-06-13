/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef IDENT_METRICS_H__
#define IDENT_METRICS_H__

#include <inttypes.h>
#include <string.h>
#include <unordered_map>
#include "Tag.h"
#include "Identity.h"
#include "Crypto.h"

namespace i2p
{
namespace data
{
	// kademlia
	struct XORMetric
	{
		union
		{
			uint8_t metric[32];
			uint64_t metric_ll[4];
		};

		void SetMin () { memset (metric, 0, 32); };
		void SetMax () { memset (metric, 0xFF, 32); };
		bool operator< (const XORMetric& other) const { return memcmp (metric, other.metric, 32) < 0; };
	};

	IdentHash CreateRoutingKey (const IdentHash& ident, bool nextDay = false);
	XORMetric operator^(const IdentHash& key1, const IdentHash& key2);

	// peer ordering
	constexpr uint64_t PEER_ORDERING_INACTIVITY_TIMEOUT = 400; // in seconds
	class PeerOrdering
	{
		public:

			PeerOrdering ();
			~PeerOrdering ();
			void CleanUp (uint64_t ts);

			void SetKey (const uint8_t * key);
			const Tag<16>& GetKey () const { return m_PeerOrderingKey; }

			int GetPeerOrderingGroup (const IdentHash& routerIdent);
			bool IsFirstHop (const IdentHash& routerIdent) { return !GetPeerOrderingGroup (routerIdent); };
			bool IsLastHop (const IdentHash& routerIdent) { return GetPeerOrderingGroup (routerIdent) & 0x02; }; // IBGW or OBEP

		private:

			int CalculatePeerOrderingGroup (const IdentHash& routerIdent);

		private:

			Tag<16> m_PeerOrderingKey;
			std::unordered_map<IdentHash, std::pair<int, uint64_t> > m_OrderingGroups; // router ident hash -> (group, last request time)
#if OPENSSL_SIPHASH
			EVP_MD_CTX * m_MDCtx = nullptr;
#endif
	};
}
}

#endif
