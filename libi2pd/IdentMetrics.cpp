/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "Siphash.h"
#include "util.h"
#include "Timestamp.h"
#include "IdentMetrics.h"

namespace i2p
{
namespace data
{
	IdentHash CreateRoutingKey (const IdentHash& ident, bool nextDay)
	{
		uint8_t buf[41]; // ident + yyyymmdd
		memcpy (buf, (const uint8_t *)ident, 32);
		if (nextDay)
			i2p::util::GetNextDayDate ((char *)(buf + 32));
		else
			i2p::util::GetCurrentDate ((char *)(buf + 32));
		IdentHash key;
		SHA256(buf, 40, key);
		return key;
	}

	XORMetric operator^(const IdentHash& key1, const IdentHash& key2)
	{
		XORMetric m;

		const uint64_t * hash1 = key1.GetLL (), * hash2 = key2.GetLL ();
		m.metric_ll[0] = hash1[0] ^ hash2[0];
		m.metric_ll[1] = hash1[1] ^ hash2[1];
		m.metric_ll[2] = hash1[2] ^ hash2[2];
		m.metric_ll[3] = hash1[3] ^ hash2[3];

		return m;
	}

	PeerOrdering::PeerOrdering ()
	{
		SetKey (nullptr);
	}

	PeerOrdering::~PeerOrdering ()
	{
#if OPENSSL_SIPHASH
		if (m_MDCtx) EVP_MD_CTX_destroy (m_MDCtx);
#endif
	}

	void PeerOrdering::SetKey (const uint8_t * key)
	{
		if (key)
			memcpy (m_PeerOrderingKey, key, 16);
		else
			RAND_bytes (m_PeerOrderingKey, 16);
#if OPENSSL_SIPHASH
		if (m_MDCtx) EVP_MD_CTX_destroy (m_MDCtx); // delete previous
		EVP_PKEY * sipKey = EVP_PKEY_new_raw_private_key (EVP_PKEY_SIPHASH, nullptr, m_PeerOrderingKey, 16);
		m_MDCtx = EVP_MD_CTX_create ();
		EVP_DigestSignInit (m_MDCtx, nullptr, nullptr, nullptr, sipKey);
		EVP_PKEY_free (sipKey);
#endif
	}

	int PeerOrdering::CalculatePeerOrderingGroup (const IdentHash& routerIdent)
	{
		uint8_t hash[16];
#if OPENSSL_SIPHASH
		EVP_DigestSignInit (m_MDCtx, nullptr, nullptr, nullptr, nullptr);
		EVP_DigestSignUpdate (m_MDCtx, routerIdent, 32);
		size_t l = 16;
		EVP_DigestSignFinal (m_MDCtx, hash, &l);
#else
		i2p::crypto::Siphash<16> (hash, routerIdent, 32, m_PeerOrderingKey);
#endif
		return hash[0] & 0x03;
	}

	int PeerOrdering::GetPeerOrderingGroup (const IdentHash& routerIdent)
	{
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		auto it = m_OrderingGroups.find (routerIdent);
		if (it != m_OrderingGroups.end ())
		{
			it->second.second = ts;
			return it->second.first;
		}
		int group = CalculatePeerOrderingGroup (routerIdent);
		m_OrderingGroups.emplace (routerIdent, std::pair{group, ts});
		return group;
	}

	void PeerOrdering::CleanUp (uint64_t ts)
	{
		for (auto it = m_OrderingGroups.begin (); it != m_OrderingGroups.end ();)
		{
			if (ts > it->second.second + PEER_ORDERING_INACTIVITY_TIMEOUT)
				it = m_OrderingGroups.erase (it);
			else
				it++;
		}
	}
}
}
