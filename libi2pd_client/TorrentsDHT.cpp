/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NO_TORRENTS

#include <string.h>
#include "I2PEndian.h"
#include "TorrentsTunnel.h"
#include "TorrentsDHT.h"

namespace i2p
{
namespace torrents
{
	NodeDistance operator^(const NodeID& node1, const NodeID& node2)
	{
		NodeDistance d;

		d.l[0] = node1.l[0] ^ node2.l[0];
		d.l[1] = node1.l[1] ^ node2.l[1];
		d.l[2] = node1.l[2] ^ node2.l[2];
		d.l[3] = node1.l[3] ^ node2.l[3];
		d.l[4] = node1.l[4] ^ node2.l[4];

		return d;
	}

	RoutingTable::RoutingTable (const NodeID& ourNode):
		m_OurNode (ourNode)
	{
		m_Buckets.push_back (std::make_shared<Bucket> ());
	}

	std::shared_ptr<Bucket> RoutingTable::FindBucket (const NodeID& id)
	{
		if (m_Buckets.empty ()) return nullptr;
		auto it = m_Buckets.begin ();
		while (std::next (it) != m_Buckets.end ())
		{
			if (id < (*std::next (it))->start)
				return *it;
			it++;
		}
		return *it;
	}

	std::shared_ptr<Node> RoutingTable::AddNode (const NodeID& id, i2p::data::IdentHash& peer, uint16_t port)
	{
		if (id == m_OurNode) return nullptr;
		auto bucket = FindBucket (id);
		if (!bucket) return nullptr;
		auto node = std::make_shared<Node>(id, peer, port);
		bucket->nodes.emplace_back (node);
		return node;
	}

	TorrentsDHT::TorrentsDHT (TorrentsTunnel& tunnel, uint16_t port):
		m_Tunnel (tunnel), m_Port (port)
	{
		auto dest = tunnel.GetLocalDestination ();
		if (dest)
		{
			memcpy (m_NodeID.buf, dest->GetIdentHash (), m_NodeID.len);
			m_NodeID.buf[4] ^= (port >> 8);
			m_NodeID.buf[5] ^= (port & 0xFF);
			memcpy (m_NodeInfo.data (), m_NodeID.buf, m_NodeID.len);
			memcpy (m_NodeInfo.data () + m_NodeID.len, dest->GetIdentHash (), i2p::data::IdentHash::len);
			htobe16buf (m_NodeInfo.data () + m_NodeInfo.size () - 2, port);
			m_RoutingTable = std::make_unique<RoutingTable> (m_NodeID);
		}
		else
		{
			memset (m_NodeID.buf, 0, m_NodeID.len);
			m_NodeInfo.fill (0);
		}
	}

	void TorrentsDHT::Start ()
	{
		auto dest = m_Tunnel.GetLocalDestination ();
		if (dest)
		{
			auto dgramDest = dest->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->SetReceiver (std::bind_front (&TorrentsDHT::HandleDatagram, this));
		}
	}

	void TorrentsDHT::Stop ()
	{
		auto dest = m_Tunnel.GetLocalDestination ();
		if (dest)
		{
			auto dgramDest = dest->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->ResetReceiver ();
		}
	}

	void TorrentsDHT::HandleRawDatagram (const uint8_t * buf, size_t len)
	{
	}

	void TorrentsDHT::HandleDatagram (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
			const uint8_t * buf, size_t len, const i2p::util::Mapping * options)
	{
	}
}
}

#endif
