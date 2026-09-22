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
	NodeID Bucket::GetMiddleID () const
	{
		NodeID middleID = start;
		int bit = std::max (start.FindLowestBit (), next ? next->start.FindLowestBit () : -1) + 1;
		middleID[bit >> 3] |= (0x80 >> (bit & 0x07));
		return middleID;
	}

	void Bucket::Split ()
	{
		auto middleID = GetMiddleID ();
		auto newBucket = new Bucket (middleID);
		newBucket->next = next;
		next = newBucket;
		// move some nodes
		auto it = nodes.begin ();
		while (it != nodes.end ())
		{
			if ((*it)->id < middleID)
				it++; // stay in old bucket
			else
			{
				// move to new bucket
				auto node = *it;
				it = nodes.erase (it);
				newBucket->nodes.push_back (node);
			}
		}
	}

	RoutingTable::RoutingTable (const NodeID& ourNode):
		m_OurNode (ourNode)
	{
		m_Buckets = new Bucket;
	}

	RoutingTable::~RoutingTable ()
	{
		while (m_Buckets)
		{
			auto bucket = m_Buckets;
			m_Buckets = m_Buckets->next;
			delete bucket;
		}
	}

	Bucket * RoutingTable::FindBucket (const Torrent::InfoHash& id) const
	{
		if (!m_Buckets) return nullptr;
		auto bucket = m_Buckets;
		while (bucket->next)
		{
			if (id < bucket->next->start)
				return bucket;
			bucket = bucket->next;
		}
		return bucket;
	}

	void RoutingTable::RemoveEmptyBuckers ()
	{
		if (m_Buckets)
		{
			auto prev = m_Buckets, bucket = m_Buckets->next;
			while (bucket)
			{
				if (bucket->nodes.empty ())
				{
					prev->next = bucket->next;
					auto tmp = bucket;
					bucket = bucket->next;
					delete tmp;
				}
				else
				{
					prev = bucket;
					bucket = bucket->next;
				}
			}
		}
	}

	std::shared_ptr<Node> RoutingTable::AddNode (const NodeID& id, i2p::data::IdentHash& peer, uint16_t port)
	{
		if (id == m_OurNode) return nullptr;
		auto bucket = FindBucket (id);
		if (!bucket) return nullptr;
		if (bucket->IsFull () && !bucket->IsInBucket (m_OurNode)) return nullptr;

		std::shared_ptr<Node> node;
		do
		{
			bucket->Split ();
			bucket = FindBucket (id);
		}
		while (bucket->IsFull ());

		if (bucket)
		{
			node = std::make_shared<Node>(id, peer, port);
			bucket->nodes.emplace_back (node);
		}
		RemoveEmptyBuckers ();
		return node;
	}

	std::list<std::pair<std::shared_ptr<Node>, Distance> > RoutingTable::FindClosestNodes (const Torrent::InfoHash& infoHash, size_t num) const
	{
		std::list<std::pair<std::shared_ptr<Node>, Distance> > ret;
		if (num > 0)
		{
			auto bucket = FindBucket (infoHash);
			if (bucket)
			{
				for (auto it: bucket->nodes)
				{
					auto nodeDistance = it->id ^ infoHash;
					auto it1 = std::find_if (ret.begin (), ret.end (),
						[&nodeDistance](const std::pair<std::shared_ptr<Node>, Distance>& alreadyFound)
						{
							return nodeDistance < alreadyFound.second;
						});
					ret.insert (it1, { it, nodeDistance } );
				}
				if (ret.size () > num) ret.resize (num);
			}
		}
		return ret;
	}

	TorrentsDHT::TorrentsDHT (TorrentsTunnel& tunnel, uint16_t port):
		m_Tunnel (tunnel), m_Port (port)
	{
		auto dest = tunnel.GetLocalDestination ();
		if (dest)
		{
			memcpy (m_NodeID.data (), dest->GetIdentHash (), m_NodeID.size ());
			m_NodeID[4] ^= (port >> 8);
			m_NodeID[5] ^= (port & 0xFF);
			memcpy (m_NodeInfo.data (), m_NodeID.data (), m_NodeID.size ());
			memcpy (m_NodeInfo.data () + m_NodeID.size (), dest->GetIdentHash (), i2p::data::IdentHash::len);
			htobe16buf (m_NodeInfo.data () + m_NodeInfo.size () - 2, port);
			m_RoutingTable = std::make_unique<RoutingTable> (m_NodeID);
		}
		else
		{
			m_NodeID.fill (0);
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
