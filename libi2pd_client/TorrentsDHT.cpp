/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NO_TORRENTS

#include <string.h>
#include <vector>
#include <fstream>
#include "I2PEndian.h"
#include "TorrentsTunnel.h"
#include "TorrentsDHT.h"

namespace i2p
{
namespace torrents
{
	Node::Node (const NodeInfo& nodeInfo)
	{
		memcpy (id.data (), nodeInfo.data (), id.size ());
		memcpy ((uint8_t *)peer, nodeInfo.data () + id.size (), peer.len);
		port = bufbe16toh (nodeInfo.data () + nodeInfo.size () - 2);
	}

	NodeInfo Node::GetNodeInfo () const
	{
		NodeInfo nodeInfo;
		memcpy (nodeInfo.data (), id.data (), id.size ());
		memcpy (nodeInfo.data () + id.size (), peer, peer.len);
		htobe16buf (nodeInfo.data () + nodeInfo.size () - 2, port);
		return nodeInfo;
	}

	std::shared_ptr<Node> Bucket::FindNode (const NodeID& id) const
	{
		auto it = std::find_if (nodes.begin (), nodes.end (),
			[&id](std::shared_ptr<const Node> node)
			{
				return node->id == id;
			});
		return (it != nodes.end ()) ? *it : nullptr;
	}

	std::optional<NodeID> Bucket::GetMiddleID () const
	{
		uint8_t bit = std::max (start.FindLowestBit (), next ? next->start.FindLowestBit () : -1) + 1;
		if (bit >= NodeID::len * 8) return {};
		NodeID middleID = start;
		middleID[bit >> 3] |= (0x80 >> (bit & 0x07));
		return { middleID };
	}

	bool Bucket::Split ()
	{
		auto middleID = GetMiddleID ();
		if (!middleID) return false;
		auto newBucket = new Bucket (*middleID);
		newBucket->next = next;
		next = newBucket;
		// move some nodes
		auto it = nodes.begin ();
		while (it != nodes.end ())
		{
			if ((*it)->id < *middleID)
				it++; // stay in old bucket
			else
			{
				// move to new bucket
				auto node = *it;
				it = nodes.erase (it);
				newBucket->nodes.push_back (node);
			}
		}
		return true;
	}

	RoutingTable::RoutingTable (const NodeID& ourNode):
		m_OurNode (ourNode)
	{
		m_Buckets = new Bucket;
	}

	RoutingTable::~RoutingTable ()
	{
		CleanUp ();
		delete m_Buckets;
	}

	void RoutingTable::CleanUp ()
	{
		if (!m_Buckets) return;
		auto bucket = m_Buckets->next;
		while (bucket)
		{
			auto tmp = bucket;
			bucket = bucket->next;
			delete tmp;
		}
		m_Buckets->next = nullptr;
		m_Buckets->nodes.clear ();
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

	std::shared_ptr<Node> RoutingTable::AddNode (const NodeID& id, const i2p::data::IdentHash& peer, uint16_t port)
	{
		if (id == m_OurNode) return nullptr;
		auto bucket = FindBucket (id);
		if (!bucket) return nullptr;
		std::shared_ptr<Node> node = bucket->FindNode (id);
		if (node) return node;
		if (bucket->IsFull ())
		{
			if (!bucket->IsInBucket (m_OurNode)) return nullptr;
			do
			{
				if (!bucket->Split ()) return nullptr;
				bucket = FindBucket (id);
			}
			while (bucket->IsFull ());
		}
		if (bucket)
		{
			node = std::make_shared<Node>(id, peer, port);
			bucket->nodes.emplace_back (node);
		}
		RemoveEmptyBuckers ();
		return node;
	}

	std::shared_ptr<Node> RoutingTable::AddNode (const NodeInfo& nodeInfo)
	{
		Node node (nodeInfo);
		return AddNode (node.id, node.peer, node.port);
	}

	std::shared_ptr<Node> RoutingTable::FindNode (const NodeID& id) const
	{
		auto bucket = FindBucket (id);
		if (!bucket) return nullptr;
		return bucket->FindNode (id);
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

	void RoutingTable::Save (const std::filesystem::path& file)
	{
		std::ofstream f(file, std::ofstream::binary);
		if (f.is_open ())
		{
			auto bucket = m_Buckets;
			while (bucket)
			{
				for (auto it: bucket->nodes)
				{
					auto nodeInfo = it->GetNodeInfo ();
					f.write ((const char *)nodeInfo.data (), nodeInfo.size ());
				}
				bucket = bucket->next;
			}
		}
	}

	void RoutingTable::Load (const std::filesystem::path& file)
	{
		std::ifstream f (file, std::ios::in | std::ios::binary);
		if (f.is_open ())
		{
			CleanUp ();
			NodeInfo nodeInfo;
			while (f.read ((char *)nodeInfo.data (), nodeInfo.size ()))
			{
				auto bytesRead = f.gcount();
				if (bytesRead == nodeInfo.size ())
					AddNode (nodeInfo);
			}
		}
	}

	std::string DHTTorrent::GetBEncodedPeers () const
	{
		std::vector<std::string> peers;
		for (const auto& [peer, ts]: m_Peers)
			peers.emplace_back (CreateByteString (std::string_view ((const char *)peer.data (), peer.len)));
		return CreateList (peers);
	}

	void DHTTorrent::AddIncomingGetPeerNode (GetPeersToken token, std::shared_ptr<Node> node)
	{
		if (!node) return;
		m_IncomingGetPeers.emplace (token, node);
	}

	void DHTTorrent::AddOutgoingGetPeerNode (GetPeersToken token, std::shared_ptr<Node> node)
	{
		if (!node) return;
		m_OutgoingGetPeers.emplace (token, node);
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
			m_NodeInfo = Node (m_NodeID,  dest->GetIdentHash (), port).GetNodeInfo ();
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
		// response or error
		char type = 0;
		std::string transactionID, id;
		uint64_t token = 0;
		std::vector<std::string_view> values;
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&type, &transactionID, &id, &values, &token](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "y")
				{
					auto [value, l] = ExtractByteString (buf);
					if (l && !value.empty ()) type = value[0];
					return l;
				}
				else if (key == "t")
				{
					auto [value, l] = ExtractByteString (buf);
					if (l) transactionID = value;
					return l;
				}
				else if (key == "token")
				{
					auto [value, l] = ExtractByteString (buf);
					if (l && value.size () >= 8)
						memcpy (&token, value.data (), 8);
					return l;
				}
				else if (key == "r")
				{
					return ParseDictionary (buf,
						[&id, &values](std::string_view key, std::string_view buf)->size_t
						{
							if (key == "id")
							{
								auto [value, l] = ExtractByteString (buf);
								if (l) id = value;
								return l;
							}
							else if (key == "values")
							{
								auto [v, l] = ParseStringList (buf);
								if (l) values = v;
								return l;
							}
							return 0;
						});
				}
				return 0;
			});
		if (type)
		{
			switch (type)
			{
				 case 'r':
					HandleResponse (transactionID, id, token, values);
				 break;
				 case 'e':
					LogPrint (eLogDebug, "TorrentsDHT: Error msg received");
				 break;
				 case 'q':
					LogPrint (eLogError, "TorrentsDHT: Query can't come as raw datagram");
				break;
				 default:
					LogPrint (eLogInfo, "TorrentsDHT: Unxpected msg type ", (int)type);
			}
		}
	}

	void TorrentsDHT::HandleDatagram (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
			const uint8_t * buf, size_t len, const i2p::util::Mapping * options)
	{
		// query
		char type = 0;
		std::string transactionID, query, id, infoHash;
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&type, &transactionID, &query, &id, &infoHash](std::string_view key, std::string_view buf)->size_t
			{
				if (key == "y")
				{
					auto [value, l] = ExtractByteString (buf);
					if (l && !value.empty ()) type = value[0];
					return l;
				}
				else if (key == "t")
				{
					auto [value, l] = ExtractByteString (buf);
					if (l) transactionID = value;
					return l;
				}
				else if (key == "q")
				{
					auto [value, l] = ExtractByteString (buf);
					if (l) query = value;
					return l;
				}
				else if (key == "a")
				{
					return ParseDictionary (buf,
						[&id, &infoHash](std::string_view key, std::string_view buf)->size_t
						{
							if (key == "id")
							{
								auto [value, l] = ExtractByteString (buf);
								if (l) id = value;
								return l;
							}
							else if (key == "info_hash")
							{
								auto [value, l] = ExtractByteString (buf);
								if (l) infoHash = value;
								return l;
							}
							return 0;
						});
				}
				return 0;
			});
		if (type == 'q')
		{
			if (query == "ping")
				HandlePingQuery (from.GetIdentHash (), fromPort, transactionID, id);
			else if (query == "get_peers")
				HandleGetPeersQuery (from.GetIdentHash (), fromPort, transactionID, id, infoHash);
			else
				LogPrint (eLogDebug, "TorrentsDHT: Unexpected query ", query);
		}
		else if (type)
			LogPrint (eLogInfo, "TorrentsDHT: Unxpected msg type ", (int)type);
	}

	void TorrentsDHT::HandlePingQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
		std::string_view transactionID, std::string_view id)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Ping query msg received");
		SendPingResponse (transactionID, fromIdent, fromPort + 1); // to rport
	}

	void TorrentsDHT::HandleGetPeersQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
		std::string_view transactionID, std::string_view id, std::string_view infoHash)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Get peers query msg received");
		if (id.size () < NodeID::len)
		{
			LogPrint (eLogInfo, "TorrentsDHT: received id is too short ", id.size ());
			return;
		}
		NodeID nodeID;
		memcpy (nodeID.data (), id.data (), NodeID::len);
		auto node = m_RoutingTable->AddNode (nodeID, fromIdent, fromPort);
		if (!node)
		{
			LogPrint (eLogError, "TorrentsDHT: Failed to add node ", fromIdent.ToBase64 ());
			return;
		}
		Torrent::InfoHash hash;
		if (infoHash.size () < hash.size ())
		{
			LogPrint (eLogInfo, "TorrentsDHT: Requested info hash is too short ", infoHash.size ());
			return;
		}
		memcpy (hash.data (), infoHash.data (), hash.size ());
		auto it = m_Torrents.find (hash);
		if (it != m_Torrents.end ())
		{
			uint64_t token = m_Tunnel.GetLocalDestination () ? m_Tunnel.GetLocalDestination ()->GetRng ()() : 1;
			it->second->AddIncomingGetPeerNode (token, node);
			SendGetPeersResponse (transactionID, it->second, token, fromIdent, fromPort + 1); // to rport
		}
		else if (m_RoutingTable)
		{
			auto nodes = m_RoutingTable->FindClosestNodes (hash);
			if (!nodes.empty ())
			{
				uint64_t token = m_Tunnel.GetLocalDestination () ? m_Tunnel.GetLocalDestination ()->GetRng ()() : 1;
				SendGetPeersResponse (transactionID, nodes.front ().first, token, fromIdent, fromPort + 1); // to rport
			}
		}
	}

	void TorrentsDHT::HandleResponse (std::string_view transactionID, std::string_view id,
		uint64_t token, const std::vector<std::string_view>& values)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Response msg received");
		uint16_t t = 0;
		if (transactionID.size () >= 2)
			memcpy (&t, transactionID.data (), 2);
		auto it = m_Queries.find (t);
		if (t && it != m_Queries.end ())
		{
			if (id.size () < NodeID::len)
			{
				LogPrint (eLogInfo, "TorrentsDHT: received id is too short ", id.size ());
				return;
			}
			NodeID nodeID;
			memcpy (nodeID.data (), id.data (), NodeID::len);
			if (m_RoutingTable)
			{
				const auto& [ident, port, query, torrentw] = it->second;
				if (query == "ping")
				{
					LogPrint (eLogDebug, "TorrentsDHT: Ping response received");
					if (m_RoutingTable->AddNode (nodeID, ident, port))
						LogPrint (eLogDebug, "TorrentsDHT: Node ", ident.ToBase64 (), ":", port, " added");
					else
						LogPrint (eLogError, "TorrentsDHT: Failed to add node ", ident.ToBase64 ());
				}
				else if (query == "get_peers")
				{
					LogPrint (eLogDebug, "TorrentsDHT: get_peers response received");
					auto torrent = torrentw.lock ();
					if (!torrent)
					{
						auto node = m_RoutingTable->FindNode (nodeID);
						if (node)
						{
							std::shared_ptr<DHTTorrent> dhtTorrent;
							auto it1 = m_Torrents.find (torrent->GetInfoHash ());
							if (it1 != m_Torrents.end ())
								dhtTorrent = it1->second;
							else
							{
								dhtTorrent = std::make_shared<DHTTorrent>();
								m_Torrents.emplace (torrent->GetInfoHash (), dhtTorrent);
							}
							dhtTorrent->AddOutgoingGetPeerNode (token, node);
						}
					}
				}
			}
		}
		else
			LogPrint (eLogInfo, "TorrentsDHT: Query now found");
	}

	void TorrentsDHT::SendDatagram (std::string_view msg, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		auto dest = m_Tunnel.GetLocalDestination ();
		if (dest)
		{
			auto dgramDest = dest->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->SendDatagramTo ((const uint8_t *)msg.data (), msg.size (), toIdent, m_Port, toPort);
		}
	}

	void TorrentsDHT::SendRawDatagram (std::string_view msg, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		auto dest = m_Tunnel.GetLocalDestination ();
		if (dest)
		{
			auto dgramDest = dest->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->SendRawDatagramTo ((const uint8_t *)msg.data (), msg.size (), toIdent, m_Port, toPort);
		}
	}

	void TorrentsDHT::SendQueryMsg (std::string_view query, std::string_view arguments,
		const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		uint16_t transactionID = m_Tunnel.GetLocalDestination () ? m_Tunnel.GetLocalDestination ()->GetRng ()() : 1;
		auto msg = CreateDictionary ({
				{ "a", arguments },
				{ "q", CreateByteString (query) },
				{ "t", CreateByteString (std::string_view ((const char *)&transactionID, 2)) },
				{ "y", CreateByteString ("q") }
									});
		m_Queries.insert_or_assign (transactionID, std::make_tuple (toIdent, toPort, query, std::shared_ptr<Torrent>{}));
		SendDatagram (msg, toIdent, toPort);
	}

	void TorrentsDHT::SendResponseMsg (std::string_view response, std::string_view transactionID,
		const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		auto msg = CreateDictionary ({
				{ "r", response },
				{ "t", CreateByteString (transactionID) },
				{ "y", CreateByteString ("r") }
									});
		SendRawDatagram (msg, toIdent, toPort);
	}

	void TorrentsDHT::SendPingQuery (const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		SendQueryMsg ("ping", CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) }
												}),
			toIdent, toPort);
	}

	void TorrentsDHT::SendPingResponse (std::string_view transactionID, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		SendResponseMsg (CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) }
											}),
			transactionID, toIdent, toPort);
	}

	void TorrentsDHT::SendGetPeersResponse (std::string_view transactionID, std::shared_ptr<DHTTorrent> torrent,
		uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		if (!torrent) return;
		SendResponseMsg (CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "token", CreateByteString (std::string_view ((const char *)&token, 8)) },
			{ "values", torrent->GetBEncodedPeers () }
											}),
			transactionID, toIdent, toPort);
	}

	void TorrentsDHT::SendGetPeersResponse (std::string_view transactionID, std::shared_ptr<Node> node,
		uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		if (!node) return;
		NodeInfo nodeInfo = node->GetNodeInfo ();
		SendResponseMsg (CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "token", CreateByteString (std::string_view ((const char *)&token, 8)) },
			{ "nodes", CreateByteString (std::string_view ((const char *)nodeInfo.data (), nodeInfo.size ())) }
											}),
			transactionID, toIdent, toPort);
	}
}
}

#endif
