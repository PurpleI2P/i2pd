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
#include "Timestamp.h"
#include "FS.h"
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

	bool Bucket::ContainsNode (const NodeID& id) const
	{
		auto it = std::find_if (nodes.begin (), nodes.end (),
			[&id](const NodeID& nodeID)
			{
				return nodeID == id;
			});
		return it != nodes.end ();
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
			if (*it < *middleID)
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

	void RoutingTable::RemoveEmptyBuckets ()
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

	bool RoutingTable::AddNode (const NodeID& id)
	{
		if (id == m_OurNode) return false;
		auto bucket = FindBucket (id);
		if (!bucket) return false;
		if (bucket->ContainsNode (id)) return true;
		if (bucket->IsFull ())
		{
			if (!bucket->IsInBucket (m_OurNode)) return false;
			do
			{
				if (!bucket->Split ()) return false;
				bucket = FindBucket (id);
			}
			while (bucket->IsFull ());
		}
		if (bucket)
			bucket->nodes.emplace_back (id);
		RemoveEmptyBuckets ();
		return true;
	}

	std::list<std::pair<NodeID, Distance> > RoutingTable::FindClosestNodes (const Torrent::InfoHash& infoHash, size_t num) const
	{
		std::list<std::pair<NodeID, Distance> > ret;
		if (num > 0)
		{
			auto bucket = FindBucket (infoHash);
			if (bucket)
			{
				for (auto it: bucket->nodes)
				{
					auto nodeDistance = it ^ infoHash;
					auto it1 = std::find_if (ret.begin (), ret.end (),
						[&nodeDistance](const std::pair<NodeID, Distance>& alreadyFound)
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

	std::shared_ptr<Node> DHTTorrent::GetIncomingGetPeerNode (GetPeersToken token) const
	{
		auto it = m_IncomingGetPeers.find (token);
		if (it != m_IncomingGetPeers.end ())
			return it->second.lock ();
		return nullptr;
	}

	void DHTTorrent::AddPeer (const i2p::data::IdentHash& peer)
	{
		m_Peers.push_back ( { peer, i2p::util::GetMonotonicSeconds () } );
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
		std::string filename ("nodest");
		auto dest = m_Tunnel.GetLocalDestination ();
		if (dest)
		{
			auto dgramDest = dest->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->SetReceiver (std::bind_front (&TorrentsDHT::HandleDatagram, this));
			filename = dest->GetIdentHash ().ToBase32 ();
		}
		Load (GetDHTFilePath (filename));
	}

	void TorrentsDHT::Stop ()
	{
		std::string filename ("nodest");
		auto dest = m_Tunnel.GetLocalDestination ();
		if (dest)
		{
			auto dgramDest = dest->GetDatagramDestination ();
			if (dgramDest)
				dgramDest->ResetReceiver ();
			filename = dest->GetIdentHash ().ToBase32 ();
		}
		Save (GetDHTFilePath (filename));
	}

	std::filesystem::path TorrentsDHT::GetDHTFilePath (std::string_view filename) const
	{
		std::filesystem::path dhtFilePath (i2p::fs::GetDataDir()); dhtFilePath /= "torrents";
		if (!std::filesystem::exists (dhtFilePath))
			std::filesystem::create_directories (dhtFilePath);
		dhtFilePath /= filename; dhtFilePath += ".dht";
		return dhtFilePath;
	}

	void TorrentsDHT::Save (const std::filesystem::path& file)
	{
		if (!m_Nodes.empty ())
		{
			std::ofstream f(file, std::ofstream::binary);
			if (f.is_open ())
			{
				int numSaved = 0;
				for (auto it: m_Nodes)
				{
					auto nodeInfo = it.second->GetNodeInfo ();
					if (f.write ((const char *)nodeInfo.data (), nodeInfo.size ()))
						numSaved++;
				}
				if (numSaved > 0)
					LogPrint (eLogInfo, "TorrentsDHT: ", numSaved, " DHT nodes saved");
			}
		}
	}

	void TorrentsDHT::Load (const std::filesystem::path& file)
	{
		std::ifstream f (file, std::ifstream::in | std::ifstream::binary);
		if (f.is_open ())
		{
			if (m_RoutingTable) m_RoutingTable->CleanUp ();
			int numLoaded = 0;
			NodeInfo nodeInfo;
			while (f.read ((char *)nodeInfo.data (), nodeInfo.size ()))
			{
				auto bytesRead = f.gcount();
				if (bytesRead == nodeInfo.size ())
				{
					auto node = std::make_shared<Node>(nodeInfo);
					if (m_Nodes.emplace (node->id, node).second)
					{
						numLoaded++;
						if (m_RoutingTable) m_RoutingTable->AddNode (node->id);
					}
				}
			}
			if (numLoaded > 0)
				LogPrint (eLogInfo, "TorrentsDHT: ", numLoaded, " DHT nodes loaded");
		}
	}

	void TorrentsDHT::HandleRawDatagram (const uint8_t * buf, size_t len)
	{
		// response or error
		char type = 0; uint64_t token = 0;
		bool isMalformed = false;
		NodeID id; Torrent::InfoHash infoHash;
		std::string transactionID, query;
		std::vector<std::string_view> values;
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&type, &transactionID, &id, &values, &token, &infoHash, &query, &isMalformed]
				(std::string_view key, std::string_view buf)->size_t
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
				else if (key == "r" || key == "a")
				{
					return ParseDictionary (buf,
						[&id, &values, &token, &infoHash, &isMalformed](std::string_view key, std::string_view buf)->size_t
						{
							if (key == "id")
							{
								auto [l, success] = ParseByteArray (buf, id);
								if (!success) isMalformed = true;
								return l;
							}
							else if (key == "values")
							{
								auto [v, l] = ParseStringList (buf);
								if (l) values = v;
								return l;
							}
							else if (key == "token")
							{
								auto [value, l] = ExtractByteString (buf);
								if (l && value.size () >= 8)
									memcpy (&token, value.data (), 8);
								return l;
							}
							else if (key == "info_hash")
							{
								auto [l, success] = ParseByteArray (buf, infoHash);
								if (!success) isMalformed = true;
								return l;
							}
							return 0;
						});
				}
				return 0;
			});
		if (isMalformed)
		{
			LogPrint (eLogInfo, "TorrentsDHT: Malformed raw datagram received");
			return;
		}
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
					if (query == "announce_peer")
						HandleAnnouncePeer (transactionID, infoHash, token);
					else
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
		bool isMalformed = false;
		std::string transactionID, query;
		NodeID id; Torrent::InfoHash infoHash;
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&type, &transactionID, &query, &id, &infoHash, &isMalformed]
				(std::string_view key, std::string_view buf)->size_t
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
						[&id, &infoHash,&isMalformed](std::string_view key, std::string_view buf)->size_t
						{
							if (key == "id")
							{
								auto [l, success] = ParseByteArray (buf, id);
								if (!success) isMalformed = true;
								return l;
							}
							else if (key == "info_hash")
							{
								auto [l, success] = ParseByteArray (buf, infoHash);
								if (!success) isMalformed = true;
								return l;
							}
							return 0;
						});
				}
				return 0;
			});
		if (isMalformed)
		{
			LogPrint (eLogInfo, "TorrentsDHT: Malformed datagram received");
			return;
		}
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
		std::string_view transactionID, const NodeID& nodeID)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Ping query msg received");
		if (m_Nodes.emplace (nodeID, std::make_shared<Node> (nodeID, fromIdent, fromPort)).second)
			m_RoutingTable->AddNode (nodeID);
		SendPingResponse (transactionID, fromIdent, fromPort + 1); // to rport
	}

	void TorrentsDHT::HandleGetPeersQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
		std::string_view transactionID, const NodeID& nodeID, const Torrent::InfoHash& infoHash)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Get peers query msg received");
		auto [nodesIt, inserted] = m_Nodes.emplace (nodeID, std::make_shared<Node> (nodeID, fromIdent, fromPort));
		if (inserted)
			m_RoutingTable->AddNode (nodeID);

		std::shared_ptr<DHTTorrent> torrent;
		auto it = m_Torrents.find (infoHash);
		if (it != m_Torrents.end ())
			torrent = it->second;
		else
		{
			torrent = std::make_shared<DHTTorrent>();
			m_Torrents.emplace (infoHash, torrent);
		}
		uint64_t token = m_Tunnel.GetLocalDestination () ? m_Tunnel.GetLocalDestination ()->GetRng ()() : 1;
		torrent->AddIncomingGetPeerNode (token, nodesIt->second);

		if (m_RoutingTable)
		{
			auto nodes = m_RoutingTable->FindClosestNodes (infoHash);
			if (!nodes.empty () && nodes.front ().second < (m_NodeID ^ infoHash))
			{
				auto it1 = m_Nodes.find (nodes.front ().first);
				if (it1 != m_Nodes.end ())
					SendGetPeersResponse (transactionID, it1->second, token, fromIdent, fromPort + 1); // to rport
			}
			else
				SendGetPeersResponse (transactionID, torrent, token, fromIdent, fromPort + 1); // to rport
		}
	}

	void TorrentsDHT::HandleAnnouncePeer (std::string_view transactionID, const Torrent::InfoHash& infoHash, uint64_t token)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Announce peer received");
		auto it = m_Torrents.find (infoHash);
		if (it != m_Torrents.end ())
		{
			auto node = it->second->GetIncomingGetPeerNode (token);
			if (node)
			{
				it->second->AddPeer (node->peer);
				SendResponseMsg (CreateDictionary ({
						{ "id", CreateByteString (std::string_view ((const char *)node->id.data (), node->id.size ())) },
												}),
					transactionID, node->peer, node->port + 1); // to rport
			}
		}
	}

	void TorrentsDHT::HandleResponse (std::string_view transactionID, const NodeID& nodeID,
		uint64_t token, const std::vector<std::string_view>& values)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Response msg received");
		uint16_t t = 0;
		if (transactionID.size () >= 2)
			memcpy (&t, transactionID.data (), 2);
		auto it = m_Queries.find (t);
		if (t && it != m_Queries.end ())
		{
			if (m_RoutingTable)
			{
				const auto& [ident, port, query, torrentw] = it->second;
				if (query == "ping")
				{
					LogPrint (eLogDebug, "TorrentsDHT: Ping response received");
					if (m_Nodes.emplace (nodeID, std::make_shared<Node> (nodeID, ident, port)).second)
					{
						m_RoutingTable->AddNode (nodeID);
						LogPrint (eLogDebug, "TorrentsDHT: Node ", ident.ToBase64 (), ":", port, " added");
					}
				}
				else if (query == "get_peers")
				{
					LogPrint (eLogDebug, "TorrentsDHT: get_peers response received");
					// TODO:
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
