/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef NO_TORRENTS

#include <openssl/rand.h>
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
	Node::Node (const NodeInfo& nodeInfo):
		lastUpdateTime (i2p::util::GetMonotonicSeconds ())
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

	bool Node::VerifyID () const
	{
		return !memcmp (id.data (), peer, 4) && (((uint16_t)(id[4] ^ peer[4]) << 8) | (id[5] ^ peer[5])) == port;
	}

	std::optional<NodeID> Bucket::GetMiddleID () const
	{
		uint8_t bit = std::max (start.FindLowestBit (), next ? next->start.FindLowestBit () : -1) + 1;
		if (bit >= NodeID::len * 8) return {};
		NodeID middleID = start;
		middleID[bit >> 3] |= (0x80 >> (bit & 0x07));
		return { middleID };
	}

	NodeID Bucket::GetRandomID (std::mt19937& rng) const
	{
		uint8_t bit = std::max (start.FindLowestBit (), next ? next->start.FindLowestBit () : -1) + 1;
		if (bit >= NodeID::len * 8) return start;

		NodeID randomID;
		auto d = div (bit, 8);
		memcpy (randomID.data (), start.data (), d.quot);
		randomID[d.quot] = (start[d.quot] & (0xFF00 >> d.rem)) | (rng () & (0xFF >> d.rem));
		for (size_t i = d.quot + 1; i < NodeID::len; i += 4)
		{
			uint32_t r = rng ();
			if (i + 4 <= NodeID::len)
				memcpy (randomID.data () + i, &r, 4);
			else
				memcpy (randomID.data () + i, &r, NodeID::len - i);
		}
		return randomID;
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
			if (it->first < *middleID)
				it++; // stay in old bucket
			else
				// move to new bucket
				newBucket->nodes.insert (nodes.extract (it++));
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

	size_t RoutingTable::GetNumBuckets () const
	{
		size_t num = 0;
		auto bucket = m_Buckets;
		while (bucket)
		{
			num++;
			bucket = bucket->next;
		}
		return num;
	}

	size_t RoutingTable::GetNumNodes () const
	{
		size_t num = 0;
		auto bucket = m_Buckets;
		while (bucket)
		{
			num += bucket->nodes.size ();
			bucket = bucket->next;
		}
		return num;
	}

	std::list<std::shared_ptr<Node> > RoutingTable::GetNodes ()
	{
		std::list<std::shared_ptr<Node> > nodes;
		auto bucket = m_Buckets;
		while (bucket)
		{
			for (auto it: bucket->nodes)
				nodes.emplace_back (it.second);
			bucket = bucket->next;
		}
		return nodes;
	}

	Bucket * RoutingTable::FindBucket (const Torrent::InfoHash& id) const
	{
		if (!m_Buckets) return nullptr;
		auto bucket = m_Buckets;
		while (bucket->next)
		{
			if (id < bucket->next->start)
				break;
			bucket = bucket->next;
		}
		return bucket;
	}

	void RoutingTable::RemoveEmptyBuckets ()
	{
		// TODO: remove only if difference is 1 bit
		/*if (m_Buckets)
		{
			auto prev = m_Buckets, bucket = m_Buckets->next;
			while (bucket)
			{
				if (bucket->IsEmpty ())
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
			if (m_Buckets->IsEmpty () && m_Buckets->next)
			{
				m_Buckets = m_Buckets->next;
				m_Buckets->start.fill (0);
			}
		}*/
	}

	size_t RoutingTable::DeleteExpiredNodes (uint64_t ts)
	{
		size_t numDeleted = 0;
		auto bucket = m_Buckets;
		while (bucket)
		{
			if (ts > bucket->lastUpdateTime + DHT_BUCKET_EXPIRATION_THRESHOLD)
			{
				auto it = bucket->nodes.begin ();
				while (it != bucket->nodes.end ())
				{
					if (ts > it->second->lastUpdateTime + DHT_NODE_EXPIRATION_TIME)
					{
						numDeleted++;
						it = bucket->nodes.erase (it);
					}
					else
						it++;
				}
			}
			bucket = bucket->next;
		}
		if (numDeleted > 0)
			RemoveEmptyBuckets ();
		return numDeleted;
	}

	std::list<std::shared_ptr<Node> > RoutingTable::GetNodesToPing (uint64_t ts)
	{
		std::list<std::shared_ptr<Node> > toPing;
		auto bucket = m_Buckets;
		while (bucket)
		{
			if (ts > bucket->lastUpdateTime + DHT_BUCKET_EXPIRATION_THRESHOLD)
			{
				for (const auto& it: bucket->nodes)
					if (ts > it.second->lastUpdateTime + DHT_NODE_SEND_PING_TIME)
						toPing.push_back (it.second);
			}
			bucket = bucket->next;
		}
		return toPing;
	}

	bool RoutingTable::AddNode (std::shared_ptr<Node> node)
	{
		if (!node) return false;
		if (node->id == m_OurNode) return false;
		auto bucket = FindBucket (node->id);
		if (!bucket) return false;
		auto it = bucket->nodes.find (node->id);
		if (it != bucket->nodes.end ())
		{
			it->second = node;
			bucket->lastUpdateTime = i2p::util::GetMonotonicSeconds ();
			return false;
		}
		if (bucket->IsFull ())
		{
			do
			{
				if (!bucket->IsInBucket (m_OurNode)) return false;
				if (!bucket->Split ()) return false;
				bucket = FindBucket (node->id);
			}
			while (bucket->IsFull ());
		}
		if (bucket)
		{
			bucket->nodes.emplace (node->id, node);
			bucket->lastUpdateTime = i2p::util::GetMonotonicSeconds ();
		}
		return true;
	}

	void RoutingTable::RemoveNode (const NodeID& id)
	{
		auto bucket = FindBucket (id);
		if (!bucket) return;
		bucket->nodes.erase (id);
		if (bucket->IsEmpty ())
			RemoveEmptyBuckets ();
	}

	std::list<std::pair<NodeID, Bucket * > > RoutingTable::GetExploratoryTargets (std::mt19937& rng) const
	{
		std::list<std::pair<NodeID, Bucket * > > ret;
		auto bucket = m_Buckets;
		while (bucket)
		{
			if (!bucket->IsFull () || bucket->IsInBucket (m_OurNode))
				ret.emplace_back (std::make_pair (bucket->GetRandomID (rng), bucket));
			bucket = bucket->next;
		}
		return ret;
	}

	DHTTorrent::DHTTorrent ():
		m_LastUpdateTime (i2p::util::GetMonotonicSeconds ())
	{
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
		auto ts = i2p::util::GetMonotonicSeconds ();
		m_IncomingGetPeers.emplace (token, std::make_pair (node, ts));
		m_LastUpdateTime = ts;
	}

	std::shared_ptr<Node> DHTTorrent::GetIncomingGetPeerNode (GetPeersToken token) const
	{
		auto it = m_IncomingGetPeers.find (token);
		if (it != m_IncomingGetPeers.end ())
			return it->second.first;
		return nullptr;
	}

	bool DHTTorrent::AddPeer (const i2p::data::IdentHash& peer)
	{
		auto ts = i2p::util::GetMonotonicSeconds ();
		m_LastUpdateTime = ts;
		auto [it, inserted] = m_Peers.emplace (peer, ts);
		if (!inserted)
			it->second = ts;
		return inserted;
	}

	bool DHTTorrent::CleanUp (uint64_t ts)
	{
		{
			auto it = m_Peers.begin ();
			while (it != m_Peers.end ())
			{
				if (ts > it->second + DHT_TORRENT_PEER_EXPIRATION_TIME)
					it = m_Peers.erase (it);
				else
					it++;
			}
		}
		{
			auto it = m_IncomingGetPeers.begin ();
			while (it != m_IncomingGetPeers.end ())
			{
				if (ts > it->second.second + DHT_INCOMING_GET_PEERS_TOKEN_EXPIRATION_TIME)
					it = m_IncomingGetPeers.erase (it);
				else
					it++;
			}
		}
		if (m_Peers.empty () && m_IncomingGetPeers.empty () && ts > m_LastUpdateTime + DHT_EMPTY_TORRENT_EXPIRATION_TIME)
			return true;
		return false;
	}

	bool RequestInfo::AddNode (std::shared_ptr<Node> node)
	{
		if (!node || tried.contains (node->id)) return false;
		return nodesToRequest.emplace (torrent ? node->id ^ torrent->GetInfoHash () : node->id ^ target, node).second;
	}

	bool RequestInfo::AddNodeToken (std::shared_ptr<Node> node, uint64_t token)
	{
		if (!node || !token || !torrent) return false;
		return tokens.emplace (node->id ^ torrent->GetInfoHash (), node, token).second;
	}

	std::shared_ptr<Node> RequestInfo::GetNextNode ()
	{
		if (nodesToRequest.empty ()) return nullptr;
		auto node = nodesToRequest.begin ()->second;
		nodesToRequest.erase (nodesToRequest.begin ());
		numAttempts++;
		tried.emplace (node->id);
		lastNode = node;
		return node;
	}

	TorrentsDHT::TorrentsDHT (TorrentsTunnel& tunnel, uint16_t port):
		m_Tunnel (tunnel), m_DHTUpdateCheckTimer (tunnel.GetService ()),
		m_DHTExpirationCheckTimer (tunnel.GetService ()),
		m_DHTSendPingCheckTimer (tunnel.GetService ()),
		m_DHTQueryExpirationCheckTimer (tunnel.GetService ()), m_Port (port),
		m_NextDHTExploratoryTime (i2p::util::GetMonotonicSeconds () + DHT_INITIAL_EXPLORATORY_INTERVAL)
	{
		auto dest = tunnel.GetLocalDestination ();
		if (dest)
		{
			memcpy (m_NodeID.data (), dest->GetIdentHash (), 6);
			m_NodeID[4] ^= (port >> 8);
			m_NodeID[5] ^= (port & 0xFF);
			RAND_bytes (m_NodeID.data () + 6, m_NodeID.size () - 6);
			m_RoutingTable = std::make_unique<RoutingTable> (m_NodeID);
		}
		else
			m_NodeID.fill (0);
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
		ScheduleDHTUpdateCheck ();
		ScheduleDHTExpirationCheck ();
		ScheduleDHTSendPingCheck ();
		ScheduleDHTQueryExpirationCheck ();
	}

	void TorrentsDHT::Stop ()
	{
		m_DHTUpdateCheckTimer.cancel ();
		m_DHTExpirationCheckTimer.cancel ();
		m_DHTSendPingCheckTimer.cancel ();
		m_DHTQueryExpirationCheckTimer.cancel ();
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
		if (m_RoutingTable)
		{
			std::ofstream f(file, std::ofstream::binary);
			if (f.is_open ())
			{
				auto dest = m_Tunnel.GetLocalDestination ();
				if (dest)
				{
					// save our nodeInfo first
					NodeInfo nodeInfo = Node (m_NodeID, dest->GetIdentHash (), m_Port).GetNodeInfo ();
					f.write ((const char *)nodeInfo.data (), nodeInfo.size ());
				}
				int numSaved = 0;
				for (auto it: m_RoutingTable->GetNodes ())
				{
					auto nodeInfo = it->GetNodeInfo ();
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
			NodeInfo nodeInfo;
			if (f.read ((char *)nodeInfo.data (), nodeInfo.size ()))
			{
				auto dest = m_Tunnel.GetLocalDestination ();
				if (dest)
				{
					Node node (nodeInfo);
					if (Node (nodeInfo).peer == dest->GetIdentHash ()) // first nodeInfo is ours
					{
						m_NodeID = node.id;
						m_Port = node.port;
					}
					else
						f.seekg (0, std::ios::beg);
				}
			}
			else
				return;

			m_RoutingTable = std::make_unique<RoutingTable> (m_NodeID);
			while (f.read ((char *)nodeInfo.data (), nodeInfo.size ()))
			{
				auto bytesRead = f.gcount();
				if (bytesRead == nodeInfo.size ())
				{
					auto node = std::make_shared<Node>(nodeInfo);
					if (node->VerifyID ())
						m_RoutingTable->AddNode (node);
				}
			}
			LogPrint (eLogInfo, "TorrentsDHT: ", m_RoutingTable->GetNumNodes (),
				" DHT nodes loaded to ", m_RoutingTable->GetNumBuckets (), " buckets");
		}
	}

	void TorrentsDHT::HandleRawDatagram (const uint8_t * buf, size_t len)
	{
		// response or error
		char type = 0; uint64_t token = 0;
		bool isMalformed = false;
		NodeID id; Torrent::InfoHash infoHash;
		std::string_view nodes;
		std::string transactionID, query;
		std::vector<std::string_view> values{""};
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&type, &transactionID, &id, &values, &token, &infoHash, &query, &isMalformed, &nodes]
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
						[&id, &values, &token, &infoHash, &isMalformed, &nodes](std::string_view key, std::string_view buf)->size_t
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
							else if (key == "nodes")
							{
								auto [value, l] = ExtractByteString (buf);
								if (l) nodes = value;
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
			UpdateHeardFrom (id);
			switch (type)
			{
				 case 'r':
					HandleResponse (transactionID, id, token, values, nodes);
				 break;
				 case 'e':
					LogPrint (eLogDebug, "TorrentsDHT: Error msg received");
				 break;
				 case 'q':
					if (query == "announce_peer")
						HandleAnnouncePeer (transactionID, id, infoHash, token);
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
		NodeID id, target; Torrent::InfoHash infoHash;
		ParseDictionary (std::string_view ((const char *)buf, len),
			[&type, &transactionID, &query, &id, &infoHash, &isMalformed, &target]
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
						[&id, &infoHash, &isMalformed, &target](std::string_view key, std::string_view buf)->size_t
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
							else if (key == "target")
							{
								auto [l, success] = ParseByteArray (buf, target);
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
			UpdateHeardFrom (id);
			auto node = UpdateNode (std::make_shared<Node> (id, from.GetIdentHash (), fromPort));
			if (!node) return;
			if (query == "ping")
				HandlePingQuery (from.GetIdentHash (), fromPort, transactionID, id);
			else if (query == "get_peers")
				HandleGetPeersQuery (from.GetIdentHash (), fromPort, transactionID, node, infoHash);
			else if (query == "find_node")
				HandleFindNodeQuery (from.GetIdentHash (), fromPort, transactionID, target);
			else
				LogPrint (eLogDebug, "TorrentsDHT: Unexpected query ", query);
		}
		else if (type)
			LogPrint (eLogInfo, "TorrentsDHT: Unxpected msg type ", (int)type);
	}

	void TorrentsDHT::HandlePingQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
		std::string_view transactionID, const NodeID& nodeID)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Ping query msg received from ", nodeID.ToBase64 ());
		SendPingResponse (transactionID, fromIdent, fromPort + 1); // to rport
	}

	void TorrentsDHT::HandleGetPeersQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
		std::string_view transactionID, std::shared_ptr<Node> from, const Torrent::InfoHash& infoHash)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Get peers query msg received from ", from->id.ToBase64 ());
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
		torrent->AddIncomingGetPeerNode (token, from);
		m_IncomingTokens.emplace (token, std::make_pair(from, i2p::util::GetMonotonicSeconds ()));

		if (torrent->HasPeers ())
			SendGetPeersResponse (transactionID, torrent, token, fromIdent, fromPort + 1); // to rport
		else if (m_RoutingTable)
		{
			std::vector<uint8_t> nodes;
			auto bucket = m_RoutingTable->FindBucket (infoHash);
			if (bucket && bucket->IsEmpty () && bucket->next && !bucket->next->IsEmpty ())
				bucket = bucket->next;

			if (bucket && !bucket->IsEmpty ())
				for (auto it: bucket->nodes)
				{
					auto nodeInfo = it.second->GetNodeInfo ();
					nodes.insert (nodes.end(), nodeInfo.data (), nodeInfo.data () + nodeInfo.size ());
				}

			SendGetPeersResponse (transactionID, std::string_view ((const char *)nodes.data (), nodes.size ()),
				token, fromIdent, fromPort + 1); // to rport
		}
	}

	void TorrentsDHT::HandleFindNodeQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
		std::string_view transactionID, const NodeID& target)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Find node query received");
		if (m_RoutingTable)
		{
			auto bucket = m_RoutingTable->FindBucket (target);
			if (bucket && bucket->IsEmpty () && bucket->next && !bucket->next->IsEmpty ())
				bucket = bucket->next;
			if (bucket && !bucket->IsEmpty ())
			{
				std::vector<uint8_t> nodes;
				for (auto it: bucket->nodes)
				{
					auto nodeInfo = it.second->GetNodeInfo ();
					nodes.insert (nodes.end(), nodeInfo.data (), nodeInfo.data () + nodeInfo.size ());
				}
				SendFindNodeResponse (transactionID, std::string_view ((const char *)nodes.data (), nodes.size ()), fromIdent, fromPort + 1); // to rport
			}
		}
	}

	void TorrentsDHT::HandleAnnouncePeer (std::string_view transactionID, const NodeID& nodeID,
		const Torrent::InfoHash& infoHash, uint64_t token)
	{
		LogPrint (eLogDebug, "TorrentsDHT: Announce peer received from ", nodeID.ToBase64 ());
		auto it = m_Torrents.find (infoHash);
		if (it != m_Torrents.end ())
		{
			auto node = it->second->GetIncomingGetPeerNode (token);
			if (node)
			{
				if (node->id == nodeID)
				{
					it->second->AddPeer (node->peer);
					SendResponseMsg (CreateDictionary ({
							{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
													}),
						transactionID, node->peer, node->port + 1); // to rport
				}
				else
					LogPrint (eLogInfo, "TorrentsDHT: Announce peer node/token mismatch");
			}
			else
				LogPrint (eLogInfo, "TorrentsDHT: Announce peer token not found");
		}
		else
		{
			auto it = m_IncomingTokens.find (token);
			if (it != m_IncomingTokens.end ())
			{
				auto node = it->second.first;
				auto torrent = std::make_shared<DHTTorrent>();
				torrent->AddIncomingGetPeerNode (token, node);
				torrent->AddPeer (node->peer);
				m_Torrents.emplace (infoHash, torrent);
				SendResponseMsg (CreateDictionary ({
							{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
													}),
						transactionID, node->peer, node->port + 1); // to rport
			}
			else
				LogPrint (eLogInfo, "TorrentsDHT: Token for announce not found");
		}
	}

	void TorrentsDHT::HandleResponse (std::string_view transactionID, const NodeID& nodeID,
		uint64_t token, const std::vector<std::string_view>& values, std::string_view nodes)
	{
		uint16_t t = 0;
		if (transactionID.size () >= 2)
			memcpy (&t, transactionID.data (), 2);
		auto it = m_Queries.find (t);
		if (t && it != m_Queries.end ())
		{
			if (m_RoutingTable)
			{
				const auto& [ident, port, query, info, time] = it->second;
				if (query != eKRPCQueryAnnouncePeer) // port is rport there
					UpdateNode (std::make_shared<Node> (nodeID, ident, port));
				switch (query)
				{
					case eKRPCQueryPing:
					{
						LogPrint (eLogDebug, "TorrentsDHT: Ping response received");
						break;
					}
					case eKRPCQueryGetPeers:
					{
						LogPrint (eLogDebug, "TorrentsDHT: get_peers response received from peer ", ident.ToBase64 (), "after attempt #", info->numAttempts);
						if (!values.empty () && values[0].empty ()) // nodes, because values not set
						{
							if (info && token)
								info->AddNodeToken (std::make_shared<Node>(nodeID, ident, port), token);
							HandleGetPeersResponseNodes (info, nodes);
						}
						else //values
							HandleGetPeersResponsePeersAndAnnounce (info, values, token, ident, port + 1); // to rport
						break;
					}
					case eKRPCQueryFindNode:
					{
						LogPrint (eLogDebug, "TorrentsDHT: find_node response received after attempt #", info->numAttempts);
						HandleFindNodeResponse (info, nodes);
						break;
					}
					case eKRPCQueryAnnouncePeer:
						LogPrint (eLogDebug, "TorrentsDHT: Announce peer response received");
					break;
					default:
						LogPrint (eLogInfo, "TorrentsDHT: Response to unknown KRPC query ", (int)query);
				}
			}
			m_Queries.erase (it);
		}
		else
			LogPrint (eLogInfo, "TorrentsDHT: Query not found");
	}

	void TorrentsDHT::HandleGetPeersResponseNodes (std::shared_ptr<RequestInfo> info, std::string_view nodes)
	{
		NodeInfo nodeInfo;
		while (nodes.size () >= nodeInfo.size ())
		{
			memcpy (nodeInfo.data (), nodes.data (), nodeInfo.size ());
			auto node = std::make_shared<Node>(nodeInfo);
			if (info && info->AddNode (node))
			{
				if (m_HeardFrom.contains (node->id))
					UpdateNode (node);
				else
					SendPingQuery (node->peer, node->port);
			}
			nodes = nodes.substr (nodeInfo.size ());
		}
		if (info)
			SendNextGetPeersQuery (info);
	}

	void TorrentsDHT::HandleGetPeersResponsePeersAndAnnounce (std::shared_ptr<RequestInfo> info,
		const std::vector<std::string_view>& peers, uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		if (!info->torrent->IsComplete ())
		{
			std::unordered_set<i2p::data::IdentHash> newPeers;
			for (auto it: peers)
				if (it.size () == i2p::data::IdentHash::len)
					newPeers.emplace ((const uint8_t *)it.data ());
			if (!newPeers.empty ())
			{
				LogPrint (eLogDebug, "TorrentsDHT: ", newPeers.size (), " new peers received");
				m_Tunnel.ConnectToNewPeers (info->torrent, newPeers, ePeerConnectionOriginDHT);
			}
		}
		LogPrint (eLogDebug, "TorrentsDHT: Send announce to ", toIdent.ToBase64 ());
		SendAnnouncePeerQuery (info->torrent->GetInfoHash (), token, toIdent, toPort);
	}

	void TorrentsDHT::HandleFindNodeResponse (std::shared_ptr<RequestInfo> info, std::string_view nodes)
	{
		NodeInfo nodeInfo;
		while (nodes.size () >= nodeInfo.size ())
		{
			memcpy (nodeInfo.data (), nodes.data (), nodeInfo.size ());
			auto node = std::make_shared<Node>(nodeInfo);
			if (info && info->AddNode (node))
			{
				if (m_HeardFrom.contains (node->id))
					UpdateNode (node);
				else
					SendPingQuery (node->peer, node->port);
			}
			nodes = nodes.substr (nodeInfo.size ());
		}
		if (info)
			SendNextFindNodeQuery (info);
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

	void TorrentsDHT::SendQueryMsg (KRPCQuery query, std::string_view arguments,
		const i2p::data::IdentHash& toIdent, uint16_t toPort, bool isRaw, std::shared_ptr<RequestInfo> info)
	{
		uint16_t transactionID = m_Tunnel.GetLocalDestination () ? static_cast<uint16_t>(m_Tunnel.GetLocalDestination ()->GetRng ()()) : 1;
		auto msg = CreateDictionary ({
				{ "a", arguments },
				{ "q", CreateByteString (KRPCQueryStr[query]) },
				{ "t", CreateByteString (std::string_view ((const char *)&transactionID, 2)) },
				{ "y", CreateByteString ("q") }
									});
		m_Queries.insert_or_assign (transactionID, std::make_tuple (toIdent, toPort,
			query, info, i2p::util::GetMonotonicSeconds ()));
		if (isRaw)
			SendRawDatagram (msg, toIdent, toPort);
		else
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
		SendQueryMsg (eKRPCQueryPing, CreateDictionary ({
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

	void TorrentsDHT::SendGetPeersQuery (std::shared_ptr<RequestInfo> info, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		if (!info || !info->torrent) return;
		const auto& infoHash = info->torrent->GetInfoHash ();
		SendQueryMsg (eKRPCQueryGetPeers, CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "info_hash", CreateByteString (std::string_view ((const char *)infoHash.data (), infoHash.size ())) }
													}),
			toIdent, toPort, false, info);
	}

	void TorrentsDHT::SendNextGetPeersQuery (std::shared_ptr<RequestInfo> info)
	{
		if (!info) return;
		bool sent = false;
		if (!info->IsDone () && m_RoutingTable)
		{
			auto nextNode = info->GetNextNode ();
			if (nextNode)
			{
				sent = true;
				SendGetPeersQuery (info, nextNode->peer, nextNode->port);
			}
			else
				LogPrint (eLogDebug, "TorrentsDHT: No more nodes to send get_peers");
		}
		else
			LogPrint (eLogDebug, "TorrentsDHT: Closest node not found after ", DHT_MAX_NUM_GET_PEERS_ATTEMPTS, " get_peers attempts");
		if (!sent && !info->tokens.empty () && info->torrent)
		{
			// announce
			int numAnnounces = 0;
			for (const auto& [distance, node, token]: info->tokens)
			{
				SendAnnouncePeerQuery (info->torrent->GetInfoHash (), token, node->peer, node->port + 1); // to rport
				numAnnounces++;
				if (numAnnounces >= DHT_MAX_NUM_CLOSEST_NODES_TO_ANNOUNCE) break;
			}
			if (numAnnounces > 0)
				LogPrint (eLogDebug, "TorrentsDHT: Announce sent to ", numAnnounces, " closest nodes");
		}
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

	void TorrentsDHT::SendGetPeersResponse (std::string_view transactionID, std::string_view nodes,
		uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		SendResponseMsg (CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "token", CreateByteString (std::string_view ((const char *)&token, 8)) },
			{ "nodes", CreateByteString (nodes) }
											}),
			transactionID, toIdent, toPort);
	}

	void TorrentsDHT::SendFindNodeQuery (std::shared_ptr<RequestInfo> info, const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		if (!info) return;
		SendQueryMsg (eKRPCQueryFindNode, CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "target", CreateByteString (std::string_view ((const char *)info->target.data (), info->target.size ())) }
													}),
			toIdent, toPort, false, info);
	}

	void TorrentsDHT::SendNextFindNodeQuery (std::shared_ptr<RequestInfo> info)
	{
		if (!info) return;
		if (!info->IsDone () && m_RoutingTable)
		{
			auto nextNode = info->GetNextNode ();
			if (nextNode)
				SendFindNodeQuery (info, nextNode->peer, nextNode->port);
			else
				LogPrint (eLogDebug, "TorrentsDHT: No more nodes to send find_node");
		}
	}

	void TorrentsDHT::SendFindNodeResponse (std::string_view transactionID, std::string_view nodes,
		const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		SendResponseMsg (CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "nodes", CreateByteString (nodes) }
											}),
			transactionID, toIdent, toPort);
	}

	void TorrentsDHT::SendAnnouncePeerQuery (const Torrent::InfoHash& infoHash, uint64_t token,
		const i2p::data::IdentHash& toIdent, uint16_t toPort)
	{
		SendQueryMsg (eKRPCQueryAnnouncePeer, CreateDictionary ({
			{ "id", CreateByteString (std::string_view ((const char *)m_NodeID.data (), m_NodeID.size ())) },
			{ "info_hash",  CreateByteString (std::string_view ((const char *)infoHash.data (), infoHash.size ())) },
			{ "token", CreateByteString (std::string_view ((const char *)&token, 8)) }
											}),
			toIdent, toPort, true); // raw
	}

	void TorrentsDHT::Explore ()
	{
		if (m_RoutingTable && m_Tunnel.GetLocalDestination ())
		{
			auto targets = m_RoutingTable->GetExploratoryTargets (m_Tunnel.GetLocalDestination ()->GetRng ());
			for (auto [target, bucket]: targets)
			{
				auto request = std::make_shared<RequestInfo>(nullptr, DHT_MAX_NUM_FIND_NODE_ATTEMPTS);
				request->target = target;
				if (bucket->IsEmpty ())
				{
					if (bucket->next && !bucket->next->IsEmpty ())
						bucket = bucket->next;
					else
						continue;
				}
				// fill initial list of nodes to request from bucket
				for (auto it: bucket->nodes)
					request->AddNode (it.second);
				SendNextFindNodeQuery (request);
			}
		}
	}

	std::shared_ptr<Node> TorrentsDHT::UpdateNode (std::shared_ptr<Node> node)
	{
		if (!node) return nullptr;
		if (!node->VerifyID ())
		{
			LogPrint (eLogInfo, "TorrentsDHT: Invalid node ID received ", node->id.ToBase64 ());
			return nullptr;
		}
		if (m_RoutingTable && m_RoutingTable->AddNode (node))
			LogPrint (eLogDebug, "TorrentsDHT: Node ", node->id.ToBase64 (), " added");
		return node;
	}

	void TorrentsDHT::UpdateHeardFrom (const NodeID& nodeID)
	{
		m_HeardFrom[nodeID] = i2p::util::GetMonotonicSeconds ();
	}

	void TorrentsDHT::ScheduleDHTUpdateCheck ()
	{
		m_DHTUpdateCheckTimer.cancel ();
		m_DHTUpdateCheckTimer.expires_after (std::chrono::seconds (DHT_UPDATE_CHECK_INTERVAL));
		m_DHTUpdateCheckTimer.async_wait (std::bind_front(&TorrentsDHT::HandleDHTUpdateCheckTimer, this));
	}

	void TorrentsDHT::HandleDHTUpdateCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetMonotonicSeconds ();
			if (ts > m_NextDHTExploratoryTime)
			{
				Explore ();
				m_NextDHTExploratoryTime = ts + DHT_EXPLORATORY_INTERVAL + (m_Tunnel.GetLocalDestination () ?
					m_Tunnel.GetLocalDestination ()->GetRng ()() % DHT_EXPLORATORY_INTERVAL_VARIANCE : 0);
			}
			ScheduleDHTUpdateCheck ();
		}
	}

	void TorrentsDHT::ScheduleDHTExpirationCheck ()
	{
		m_DHTExpirationCheckTimer.cancel ();
		m_DHTExpirationCheckTimer.expires_after (std::chrono::seconds (DHT_EXPIRATION_CHECK_INTERVAL));
		m_DHTExpirationCheckTimer.async_wait (std::bind_front(&TorrentsDHT::HandleDHTExpirationCheckTimer, this));
	}

	void TorrentsDHT::HandleDHTExpirationCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetMonotonicSeconds ();
			if (m_RoutingTable)
			{
				m_RoutingTable->DeleteExpiredNodes (ts);
				LogPrint (eLogDebug, "TorrentsDHT: Stats ", m_RoutingTable->GetNumNodes (), " nodes in ",  m_RoutingTable->GetNumBuckets (), " buckets ");
			}
			{
				auto it = m_Torrents.begin ();
				while (it != m_Torrents.end ())
				{
					if (it->second->CleanUp (ts))
						it = m_Torrents.erase (it);
					else
						it++;
				}
			}
			{
				auto it = m_HeardFrom.begin ();
				while (it != m_HeardFrom.end ())
				{
					if (ts > it->second + DHT_HEARD_FROM_EXPIRATION_TIME)
						it = m_HeardFrom.erase (it);
					else
						it++;
				}
			}
			{
				auto it = m_IncomingTokens.begin ();
				while (it != m_IncomingTokens.end ())
				{
					if (ts > it->second.second + DHT_INCOMING_GET_PEERS_TOKEN_EXPIRATION_TIME)
						it = m_IncomingTokens.erase (it);
					else
						it++;
				}
			}
			ScheduleDHTExpirationCheck ();
		}
	}

	void TorrentsDHT::ScheduleDHTSendPingCheck ()
	{
		m_DHTSendPingCheckTimer.cancel ();
		m_DHTSendPingCheckTimer.expires_after (std::chrono::seconds (DHT_SEND_PING_CHECK_INTERVAL));
		m_DHTSendPingCheckTimer.async_wait (std::bind_front(&TorrentsDHT::HandleDHTSendPingCheckTimer, this));
	}

	void TorrentsDHT::HandleDHTSendPingCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto ts = i2p::util::GetMonotonicSeconds ();
			if (m_RoutingTable)
			{
				auto toPing = m_RoutingTable->GetNodesToPing (ts);
				for (const auto& it: toPing)
					SendPingQuery (it->peer, it->port);
			}
			ScheduleDHTSendPingCheck ();
		}
	}

	void TorrentsDHT::ScheduleDHTQueryExpirationCheck ()
	{
		m_DHTQueryExpirationCheckTimer.cancel ();
		m_DHTQueryExpirationCheckTimer.expires_after (std::chrono::seconds (DHT_QUERY_EXPIRATION_CHECK_INTERVAL));
		m_DHTQueryExpirationCheckTimer.async_wait (std::bind_front(&TorrentsDHT::DHTQueryExpirationCheckTimer, this));
	}

	void TorrentsDHT::DHTQueryExpirationCheckTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			std::list<std::shared_ptr<RequestInfo> > getpeers, findnode;
			auto ts = i2p::util::GetMonotonicSeconds ();
			auto it = m_Queries.begin ();
			while (it != m_Queries.end ())
			{
				if (ts > std::get<4>(it->second) + DHT_QUERY_EXPIRATION_TIME)
				{
					switch (std::get<2>(it->second))
					{
						case eKRPCQueryGetPeers:
							getpeers.push_back (std::get<3>(it->second));
						break;
						case eKRPCQueryFindNode:
							findnode.push_back (std::get<3>(it->second));
						break;
						default: ;
					}
					it = m_Queries.erase (it);
				}
				else
					it++;
			}
			for (auto it1: getpeers)
			{
				LogPrint (eLogDebug, "TorrentsDHT: get_peers response timeout after attempt #", it1->numAttempts);
				if (m_RoutingTable && it1->lastNode && !m_HeardFrom.contains (it1->lastNode->id))
				{
					auto bucket = m_RoutingTable->FindBucket (it1->lastNode->id);
					if (bucket && bucket->nodes.size () > MAX_BUCKET_CAPACITY/2)
						bucket->nodes.erase (it1->lastNode->id);
				}
				SendNextGetPeersQuery (it1);
			}
			for (auto it1: findnode)
			{
				LogPrint (eLogDebug, "TorrentsDHT: find_node response timeout after attempt #", it1->numAttempts);
				if (m_RoutingTable && it1->lastNode && !m_HeardFrom.contains (it1->lastNode->id))
				{
					auto bucket = m_RoutingTable->FindBucket (it1->lastNode->id);
					if (bucket && bucket->nodes.size () > MAX_BUCKET_CAPACITY/2)
						bucket->nodes.erase (it1->lastNode->id);
				}
				SendNextFindNodeQuery (it1);
			}
			ScheduleDHTQueryExpirationCheck ();
		}
	}

	void TorrentsDHT::GetPeersAndAnnounce (std::shared_ptr<Torrent> torrent)
	{
		if (!torrent || !m_RoutingTable) return;
		auto request = std::make_shared<RequestInfo>(torrent, DHT_MAX_NUM_GET_PEERS_ATTEMPTS);
		auto bucket = m_RoutingTable->FindBucket (torrent->GetInfoHash ());
		if (!bucket) return; // DHT is empty
		if (bucket->IsEmpty ())
		{
			if (bucket->next && !bucket->next->IsEmpty ())
				bucket = bucket->next;
			else
				return;
		}
		// fill initial list of nodes to request from bucket
		for (auto it: bucket->nodes)
			request->AddNode (it.second);
		SendNextGetPeersQuery (request);
	}
}
}

#endif
