/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TORRENTS_DHT_H__
#define TORRENTS_DHT_H__

#ifndef NO_TORRENTS

#include <inttypes.h>
#include <openssl/sha.h>
#include <string>
#include <string_view>
#include <tuple>
#include <memory>
#include <random>
#include <array>
#include <list>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <utility>
#include <optional>
#include <filesystem>
#include <boost/asio.hpp>
#include "Base.h"
#include "Identity.h"
#include "I2PService.h"
#include "util.h"
#include "Timestamp.h"
#include "Torrents.h"

namespace i2p
{
namespace torrents
{
	constexpr int DHT_UPDATE_CHECK_INTERVAL = 24; // in seconds
	constexpr int DHT_EXPIRATION_CHECK_INTERVAL = 73; // in seconds
	constexpr int DHT_SEND_PING_CHECK_INTERVAL = 38; // in seconds
	constexpr int DHT_QUERY_EXPIRATION_CHECK_INTERVAL = 8; // in seconds
	constexpr int DHT_EXPLORATORY_INTERVAL = 130; // in seconds
	constexpr int DHT_EXPLORATORY_INTERVAL_VARIANCE = 40; // in seconds
	constexpr int DHT_INITIAL_EXPLORATORY_INTERVAL = 90; // in seconds
	constexpr int DHT_NODE_SEND_PING_TIME = 740; // in seconds
	constexpr int DHT_ROUTING_TABLE_NODE_EXPIRATION_TIME = 855; // in seconds
	constexpr int DHT_NODE_EXPIRATION_TIME = 1315; // in seconds
	constexpr int DHT_BUCKET_EXPIRATION_THRESHOLD = 290; // in seconds
	constexpr int DHT_TORRENT_PEER_EXPIRATION_TIME = 3*3600; // in seconds
	constexpr int DHT_INCOMING_GET_PEERS_TOKEN_EXPIRATION_TIME = 600; // in seconds
	constexpr int DHT_EMPTY_TORRENT_EXPIRATION_TIME = 30; // in seconds
	constexpr int DHT_QUERY_EXPIRATION_TIME = 20; // in seconds
	constexpr int DHT_MAX_NUM_GET_PEERS_ATTEMPTS = 22;

	using Distance = Torrent::InfoHash;
	struct NodeID: public Torrent::InfoHash
	{
		static constexpr size_t len = std::tuple_size<Torrent::InfoHash>::value;
		constexpr Distance operator^(const Torrent::InfoHash& hash) const
		{
			Distance d;
			for (size_t i = 0; i < size (); i++)
				d[i] = (*this)[i] ^ hash[i];
			return d;
		}
		constexpr int FindLowestBit () const // -1 in not found
		{
			for (int i = size () - 1; i >= 0; i--)
			{
				uint8_t byte = (*this)[i];
				if (byte)
				{
					for (int j = 7; j >= 0; j--)
					if (byte & (0x80 >> j))
						return i*8 + j;
				}
			}
			return -1;
		}
		std::string ToBase64 () const
		{
			return i2p::data::ByteStreamToBase64 (data (), size ());
		}
	};

	using NodeInfo = std::array<uint8_t, NodeID::len + i2p::data::IdentHash::len + 2>;
	struct Node
	{
		NodeID id;
		i2p::data::IdentHash peer;
		uint16_t port;
		uint64_t lastUpdateTime; // monotonic seconds

		Node (const NodeID& id1, const i2p::data::IdentHash& peer1, uint16_t port1):
			id (id1), peer (peer1), port (port1), lastUpdateTime (i2p::util::GetMonotonicSeconds ()) {}
		Node (const NodeInfo& nodeInfo);

		NodeInfo GetNodeInfo () const;
		bool VerifyID () const;
	};

	constexpr size_t MAX_BUCKET_CAPACITY = 8;
	struct Bucket
	{
		Bucket * next;
		std::map<NodeID, std::shared_ptr<Node> > nodes;
		NodeID start;
		uint64_t lastUpdateTime; // monotonic seconds

		Bucket (): next (nullptr), start{}, lastUpdateTime (i2p::util::GetMonotonicSeconds ()) {}
		Bucket (const NodeID& start1): next (nullptr), start (start1),
			lastUpdateTime (i2p::util::GetMonotonicSeconds ()) {}
		bool IsFull () const { return nodes.size () >= MAX_BUCKET_CAPACITY; }
		bool IsEmpty () const { return nodes.empty (); }
		bool IsInBucket (const NodeID& id) const { return id >= start && (!next || id < next->start); }
		std::optional<NodeID> GetMiddleID () const;
		NodeID GetRandomID (std::mt19937& rng) const;
		bool Split ();
	};

	class RoutingTable
	{
		public:

			RoutingTable (const NodeID& ourNode);
			~RoutingTable ();
			void CleanUp ();
			size_t GetNumBuckets () const;
			size_t GetNumNodes () const;
			Bucket * FindBucket (const Torrent::InfoHash& id) const;

			bool AddNode (std::shared_ptr<Node> node);
			void RemoveNode (const NodeID& id);
			std::list<std::pair<std::shared_ptr<Node>, Distance> > FindClosestNodes (const Torrent::InfoHash& infoHash,
				size_t num = 1, std::set<NodeID> * excluded = nullptr) const;
			std::shared_ptr<Node> FindClosestNode (const Torrent::InfoHash& infoHash,
				std::set<NodeID> * excluded = nullptr) const;
			std::list<std::pair<NodeID, std::shared_ptr<Node> > > GetExploratoryTargets (std::mt19937& rng) const; // (target, node to send find_node to)
			std::shared_ptr<Node> FindClosestNodeInBucket (const NodeID& target) const;
			size_t DeleteExpiredNodes (uint64_t ts);
			std::list<NodeID> GetNodesToPing (uint64_t ts);
			void RemoveEmptyBuckets ();

		private:

			Bucket * m_Buckets;
			NodeID m_OurNode;
	};

	using GetPeersToken = uint64_t;
	class DHTTorrent
	{
		public:

			DHTTorrent ();

			std::string GetBEncodedPeers () const;
			void AddIncomingGetPeerNode (GetPeersToken token, std::shared_ptr<Node> node);
			std::shared_ptr<Node> GetIncomingGetPeerNode (GetPeersToken token) const;
			bool AddPeer (const i2p::data::IdentHash& peer);
			bool CleanUp (uint64_t ts); // return true if empty

		private:

			std::unordered_map<i2p::data::IdentHash, uint64_t> m_Peers; // ident -> update time in monotonic seconds
			std::unordered_map<GetPeersToken, std::pair<std::weak_ptr<Node>, uint64_t> > m_IncomingGetPeers; // they request peers and send announces to us
			uint64_t m_LastUpdateTime; // monotonic second
	};

	enum KRPCQuery
	{
		eKRPCQueryPing = 0,
		eKRPCQueryFindNode,
		eKRPCQueryGetPeers,
		eKRPCQueryAnnouncePeer,
		eNumKRPCQueries
	};

	constexpr std::array<std::string_view, eNumKRPCQueries> KRPCQueryStr
	{
		"ping", "find_node", "get_peers", "announce_peer"
	};

	struct GetPeersRequestInfo
	{
		std::shared_ptr<Torrent> torrent;
		std::map<Distance, std::shared_ptr<Node> > nodesToRequest;
		std::set<NodeID> tried;
		uint64_t token;
		int numAttempts;

		GetPeersRequestInfo (std::shared_ptr<Torrent> t): torrent (t), token (0), numAttempts (0) { }
		bool IsDone () const { return numAttempts >= DHT_MAX_NUM_GET_PEERS_ATTEMPTS; }
		bool AddNode (std::shared_ptr<Node> node);
		std::shared_ptr<Node> GetNextNode ();
	};

	class TorrentsTunnel;
	class TorrentsDHT
	{
		public:

			TorrentsDHT (TorrentsTunnel& tunnel, uint16_t port);

			void Start ();
			void Stop ();

			uint16_t GetPort () const { return m_Port; };
			uint16_t GetRPort () const { return m_Port + 1; };
			void HandleRawDatagram (const uint8_t * buf, size_t len);

			void SendPingQuery (const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void GetPeersAndAnnounce (std::shared_ptr<Torrent> torrent);

		private:

			void HandleDatagram (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
				const uint8_t * buf, size_t len, const i2p::util::Mapping * options);
			void HandlePingQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
				std::string_view transactionID, const NodeID& nodeID);
			void HandleGetPeersQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
				std::string_view transactionID, std::shared_ptr<Node> from, const Torrent::InfoHash& infoHash);
			void HandleFindNodeQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
				std::string_view transactionID, const NodeID& target);
			void HandleResponse (std::string_view transactionID, const NodeID& nodeID, uint64_t token,
				const std::vector<std::string_view>& values, std::string_view nodes);
			void HandleGetPeersResponseNodes (std::shared_ptr<GetPeersRequestInfo> info,
				const NodeID& nodeID, uint64_t token, std::string_view nodes);
			void HandleGetPeersResponsePeersAndAnnounce (std::shared_ptr<GetPeersRequestInfo> info,
				const std::vector<std::string_view>& peers, uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void HandleFindNodeResponse (std::string_view nodes);
			void HandleAnnouncePeer (std::string_view transactionID, const Torrent::InfoHash& infoHash, uint64_t token);

			void SendDatagram (std::string_view msg, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendRawDatagram (std::string_view msg, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendQueryMsg (KRPCQuery query, std::string_view arguments, const i2p::data::IdentHash& toIdent,
				uint16_t toPort, bool isRaw = false, std::shared_ptr<GetPeersRequestInfo> info = nullptr);
			void SendFindNodeQuery (const NodeID& target, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendGetPeersQuery (std::shared_ptr<GetPeersRequestInfo> info, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendNextGetPeersQuery (std::shared_ptr<GetPeersRequestInfo> info);
			void SendResponseMsg (std::string_view response, std::string_view transactionID, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendPingResponse (std::string_view transactionID, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendGetPeersResponse (std::string_view transactionID, std::shared_ptr<DHTTorrent> torrent,
				uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendGetPeersResponse (std::string_view transactionID, std::shared_ptr<const Node> node,
				uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendFindNodeResponse (std::string_view transactionID, const NodeInfo& nodeInfo,
				const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendAnnouncePeerQuery (const Torrent::InfoHash& infoHash, uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort);

			std::filesystem::path GetDHTFilePath (std::string_view filename) const;
			void Save (const std::filesystem::path& file);
			void Load (const std::filesystem::path& file);
			void Explore ();
			std::shared_ptr<Node> UpdateNode (std::shared_ptr<Node> node); // return true if added

			void ScheduleDHTUpdateCheck ();
			void HandleDHTUpdateCheckTimer (const boost::system::error_code& ecode);

			void ScheduleDHTExpirationCheck ();
			void HandleDHTExpirationCheckTimer (const boost::system::error_code& ecode);

			void ScheduleDHTSendPingCheck ();
			void HandleDHTSendPingCheckTimer (const boost::system::error_code& ecode);

			void ScheduleDHTQueryExpirationCheck ();
			void DHTQueryExpirationCheckTimer (const boost::system::error_code& ecode);

		private:

			TorrentsTunnel& m_Tunnel;
			boost::asio::steady_timer m_DHTUpdateCheckTimer, m_DHTExpirationCheckTimer,
				m_DHTSendPingCheckTimer, m_DHTQueryExpirationCheckTimer;
			uint16_t m_Port;
			NodeID m_NodeID;
			std::unique_ptr<RoutingTable> m_RoutingTable;
			std::map<NodeID, std::shared_ptr<Node> > m_Nodes;
			// transactionID -> (ident, port, query, get peers request info, time in monotonic seconds)
			std::unordered_map<uint16_t, std::tuple<i2p::data::IdentHash, uint16_t, KRPCQuery, std::shared_ptr<GetPeersRequestInfo>, uint64_t > > m_Queries;
			std::map<Torrent::InfoHash, std::shared_ptr<DHTTorrent> > m_Torrents;
			uint64_t m_NextDHTExploratoryTime; // monotonic seconds
	};
}
}

#endif

#endif
