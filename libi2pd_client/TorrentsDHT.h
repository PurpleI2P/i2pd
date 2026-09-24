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
#include <array>
#include <list>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <utility>
#include <optional>
#include <filesystem>
#include "Identity.h"
#include "I2PService.h"
#include "util.h"
#include "Torrents.h"

namespace i2p
{
namespace torrents
{
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
	};

	using NodeInfo = std::array<uint8_t, NodeID::len + i2p::data::IdentHash::len + 2>;
	struct Node
	{
		NodeID id;
		i2p::data::IdentHash peer;
		uint16_t port;

		Node (const NodeID& id1, const i2p::data::IdentHash& peer1, uint16_t port1):
			id (id1), peer (peer1), port (port1) {}
		Node (const NodeInfo& nodeInfo);

		NodeInfo GetNodeInfo () const;
	};

	constexpr size_t MAX_BUCKET_CAPACITY = 8;
	struct Bucket
	{
		Bucket * next;
		std::list<std::shared_ptr<Node> > nodes;
		NodeID start;

		Bucket (): next (nullptr), start{} {}
		Bucket (const NodeID& start1): next (nullptr), start (start1) {}
		bool IsFull () const { return nodes.size () >= MAX_BUCKET_CAPACITY; }
		bool IsInBucket (const NodeID& id) const { return id >= start && (!next || id < next->start); }
		std::shared_ptr<Node> FindNode (const NodeID& id) const;
		std::optional<NodeID> GetMiddleID () const;
		bool Split ();
	};

	class RoutingTable
	{
		public:

			RoutingTable (const NodeID& ourNode);
			~RoutingTable ();

			std::shared_ptr<Node> AddNode (const NodeID& id, const i2p::data::IdentHash& peer, uint16_t port);
			std::shared_ptr<Node> FindNode (const NodeID& id) const;
			std::list<std::pair<std::shared_ptr<Node>, Distance> > FindClosestNodes (const Torrent::InfoHash& infoHash, size_t num = 1) const;

			void Save (const std::filesystem::path& file);
			void Load (const std::filesystem::path& file);

		private:

			std::shared_ptr<Node> AddNode (const NodeInfo& nodeInfo);
			Bucket * FindBucket (const Torrent::InfoHash& id) const;
			void RemoveEmptyBuckers ();
			void CleanUp ();

		private:

			Bucket * m_Buckets;
			NodeID m_OurNode;
	};

	using GetPeersToken = uint64_t;
	class DHTTorrent
	{
		public:

			DHTTorrent () = default;

			std::string GetBEncodedPeers () const;
			void AddIncomingGetPeerNode (GetPeersToken token, std::shared_ptr<Node> node);
			void AddOutgoingGetPeerNode (GetPeersToken token, std::shared_ptr<Node> node);

		private:

			std::list<std::pair<i2p::data::IdentHash, uint64_t> > m_Peers; // (ident, update time in monotonic seconds)
			std::unordered_map<GetPeersToken, std::weak_ptr<Node> > m_IncomingGetPeers; // we send announces to
			std::unordered_map<GetPeersToken, std::weak_ptr<Node> > m_OutgoingGetPeers; // we recive announces from
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

		private:

			void HandleDatagram (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
				const uint8_t * buf, size_t len, const i2p::util::Mapping * options);
			void HandlePingQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
				std::string_view transactionID, std::string_view id);
			void HandleGetPeersQuery (const i2p::data::IdentHash& fromIdent, uint16_t fromPort,
				std::string_view transactionID, std::string_view id, std::string_view infoHash);
			void HandleResponse (std::string_view transactionID, std::string_view id, uint64_t token,
				const std::vector<std::string_view>& values);

			void SendDatagram (std::string_view msg, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendRawDatagram (std::string_view msg, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendQueryMsg (std::string_view query, std::string_view arguments, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendResponseMsg (std::string_view response, std::string_view transactionID, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendPingResponse (std::string_view transactionID, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendGetPeersResponse (std::string_view transactionID, std::shared_ptr<DHTTorrent> torrent,
				uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort);
			void SendGetPeersResponse (std::string_view transactionID, std::shared_ptr<Node> node,
				uint64_t token, const i2p::data::IdentHash& toIdent, uint16_t toPort);

		private:

			TorrentsTunnel& m_Tunnel;
			uint16_t m_Port;
			NodeID m_NodeID;
			NodeInfo m_NodeInfo; // 20 byte Node ID + 32 byte IdentHash + 2 byte port
			std::unique_ptr<RoutingTable> m_RoutingTable;
			std::unordered_map<uint16_t, std::tuple<i2p::data::IdentHash, uint16_t, std::string, std::weak_ptr<Torrent> > > m_Queries;
			std::map<Torrent::InfoHash, std::shared_ptr<DHTTorrent> > m_Torrents;
	};
}
}

#endif

#endif
