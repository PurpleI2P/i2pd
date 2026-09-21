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
#include <memory>
#include <array>
#include <list>
#include <algorithm>
#include <utility>
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
		constexpr Distance operator^(const Torrent::InfoHash& hash)
		{
			Distance d;
			for (size_t i = 0; i < size (); i++)
				d[i] = (*this)[i] ^ hash[i];
			return d;
		}
	};

	struct Node
	{
		NodeID id;
		i2p::data::IdentHash peer;
		uint16_t port;

		Node (const NodeID& id1, const i2p::data::IdentHash& peer1, uint16_t port1):
			id (id1), peer (peer1), port (port1) {}
	};

	constexpr size_t MAX_BUCKET_CAPACITY = 8;
	struct Bucket
	{
		std::list<std::shared_ptr<Node> > nodes;
		NodeID start;

		Bucket (): start{} {}
	};

	class RoutingTable
	{
		public:

			RoutingTable (const NodeID& ourNode);

			std::shared_ptr<Node> AddNode (const NodeID& id, i2p::data::IdentHash& peer, uint16_t port);
			std::list<std::pair<std::shared_ptr<Node>, Distance> > FindClosestNodes (const Torrent::InfoHash& infoHash, size_t num) const;

		private:

			std::shared_ptr<Bucket> FindBucket (const Torrent::InfoHash& id) const;

		private:

			std::list<std::shared_ptr<Bucket> > m_Buckets;
			NodeID m_OurNode;
	};

	using NodeInfo = std::array<uint8_t, NodeID::len + i2p::data::IdentHash::len + 2>;

	class TorrentsTunnel;
	class TorrentsDHT
	{
		public:

			TorrentsDHT (TorrentsTunnel& tunnel, uint16_t port);

			void Start ();
			void Stop ();

			uint16_t GetRPort () const { return m_Port + 1; };
			void HandleRawDatagram (const uint8_t * buf, size_t len);

		private:

			void HandleDatagram (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort,
				const uint8_t * buf, size_t len, const i2p::util::Mapping * options);

		private:

			TorrentsTunnel& m_Tunnel;
			uint16_t m_Port;
			NodeID m_NodeID;
			NodeInfo m_NodeInfo; // 20 byte Node ID + 32 byte IdentHash + 2 byte port
			std::unique_ptr<RoutingTable> m_RoutingTable;
	};
}
}

#endif

#endif
