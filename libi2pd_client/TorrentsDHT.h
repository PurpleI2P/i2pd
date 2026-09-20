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
#include "Identity.h"
#include "I2PService.h"
#include "util.h"

namespace i2p
{
namespace torrents
{
	struct NodeID
	{
		static constexpr size_t len = SHA_DIGEST_LENGTH;

		union // 4 bytes aligned
		{
			uint8_t buf[len];
			uint32_t l[len/4];
		};
	};

	struct NodeDistance: public NodeID
	{
		auto operator<=>(const NodeDistance& other) const { return memcmp (buf, other.buf, len) <=> 0; }
	};
	NodeDistance operator^(const NodeID& node1, const NodeID& node2);

	struct Node
	{
		NodeID id;
		i2p::data::IdentHash peerInfo;
	};

	constexpr size_t MAX_BUCKET_CAPACITY = 8;
	struct Bucket
	{
		std::list<std::shared_ptr<Node> > nodes;
		NodeID start;
	};

	class RoutingTable
	{
		public:

			RoutingTable () = default;

		private:

			std::list<std::shared_ptr<Bucket> > m_Buckets;
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
			RoutingTable m_RoutingTable;
	};
}
}

#endif

#endif
