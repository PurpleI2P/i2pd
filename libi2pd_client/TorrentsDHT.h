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
#include <utility>
#include "Identity.h"
#include "I2PService.h"

namespace i2p
{
namespace torrents
{
	using NodeID = std::array<uint8_t, SHA_DIGEST_LENGTH>;
	using NodeInfo = std::array<uint8_t, std::tuple_size<NodeID>::value + i2p::data::IdentHash::len + 2>;
	class TorrentsDHT
	{
		public:

			TorrentsDHT (std::shared_ptr<i2p::client::I2PService> service, uint16_t port);

		private:

			std::weak_ptr<i2p::client::I2PService> m_Service;
			NodeID m_NodeID;
			NodeInfo m_NodeInfo; // 20 byte Node ID + 32 byte IdentHash + 2 byte port
	};
}
}

#endif

#endif
