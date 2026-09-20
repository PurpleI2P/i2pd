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
#include "TorrentsDHT.h"

namespace i2p
{
namespace torrents
{
	TorrentsDHT::TorrentsDHT (std::shared_ptr<i2p::client::I2PService> service, uint16_t port):
		m_Service (service)
	{
		if (service)
		{
			auto dest = service->GetLocalDestination ();
			if (dest)
			{
				memcpy (m_NodeID.data (), dest->GetIdentHash (), m_NodeID.size ());
				m_NodeID[4] ^= (port >> 8);
				m_NodeID[5] ^= (port & 0xFF);
				memcpy (m_NodeInfo.data (), m_NodeID.data (), m_NodeID.size ());
				memcpy (m_NodeInfo.data () + m_NodeID.size (), dest->GetIdentHash (), i2p::data::IdentHash::len);
				htobe16buf (m_NodeInfo.data () + m_NodeInfo.size () - 2, port);
			}
			else
			{
				m_NodeID.fill (0);
				m_NodeInfo.fill (0);
			}
		}
	}
}
}

#endif
