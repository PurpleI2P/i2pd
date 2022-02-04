/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "SSU2.h"

namespace i2p
{
namespace transport
{
	SSU2Session::SSU2Session (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter,
		std::shared_ptr<const i2p::data::RouterInfo::Address> addr, bool peerTest):
		TransportSession (in_RemoteRouter, SSU2_TERMINATION_TIMEOUT)
	{
	}
	
	SSU2Session::~SSU2Session ()
	{	
	}
}
}
