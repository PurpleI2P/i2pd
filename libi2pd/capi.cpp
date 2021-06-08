/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "capi.h"

#ifdef __cplusplus
extern "C" {
#endif

void C_InitI2P (int argc, char* argv[], const char * appName)
{
	return i2p::api::InitI2P(argc, argv, appName);
}

void C_TerminateI2P ()
{
	return i2p::api::TerminateI2P();
}

void C_StartI2P (std::shared_ptr<std::ostream> logStream)
{
	return i2p::api::StartI2P(logStream);
}

void C_StopI2P ()
{
	return i2p::api::StopI2P();
}

void C_RunPeerTest ()
{
	return i2p::api::RunPeerTest();
}

std::shared_ptr<i2p::client::ClientDestination> C_CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
	const std::map<std::string, std::string> * params)
{
	return i2p::api::CreateLocalDestination(keys, isPublic, params);
}

std::shared_ptr<i2p::client::ClientDestination> C_CreateTransientLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
	const std::map<std::string, std::string> * params)
{
	return i2p::api::CreateLocalDestination(isPublic, sigType, params);
}

void C_DestroyLocalDestination (std::shared_ptr<i2p::client::ClientDestination> dest)
{
	return i2p::api::DestroyLocalDestination(dest);
}

void C_RequestLeaseSet (std::shared_ptr<i2p::client::ClientDestination> dest, const i2p::data::IdentHash& remote)
{
	return i2p::api::RequestLeaseSet(dest, remote);
}

std::shared_ptr<i2p::stream::Stream> C_CreateStream (std::shared_ptr<i2p::client::ClientDestination> dest, const i2p::data::IdentHash& remote)
{
	return i2p::api::CreateStream(dest, remote);
}

void C_AcceptStream (std::shared_ptr<i2p::client::ClientDestination> dest, const i2p::stream::StreamingDestination::Acceptor& acceptor)
{
	return i2p::api::AcceptStream(dest, acceptor);
}

void C_DestroyStream (std::shared_ptr<i2p::stream::Stream> stream)
{
	return i2p::api::DestroyStream(stream);
}

#ifdef __cplusplus
}
#endif

