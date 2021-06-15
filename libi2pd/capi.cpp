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

void C_StartI2P (std::ostream *logStream)
{
	std::shared_ptr<std::ostream> cppLogStream(logStream);
	return i2p::api::StartI2P(cppLogStream);
}

void C_StopI2P ()
{
	return i2p::api::StopI2P();
}

void C_RunPeerTest ()
{
	return i2p::api::RunPeerTest();
}

i2p::client::ClientDestination *C_CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
	const std::map<std::string, std::string> * params)
{
	return i2p::api::CreateLocalDestination(keys, isPublic, params).get();
}

i2p::client::ClientDestination *C_CreateTransientLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
	const std::map<std::string, std::string> * params)
{
	return i2p::api::CreateLocalDestination(isPublic, sigType, params).get();
}

void C_DestroyLocalDestination (i2p::client::ClientDestination *dest)
{
	std::shared_ptr<i2p::client::ClientDestination> cppDest(dest);
	return i2p::api::DestroyLocalDestination(cppDest);
}

void C_RequestLeaseSet (i2p::client::ClientDestination *dest, const i2p::data::IdentHash& remote)
{
	std::shared_ptr<i2p::client::ClientDestination> cppDest(dest);
	return i2p::api::RequestLeaseSet(cppDest, remote);
}

i2p::stream::Stream *C_CreateStream (i2p::client::ClientDestination *dest, const i2p::data::IdentHash& remote)
{
	std::shared_ptr<i2p::client::ClientDestination> cppDest(dest);
	return i2p::api::CreateStream(cppDest, remote).get();
}

void C_AcceptStream (i2p::client::ClientDestination *dest, const i2p::stream::StreamingDestination::Acceptor& acceptor)
{
	std::shared_ptr<i2p::client::ClientDestination> cppDest(dest);
	return i2p::api::AcceptStream(cppDest, acceptor);
}

void C_DestroyStream (i2p::stream::Stream *stream)
{
	std::shared_ptr<i2p::stream::Stream> cppStream(stream);
	return i2p::api::DestroyStream(cppStream);
}

#ifdef __cplusplus
}
#endif

