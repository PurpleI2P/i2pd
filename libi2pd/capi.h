/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef CAPI_H__
#define CAPI_H__

#include "api.h"


#ifdef __cplusplus
extern "C" {
#endif

// initialization start and stop
void C_InitI2P (int argc, char* argv[], const char * appName);
void C_TerminateI2P ();
void C_StartI2P (std::ostream *logStream = nullptr);
// write system log to logStream, if not specified to <appName>.log in application's folder
void C_StopI2P ();
void C_RunPeerTest (); // should be called after UPnP

// destinations
i2p::client::ClientDestination *C_CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true,
	const std::map<std::string, std::string> * params = nullptr);
i2p::client::ClientDestination *C_CreateTransientLocalDestination (bool isPublic = false, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256,
	const std::map<std::string, std::string> * params = nullptr); // transient destinations usually not published
void C_DestroyLocalDestination (i2p::client::ClientDestination *dest);

// streams
void C_RequestLeaseSet (i2p::client::ClientDestination *dest, const i2p::data::IdentHash& remote);
i2p::stream::Stream *C_CreateStream (i2p::client::ClientDestination *dest, const i2p::data::IdentHash& remote);
void C_AcceptStream (i2p::client::ClientDestination *dest, const i2p::stream::StreamingDestination::Acceptor& acceptor);
void C_DestroyStream (i2p::stream::Stream *stream);

#ifdef __cplusplus
}
#endif

#endif
