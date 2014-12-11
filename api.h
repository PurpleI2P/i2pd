#ifndef API_H__
#define API_H__

#include <memory>
#include <iostream>
#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"

namespace i2p
{
namespace api
{
	// initialization start and stop	
	void InitI2P (int argc, char* argv[], const char * appName);
	void StartI2P (std::ostream * logStream = nullptr);
	// write system log to logStream, if not specified to <appName>.log in application's folder
	void StopI2P ();

	// destinations
	i2p::client::ClientDestination * CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true,
		const std::map<std::string, std::string> * params = nullptr); 
	i2p::client::ClientDestination * CreateLocalDestination (bool isPublic = false, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256, 
		const std::map<std::string, std::string> * params = nullptr); // transient destinations usually not published
	void DestroyLocalDestination (i2p::client::ClientDestination * dest);

	// streams
	void RequestLeaseSet (i2p::client::ClientDestination * dest, const i2p::data::IdentHash& remote);
	std::shared_ptr<i2p::stream::Stream> CreateStream (i2p::client::ClientDestination * dest, const i2p::data::IdentHash& remote);
	void AcceptStream (i2p::client::ClientDestination * dest, const i2p::stream::StreamingDestination::Acceptor& acceptor);
	void DestroyStream (std::shared_ptr<i2p::stream::Stream> stream);
}
}

#endif

