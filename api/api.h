#ifndef API_H__
#define API_H__

#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"

namespace i2p
{
namespace api
{
	// initialization start and stop	
	void InitI2P (int argc, char* argv[], const char * appName);
	void StartI2P ();
	void StopI2P ();

	// destinations
	i2p::client::ClientDestination * CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true); 
	i2p::client::ClientDestination * CreateLocalDestination (bool isPublic = false, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1); // transient destinations usually not published
	void DestoroyLocalDestination (i2p::client::ClientDestination * dest);

	// streams
	void RequestLeaseSet (i2p::client::ClientDestination * dest, const i2p::data::IdentHash& remote);
	i2p::stream::Stream * CreateStream (i2p::client::ClientDestination * dest, const i2p::data::IdentHash& remote);
	void AcceptStream (i2p::client::ClientDestination * dest, const i2p::stream::StreamingDestination::Acceptor& acceptor);
	void DestroyStream (i2p::stream::Stream * stream);
}
}

#endif

