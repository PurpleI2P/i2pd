#ifndef API_H__
#define API_H__

#include "Identity.h"

namespace i2p
{
namespace api
{
	void InitI2P (int argc, char* argv[]);
	void StartI2P ();
	void StopI2P ();

	i2p::client::ClientDestination * CreateLocalDestination (const i2p::data::PrivateKeys& keys);
	i2p::client::ClientDestination * CreateLocalDestination (i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1);
	void DestoroyLocalDestination (i2p::client::ClientDestination * dest);
}
}

#endif

