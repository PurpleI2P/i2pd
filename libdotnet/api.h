#ifndef API_H__
#define API_H__

#include <memory>
#include <iostream>
#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"

namespace dotnet
{
namespace api
{
	// initialization start and stop
	void InitDOTNET (int argc, char* argv[], const char * appName);
	void TerminateDOTNET ();
	void StartDOTNET (std::shared_ptr<std::ostream> logStream = nullptr);
	// write system log to logStream, if not specified to <appName>.log in application's folder
	void StopDOTNET ();
	void RunPeerTest (); // should be called after UPnP

	// destinations
	std::shared_ptr<dotnet::client::ClientDestination> CreateLocalDestination (const dotnet::data::PrivateKeys& keys, bool isPublic = true,
		const std::map<std::string, std::string> * params = nullptr);
	std::shared_ptr<dotnet::client::ClientDestination> CreateLocalDestination (bool isPublic = false, dotnet::data::SigningKeyType sigType = dotnet::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256,
		const std::map<std::string, std::string> * params = nullptr); // transient destinations usually not published
	void DestroyLocalDestination (std::shared_ptr<dotnet::client::ClientDestination> dest);

	// streams
	void RequestLeaseSet (std::shared_ptr<dotnet::client::ClientDestination> dest, const dotnet::data::IdentHash& remote);
	std::shared_ptr<dotnet::stream::Stream> CreateStream (std::shared_ptr<dotnet::client::ClientDestination> dest, const dotnet::data::IdentHash& remote);
	void AcceptStream (std::shared_ptr<dotnet::client::ClientDestination> dest, const dotnet::stream::StreamingDestination::Acceptor& acceptor);
	void DestroyStream (std::shared_ptr<dotnet::stream::Stream> stream);
}
}

#endif

