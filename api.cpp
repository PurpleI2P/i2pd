#include <string>
#include <map>
#include "Config.h"
#include "Log.h"
#include "NetDb.h"
#include "Transports.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "Identity.h"
#include "Destination.h"
#include "Crypto.h"
#include "util.h"
#include "api.h"

namespace i2p
{
namespace api
{
	void InitI2P (int argc, char* argv[], const char * appName)
	{
		i2p::util::filesystem::SetAppName (appName);
		i2p::config::Init ();
		i2p::config::ParseCmdline (argc, argv);
		i2p::config::Finalize ();
		i2p::crypto::InitCrypto ();
		i2p::context.Init ();	
	}

	void TerminateI2P ()
	{
		i2p::crypto::TerminateCrypto ();
	}	
	
	void StartI2P (std::shared_ptr<std::ostream> logStream)
	{
		if (logStream)
			StartLog (logStream);
		else
			StartLog (i2p::util::filesystem::GetFullPath (i2p::util::filesystem::GetAppName () + ".log"));
		LogPrint(eLogInfo, "API: starting NetDB");
		i2p::data::netdb.Start();
		LogPrint(eLogInfo, "API: starting Transports");
		i2p::transport::transports.Start();
		LogPrint(eLogInfo, "API: starting Tunnels");
		i2p::tunnel::tunnels.Start();
	}

	void StopI2P ()
	{
		LogPrint(eLogInfo, "API: shutting down");
		LogPrint(eLogInfo, "API: stopping Tunnels");
		i2p::tunnel::tunnels.Stop();
		LogPrint(eLogInfo, "API: stopping Transports");
		i2p::transport::transports.Stop();
		LogPrint(eLogInfo, "API: stopping NetDB");
		i2p::data::netdb.Stop();
		StopLog ();
	}

	void RunPeerTest ()
	{
		i2p::transport::transports.PeerTest ();
	}	
	
	std::shared_ptr<i2p::client::ClientDestination> CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
		const std::map<std::string, std::string> * params)
	{
		auto localDestination = std::make_shared<i2p::client::ClientDestination> (keys, isPublic, params);
		localDestination->Start ();
		return localDestination;
	}

	std::shared_ptr<i2p::client::ClientDestination> CreateLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
		const std::map<std::string, std::string> * params)
	{
		i2p::data::PrivateKeys keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
		auto localDestination = std::make_shared<i2p::client::ClientDestination> (keys, isPublic, params);
		localDestination->Start ();
		return localDestination;
	}

	void DestroyLocalDestination (std::shared_ptr<i2p::client::ClientDestination> dest)
	{
		if (dest)
			dest->Stop ();
	}

	void RequestLeaseSet (std::shared_ptr<i2p::client::ClientDestination> dest, const i2p::data::IdentHash& remote)
	{
		if (dest)
			dest->RequestDestination (remote);
	}

	std::shared_ptr<i2p::stream::Stream> CreateStream (std::shared_ptr<i2p::client::ClientDestination> dest, const i2p::data::IdentHash& remote)
	{
		if (!dest) return nullptr;
		auto leaseSet = dest->FindLeaseSet (remote);
		if (leaseSet)
		{
			auto stream = dest->CreateStream (leaseSet);
			stream->Send (nullptr, 0); // connect
			return stream;
		}
		else
		{
			RequestLeaseSet (dest, remote);
			return nullptr;	
		}	
	}

	void AcceptStream (std::shared_ptr<i2p::client::ClientDestination> dest, const i2p::stream::StreamingDestination::Acceptor& acceptor)
	{
		if (dest)
			dest->AcceptStreams (acceptor);
	}

	void DestroyStream (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
			stream->Close ();
	}
}
}

