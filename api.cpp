#include <string>
#include <map>
#include "Log.h"
#include "NetDb.h"
#include "Transports.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "Identity.h"
#include "Destination.h"
#include "util.h"
#include "api.h"

namespace i2p
{
namespace api
{
	void InitI2P (int argc, char* argv[], const char * appName)
	{
		i2p::util::filesystem::SetAppName (appName);
		i2p::util::config::OptionParser(argc, argv);
		i2p::context.Init ();	
	}

	void StartI2P (std::ostream * logStream)
	{
		if (logStream)
			StartLog (logStream);
		else
			StartLog (i2p::util::filesystem::GetAppName () + ".log");
		i2p::data::netdb.Start();
		LogPrint("NetDB started");
		i2p::transport::transports.Start();
		LogPrint("Transports started");
		i2p::tunnel::tunnels.Start();
		LogPrint("Tunnels started");
	}

	void StopI2P ()
	{
		LogPrint("Shutdown started.");
		i2p::tunnel::tunnels.Stop();
		LogPrint("Tunnels stoped");
		i2p::transport::transports.Stop();
		LogPrint("Transports stoped");
		i2p::data::netdb.Stop();
		LogPrint("NetDB stoped");
		StopLog ();
	}

	i2p::client::ClientDestination * CreateLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
		const std::map<std::string, std::string> * params)
	{
		auto localDestination = new i2p::client::ClientDestination (keys, isPublic, params);
		localDestination->Start ();
		return localDestination;
	}

	i2p::client::ClientDestination * CreateLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
		const std::map<std::string, std::string> * params)
	{
		i2p::data::PrivateKeys keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
		auto localDestination = new i2p::client::ClientDestination (keys, isPublic, params);
		localDestination->Start ();
		return localDestination;
	}

	void DestroyLocalDestination (i2p::client::ClientDestination * dest)
	{
		if (dest)
		{
			dest->Stop ();
			delete dest;
		}
	}

	void RequestLeaseSet (i2p::client::ClientDestination * dest, const i2p::data::IdentHash& remote)
	{
		if (dest)
			dest->RequestDestination (remote);
	}

	std::shared_ptr<i2p::stream::Stream> CreateStream (i2p::client::ClientDestination * dest, const i2p::data::IdentHash& remote)
	{
		if (!dest) return nullptr;
		auto leaseSet = dest->FindLeaseSet (remote);
		if (leaseSet)
		{
			auto stream = dest->CreateStream (*leaseSet);
			stream->Send (nullptr, 0); // connect
			return stream;
		}
		else
		{
			RequestLeaseSet (dest, remote);
			return nullptr;	
		}	
	}

	void AcceptStream (i2p::client::ClientDestination * dest, const i2p::stream::StreamingDestination::Acceptor& acceptor)
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

