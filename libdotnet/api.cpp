#include <string>
#include <map>
#include "Config.h"
#include "Log.h"
#include "NetDb.hpp"
#include "Transports.h"
#include "Tunnel.h"
#include "RouterContext.h"
#include "Identity.h"
#include "Destination.h"
#include "Crypto.h"
#include "FS.h"
#include "api.h"

namespace dotnet
{
namespace api
{
	void InitDOTNET (int argc, char* argv[], const char * appName)
	{
		dotnet::config::Init ();
		dotnet::config::ParseCmdline (argc, argv, true); // ignore unknown options and help
		dotnet::config::Finalize ();

		std::string datadir; dotnet::config::GetOption("datadir", datadir);

		dotnet::fs::SetAppName (appName);
		dotnet::fs::DetectDataDir(datadir, false);
		dotnet::fs::Init();

		bool precomputation; dotnet::config::GetOption("precomputation.elgamal", precomputation);
		dotnet::crypto::InitCrypto (precomputation);

        int netID; dotnet::config::GetOption("netid", netID);
        dotnet::context.SetNetID (netID);

		dotnet::context.Init ();
	}

	void TerminateDOTNET ()
	{
		dotnet::crypto::TerminateCrypto ();
	}

	void StartDOTNET (std::shared_ptr<std::ostream> logStream)
	{
		if (logStream)
			dotnet::log::Logger().SendTo (logStream);
		else
			dotnet::log::Logger().SendTo (dotnet::fs::DataDirPath (dotnet::fs::GetAppName () + ".log"));
		dotnet::log::Logger().Start ();
		LogPrint(eLogInfo, "API: starting NetDB");
		dotnet::data::netdb.Start();
		LogPrint(eLogInfo, "API: starting Transports");
		dotnet::transport::transports.Start();
		LogPrint(eLogInfo, "API: starting Tunnels");
		dotnet::tunnel::tunnels.Start();
	}

	void StopDOTNET ()
	{
		LogPrint(eLogInfo, "API: shutting down");
		LogPrint(eLogInfo, "API: stopping Tunnels");
		dotnet::tunnel::tunnels.Stop();
		LogPrint(eLogInfo, "API: stopping Transports");
		dotnet::transport::transports.Stop();
		LogPrint(eLogInfo, "API: stopping NetDB");
		dotnet::data::netdb.Stop();
		dotnet::log::Logger().Stop ();
	}

	void RunPeerTest ()
	{
		dotnet::transport::transports.PeerTest ();
	}

	std::shared_ptr<dotnet::client::ClientDestination> CreateLocalDestination (const dotnet::data::PrivateKeys& keys, bool isPublic,
		const std::map<std::string, std::string> * params)
	{
		auto localDestination = std::make_shared<dotnet::client::ClientDestination> (keys, isPublic, params);
		localDestination->Start ();
		return localDestination;
	}

	std::shared_ptr<dotnet::client::ClientDestination> CreateLocalDestination (bool isPublic, dotnet::data::SigningKeyType sigType,
		const std::map<std::string, std::string> * params)
	{
		dotnet::data::PrivateKeys keys = dotnet::data::PrivateKeys::CreateRandomKeys (sigType);
		auto localDestination = std::make_shared<dotnet::client::ClientDestination> (keys, isPublic, params);
		localDestination->Start ();
		return localDestination;
	}

	void DestroyLocalDestination (std::shared_ptr<dotnet::client::ClientDestination> dest)
	{
		if (dest)
			dest->Stop ();
	}

	void RequestLeaseSet (std::shared_ptr<dotnet::client::ClientDestination> dest, const dotnet::data::IdentHash& remote)
	{
		if (dest)
			dest->RequestDestination (remote);
	}

	std::shared_ptr<dotnet::stream::Stream> CreateStream (std::shared_ptr<dotnet::client::ClientDestination> dest, const dotnet::data::IdentHash& remote)
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

	void AcceptStream (std::shared_ptr<dotnet::client::ClientDestination> dest, const dotnet::stream::StreamingDestination::Acceptor& acceptor)
	{
		if (dest)
			dest->AcceptStreams (acceptor);
	}

	void DestroyStream (std::shared_ptr<dotnet::stream::Stream> stream)
	{
		if (stream)
			stream->Close ();
	}
}
}

