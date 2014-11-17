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
	static std::map<i2p::data::IdentHash, i2p::client::ClientDestination *> g_Destinations;

	void InitI2P (int argc, char* argv[])
	{
		i2p::util::config::OptionParser(argc, argv);
		i2p::context.Init ();	
	}

	void StartI2P ()
	{
		std::string logfilePath ("libi2pd.log");
		StartLog (logfilePath);
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
		for (auto it: g_Destinations)
		{	
			it.second->Stop ();
			delete it.second;
		}		
		g_Destinations.clear ();
		LogPrint("Local destinations deleted");

		StopLog ();
	}
}
}

