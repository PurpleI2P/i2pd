#include "util.h"
#include "Log.h"
#include "ClientContext.h"

namespace i2p
{
namespace client
{
	ClientContext context;	

	ClientContext::ClientContext (): m_SharedLocalDestination (nullptr),
		m_HttpProxy (nullptr), m_SocksProxy (nullptr), m_IrcTunnel (nullptr),
		m_ServerTunnel (nullptr), m_SamBridge (nullptr)	
	{
	}
	
	ClientContext::~ClientContext () 
	{
		delete m_HttpProxy;
		delete m_SocksProxy;
		delete m_IrcTunnel;
		delete m_ServerTunnel;
		delete m_SamBridge;
	}
	
	void ClientContext::Start ()
	{
		if (!m_SharedLocalDestination)
		{	
			m_SharedLocalDestination = new ClientDestination (false, i2p::data::SIGNING_KEY_TYPE_DSA_SHA1); // non-public, DSA
			m_Destinations[m_SharedLocalDestination->GetIdentity ().GetIdentHash ()] = m_SharedLocalDestination;
			m_SharedLocalDestination->Start ();
		}

		m_HttpProxy = new i2p::proxy::HTTPProxy(i2p::util::config::GetArg("-httpproxyport", 4446));
		m_HttpProxy->Start();
		LogPrint("HTTP Proxy started");
		m_SocksProxy = new i2p::proxy::SOCKSProxy(i2p::util::config::GetArg("-socksproxyport", 4447));
		m_SocksProxy->Start();
		LogPrint("SOCKS Proxy Started");
		std::string ircDestination = i2p::util::config::GetArg("-ircdest", "");
		if (ircDestination.length () > 0) // ircdest is presented
		{
			ClientDestination * localDestination = nullptr;
			std::string ircKeys = i2p::util::config::GetArg("-irckeys", "");	
			if (ircKeys.length () > 0)
				localDestination = i2p::client::context.LoadLocalDestination (ircKeys, false);
			m_IrcTunnel = new I2PClientTunnel (m_SocksProxy->GetService (), ircDestination,
				i2p::util::config::GetArg("-ircport", 6668), localDestination);
			m_IrcTunnel->Start ();
			LogPrint("IRC tunnel started");
		}	
		std::string eepKeys = i2p::util::config::GetArg("-eepkeys", "");
		if (eepKeys.length () > 0) // eepkeys file is presented
		{
			auto localDestination = i2p::client::context.LoadLocalDestination (eepKeys, true);
			m_ServerTunnel = new I2PServerTunnel (m_SocksProxy->GetService (), 
				i2p::util::config::GetArg("-eephost", "127.0.0.1"), i2p::util::config::GetArg("-eepport", 80),
				localDestination);
			m_ServerTunnel->Start ();
			LogPrint("Server tunnel started");
		}
		int samPort = i2p::util::config::GetArg("-samport", 0);
		if (samPort)
		{
			m_SamBridge = new SAMBridge (samPort);
			m_SamBridge->Start ();
			LogPrint("SAM bridge started");
		} 
	}
		
	void ClientContext::Stop ()
	{
		m_HttpProxy->Stop();
		delete m_HttpProxy;
		m_HttpProxy = nullptr;
		LogPrint("HTTP Proxy stoped");
		m_SocksProxy->Stop();
		delete m_SocksProxy;
		m_SocksProxy = nullptr;
		LogPrint("SOCKS Proxy stoped");
		if (m_IrcTunnel)
		{
			m_IrcTunnel->Stop ();
			delete m_IrcTunnel; 
			m_IrcTunnel = nullptr;
			LogPrint("IRC tunnel stoped");	
		}
		if (m_ServerTunnel)
		{
			m_ServerTunnel->Stop ();
			delete m_ServerTunnel; 
			m_ServerTunnel = nullptr;
			LogPrint("Server tunnel stoped");	
		}			
		if (m_SamBridge)
		{
			m_SamBridge->Stop ();
			delete m_SamBridge; 
			m_SamBridge = nullptr;
			LogPrint("SAM brdige stoped");	
		}		
		
		for (auto it: m_Destinations)
		{	
			it.second->Stop ();
			delete it.second;
		}		
		m_Destinations.clear ();
		m_SharedLocalDestination = 0; // deleted through m_Destination
	}	

	void ClientContext::LoadLocalDestinations ()
	{
		int numDestinations = 0;
		boost::filesystem::path p (i2p::util::filesystem::GetDataDir());
		boost::filesystem::directory_iterator end;
		for (boost::filesystem::directory_iterator it (p); it != end; ++it)
		{
			if (boost::filesystem::is_regular_file (*it) && it->path ().extension () == ".dat")
			{
				auto fullPath =
#if BOOST_VERSION > 10500
				it->path().string();
#else
				it->path();
#endif
				auto localDestination = new ClientDestination (fullPath, true);
				m_Destinations[localDestination->GetIdentHash ()] = localDestination;
				numDestinations++;
			}	
		}	
		if (numDestinations > 0)
			LogPrint (numDestinations, " local destinations loaded");
	}	
	
	ClientDestination * ClientContext::LoadLocalDestination (const std::string& filename, bool isPublic)
	{
		auto localDestination = new ClientDestination (i2p::util::filesystem::GetFullPath (filename), isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);	
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	ClientDestination * ClientContext::CreateNewLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType)
	{
		auto localDestination = new ClientDestination (isPublic, sigType);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	void ClientContext::DeleteLocalDestination (ClientDestination * destination)
	{
		if (!destination) return;
		auto it = m_Destinations.find (destination->GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			auto d = it->second;
			{
				std::unique_lock<std::mutex> l(m_DestinationsMutex);
				m_Destinations.erase (it);
			}	
			d->Stop ();
			delete d;
		}
	}

	ClientDestination * ClientContext::CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic)
	{
		auto it = m_Destinations.find (keys.GetPublic ().GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			LogPrint ("Local destination ", keys.GetPublic ().GetIdentHash ().ToBase32 (), ".b32.i2p exists");
			if (!it->second->IsRunning ())
			{	
				it->second->Start ();
				return it->second;
			}	
			return nullptr;
		}	
		auto localDestination = new ClientDestination (keys, isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[keys.GetPublic ().GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}
	
	ClientDestination * ClientContext::FindLocalDestination (const i2p::data::IdentHash& destination) const
	{
		auto it = m_Destinations.find (destination);
		if (it != m_Destinations.end ())
			return it->second;
		return nullptr;
	}	
}		
}	
