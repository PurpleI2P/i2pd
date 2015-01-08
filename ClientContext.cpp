#include <fstream>
#include "util.h"
#include "Log.h"
#include "Identity.h"
#include "ClientContext.h"

namespace i2p
{
namespace client
{
	ClientContext context;	

	ClientContext::ClientContext (): m_SharedLocalDestination (nullptr),
		m_HttpProxy (nullptr), m_SocksProxy (nullptr), m_IrcTunnel (nullptr),
		m_ServerTunnel (nullptr), m_SamBridge (nullptr), m_BOBCommandChannel (nullptr),
		m_I2PControlService (nullptr)
	{
	}
	
	ClientContext::~ClientContext () 
	{
		delete m_HttpProxy;
		delete m_SocksProxy;
		delete m_IrcTunnel;
		delete m_ServerTunnel;
		delete m_SamBridge;
		delete m_BOBCommandChannel;
		delete m_I2PControlService;
	}
	
	void ClientContext::Start ()
	{
		if (!m_SharedLocalDestination)
		{	
			m_SharedLocalDestination = CreateNewLocalDestination (); // non-public, DSA
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
				localDestination = LoadLocalDestination (ircKeys, false);
			m_IrcTunnel = new I2PClientTunnel (ircDestination, i2p::util::config::GetArg("-ircport", 6668), localDestination);
			m_IrcTunnel->Start ();
			LogPrint("IRC tunnel started");
		}	
		std::string eepKeys = i2p::util::config::GetArg("-eepkeys", "");
		if (eepKeys.length () > 0) // eepkeys file is presented
		{
			auto localDestination = LoadLocalDestination (eepKeys, true);
			m_ServerTunnel = new I2PServerTunnel (i2p::util::config::GetArg("-eephost", "127.0.0.1"),
 				i2p::util::config::GetArg("-eepport", 80), localDestination);
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
		int bobPort = i2p::util::config::GetArg("-bobport", 0);
		if (bobPort)
		{
			m_BOBCommandChannel = new BOBCommandChannel (bobPort);
			m_BOBCommandChannel->Start ();
			LogPrint("BOB command channel started");
		} 
		int i2pcontrolPort = i2p::util::config::GetArg("-i2pcontrolport", 0);
		if (i2pcontrolPort)
		{
			m_I2PControlService = new I2PControlService (i2pcontrolPort);
			m_I2PControlService->Start ();
			LogPrint("I2PControl started");
		}
		m_AddressBook.StartSubscriptions ();
	}
		
	void ClientContext::Stop ()
	{
		m_AddressBook.StopSubscriptions ();	
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
		if (m_BOBCommandChannel)
		{
			m_BOBCommandChannel->Stop ();
			delete m_BOBCommandChannel; 
			m_BOBCommandChannel = nullptr;
			LogPrint("BOB command channel stoped");	
		}			
		if (m_I2PControlService)
		{
			m_I2PControlService->Stop ();
			delete m_I2PControlService; 
			m_I2PControlService = nullptr;
			LogPrint("I2PControl stoped");	
		}	

		for (auto it: m_Destinations)
		{	
			it.second->Stop ();
			delete it.second;
		}		
		m_Destinations.clear ();
		m_SharedLocalDestination = 0; // deleted through m_Destination
	}	
	
	ClientDestination * ClientContext::LoadLocalDestination (const std::string& filename, bool isPublic)
	{
		i2p::data::PrivateKeys keys;
		std::string fullPath = i2p::util::filesystem::GetFullPath (filename);
		std::ifstream s(fullPath.c_str (), std::ifstream::binary);
		if (s.is_open ())	
		{	
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			keys.FromBuffer (buf, len);
			delete[] buf;
			LogPrint ("Local address ", m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " loaded");
		}	
		else
		{
			LogPrint ("Can't open file ", fullPath, " Creating new one");
			keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_DSA_SHA1); 
			std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
			size_t len = keys.GetFullLen ();
			uint8_t * buf = new uint8_t[len];
			len = keys.ToBuffer (buf, len);
			f.write ((char *)buf, len);
			delete[] buf;
			
			LogPrint ("New private keys file ", fullPath, " for ", m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " created");
		}	

		auto localDestination = new ClientDestination (keys, isPublic);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);	
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	ClientDestination * ClientContext::CreateNewLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
		const std::map<std::string, std::string> * params)
	{
		i2p::data::PrivateKeys keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
		auto localDestination = new ClientDestination (keys, isPublic, params);
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

	ClientDestination * ClientContext::CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
		const std::map<std::string, std::string> * params)
	{
		auto it = m_Destinations.find (keys.GetPublic ().GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			LogPrint ("Local destination ", m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " exists");
			if (!it->second->IsRunning ())
			{	
				it->second->Start ();
				return it->second;
			}	
			return nullptr;
		}	
		auto localDestination = new ClientDestination (keys, isPublic, params);
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
