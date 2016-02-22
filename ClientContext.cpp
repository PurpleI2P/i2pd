#include <fstream>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "Config.h"
#include "FS.h"
#include "Log.h"
#include "Identity.h"
#include "ClientContext.h"

namespace i2p
{
namespace client
{
	ClientContext context;	

	ClientContext::ClientContext (): m_SharedLocalDestination (nullptr),
		m_HttpProxy (nullptr), m_SocksProxy (nullptr), m_SamBridge (nullptr), 
		m_BOBCommandChannel (nullptr)
	{
	}
	
	ClientContext::~ClientContext () 
	{
		delete m_HttpProxy;
		delete m_SocksProxy;
		delete m_SamBridge;
		delete m_BOBCommandChannel;
	}
	
	void ClientContext::Start ()
	{
		if (!m_SharedLocalDestination)
		{	
			m_SharedLocalDestination = CreateNewLocalDestination (); // non-public, DSA
			m_Destinations[m_SharedLocalDestination->GetIdentity ()->GetIdentHash ()] = m_SharedLocalDestination;
			m_SharedLocalDestination->Start ();
		}

		m_AddressBook.Start ();	
		
		std::shared_ptr<ClientDestination> localDestination;	
		bool httproxy; i2p::config::GetOption("httpproxy.enabled", httproxy);
		if (httproxy) {
			std::string httpProxyKeys; i2p::config::GetOption("httpproxy.keys",    httpProxyKeys);
			std::string httpProxyAddr; i2p::config::GetOption("httpproxy.address", httpProxyAddr);
			uint16_t    httpProxyPort; i2p::config::GetOption("httpproxy.port",    httpProxyPort);
			LogPrint(eLogInfo, "Clients: starting HTTP Proxy at ", httpProxyAddr, ":", httpProxyPort);
			if (httpProxyKeys.length () > 0)
			{
				i2p::data::PrivateKeys keys;
				LoadPrivateKeys (keys, httpProxyKeys);
				localDestination = CreateNewLocalDestination (keys, false);
			}
			m_HttpProxy = new i2p::proxy::HTTPProxy(httpProxyAddr, httpProxyPort, localDestination);
			m_HttpProxy->Start();
		}

		bool socksproxy; i2p::config::GetOption("socksproxy.enabled", socksproxy);
		if (socksproxy) {
			std::string socksProxyKeys; i2p::config::GetOption("socksproxy.keys",    socksProxyKeys);
			std::string socksProxyAddr; i2p::config::GetOption("socksproxy.address", socksProxyAddr);
			uint16_t    socksProxyPort; i2p::config::GetOption("socksproxy.port",    socksProxyPort);
			std::string socksOutProxyAddr; i2p::config::GetOption("socksproxy.outproxy",     socksOutProxyAddr);
			uint16_t    socksOutProxyPort; i2p::config::GetOption("socksproxy.outproxyport", socksOutProxyPort);
			LogPrint(eLogInfo, "Clients: starting SOCKS Proxy at ", socksProxyAddr, ":", socksProxyPort);
			if (socksProxyKeys.length () > 0)
			{
				i2p::data::PrivateKeys keys;
				LoadPrivateKeys (keys, socksProxyKeys);
				localDestination = CreateNewLocalDestination (keys, false);
			}
			m_SocksProxy = new i2p::proxy::SOCKSProxy(socksProxyAddr, socksProxyPort, socksOutProxyAddr, socksOutProxyPort, localDestination);
			m_SocksProxy->Start();
		}
	
		// I2P tunnels
		ReadTunnels ();

		// SAM
		bool sam; i2p::config::GetOption("sam.enabled", sam);
		if (sam) {
			std::string samAddr; i2p::config::GetOption("sam.address", samAddr);
			uint16_t    samPort; i2p::config::GetOption("sam.port",    samPort);
			LogPrint(eLogInfo, "Clients: starting SAM bridge at ", samAddr, ":", samPort);
			m_SamBridge = new SAMBridge (samAddr, samPort);
			m_SamBridge->Start ();
		} 

		// BOB
		bool bob; i2p::config::GetOption("bob.enabled", bob);
		if (bob) {
			std::string bobAddr; i2p::config::GetOption("bob.address", bobAddr);
			uint16_t    bobPort; i2p::config::GetOption("bob.port",    bobPort);
			LogPrint(eLogInfo, "Clients: starting BOB command channel at ", bobAddr, ":", bobPort);
			m_BOBCommandChannel = new BOBCommandChannel (bobAddr, bobPort);
			m_BOBCommandChannel->Start ();
		} 
	}
		
	void ClientContext::Stop ()
	{
		LogPrint(eLogInfo, "Clients: stopping HTTP Proxy");
		m_HttpProxy->Stop();
		delete m_HttpProxy;
		m_HttpProxy = nullptr;

		LogPrint(eLogInfo, "Clients: stopping SOCKS Proxy");
		m_SocksProxy->Stop();
		delete m_SocksProxy;
		m_SocksProxy = nullptr;

		for (auto& it: m_ClientTunnels)
		{
			LogPrint(eLogInfo, "Clients: stopping I2P client tunnel on port ", it.first);
			it.second->Stop ();
		}
		m_ClientTunnels.clear ();	

		for (auto& it: m_ServerTunnels)
		{
			LogPrint(eLogInfo, "Clients: stopping I2P server tunnel");
			it.second->Stop ();
		}
		m_ServerTunnels.clear ();	

		if (m_SamBridge)
		{
			LogPrint(eLogInfo, "Clients: stopping SAM bridge");
			m_SamBridge->Stop ();
			delete m_SamBridge; 
			m_SamBridge = nullptr;
		}		

		if (m_BOBCommandChannel)
		{
			LogPrint(eLogInfo, "Clients: stopping BOB command channel");
			m_BOBCommandChannel->Stop ();
			delete m_BOBCommandChannel; 
			m_BOBCommandChannel = nullptr;
		}

		LogPrint(eLogInfo, "Clients: stopping AddressBook");
		m_AddressBook.Stop ();		
		for (auto it: m_Destinations)
			it.second->Stop ();
		m_Destinations.clear ();
		m_SharedLocalDestination = nullptr; 
	}	
	
	void ClientContext::LoadPrivateKeys (i2p::data::PrivateKeys& keys, const std::string& filename, i2p::data::SigningKeyType sigType)
	{
		std::string fullPath = i2p::fs::DataDirPath (filename);
		std::ifstream s(fullPath, std::ifstream::binary);
		if (s.is_open ())	
		{	
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			keys.FromBuffer (buf, len);
			delete[] buf;
			LogPrint (eLogInfo, "Clients: Local address ", m_AddressBook.ToAddress(keys.GetPublic ()->GetIdentHash ()), " loaded");
		}	
		else
		{
			LogPrint (eLogError, "Clients: can't open file ", fullPath, " Creating new one with signature type ", sigType);
			keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType); 
			std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
			size_t len = keys.GetFullLen ();
			uint8_t * buf = new uint8_t[len];
			len = keys.ToBuffer (buf, len);
			f.write ((char *)buf, len);
			delete[] buf;
			
			LogPrint (eLogInfo, "Clients: New private keys file ", fullPath, " for ", m_AddressBook.ToAddress(keys.GetPublic ()->GetIdentHash ()), " created");
		}	
	}

	std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
		const std::map<std::string, std::string> * params)
	{
		i2p::data::PrivateKeys keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
		auto localDestination = std::make_shared<ClientDestination> (keys, isPublic, params);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	void ClientContext::DeleteLocalDestination (std::shared_ptr<ClientDestination> destination)
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
		}
	}

	std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
		const std::map<std::string, std::string> * params)
	{
		auto it = m_Destinations.find (keys.GetPublic ()->GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			LogPrint (eLogWarning, "Clients: Local destination ", m_AddressBook.ToAddress(keys.GetPublic ()->GetIdentHash ()), " exists");
			if (!it->second->IsRunning ())
			{	
				it->second->Start ();
				return it->second;
			}	
			return nullptr;
		}	
		auto localDestination = std::make_shared<ClientDestination> (keys, isPublic, params);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[keys.GetPublic ()->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}
	
	std::shared_ptr<ClientDestination> ClientContext::FindLocalDestination (const i2p::data::IdentHash& destination) const
	{
		auto it = m_Destinations.find (destination);
		if (it != m_Destinations.end ())
			return it->second;
		return nullptr;
	}	

	template<typename Section, typename Type>
	std::string ClientContext::GetI2CPOption (const Section& section, const std::string& name, const Type& value) const
	{
		return section.second.get (boost::property_tree::ptree::path_type (name, '/'), std::to_string (value));
	}	

	template<typename Section>
	void ClientContext::ReadI2CPOptions (const Section& section, std::map<std::string, std::string>& options) const
	{
		options[I2CP_PARAM_INBOUND_TUNNEL_LENGTH] = GetI2CPOption (section, I2CP_PARAM_INBOUND_TUNNEL_LENGTH,  DEFAULT_INBOUND_TUNNEL_LENGTH);
		options[I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH] = GetI2CPOption (section, I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH, DEFAULT_OUTBOUND_TUNNEL_LENGTH);
		options[I2CP_PARAM_INBOUND_TUNNELS_QUANTITY] = GetI2CPOption (section, I2CP_PARAM_INBOUND_TUNNELS_QUANTITY, DEFAULT_INBOUND_TUNNELS_QUANTITY);
		options[I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY] = GetI2CPOption (section, I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY, DEFAULT_OUTBOUND_TUNNELS_QUANTITY);
		options[I2CP_PARAM_TAGS_TO_SEND] = GetI2CPOption (section, I2CP_PARAM_TAGS_TO_SEND, DEFAULT_TAGS_TO_SEND);
	}	

	void ClientContext::ReadTunnels ()
	{
		boost::property_tree::ptree pt;
		std::string tunConf; i2p::config::GetOption("tunconf", tunConf);
		if (tunConf == "")
			tunConf = i2p::fs::DataDirPath ("tunnels.cfg");
		LogPrint(eLogDebug, "FS: tunnels config file: ", tunConf);
		try 
		{
			boost::property_tree::read_ini (tunConf, pt);
		} 
		catch (std::exception& ex) 
		{
			LogPrint (eLogWarning, "Clients: Can't read ", tunConf, ": ", ex.what ());
			return;
		}
			
		int numClientTunnels = 0, numServerTunnels = 0;
		for (auto& section: pt)
		{
			std::string name = section.first;			
			try
			{
				std::string type = section.second.get<std::string> (I2P_TUNNELS_SECTION_TYPE);
				if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT)
				{
					// mandatory params
					std::string dest = section.second.get<std::string> (I2P_CLIENT_TUNNEL_DESTINATION);
					int port = section.second.get<int> (I2P_CLIENT_TUNNEL_PORT);
					// optional params
					std::string keys = section.second.get (I2P_CLIENT_TUNNEL_KEYS, "");
					std::string address = section.second.get (I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
					int destinationPort = section.second.get (I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);
					i2p::data::SigningKeyType sigType = section.second.get (I2P_CLIENT_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
					// I2CP
					std::map<std::string, std::string> options;			
					ReadI2CPOptions (section, options);	

					std::shared_ptr<ClientDestination> localDestination = nullptr;
					if (keys.length () > 0)
					{
						i2p::data::PrivateKeys k;
						LoadPrivateKeys (k, keys, sigType);
						localDestination = FindLocalDestination (k.GetPublic ()->GetIdentHash ());
						if (!localDestination)
							localDestination = CreateNewLocalDestination (k, false, &options);
					}
					auto clientTunnel = new I2PClientTunnel (name, dest, address, port, localDestination, destinationPort);
					if (m_ClientTunnels.insert (std::make_pair (port, std::unique_ptr<I2PClientTunnel>(clientTunnel))).second)
						clientTunnel->Start ();
					else
						LogPrint (eLogError, "Clients: I2P client tunnel with port ", port, " already exists");
					numClientTunnels++;
				}
				else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER || type == I2P_TUNNELS_SECTION_TYPE_HTTP || type == I2P_TUNNELS_SECTION_TYPE_IRC)
				{	
					// mandatory params
					std::string host = section.second.get<std::string> (I2P_SERVER_TUNNEL_HOST);
					int port = section.second.get<int> (I2P_SERVER_TUNNEL_PORT);
					std::string keys = section.second.get<std::string> (I2P_SERVER_TUNNEL_KEYS);
					// optional params
					int inPort = section.second.get (I2P_SERVER_TUNNEL_INPORT, 0);
					std::string accessList = section.second.get (I2P_SERVER_TUNNEL_ACCESS_LIST, "");
					std::string hostOverride = section.second.get (I2P_SERVER_TUNNEL_HOST_OVERRIDE, "");
					i2p::data::SigningKeyType sigType = section.second.get (I2P_SERVER_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
					// I2CP
					std::map<std::string, std::string> options;							 
					ReadI2CPOptions (section, options);				

					std::shared_ptr<ClientDestination> localDestination = nullptr;
					i2p::data::PrivateKeys k;
					LoadPrivateKeys (k, keys, sigType);
					localDestination = FindLocalDestination (k.GetPublic ()->GetIdentHash ());
					if (!localDestination)		
						localDestination = CreateNewLocalDestination (k, true, &options);

					I2PServerTunnel * serverTunnel;
					if (type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
                        serverTunnel = new I2PServerTunnelHTTP (name, host, port, localDestination, inPort);
               		} else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER) {
                       	serverTunnel = new I2PServerTunnel (name, host, port, localDestination, inPort);
               		} else if (type == I2P_TUNNELS_SECTION_TYPE_IRC) {
                       	serverTunnel = new I2PServerTunnelIRC (name, host, port, localDestination, inPort);
               		}

					if (accessList.length () > 0)
					{
						std::set<i2p::data::IdentHash> idents;
						size_t pos = 0, comma;
						do
						{
							comma = accessList.find (',', pos);
							i2p::data::IdentHash ident;
							ident.FromBase32 (accessList.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));	
							idents.insert (ident);
							pos = comma + 1;
						}
						while (comma != std::string::npos);
						serverTunnel->SetAccessList (idents);
					}
					if (m_ServerTunnels.insert (std::make_pair (
							std::make_tuple (localDestination->GetIdentHash (), inPort), 
					        std::unique_ptr<I2PServerTunnel>(serverTunnel))).second)
						serverTunnel->Start ();
					else
						LogPrint (eLogError, "Clients: I2P server tunnel for destination ",   m_AddressBook.ToAddress(localDestination->GetIdentHash ()), " already exists");
					numServerTunnels++;
				}
				else
					LogPrint (eLogWarning, "Clients: Unknown section type=", type, " of ", name, " in ", tunConf);
				
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "Clients: Can't read tunnel ", name, " params: ", ex.what ());
			}
		}	
		LogPrint (eLogInfo, "Clients: ", numClientTunnels, " I2P client tunnels created");
		LogPrint (eLogInfo, "Clients: ", numServerTunnels, " I2P server tunnels created");
	}	
}		
}	
