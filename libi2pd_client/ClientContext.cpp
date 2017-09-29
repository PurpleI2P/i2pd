#include <fstream>
#include <iostream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "Config.h"
#include "FS.h"
#include "Log.h"
#include "Identity.h"
#include "util.h"
#include "ClientContext.h"
#include "SOCKS.h"
#include "WebSocks.h"
#include "MatchedDestination.h"

namespace i2p
{
namespace client
{
	ClientContext context;

	ClientContext::ClientContext (): m_SharedLocalDestination (nullptr),
		m_HttpProxy (nullptr), m_SocksProxy (nullptr), m_SamBridge (nullptr),
		m_BOBCommandChannel (nullptr), m_I2CPServer (nullptr)
	{
	}

	ClientContext::~ClientContext ()
	{
		delete m_HttpProxy;
		delete m_SocksProxy;
		delete m_SamBridge;
		delete m_BOBCommandChannel;
		delete m_I2CPServer;
	}

	void ClientContext::Start ()
	{
		if (!m_SharedLocalDestination)
		{
			m_SharedLocalDestination = CreateNewLocalDestination (); // non-public, DSA
			m_SharedLocalDestination->Acquire ();
			m_Destinations[m_SharedLocalDestination->GetIdentity ()->GetIdentHash ()] = m_SharedLocalDestination;
			m_SharedLocalDestination->Start ();
		}


		m_AddressBook.Start ();

		std::shared_ptr<ClientDestination> localDestination;
		bool httproxy; i2p::config::GetOption("httpproxy.enabled", httproxy);
		if (httproxy)
		{
			std::string httpProxyKeys; i2p::config::GetOption("httpproxy.keys",    httpProxyKeys);
			std::string httpProxyAddr; i2p::config::GetOption("httpproxy.address", httpProxyAddr);
			uint16_t    httpProxyPort; i2p::config::GetOption("httpproxy.port",    httpProxyPort);
			i2p::data::SigningKeyType sigType; i2p::config::GetOption("httpproxy.signaturetype",  sigType);
			LogPrint(eLogInfo, "Clients: starting HTTP Proxy at ", httpProxyAddr, ":", httpProxyPort);
			if (httpProxyKeys.length () > 0)
			{
				i2p::data::PrivateKeys keys;
				if(LoadPrivateKeys (keys, httpProxyKeys, sigType))
				{
					std::map<std::string, std::string> params;
					ReadI2CPOptionsFromConfig ("httpproxy.", params);
					localDestination = CreateNewLocalDestination (keys, false, &params);
					localDestination->Acquire ();
				}
				else
					LogPrint(eLogError, "Clients: failed to load HTTP Proxy key");
			}
			try
			{
			  m_HttpProxy = new i2p::proxy::HTTPProxy(httpProxyAddr, httpProxyPort, localDestination);
			  m_HttpProxy->Start();
			}
			catch (std::exception& e)
			{
			  LogPrint(eLogError, "Clients: Exception in HTTP Proxy: ", e.what());
			}
		}

		localDestination = nullptr;
		bool socksproxy; i2p::config::GetOption("socksproxy.enabled", socksproxy);
		if (socksproxy)
		{
			std::string socksProxyKeys; i2p::config::GetOption("socksproxy.keys",     socksProxyKeys);
			std::string socksProxyAddr; i2p::config::GetOption("socksproxy.address",  socksProxyAddr);
			uint16_t    socksProxyPort; i2p::config::GetOption("socksproxy.port",     socksProxyPort);
			bool socksOutProxy; i2p::config::GetOption("socksproxy.outproxy.enabled", socksOutProxy);
			std::string socksOutProxyAddr; i2p::config::GetOption("socksproxy.outproxy",     socksOutProxyAddr);
			uint16_t    socksOutProxyPort; i2p::config::GetOption("socksproxy.outproxyport", socksOutProxyPort);
			i2p::data::SigningKeyType sigType; i2p::config::GetOption("socksproxy.signaturetype",  sigType);
			LogPrint(eLogInfo, "Clients: starting SOCKS Proxy at ", socksProxyAddr, ":", socksProxyPort);
			if (socksProxyKeys.length () > 0)
			{
				i2p::data::PrivateKeys keys;
				if (LoadPrivateKeys (keys, socksProxyKeys, sigType))
				{
					std::map<std::string, std::string> params;
					ReadI2CPOptionsFromConfig ("socksproxy.", params);
					localDestination = CreateNewLocalDestination (keys, false, &params);
					localDestination->Acquire ();
				}
				else
					LogPrint(eLogError, "Clients: failed to load SOCKS Proxy key");
			}
			try
			{
				m_SocksProxy = new i2p::proxy::SOCKSProxy(socksProxyAddr, socksProxyPort, socksOutProxy, socksOutProxyAddr, socksOutProxyPort, localDestination);
				m_SocksProxy->Start();
			}
			catch (std::exception& e)
			{
				LogPrint(eLogError, "Clients: Exception in SOCKS Proxy: ", e.what());
			}
		}

		// I2P tunnels
		ReadTunnels ();

		// SAM
		bool sam; i2p::config::GetOption("sam.enabled", sam);
		if (sam) {
			std::string samAddr; i2p::config::GetOption("sam.address", samAddr);
			uint16_t    samPort; i2p::config::GetOption("sam.port",    samPort);
			LogPrint(eLogInfo, "Clients: starting SAM bridge at ", samAddr, ":", samPort);
			try {
			  m_SamBridge = new SAMBridge (samAddr, samPort);
			  m_SamBridge->Start ();
			} catch (std::exception& e) {
			  LogPrint(eLogError, "Clients: Exception in SAM bridge: ", e.what());
			}
		}

		// BOB
		bool bob; i2p::config::GetOption("bob.enabled", bob);
		if (bob) {
			std::string bobAddr; i2p::config::GetOption("bob.address", bobAddr);
			uint16_t    bobPort; i2p::config::GetOption("bob.port",    bobPort);
			LogPrint(eLogInfo, "Clients: starting BOB command channel at ", bobAddr, ":", bobPort);
			try {
			  m_BOBCommandChannel = new BOBCommandChannel (bobAddr, bobPort);
			  m_BOBCommandChannel->Start ();
			} catch (std::exception& e) {
			  LogPrint(eLogError, "Clients: Exception in BOB bridge: ", e.what());
			}
		}

		// I2CP
		bool i2cp; i2p::config::GetOption("i2cp.enabled", i2cp);
		if (i2cp)
		{
			std::string i2cpAddr; i2p::config::GetOption("i2cp.address", i2cpAddr);
			uint16_t i2cpPort; i2p::config::GetOption("i2cp.port", i2cpPort);
			LogPrint(eLogInfo, "Clients: starting I2CP at ", i2cpAddr, ":", i2cpPort);
			try
			{
				m_I2CPServer = new I2CPServer (i2cpAddr, i2cpPort);
			  	m_I2CPServer->Start ();
			}
			catch (std::exception& e)
			{
				LogPrint(eLogError, "Clients: Exception in I2CP: ", e.what());
			}
		}

		m_AddressBook.StartResolvers ();

		// start UDP cleanup
		if (!m_ServerForwards.empty ())
		{
			m_CleanupUDPTimer.reset (new boost::asio::deadline_timer(m_SharedLocalDestination->GetService ()));
			ScheduleCleanupUDP();
		}
	}

	void ClientContext::Stop ()
	{
		if (m_HttpProxy)
		{
			LogPrint(eLogInfo, "Clients: stopping HTTP Proxy");
			m_HttpProxy->Stop();
			delete m_HttpProxy;
			m_HttpProxy = nullptr;
		}

		if (m_SocksProxy)
		{
			LogPrint(eLogInfo, "Clients: stopping SOCKS Proxy");
			m_SocksProxy->Stop();
			delete m_SocksProxy;
			m_SocksProxy = nullptr;
		}

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

		if (m_I2CPServer)
		{
			LogPrint(eLogInfo, "Clients: stopping I2CP");
			m_I2CPServer->Stop ();
			delete m_I2CPServer;
			m_I2CPServer = nullptr;
		}

		LogPrint(eLogInfo, "Clients: stopping AddressBook");
		m_AddressBook.Stop ();

    	{
			std::lock_guard<std::mutex> lock(m_ForwardsMutex);
			m_ServerForwards.clear();
			m_ClientForwards.clear();
		}

		if (m_CleanupUDPTimer)
		{
			m_CleanupUDPTimer->cancel ();
			m_CleanupUDPTimer = nullptr;
		}

		for (auto& it: m_Destinations)
			it.second->Stop ();
		m_Destinations.clear ();
		m_SharedLocalDestination = nullptr;
	}

	void ClientContext::ReloadConfig ()
	{
		// TODO: handle config changes
		/*std::string config; i2p::config::GetOption("conf", config);
		i2p::config::ParseConfig(config);*/

		// handle tunnels
		// reset isUpdated for each tunnel
		VisitTunnels ([](I2PService * s)->bool { s->isUpdated = false; return true; });
		// reload tunnels
		ReadTunnels();
		// delete not updated tunnels (not in config anymore)
		VisitTunnels ([](I2PService * s)->bool { return s->isUpdated; });

		// delete unused destinations
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		for (auto it = m_Destinations.begin (); it != m_Destinations.end ();)
		{
			auto dest = it->second;
			if (dest->GetRefCounter () > 0) ++it; // skip
			else
			{
				dest->Stop ();
				it = m_Destinations.erase (it);
			}
		}
	}

	bool ClientContext::LoadPrivateKeys (i2p::data::PrivateKeys& keys, const std::string& filename, i2p::data::SigningKeyType sigType)
	{
		bool success = true;
		std::string fullPath = i2p::fs::DataDirPath (filename);
		std::ifstream s(fullPath, std::ifstream::binary);
		if (s.is_open ())
		{
			s.seekg (0, std::ios::end);
			size_t len = s.tellg();
			s.seekg (0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			s.read ((char *)buf, len);
			if(!keys.FromBuffer (buf, len))
			{
				LogPrint (eLogError, "Clients: failed to load keyfile ", filename);
				success = false;
			}
			else
				LogPrint (eLogInfo, "Clients: Local address ", m_AddressBook.ToAddress(keys.GetPublic ()->GetIdentHash ()), " loaded");
			delete[] buf;
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
		return success;
	}

	std::vector<std::shared_ptr<DatagramSessionInfo> > ClientContext::GetForwardInfosFor(const i2p::data::IdentHash & destination)
	{
		std::vector<std::shared_ptr<DatagramSessionInfo> > infos;
		std::lock_guard<std::mutex> lock(m_ForwardsMutex);
		for(const auto & c : m_ClientForwards)
		{
			if (c.second->IsLocalDestination(destination))
			{
				for (auto & i : c.second->GetSessions()) infos.push_back(i);
				break;
			}
		}
		for(const auto & s : m_ServerForwards)
		{
			if(std::get<0>(s.first) == destination)
			{
				for( auto & i : s.second->GetSessions()) infos.push_back(i);
				break;
			}
		}
		return infos;
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

	std::shared_ptr<ClientDestination> ClientContext::CreateNewMatchedTunnelDestination(const i2p::data::PrivateKeys &keys, const std::string & name, const std::map<std::string, std::string> * params)
	{
		MatchedTunnelDestination * cl = new MatchedTunnelDestination(keys, name, params);
		auto localDestination = std::shared_ptr<ClientDestination>(cl);
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
		options[I2CP_PARAM_MIN_TUNNEL_LATENCY] = GetI2CPOption(section, I2CP_PARAM_MIN_TUNNEL_LATENCY, DEFAULT_MIN_TUNNEL_LATENCY);
		options[I2CP_PARAM_MAX_TUNNEL_LATENCY] = GetI2CPOption(section, I2CP_PARAM_MAX_TUNNEL_LATENCY, DEFAULT_MAX_TUNNEL_LATENCY);
	}

	void ClientContext::ReadI2CPOptionsFromConfig (const std::string& prefix, std::map<std::string, std::string>& options) const
	{
		std::string value;
		if (i2p::config::GetOption(prefix + I2CP_PARAM_INBOUND_TUNNEL_LENGTH, value))
			options[I2CP_PARAM_INBOUND_TUNNEL_LENGTH] = value;
		if (i2p::config::GetOption(prefix + I2CP_PARAM_INBOUND_TUNNELS_QUANTITY, value))
			options[I2CP_PARAM_INBOUND_TUNNELS_QUANTITY] = value;
		if (i2p::config::GetOption(prefix + I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH, value))
			options[I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH] = value;
		if (i2p::config::GetOption(prefix + I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY, value))
			options[I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY] = value;
		if (i2p::config::GetOption(prefix + I2CP_PARAM_MIN_TUNNEL_LATENCY, value))
			options[I2CP_PARAM_MIN_TUNNEL_LATENCY] = value;
		if (i2p::config::GetOption(prefix + I2CP_PARAM_MAX_TUNNEL_LATENCY, value))
			options[I2CP_PARAM_MAX_TUNNEL_LATENCY] = value;
	}

	void ClientContext::ReadTunnels ()
	{
		boost::property_tree::ptree pt;
		std::string tunConf; i2p::config::GetOption("tunconf", tunConf);
		if (tunConf == "") {
			// TODO: cleanup this in 2.8.0
			tunConf = i2p::fs::DataDirPath ("tunnels.cfg");
			if (i2p::fs::Exists(tunConf)) {
				LogPrint(eLogWarning, "FS: please rename tunnels.cfg -> tunnels.conf here: ", tunConf);
			} else {
				tunConf = i2p::fs::DataDirPath ("tunnels.conf");
			}
		}
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
				if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT
						|| type == I2P_TUNNELS_SECTION_TYPE_SOCKS
						|| type == I2P_TUNNELS_SECTION_TYPE_WEBSOCKS
						|| type == I2P_TUNNELS_SECTION_TYPE_HTTPPROXY
						|| type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT)
				{
					// mandatory params
					std::string dest;
					if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT || type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT)
						dest = section.second.get<std::string> (I2P_CLIENT_TUNNEL_DESTINATION);
					int port = section.second.get<int> (I2P_CLIENT_TUNNEL_PORT);
					// optional params
					bool matchTunnels = section.second.get(I2P_CLIENT_TUNNEL_MATCH_TUNNELS, false);
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
						if(LoadPrivateKeys (k, keys, sigType))
						{
							localDestination = FindLocalDestination (k.GetPublic ()->GetIdentHash ());
							if (!localDestination)
							{
								if(matchTunnels)
									localDestination = CreateNewMatchedTunnelDestination(k, dest, &options);
								else
									localDestination = CreateNewLocalDestination (k, type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT, &options);
							}
						}
					}

					if (type == I2P_TUNNELS_SECTION_TYPE_UDPCLIENT) {
						// udp client
						// TODO: hostnames
						boost::asio::ip::udp::endpoint end(boost::asio::ip::address::from_string(address), port);
						if (!localDestination)
						{
							localDestination = m_SharedLocalDestination;
						}
						auto clientTunnel = new I2PUDPClientTunnel(name, dest, end, localDestination, destinationPort);
						if(m_ClientForwards.insert(std::make_pair(end, std::unique_ptr<I2PUDPClientTunnel>(clientTunnel))).second)
						{
							clientTunnel->Start();
						}
						else
							LogPrint(eLogError, "Clients: I2P Client forward for endpoint ", end, " already exists");

					} else {
						boost::asio::ip::tcp::endpoint clientEndpoint;
						I2PService * clientTunnel = nullptr;
						if (type == I2P_TUNNELS_SECTION_TYPE_SOCKS)
						{
							// socks proxy
							clientTunnel = new i2p::proxy::SOCKSProxy(address, port, false, "", destinationPort, localDestination);
							clientEndpoint = ((i2p::proxy::SOCKSProxy*)clientTunnel)->GetLocalEndpoint ();
						}
						else if (type == I2P_TUNNELS_SECTION_TYPE_HTTPPROXY)
						{
							// http proxy
							clientTunnel = new i2p::proxy::HTTPProxy(address, port, localDestination);
							clientEndpoint = ((i2p::proxy::HTTPProxy*)clientTunnel)->GetLocalEndpoint ();
						}
						else if (type == I2P_TUNNELS_SECTION_TYPE_WEBSOCKS)
						{
							// websocks proxy
							clientTunnel = new WebSocks(address, port, localDestination);;
							clientEndpoint = ((WebSocks*)clientTunnel)->GetLocalEndpoint();
						}
						else
						{
							// tcp client
							clientTunnel = new I2PClientTunnel (name, dest, address, port, localDestination, destinationPort);
							clientEndpoint = ((I2PClientTunnel*)clientTunnel)->GetLocalEndpoint ();
						}
						uint32_t timeout = section.second.get<uint32_t>(I2P_CLIENT_TUNNEL_CONNECT_TIMEOUT, 0);
						if(timeout)
						{
							clientTunnel->SetConnectTimeout(timeout);
							LogPrint(eLogInfo, "Clients: I2P Client tunnel connect timeout set to ", timeout);
						}

						auto ins = m_ClientTunnels.insert (std::make_pair (clientEndpoint,	std::unique_ptr<I2PService>(clientTunnel)));
						if (ins.second)
						{
							clientTunnel->Start ();
							numClientTunnels++;
						}
						else
						{
							// TODO: update
							if (ins.first->second->GetLocalDestination () != clientTunnel->GetLocalDestination ())
							{
								LogPrint (eLogInfo, "Clients: I2P client tunnel destination updated");
								ins.first->second->SetLocalDestination (clientTunnel->GetLocalDestination ());
							}
							ins.first->second->isUpdated = true;
							LogPrint (eLogInfo, "Clients: I2P client tunnel for endpoint ", clientEndpoint, " already exists");
						}
					}
				}
				else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER
								 || type == I2P_TUNNELS_SECTION_TYPE_HTTP
								 || type == I2P_TUNNELS_SECTION_TYPE_IRC
								 || type == I2P_TUNNELS_SECTION_TYPE_UDPSERVER)
				{
					// mandatory params
					std::string host = section.second.get<std::string> (I2P_SERVER_TUNNEL_HOST);
					int port = section.second.get<int> (I2P_SERVER_TUNNEL_PORT);
					std::string keys = section.second.get<std::string> (I2P_SERVER_TUNNEL_KEYS);
					// optional params
					int inPort = section.second.get (I2P_SERVER_TUNNEL_INPORT, 0);
					std::string accessList = section.second.get (I2P_SERVER_TUNNEL_ACCESS_LIST, "");
					std::string hostOverride = section.second.get (I2P_SERVER_TUNNEL_HOST_OVERRIDE, "");
					std::string webircpass = section.second.get<std::string> (I2P_SERVER_TUNNEL_WEBIRC_PASSWORD, "");
					bool gzip = section.second.get (I2P_SERVER_TUNNEL_GZIP, true);
					i2p::data::SigningKeyType sigType = section.second.get (I2P_SERVER_TUNNEL_SIGNATURE_TYPE, i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
					uint32_t maxConns = section.second.get(i2p::stream::I2CP_PARAM_STREAMING_MAX_CONNS_PER_MIN, i2p::stream::DEFAULT_MAX_CONNS_PER_MIN);
					std::string address = section.second.get<std::string> (I2P_SERVER_TUNNEL_ADDRESS, "127.0.0.1");
					bool isUniqueLocal = section.second.get(I2P_SERVER_TUNNEL_ENABLE_UNIQUE_LOCAL, true);

					// I2CP
					std::map<std::string, std::string> options;
					ReadI2CPOptions (section, options);

					std::shared_ptr<ClientDestination> localDestination = nullptr;
					i2p::data::PrivateKeys k;
					if(!LoadPrivateKeys (k, keys, sigType))
						continue;
					localDestination = FindLocalDestination (k.GetPublic ()->GetIdentHash ());
					if (!localDestination)
						localDestination = CreateNewLocalDestination (k, true, &options);
					if (type == I2P_TUNNELS_SECTION_TYPE_UDPSERVER)
					{
						// udp server tunnel
						// TODO: hostnames
						auto localAddress = boost::asio::ip::address::from_string(address);
						boost::asio::ip::udp::endpoint endpoint(boost::asio::ip::address::from_string(host), port);
						I2PUDPServerTunnel * serverTunnel = new I2PUDPServerTunnel(name, localDestination, localAddress, endpoint, port);
						if(!isUniqueLocal)
						{
							LogPrint(eLogInfo, "Clients: disabling loopback address mapping");
							serverTunnel->SetUniqueLocal(isUniqueLocal);
						}
						std::lock_guard<std::mutex> lock(m_ForwardsMutex);
						if(m_ServerForwards.insert(
							std::make_pair(
								std::make_pair(
									localDestination->GetIdentHash(), port),
								std::unique_ptr<I2PUDPServerTunnel>(serverTunnel))).second)
						{
							serverTunnel->Start();
							LogPrint(eLogInfo, "Clients: I2P Server Forward created for UDP Endpoint ", host, ":", port, " bound on ", address, " for ",localDestination->GetIdentHash().ToBase32());
						}
						else
							LogPrint(eLogError, "Clients: I2P Server Forward for destination/port ", m_AddressBook.ToAddress(localDestination->GetIdentHash()), "/", port, "already exists");

						continue;
					}

					I2PServerTunnel * serverTunnel;
					if (type == I2P_TUNNELS_SECTION_TYPE_HTTP)
                    	serverTunnel = new I2PServerTunnelHTTP (name, host, port, localDestination, hostOverride, inPort, gzip);
               		else if (type == I2P_TUNNELS_SECTION_TYPE_IRC)
                    	serverTunnel = new I2PServerTunnelIRC (name, host, port, localDestination, webircpass, inPort, gzip);
					else // regular server tunnel by default
                   		serverTunnel = new I2PServerTunnel (name, host, port, localDestination, inPort, gzip);

					LogPrint(eLogInfo, "Clients: Set Max Conns To ", maxConns);
					serverTunnel->SetMaxConnsPerMinute(maxConns);
					if(!isUniqueLocal)
					{
						LogPrint(eLogInfo, "Clients: disabling loopback address mapping");
						serverTunnel->SetUniqueLocal(isUniqueLocal);
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
					auto ins = m_ServerTunnels.insert (std::make_pair (
							std::make_pair (localDestination->GetIdentHash (), inPort),
					        std::unique_ptr<I2PServerTunnel>(serverTunnel)));
					if (ins.second)
					{
						serverTunnel->Start ();
						numServerTunnels++;
					}
					else
					{
						// TODO: update
						if (ins.first->second->GetLocalDestination () != serverTunnel->GetLocalDestination ())
						{
							LogPrint (eLogInfo, "Clients: I2P server tunnel destination updated");
							ins.first->second->SetLocalDestination (serverTunnel->GetLocalDestination ());
						}
						ins.first->second->isUpdated = true;
						LogPrint (eLogInfo, "Clients: I2P server tunnel for destination/port ",   m_AddressBook.ToAddress(localDestination->GetIdentHash ()), "/", inPort, " already exists");
					}

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

	void ClientContext::ScheduleCleanupUDP()
	{
		if (m_CleanupUDPTimer)
		{
			// schedule cleanup in 17 seconds
			m_CleanupUDPTimer->expires_from_now (boost::posix_time::seconds (17));
			m_CleanupUDPTimer->async_wait(std::bind(&ClientContext::CleanupUDP, this, std::placeholders::_1));
		}
	}

	void ClientContext::CleanupUDP(const boost::system::error_code & ecode)
	{
		if(!ecode)
		{
			std::lock_guard<std::mutex> lock(m_ForwardsMutex);
			for (auto & s : m_ServerForwards ) s.second->ExpireStale();
			ScheduleCleanupUDP();
		}
	}

	template<typename Container, typename Visitor>
	void VisitTunnelsContainer (Container& c, Visitor v)
	{
		for (auto it = c.begin (); it != c.end ();)
		{
			if (!v (it->second.get ()))
			{
				it->second->Stop ();
				it = c.erase (it);
			}
			else
				it++;
		}
	}

	template<typename Visitor>
	void ClientContext::VisitTunnels (Visitor v)
	{
		VisitTunnelsContainer (m_ClientTunnels, v);
		VisitTunnelsContainer (m_ServerTunnels, v);
		// TODO: implement UDP forwards
	}
}
}
