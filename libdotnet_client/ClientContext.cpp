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

namespace dotnet
{
namespace client
{
	ClientContext context;

	ClientContext::ClientContext (): m_SharedLocalDestination (nullptr),
		m_HttpProxy (nullptr), m_SocksProxy (nullptr), m_SamBridge (nullptr),
		m_BOBCommandChannel (nullptr), m_DNCPServer (nullptr)
	{
	}

	ClientContext::~ClientContext ()
	{
		delete m_HttpProxy;
		delete m_SocksProxy;
		delete m_SamBridge;
		delete m_BOBCommandChannel;
		delete m_DNCPServer;
	}

	void ClientContext::Start ()
	{
		// shared local destination
		if (!m_SharedLocalDestination)
			CreateNewSharedLocalDestination ();

		// addressbook
		m_AddressBook.Start ();

		// HTTP proxy
		ReadHttpProxy ();

		// SOCKS proxy
		ReadSocksProxy ();

		// DOTNET tunnels
		ReadTunnels ();

		// SAM
		bool sam; dotnet::config::GetOption("sam.enabled", sam);
		if (sam) {
			std::string samAddr; dotnet::config::GetOption("sam.address", samAddr);
			uint16_t    samPort; dotnet::config::GetOption("sam.port",    samPort);
			LogPrint(eLogInfo, "Clients: starting SAM bridge at ", samAddr, ":", samPort);
			try {
			  m_SamBridge = new SAMBridge (samAddr, samPort);
			  m_SamBridge->Start ();
			} catch (std::exception& e) {
			  LogPrint(eLogError, "Clients: Exception in SAM bridge: ", e.what());
			}
		}

		// BOB
		bool bob; dotnet::config::GetOption("bob.enabled", bob);
		if (bob) {
			std::string bobAddr; dotnet::config::GetOption("bob.address", bobAddr);
			uint16_t    bobPort; dotnet::config::GetOption("bob.port",    bobPort);
			LogPrint(eLogInfo, "Clients: starting BOB command channel at ", bobAddr, ":", bobPort);
			try {
			  m_BOBCommandChannel = new BOBCommandChannel (bobAddr, bobPort);
			  m_BOBCommandChannel->Start ();
			} catch (std::exception& e) {
			  LogPrint(eLogError, "Clients: Exception in BOB bridge: ", e.what());
			}
		}

		// DNCP
		bool dncp; dotnet::config::GetOption("dncp.enabled", dncp);
		if (dncp)
		{
			std::string dncpAddr; dotnet::config::GetOption("dncp.address", dncpAddr);
			uint16_t dncpPort; dotnet::config::GetOption("dncp.port", dncpPort);
			LogPrint(eLogInfo, "Clients: starting DNCP at ", dncpAddr, ":", dncpPort);
			try
			{
				m_DNCPServer = new DNCPServer (dncpAddr, dncpPort);
				m_DNCPServer->Start ();
			}
			catch (std::exception& e)
			{
				LogPrint(eLogError, "Clients: Exception in DNCP: ", e.what());
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
			LogPrint(eLogInfo, "Clients: stopping .NET client tunnel on port ", it.first);
			it.second->Stop ();
		}
		m_ClientTunnels.clear ();

		for (auto& it: m_ServerTunnels)
		{
			LogPrint(eLogInfo, "Clients: stopping .NET server tunnel");
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

		if (m_DNCPServer)
		{
			LogPrint(eLogInfo, "Clients: stopping DNCP");
			m_DNCPServer->Stop ();
			delete m_DNCPServer;
			m_DNCPServer = nullptr;
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
		/*std::string config; dotnet::config::GetOption("conf", config);
		dotnet::config::ParseConfig(config);*/

		// handle tunnels
		// reset isUpdated for each tunnel
		VisitTunnels ([](DotNetService * s)->bool { s->isUpdated = false; return true; });
		// reload tunnels
		ReadTunnels();
		// delete not updated tunnels (not in config anymore)
		VisitTunnels ([](DotNetService * s)->bool { return s->isUpdated; });

		// change shared local destination
		m_SharedLocalDestination->Release ();
		CreateNewSharedLocalDestination ();

		// recreate HTTP proxy
		if (m_HttpProxy)
		{
			m_HttpProxy->Stop ();
			m_HttpProxy = nullptr;
		}
		ReadHttpProxy ();

		// recreate SOCKS proxy
		if (m_SocksProxy)
		{
			m_SocksProxy->Stop ();
			m_SocksProxy = nullptr;
		}
		ReadSocksProxy ();

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

	bool ClientContext::LoadPrivateKeys (dotnet::data::PrivateKeys& keys, const std::string& filename,
		dotnet::data::SigningKeyType sigType, dotnet::data::CryptoKeyType cryptoType)
	{
		if (filename == "transient")
		{
			keys = dotnet::data::PrivateKeys::CreateRandomKeys (sigType, cryptoType);
			LogPrint (eLogInfo, "Clients: New transient keys address ", m_AddressBook.ToAddress(keys.GetPublic ()->GetIdentHash ()), " created");
			return true;
		}

		bool success = true;
		std::string fullPath = dotnet::fs::DataDirPath (filename);
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
			LogPrint (eLogError, "Clients: can't open file ", fullPath, " Creating new one with signature type ", sigType, " crypto type ", cryptoType);
			keys = dotnet::data::PrivateKeys::CreateRandomKeys (sigType, cryptoType);
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

	std::vector<std::shared_ptr<DatagramSessionInfo> > ClientContext::GetForwardInfosFor(const dotnet::data::IdentHash & destination)
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

	std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination (bool isPublic,
		dotnet::data::SigningKeyType sigType, dotnet::data::CryptoKeyType cryptoType,
		const std::map<std::string, std::string> * params)
	{
		dotnet::data::PrivateKeys keys = dotnet::data::PrivateKeys::CreateRandomKeys (sigType, cryptoType);
		auto localDestination = std::make_shared<ClientDestination> (keys, isPublic, params);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[localDestination->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	std::shared_ptr<ClientDestination> ClientContext::CreateNewMatchedTunnelDestination(const dotnet::data::PrivateKeys &keys, const std::string & name, const std::map<std::string, std::string> * params)
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

	std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination (const dotnet::data::PrivateKeys& keys, bool isPublic,
		const std::map<std::string, std::string> * params)
	{
		auto it = m_Destinations.find (keys.GetPublic ()->GetIdentHash ());
		if (it != m_Destinations.end ())
		{
			LogPrint (eLogWarning, "Clients: Local destination ", m_AddressBook.ToAddress(keys.GetPublic ()->GetIdentHash ()), " exists");
			if (!it->second->IsRunning ())
				it->second->Start ();
			return it->second;
		}
		auto localDestination = std::make_shared<ClientDestination> (keys, isPublic, params);
		std::unique_lock<std::mutex> l(m_DestinationsMutex);
		m_Destinations[keys.GetPublic ()->GetIdentHash ()] = localDestination;
		localDestination->Start ();
		return localDestination;
	}

	void ClientContext::CreateNewSharedLocalDestination ()
	{
		m_SharedLocalDestination = CreateNewLocalDestination (); // non-public, EDDSA
		m_SharedLocalDestination->Acquire ();
	}

	std::shared_ptr<ClientDestination> ClientContext::FindLocalDestination (const dotnet::data::IdentHash& destination) const
	{
		auto it = m_Destinations.find (destination);
		if (it != m_Destinations.end ())
			return it->second;
		return nullptr;
	}

	template<typename Section, typename Type>
	std::string ClientContext::GetDNCPOption (const Section& section, const std::string& name, const Type& value) const
	{
        return section.second.get (boost::property_tree::ptree::path_type (name, '/'), std::to_string (value));
	}

	template<typename Section>
	std::string ClientContext::GetDNCPStringOption (const Section& section, const std::string& name, const std::string& value) const
	{
        return section.second.get (boost::property_tree::ptree::path_type (name, '/'), value);
	}

	template<typename Section>
	void ClientContext::ReadDNCPOptions (const Section& section, std::map<std::string, std::string>& options) const
	{
		options[DNCP_PARAM_INBOUND_TUNNEL_LENGTH] = GetDNCPOption (section, DNCP_PARAM_INBOUND_TUNNEL_LENGTH,  DEFAULT_INBOUND_TUNNEL_LENGTH);
		options[DNCP_PARAM_OUTBOUND_TUNNEL_LENGTH] = GetDNCPOption (section, DNCP_PARAM_OUTBOUND_TUNNEL_LENGTH, DEFAULT_OUTBOUND_TUNNEL_LENGTH);
		options[DNCP_PARAM_INBOUND_TUNNELS_QUANTITY] = GetDNCPOption (section, DNCP_PARAM_INBOUND_TUNNELS_QUANTITY, DEFAULT_INBOUND_TUNNELS_QUANTITY);
		options[DNCP_PARAM_OUTBOUND_TUNNELS_QUANTITY] = GetDNCPOption (section, DNCP_PARAM_OUTBOUND_TUNNELS_QUANTITY, DEFAULT_OUTBOUND_TUNNELS_QUANTITY);
		options[DNCP_PARAM_TAGS_TO_SEND] = GetDNCPOption (section, DNCP_PARAM_TAGS_TO_SEND, DEFAULT_TAGS_TO_SEND);
		options[DNCP_PARAM_MIN_TUNNEL_LATENCY] = GetDNCPOption(section, DNCP_PARAM_MIN_TUNNEL_LATENCY, DEFAULT_MIN_TUNNEL_LATENCY);
		options[DNCP_PARAM_MAX_TUNNEL_LATENCY] = GetDNCPOption(section, DNCP_PARAM_MAX_TUNNEL_LATENCY, DEFAULT_MAX_TUNNEL_LATENCY);
		options[DNCP_PARAM_STREAMING_INITIAL_ACK_DELAY] = GetDNCPOption(section, DNCP_PARAM_STREAMING_INITIAL_ACK_DELAY, DEFAULT_INITIAL_ACK_DELAY);
		options[DNCP_PARAM_LEASESET_TYPE] = GetDNCPOption(section, DNCP_PARAM_LEASESET_TYPE, DEFAULT_LEASESET_TYPE);
		std::string encType = GetDNCPStringOption(section, DNCP_PARAM_LEASESET_ENCRYPTION_TYPE, "");
		if (encType.length () > 0) options[DNCP_PARAM_LEASESET_ENCRYPTION_TYPE] = encType;
	}

	void ClientContext::ReadDNCPOptionsFromConfig (const std::string& prefix, std::map<std::string, std::string>& options) const
	{
		std::string value;
		if (dotnet::config::GetOption(prefix + DNCP_PARAM_INBOUND_TUNNEL_LENGTH, value))
			options[DNCP_PARAM_INBOUND_TUNNEL_LENGTH] = value;
		if (dotnet::config::GetOption(prefix + DNCP_PARAM_INBOUND_TUNNELS_QUANTITY, value))
			options[DNCP_PARAM_INBOUND_TUNNELS_QUANTITY] = value;
		if (dotnet::config::GetOption(prefix + DNCP_PARAM_OUTBOUND_TUNNEL_LENGTH, value))
			options[DNCP_PARAM_OUTBOUND_TUNNEL_LENGTH] = value;
		if (dotnet::config::GetOption(prefix + DNCP_PARAM_OUTBOUND_TUNNELS_QUANTITY, value))
			options[DNCP_PARAM_OUTBOUND_TUNNELS_QUANTITY] = value;
		if (dotnet::config::GetOption(prefix + DNCP_PARAM_MIN_TUNNEL_LATENCY, value))
			options[DNCP_PARAM_MIN_TUNNEL_LATENCY] = value;
		if (dotnet::config::GetOption(prefix + DNCP_PARAM_MAX_TUNNEL_LATENCY, value))
			options[DNCP_PARAM_MAX_TUNNEL_LATENCY] = value;
	}

	void ClientContext::ReadTunnels ()
	{
		int numClientTunnels = 0, numServerTunnels = 0;
		std::string tunConf; dotnet::config::GetOption("tunconf", tunConf);
		if (tunConf.empty ())
		{
			// TODO: cleanup this in 2.8.0
			tunConf = dotnet::fs::DataDirPath ("tunnels.cfg");
			if (dotnet::fs::Exists(tunConf))
				LogPrint(eLogWarning, "Clients: please rename tunnels.cfg -> tunnels.conf here: ", tunConf);
			else
				tunConf = dotnet::fs::DataDirPath ("tunnels.conf");
		}
		LogPrint(eLogDebug, "Clients: tunnels config file: ", tunConf);
		ReadTunnels (tunConf, numClientTunnels, numServerTunnels);

		std::string tunDir; dotnet::config::GetOption("tunnelsdir", tunDir);
		if (tunDir.empty ())
			tunDir = dotnet::fs::DataDirPath ("tunnels.d");
		if (dotnet::fs::Exists (tunDir))
		{
			std::vector<std::string> files;
			if (dotnet::fs::ReadDir (tunDir, files))
			{
				for (auto& it: files)
				{
					LogPrint(eLogDebug, "Clients: tunnels extra config file: ", it);
					ReadTunnels (it, numClientTunnels, numServerTunnels);
				}
			}
		}

		LogPrint (eLogInfo, "Clients: ", numClientTunnels, " client tunnels created");
		LogPrint (eLogInfo, "Clients: ", numServerTunnels, " server tunnels created");
	}


	void ClientContext::ReadTunnels (const std::string& tunConf, int& numClientTunnels, int& numServerTunnels)
	{
		boost::property_tree::ptree pt;
		try
		{
			boost::property_tree::read_ini (tunConf, pt);
		}
		catch (std::exception& ex)
		{
			LogPrint (eLogWarning, "Clients: Can't read ", tunConf, ": ", ex.what ());
			return;
		}

		for (auto& section: pt)
		{
			std::string name = section.first;
			try
			{
				std::string type = section.second.get<std::string> (DOTNET_TUNNELS_SECTION_TYPE);
				if (type == DOTNET_TUNNELS_SECTION_TYPE_CLIENT
						|| type == DOTNET_TUNNELS_SECTION_TYPE_SOCKS
						|| type == DOTNET_TUNNELS_SECTION_TYPE_WEBSOCKS
						|| type == DOTNET_TUNNELS_SECTION_TYPE_HTTPPROXY
						|| type == DOTNET_TUNNELS_SECTION_TYPE_UDPCLIENT)
				{
					// mandatory params
					std::string dest;
					if (type == DOTNET_TUNNELS_SECTION_TYPE_CLIENT || type == DOTNET_TUNNELS_SECTION_TYPE_UDPCLIENT)
						dest = section.second.get<std::string> (DOTNET_CLIENT_TUNNEL_DESTINATION);
					int port = section.second.get<int> (DOTNET_CLIENT_TUNNEL_PORT);
					// optional params
					bool matchTunnels = section.second.get(DOTNET_CLIENT_TUNNEL_MATCH_TUNNELS, false);
					std::string keys = section.second.get (DOTNET_CLIENT_TUNNEL_KEYS, "transient");
					std::string address = section.second.get (DOTNET_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
					int destinationPort = section.second.get (DOTNET_CLIENT_TUNNEL_DESTINATION_PORT, 0);
					dotnet::data::SigningKeyType sigType = section.second.get (DOTNET_CLIENT_TUNNEL_SIGNATURE_TYPE, dotnet::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
					dotnet::data::CryptoKeyType cryptoType = section.second.get (DOTNET_CLIENT_TUNNEL_CRYPTO_TYPE, dotnet::data::CRYPTO_KEY_TYPE_ELGAMAL);
					// DNCP
					std::map<std::string, std::string> options;
					ReadDNCPOptions (section, options);

					std::shared_ptr<ClientDestination> localDestination = nullptr;
					if (keys.length () > 0)
					{
						dotnet::data::PrivateKeys k;
						if(LoadPrivateKeys (k, keys, sigType, cryptoType))
						{
							localDestination = FindLocalDestination (k.GetPublic ()->GetIdentHash ());
							if (!localDestination)
							{
								if(matchTunnels)
									localDestination = CreateNewMatchedTunnelDestination(k, dest, &options);
								else
									localDestination = CreateNewLocalDestination (k, type == DOTNET_TUNNELS_SECTION_TYPE_UDPCLIENT, &options);
							}
						}
					}

					if (type == DOTNET_TUNNELS_SECTION_TYPE_UDPCLIENT) {
						// udp client
						// TODO: hostnames
						boost::asio::ip::udp::endpoint end(boost::asio::ip::address::from_string(address), port);
						if (!localDestination)
						{
							localDestination = m_SharedLocalDestination;
						}
						auto clientTunnel = std::make_shared<DOTNETUDPClientTunnel>(name, dest, end, localDestination, destinationPort);
						if(m_ClientForwards.insert(std::make_pair(end, clientTunnel)).second)
						{
							clientTunnel->Start();
						}
						else
							LogPrint(eLogError, "Clients: .NET Client forward for endpoint ", end, " already exists");

					} else {
						boost::asio::ip::tcp::endpoint clientEndpoint;
						std::shared_ptr<DotNetService> clientTunnel;
						if (type == DOTNET_TUNNELS_SECTION_TYPE_SOCKS)
						{
							// socks proxy
							std::string outproxy = section.second.get("outproxy", "");
							auto tun = std::make_shared<dotnet::proxy::SOCKSProxy>(name, address, port, !outproxy.empty(), outproxy, destinationPort, localDestination);
							clientTunnel = tun;
							clientEndpoint = tun->GetLocalEndpoint ();
						}
						else if (type == DOTNET_TUNNELS_SECTION_TYPE_HTTPPROXY)
						{
							// http proxy
							std::string outproxy = section.second.get("outproxy", "");
							bool addresshelper = section.second.get("addresshelper", true);
							auto tun = std::make_shared<dotnet::proxy::HTTPProxy>(name, address, port, outproxy, addresshelper, localDestination);
							clientTunnel = tun;
							clientEndpoint = tun->GetLocalEndpoint ();
						}
						else if (type == DOTNET_TUNNELS_SECTION_TYPE_WEBSOCKS)
						{
							// websocks proxy
							auto tun = std::make_shared<WebSocks>(address, port, localDestination);
							clientTunnel = tun;
							clientEndpoint = tun->GetLocalEndpoint();
						}
						else
						{
							// tcp client
							auto tun = std::make_shared<DOTNETClientTunnel> (name, dest, address, port, localDestination, destinationPort);
							clientTunnel = tun;
							clientEndpoint = tun->GetLocalEndpoint ();
						}
						uint32_t timeout = section.second.get<uint32_t>(DOTNET_CLIENT_TUNNEL_CONNECT_TIMEOUT, 0);
						if(timeout)
						{
							clientTunnel->SetConnectTimeout(timeout);
							LogPrint(eLogInfo, "Clients: .NET Client tunnel connect timeout set to ", timeout);
						}

						auto ins = m_ClientTunnels.insert (std::make_pair (clientEndpoint, clientTunnel));
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
								LogPrint (eLogInfo, "Clients: .NET client tunnel destination updated");
								ins.first->second->SetLocalDestination (clientTunnel->GetLocalDestination ());
							}
							ins.first->second->isUpdated = true;
							LogPrint (eLogInfo, "Clients: .NET client tunnel for endpoint ", clientEndpoint, " already exists");
						}
					}
				}
				else if (type == DOTNET_TUNNELS_SECTION_TYPE_SERVER
								 || type == DOTNET_TUNNELS_SECTION_TYPE_HTTP
								 || type == DOTNET_TUNNELS_SECTION_TYPE_IRC
								 || type == DOTNET_TUNNELS_SECTION_TYPE_UDPSERVER)
				{
					// mandatory params
					std::string host = section.second.get<std::string> (DOTNET_SERVER_TUNNEL_HOST);
					int port = section.second.get<int> (DOTNET_SERVER_TUNNEL_PORT);
					std::string keys = section.second.get<std::string> (DOTNET_SERVER_TUNNEL_KEYS);
					// optional params
					int inPort = section.second.get (DOTNET_SERVER_TUNNEL_INPORT, 0);
					std::string accessList = section.second.get (DOTNET_SERVER_TUNNEL_ACCESS_LIST, "");
					std::string hostOverride = section.second.get (DOTNET_SERVER_TUNNEL_HOST_OVERRIDE, "");
					std::string webircpass = section.second.get<std::string> (DOTNET_SERVER_TUNNEL_WEBIRC_PASSWORD, "");
					bool gzip = section.second.get (DOTNET_SERVER_TUNNEL_GZIP, true);
					dotnet::data::SigningKeyType sigType = section.second.get (DOTNET_SERVER_TUNNEL_SIGNATURE_TYPE, dotnet::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
					dotnet::data::CryptoKeyType cryptoType = section.second.get (DOTNET_CLIENT_TUNNEL_CRYPTO_TYPE, dotnet::data::CRYPTO_KEY_TYPE_ELGAMAL);

					std::string address = section.second.get<std::string> (DOTNET_SERVER_TUNNEL_ADDRESS, "127.0.0.1");
					bool isUniqueLocal = section.second.get(DOTNET_SERVER_TUNNEL_ENABLE_UNIQUE_LOCAL, true);

					// DNCP
					std::map<std::string, std::string> options;
					ReadDNCPOptions (section, options);

					std::shared_ptr<ClientDestination> localDestination = nullptr;
					dotnet::data::PrivateKeys k;
					if(!LoadPrivateKeys (k, keys, sigType, cryptoType))
						continue;
					localDestination = FindLocalDestination (k.GetPublic ()->GetIdentHash ());
					if (!localDestination)
						localDestination = CreateNewLocalDestination (k, true, &options);
					if (type == DOTNET_TUNNELS_SECTION_TYPE_UDPSERVER)
					{
						// udp server tunnel
						// TODO: hostnames
						auto localAddress = boost::asio::ip::address::from_string(address);
						boost::asio::ip::udp::endpoint endpoint(boost::asio::ip::address::from_string(host), port);
						auto serverTunnel = std::make_shared<DOTNETUDPServerTunnel>(name, localDestination, localAddress, endpoint, port);
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
								serverTunnel)).second)
						{
							serverTunnel->Start();
							LogPrint(eLogInfo, "Clients: .NET Server Forward created for UDP Endpoint ", host, ":", port, " bound on ", address, " for ",localDestination->GetIdentHash().ToBase32());
						}
						else
							LogPrint(eLogError, "Clients: .NET Server Forward for destination/port ", m_AddressBook.ToAddress(localDestination->GetIdentHash()), "/", port, "already exists");

						continue;
					}

					std::shared_ptr<DOTNETServerTunnel>  serverTunnel;
					if (type == DOTNET_TUNNELS_SECTION_TYPE_HTTP)
						serverTunnel = std::make_shared<DOTNETServerTunnelHTTP> (name, host, port, localDestination, hostOverride, inPort, gzip);
					else if (type == DOTNET_TUNNELS_SECTION_TYPE_IRC)
						serverTunnel = std::make_shared<DOTNETServerTunnelIRC> (name, host, port, localDestination, webircpass, inPort, gzip);
					else // regular server tunnel by default
						serverTunnel = std::make_shared<DOTNETServerTunnel> (name, host, port, localDestination, inPort, gzip);

					if(!isUniqueLocal)
					{
						LogPrint(eLogInfo, "Clients: disabling loopback address mapping");
						serverTunnel->SetUniqueLocal(isUniqueLocal);
					}

					if (accessList.length () > 0)
					{
						std::set<dotnet::data::IdentHash> idents;
						size_t pos = 0, comma;
						do
						{
							comma = accessList.find (',', pos);
							dotnet::data::IdentHash ident;
							ident.FromBase32 (accessList.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));
							idents.insert (ident);
							pos = comma + 1;
						}
						while (comma != std::string::npos);
						serverTunnel->SetAccessList (idents);
					}
					auto ins = m_ServerTunnels.insert (std::make_pair (
							std::make_pair (localDestination->GetIdentHash (), inPort),
							serverTunnel));
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
							LogPrint (eLogInfo, "Clients: .NET server tunnel destination updated");
							ins.first->second->SetLocalDestination (serverTunnel->GetLocalDestination ());
						}
						ins.first->second->isUpdated = true;
						LogPrint (eLogInfo, "Clients: .NET server tunnel for destination/port ",   m_AddressBook.ToAddress(localDestination->GetIdentHash ()), "/", inPort, " already exists");
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
	}

	void ClientContext::ReadHttpProxy ()
	{
		std::shared_ptr<ClientDestination> localDestination;
		bool httproxy; dotnet::config::GetOption("httpproxy.enabled", httproxy);
		if (httproxy)
		{
			std::string httpProxyKeys; dotnet::config::GetOption("httpproxy.keys",    httpProxyKeys);
			std::string httpProxyAddr; dotnet::config::GetOption("httpproxy.address", httpProxyAddr);
			uint16_t    httpProxyPort; dotnet::config::GetOption("httpproxy.port",    httpProxyPort);
			dotnet::data::SigningKeyType sigType; dotnet::config::GetOption("httpproxy.signaturetype",  sigType);
			std::string httpOutProxyURL; dotnet::config::GetOption("httpproxy.outproxy",     httpOutProxyURL);
			bool httpAddresshelper; dotnet::config::GetOption("httpproxy.addresshelper", httpAddresshelper);
			LogPrint(eLogInfo, "Clients: starting HTTP Proxy at ", httpProxyAddr, ":", httpProxyPort);
			if (httpProxyKeys.length () > 0)
			{
				dotnet::data::PrivateKeys keys;
				if(LoadPrivateKeys (keys, httpProxyKeys, sigType))
				{
					std::map<std::string, std::string> params;
					ReadDNCPOptionsFromConfig ("httpproxy.", params);
					localDestination = CreateNewLocalDestination (keys, false, &params);
					if (localDestination) localDestination->Acquire ();
				}
				else
					LogPrint(eLogError, "Clients: failed to load HTTP Proxy key");
			}
			try
			{
				m_HttpProxy = new dotnet::proxy::HTTPProxy("HTTP Proxy", httpProxyAddr, httpProxyPort, httpOutProxyURL, httpAddresshelper, localDestination);
				m_HttpProxy->Start();
			}
			catch (std::exception& e)
			{
				LogPrint(eLogError, "Clients: Exception in HTTP Proxy: ", e.what());
			}
		}
	}

	void ClientContext::ReadSocksProxy ()
	{
		std::shared_ptr<ClientDestination> localDestination;
		bool socksproxy; dotnet::config::GetOption("socksproxy.enabled", socksproxy);
		if (socksproxy)
		{
			std::string socksProxyKeys; dotnet::config::GetOption("socksproxy.keys",     socksProxyKeys);
			std::string socksProxyAddr; dotnet::config::GetOption("socksproxy.address",  socksProxyAddr);
			uint16_t    socksProxyPort; dotnet::config::GetOption("socksproxy.port",     socksProxyPort);
			bool socksOutProxy; dotnet::config::GetOption("socksproxy.outproxy.enabled", socksOutProxy);
			std::string socksOutProxyAddr; dotnet::config::GetOption("socksproxy.outproxy",     socksOutProxyAddr);
			uint16_t    socksOutProxyPort; dotnet::config::GetOption("socksproxy.outproxyport", socksOutProxyPort);
			dotnet::data::SigningKeyType sigType; dotnet::config::GetOption("socksproxy.signaturetype",  sigType);
			LogPrint(eLogInfo, "Clients: starting SOCKS Proxy at ", socksProxyAddr, ":", socksProxyPort);
			if (socksProxyKeys.length () > 0)
			{
				dotnet::data::PrivateKeys keys;
				if (LoadPrivateKeys (keys, socksProxyKeys, sigType))
				{
					std::map<std::string, std::string> params;
					ReadDNCPOptionsFromConfig ("socksproxy.", params);
					localDestination = CreateNewLocalDestination (keys, false, &params);
					if (localDestination) localDestination->Acquire ();
				}
				else
					LogPrint(eLogError, "Clients: failed to load SOCKS Proxy key");
			}
			try
			{
				m_SocksProxy = new dotnet::proxy::SOCKSProxy("SOCKS", socksProxyAddr, socksProxyPort,
					socksOutProxy, socksOutProxyAddr, socksOutProxyPort, localDestination);
				m_SocksProxy->Start();
			}
			catch (std::exception& e)
			{
				LogPrint(eLogError, "Clients: Exception in SOCKS Proxy: ", e.what());
			}
		}
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
