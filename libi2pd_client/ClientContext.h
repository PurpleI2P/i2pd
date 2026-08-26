/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef CLIENT_CONTEXT_H__
#define CLIENT_CONTEXT_H__

#include <map>
#include <unordered_map>
#include <vector>
#include <utility>
#include <mutex>
#include <memory>
#include <string_view>
#include <boost/asio.hpp>
#include "Destination.h"
#include "I2PService.h"
#include "I2PTunnel.h"
#include "UDPTunnel.h"
#include "SAM.h"
#include "BOB.h"
#include "I2CP.h"
#include "AddressBook.h"
#include "TorrentsTunnel.h"
#include "TorrentsRPC.h"
#include "I18N_langs.h"

namespace i2p
{
namespace client
{
	const char I2P_TUNNELS_SECTION_TYPE[] = "type";
	const char I2P_TUNNELS_SECTION_TYPE_CLIENT[] = "client";
	const char I2P_TUNNELS_SECTION_TYPE_SERVER[] = "server";
	const char I2P_TUNNELS_SECTION_TYPE_HTTP[] = "http";
	const char I2P_TUNNELS_SECTION_TYPE_IRC[] = "irc";
	const char I2P_TUNNELS_SECTION_TYPE_UDPCLIENT[] = "udpclient";
	const char I2P_TUNNELS_SECTION_TYPE_UDPSERVER[] = "udpserver";
	const char I2P_TUNNELS_SECTION_TYPE_SOCKS[] = "socks";
	const char I2P_TUNNELS_SECTION_TYPE_WEBSOCKS[] = "websocks";
	const char I2P_TUNNELS_SECTION_TYPE_HTTPPROXY[] = "httpproxy";
	const char I2P_TUNNELS_SECTION_TYPE_TORRENTS[] = "torrents";
	const char I2P_CLIENT_TUNNEL_PORT[] = "port";
	const char I2P_CLIENT_TUNNEL_ADDRESS[] = "address";
	const char I2P_CLIENT_TUNNEL_DESTINATION[] = "destination";
	const char I2P_CLIENT_TUNNEL_KEYS[] = "keys";
	const char I2P_CLIENT_TUNNEL_GZIP[] = "gzip";
	const char I2P_CLIENT_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char I2P_CLIENT_TUNNEL_CRYPTO_TYPE[] = "cryptotype";
	const char I2P_CLIENT_TUNNEL_DESTINATION_PORT[] = "destinationport";
	const char I2P_CLIENT_TUNNEL_MATCH_TUNNELS[] = "matchtunnels";
	const char I2P_CLIENT_TUNNEL_CONNECT_TIMEOUT[] = "connecttimeout";
	const char I2P_CLIENT_TUNNEL_KEEP_ALIVE_INTERVAL[] = "keepaliveinterval";
	const char I2P_CLIENT_TUNNEL_CLOSE_IDLE_TIME[] = "i2cp.closeIdleTime";
	const char I2P_CLIENT_TUNNEL_NEW_DEST_ON_RESUME[] = "i2cp.newDestOnResume";
	const char I2P_SERVER_TUNNEL_HOST[] = "host";
	const char I2P_SERVER_TUNNEL_HOST_OVERRIDE[] = "hostoverride";
	const char I2P_SERVER_TUNNEL_I2P_HEADERS[] = "i2pheaders";
	const char I2P_SERVER_TUNNEL_PORT[] = "port";
	const char I2P_SERVER_TUNNEL_KEYS[] = "keys";
	const char I2P_SERVER_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char I2P_SERVER_TUNNEL_INPORT[] = "inport";
	const char I2P_SERVER_TUNNEL_ACCESS_LIST[] = "accesslist";
	const char I2P_SERVER_TUNNEL_WHITE_LIST[] = "whitelist";
	const char I2P_SERVER_TUNNEL_GZIP[] = "gzip";
	const char I2P_SERVER_TUNNEL_WEBIRC_PASSWORD[] = "webircpassword";
	const char I2P_SERVER_TUNNEL_ADDRESS[] = "address";
	const char I2P_SERVER_TUNNEL_ENABLE_UNIQUE_LOCAL[] = "enableuniquelocal";
	const char I2P_SERVER_TUNNEL_SSL[] = "ssl";
	const char UDP_CLIENT_TUNNEL_DATAGRAM_VERSION[] = "datagramversion";
	const char UDP_TUNNEL_MAX_WINDOW[] = "maxwindow";
	const char TORRENTS_TUNNEL_KEYS[] = "keys";
	const char TORRENTS_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char TORRENTS_TUNNEL_TORRENTS_DIR[] = "torrentsdir";
	const char TORRENTS_TUNNEL_TRACKERS[] = "trackers";
	const char TORRENTS_TUNNEL_RPC_PORT[] = "rpcport";
	const char TORRENTS_TUNNEL_RPC_PATH[] = "rpcpath";
	const char TORRENTS_TUNNEL_RPC_ADDRESS[] = "rpcaddress";

	class ClientContext
	{
		public:

			ClientContext ();
			~ClientContext ();

			void Start ();
			void Stop ();

			void ReloadConfig ();

			std::shared_ptr<ClientDestination> GetSharedLocalDestination () const { return m_SharedLocalDestination; };
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (bool isPublic = false, // transient
				i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL,
				const i2p::util::Mapping * params = nullptr); // used by SAM only
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (boost::asio::io_context& service,
				bool isPublic = false, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL,
				const i2p::util::Mapping * params = nullptr); // same as previous but on external io_service
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true,
				const i2p::util::Mapping * params = nullptr);
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (boost::asio::io_context& service,
				const i2p::data::PrivateKeys& keys, bool isPublic = true,
				const i2p::util::Mapping * params = nullptr); // same as previous but on external io_service
			std::shared_ptr<ClientDestination> CreateNewMatchedTunnelDestination(const i2p::data::PrivateKeys &keys,
				const std::string & name, const i2p::util::Mapping * params = nullptr);
			void DeleteLocalDestination (std::shared_ptr<ClientDestination> destination);
			bool ReplaceLocalDestinationHash (const i2p::data::IdentHash& oldIdentHash, const i2p::data::IdentHash& newIdentHash);
			std::shared_ptr<ClientDestination> FindLocalDestination (const i2p::data::IdentHash& destination) const;
			bool LoadPrivateKeys (i2p::data::PrivateKeys& keys, std::string_view filename,
				i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL);

			AddressBook& GetAddressBook () { return m_AddressBook; };
			const BOBCommandChannel * GetBOBCommandChannel () const { return m_BOBCommandChannel; };
			const SAMBridge * GetSAMBridge () const { return m_SamBridge; };
			const I2CPServer * GetI2CPServer () const { return m_I2CPServer; };

			std::vector<std::shared_ptr<DatagramSessionInfo> > GetForwardInfosFor(const i2p::data::IdentHash & destination);

			// i18n
			std::shared_ptr<const i2p::i18n::Locale> GetLanguage () { return m_Language; };
			void SetLanguage (const std::shared_ptr<const i2p::i18n::Locale> language) { m_Language = language; };

		private:

			void ReadTunnels ();
			void ReadTunnels (const std::string& tunConf, int& numClientTunnels, int& numServerTunnels);
			void ReadHttpProxy ();
			void ReadSocksProxy ();
			// take the proxy out under the lock, so it can be stopped without holding it
			std::shared_ptr<I2PService> DetachHttpProxy ();
			std::shared_ptr<I2PService> DetachSocksProxy ();
			template<typename Section, typename Type>
			std::string GetI2CPOption (const Section& section, const std::string& name, const Type& value) const;
			template<typename Section>
			std::string GetI2CPStringOption (const Section& section, const std::string& name, const std::string& value) const; // GetI2CPOption with string default value
			template<typename Section>
			void ReadI2CPOptionsGroup (const Section& section, const std::string& group, i2p::util::Mapping& options) const;
			template<typename Section>
			void ReadI2CPOptions (const Section& section, bool isServer, i2p::util::Mapping& options) const; // for tunnels
			void ReadI2CPOptionsFromConfig (const std::string& prefix, i2p::util::Mapping& options) const; // for HTTP and SOCKS proxy


			void VisitTunnels (bool clean);

			void CreateNewSharedLocalDestination ();
			void AddLocalDestination (std::shared_ptr<ClientDestination> localDestination);

			std::shared_ptr<i2p::torrents::TorrentsRPCServer> CreateTorrentsRPCServer (std::string_view address, uint16_t port);

		private:

			mutable std::mutex m_DestinationsMutex;
			std::map<i2p::data::IdentHash, std::shared_ptr<ClientDestination> > m_Destinations;
			std::shared_ptr<ClientDestination>  m_SharedLocalDestination;

			AddressBook m_AddressBook;

			mutable std::mutex m_ProxyMutex;
			std::shared_ptr<I2PService> m_HttpProxy, m_SocksProxy;
			std::map<boost::asio::ip::tcp::endpoint, std::shared_ptr<I2PService> > m_ClientTunnels; // local endpoint -> tunnel
			std::map<std::pair<i2p::data::IdentHash, int>, std::shared_ptr<I2PServerTunnel> > m_ServerTunnels; // <destination,port> -> tunnel

			std::mutex m_ForwardsMutex;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<I2PUDPClientTunnel> > m_ClientForwards; // local endpoint -> udp tunnel
			std::map<std::pair<i2p::data::IdentHash, int>, std::shared_ptr<I2PUDPServerTunnel> > m_ServerForwards; // <destination,port> -> udp tunnel

			std::unordered_map<i2p::data::IdentHash, std::shared_ptr<i2p::torrents::TorrentsTunnel> > m_TorrentsTunnels; // local destination -> torrents tunnel
			std::unordered_map<uint16_t, std::shared_ptr<i2p::torrents::TorrentsRPCServer> > m_TorrentsRPCServers;

			SAMBridge * m_SamBridge;
			BOBCommandChannel * m_BOBCommandChannel;
			I2CPServer * m_I2CPServer;


			// i18n
			std::shared_ptr<const i2p::i18n::Locale> m_Language;

		public:

			// for HTTP; thread-safe snapshot, safe to iterate without holding any lock
			std::vector<std::pair<i2p::data::IdentHash, std::shared_ptr<ClientDestination> > > GetDestinationsList () const
			{
				std::lock_guard<std::mutex> l(m_DestinationsMutex);
				return std::vector<std::pair<i2p::data::IdentHash, std::shared_ptr<ClientDestination> > > (m_Destinations.begin (), m_Destinations.end ());
			}
			const decltype(m_ClientTunnels)& GetClientTunnels () const { return m_ClientTunnels; };
			const decltype(m_ServerTunnels)& GetServerTunnels () const { return m_ServerTunnels; };
			const decltype(m_ClientForwards)& GetClientForwards () const { return m_ClientForwards; }
			const decltype(m_ServerForwards)& GetServerForwards () const { return m_ServerForwards; }
			const decltype(m_TorrentsTunnels)& GetTorrentsTunnels () const { return m_TorrentsTunnels; }
			const decltype(m_TorrentsRPCServers)& GetTorrentsRPCServers () const { return m_TorrentsRPCServers; }
			std::shared_ptr<const I2PService> GetHttpProxy () const
			{
				std::lock_guard<std::mutex> l(m_ProxyMutex);
				return m_HttpProxy;
			}
			std::shared_ptr<const I2PService> GetSocksProxy () const
			{
				std::lock_guard<std::mutex> l(m_ProxyMutex);
				return m_SocksProxy;
			}
	};

	extern ClientContext context;
}
}

#endif
