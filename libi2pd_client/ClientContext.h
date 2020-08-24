/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef CLIENT_CONTEXT_H__
#define CLIENT_CONTEXT_H__

#include <map>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>
#include "Destination.h"
#include "I2PService.h"
#include "HTTPProxy.h"
#include "SOCKS.h"
#include "I2PTunnel.h"
#include "SAM.h"
#include "BOB.h"
#include "I2CP.h"
#include "AddressBook.h"

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
	const char I2P_SERVER_TUNNEL_HOST[] = "host";
	const char I2P_SERVER_TUNNEL_HOST_OVERRIDE[] = "hostoverride";
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
				const std::map<std::string, std::string> * params = nullptr); // used by SAM only
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (boost::asio::io_service& service,
				bool isPublic = false, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL,
				const std::map<std::string, std::string> * params = nullptr); // same as previous but on external io_service
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true,
				const std::map<std::string, std::string> * params = nullptr);
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (boost::asio::io_service& service,
				const i2p::data::PrivateKeys& keys, bool isPublic = true,
				const std::map<std::string, std::string> * params = nullptr); // same as previous but on external io_service
			std::shared_ptr<ClientDestination> CreateNewMatchedTunnelDestination(const i2p::data::PrivateKeys &keys,
				const std::string & name, const std::map<std::string, std::string> * params = nullptr);
			void DeleteLocalDestination (std::shared_ptr<ClientDestination> destination);
			std::shared_ptr<ClientDestination> FindLocalDestination (const i2p::data::IdentHash& destination) const;
			bool LoadPrivateKeys (i2p::data::PrivateKeys& keys, const std::string& filename,
				i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL);

			AddressBook& GetAddressBook () { return m_AddressBook; };
			const BOBCommandChannel * GetBOBCommandChannel () const { return m_BOBCommandChannel; };
			const SAMBridge * GetSAMBridge () const { return m_SamBridge; };
			const I2CPServer * GetI2CPServer () const { return m_I2CPServer; };

			std::vector<std::shared_ptr<DatagramSessionInfo> > GetForwardInfosFor(const i2p::data::IdentHash & destination);

		private:

			void ReadTunnels ();
			void ReadTunnels (const std::string& tunConf, int& numClientTunnels, int& numServerTunnels);
			void ReadHttpProxy ();
			void ReadSocksProxy ();
			template<typename Section, typename Type>
			std::string GetI2CPOption (const Section& section, const std::string& name, const Type& value) const;
			template<typename Section>
			std::string GetI2CPStringOption (const Section& section, const std::string& name, const std::string& value) const; // GetI2CPOption with string default value
			template<typename Section>
			void ReadI2CPOptionsGroup (const Section& section, const std::string& group,  std::map<std::string, std::string>& options) const;
			template<typename Section>
			void ReadI2CPOptions (const Section& section, std::map<std::string, std::string>& options) const; // for tunnels
			void ReadI2CPOptionsFromConfig (const std::string& prefix, std::map<std::string, std::string>& options) const; // for HTTP and SOCKS proxy

			void CleanupUDP(const boost::system::error_code & ecode);
			void ScheduleCleanupUDP();

			template<typename Visitor>
			void VisitTunnels (Visitor v); // Visitor: (I2PService *) -> bool, true means retain

			void CreateNewSharedLocalDestination ();
			void AddLocalDestination (std::shared_ptr<ClientDestination> localDestination);

		private:

			std::mutex m_DestinationsMutex;
			std::map<i2p::data::IdentHash, std::shared_ptr<ClientDestination> > m_Destinations;
			std::shared_ptr<ClientDestination>  m_SharedLocalDestination;

			AddressBook m_AddressBook;

			i2p::proxy::HTTPProxy * m_HttpProxy;
			i2p::proxy::SOCKSProxy * m_SocksProxy;
			std::map<boost::asio::ip::tcp::endpoint, std::shared_ptr<I2PService> > m_ClientTunnels; // local endpoint->tunnel
			std::map<std::pair<i2p::data::IdentHash, int>, std::shared_ptr<I2PServerTunnel> > m_ServerTunnels; // <destination,port>->tunnel

			std::mutex m_ForwardsMutex;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<I2PUDPClientTunnel> > m_ClientForwards; // local endpoint -> udp tunnel
			std::map<std::pair<i2p::data::IdentHash, int>, std::shared_ptr<I2PUDPServerTunnel> > m_ServerForwards; // <destination,port> -> udp tunnel

			SAMBridge * m_SamBridge;
			BOBCommandChannel * m_BOBCommandChannel;
			I2CPServer * m_I2CPServer;

			std::unique_ptr<boost::asio::deadline_timer> m_CleanupUDPTimer;

		public:

			// for HTTP
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
			const decltype(m_ClientTunnels)& GetClientTunnels () const { return m_ClientTunnels; };
			const decltype(m_ServerTunnels)& GetServerTunnels () const { return m_ServerTunnels; };
			const decltype(m_ClientForwards)& GetClientForwards () const { return m_ClientForwards; }
			const decltype(m_ServerForwards)& GetServerForwards () const { return m_ServerForwards; }
			const i2p::proxy::HTTPProxy * GetHttpProxy () const { return m_HttpProxy; }
			const i2p::proxy::SOCKSProxy * GetSocksProxy () const { return m_SocksProxy; }
	};

	extern ClientContext context;
}
}

#endif
