#ifndef CLIENT_CONTEXT_H__
#define CLIENT_CONTEXT_H__

#include <map>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>
#include "Destination.h"
#include "DotNetService.h"
#include "HTTPProxy.h"
#include "SOCKS.h"
#include "DotNetTunnel.h"
#include "SAM.h"
#include "BOB.h"
#include "DNCP.h"
#include "AddressBook.h"

namespace dotnet
{
namespace client
{
	const char DOTNET_TUNNELS_SECTION_TYPE[] = "type";
	const char DOTNET_TUNNELS_SECTION_TYPE_CLIENT[] = "client";
	const char DOTNET_TUNNELS_SECTION_TYPE_SERVER[] = "server";
	const char DOTNET_TUNNELS_SECTION_TYPE_HTTP[] = "http";
	const char DOTNET_TUNNELS_SECTION_TYPE_IRC[] = "irc";
	const char DOTNET_TUNNELS_SECTION_TYPE_UDPCLIENT[] = "udpclient";
	const char DOTNET_TUNNELS_SECTION_TYPE_UDPSERVER[] = "udpserver";
	const char DOTNET_TUNNELS_SECTION_TYPE_SOCKS[] = "socks";
	const char DOTNET_TUNNELS_SECTION_TYPE_WEBSOCKS[] = "websocks";
	const char DOTNET_TUNNELS_SECTION_TYPE_HTTPPROXY[] = "httpproxy";
	const char DOTNET_CLIENT_TUNNEL_PORT[] = "port";
	const char DOTNET_CLIENT_TUNNEL_ADDRESS[] = "address";
	const char DOTNET_CLIENT_TUNNEL_DESTINATION[] = "destination";
	const char DOTNET_CLIENT_TUNNEL_KEYS[] = "keys";
	const char DOTNET_CLIENT_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char DOTNET_CLIENT_TUNNEL_CRYPTO_TYPE[] = "cryptotype";
	const char DOTNET_CLIENT_TUNNEL_DESTINATION_PORT[] = "destinationport";
	const char DOTNET_CLIENT_TUNNEL_MATCH_TUNNELS[] = "matchtunnels";
  const char DOTNET_CLIENT_TUNNEL_CONNECT_TIMEOUT[] = "connecttimeout";
	const char DOTNET_SERVER_TUNNEL_HOST[] = "host";
	const char DOTNET_SERVER_TUNNEL_HOST_OVERRIDE[] = "hostoverride";
	const char DOTNET_SERVER_TUNNEL_PORT[] = "port";
	const char DOTNET_SERVER_TUNNEL_KEYS[] = "keys";
	const char DOTNET_SERVER_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char DOTNET_SERVER_TUNNEL_INPORT[] = "inport";
	const char DOTNET_SERVER_TUNNEL_ACCESS_LIST[] = "accesslist";
	const char DOTNET_SERVER_TUNNEL_GZIP[] = "gzip";
	const char DOTNET_SERVER_TUNNEL_WEBIRC_PASSWORD[] = "webircpassword";
	const char DOTNET_SERVER_TUNNEL_ADDRESS[] = "address";
	const char DOTNET_SERVER_TUNNEL_ENABLE_UNIQUE_LOCAL[] = "enableuniquelocal";


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
				dotnet::data::SigningKeyType sigType = dotnet::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				dotnet::data::CryptoKeyType cryptoType = dotnet::data::CRYPTO_KEY_TYPE_ELGAMAL,
				const std::map<std::string, std::string> * params = nullptr); // used by SAM only
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (const dotnet::data::PrivateKeys& keys, bool isPublic = true,
				const std::map<std::string, std::string> * params = nullptr);
			std::shared_ptr<ClientDestination> CreateNewMatchedTunnelDestination(const dotnet::data::PrivateKeys &keys, const std::string & name, const std::map<std::string, std::string> * params = nullptr);
			void DeleteLocalDestination (std::shared_ptr<ClientDestination> destination);
			std::shared_ptr<ClientDestination> FindLocalDestination (const dotnet::data::IdentHash& destination) const;
			bool LoadPrivateKeys (dotnet::data::PrivateKeys& keys, const std::string& filename,
				dotnet::data::SigningKeyType sigType = dotnet::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				dotnet::data::CryptoKeyType cryptoType = dotnet::data::CRYPTO_KEY_TYPE_ELGAMAL);

			AddressBook& GetAddressBook () { return m_AddressBook; };
			const BOBCommandChannel * GetBOBCommandChannel () const { return m_BOBCommandChannel; };
			const SAMBridge * GetSAMBridge () const { return m_SamBridge; };
			const DNCPServer * GetDNCPServer () const { return m_DNCPServer; };

			std::vector<std::shared_ptr<DatagramSessionInfo> > GetForwardInfosFor(const dotnet::data::IdentHash & destination);

		private:

			void ReadTunnels ();
			void ReadTunnels (const std::string& tunConf, int& numClientTunnels, int& numServerTunnels);
			void ReadHttpProxy ();
			void ReadSocksProxy ();
			template<typename Section, typename Type>
			std::string GetDNCPOption (const Section& section, const std::string& name, const Type& value) const;
			template<typename Section>
			std::string GetDNCPStringOption (const Section& section, const std::string& name, const std::string& value) const; // GetDNCPOption with string default value
			template<typename Section>
			void ReadDNCPOptions (const Section& section, std::map<std::string, std::string>& options) const; // for tunnels
			void ReadDNCPOptionsFromConfig (const std::string& prefix, std::map<std::string, std::string>& options) const; // for HTTP and SOCKS proxy

			void CleanupUDP(const boost::system::error_code & ecode);
			void ScheduleCleanupUDP();

			template<typename Visitor>
			void VisitTunnels (Visitor v); // Visitor: (DotNetService *) -> bool, true means retain

			void CreateNewSharedLocalDestination (); 

		private:

			std::mutex m_DestinationsMutex;
			std::map<dotnet::data::IdentHash, std::shared_ptr<ClientDestination> > m_Destinations;
			std::shared_ptr<ClientDestination>  m_SharedLocalDestination;

			AddressBook m_AddressBook;

			dotnet::proxy::HTTPProxy * m_HttpProxy;
			dotnet::proxy::SOCKSProxy * m_SocksProxy;
			std::map<boost::asio::ip::tcp::endpoint, std::shared_ptr<DotNetService> > m_ClientTunnels; // local endpoint->tunnel
			std::map<std::pair<dotnet::data::IdentHash, int>, std::shared_ptr<DOTNETServerTunnel> > m_ServerTunnels; // <destination,port>->tunnel

			std::mutex m_ForwardsMutex;
			std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<DOTNETUDPClientTunnel> > m_ClientForwards; // local endpoint -> udp tunnel
			std::map<std::pair<dotnet::data::IdentHash, int>, std::shared_ptr<DOTNETUDPServerTunnel> > m_ServerForwards; // <destination,port> -> udp tunnel

			SAMBridge * m_SamBridge;
			BOBCommandChannel * m_BOBCommandChannel;
			DNCPServer * m_DNCPServer;

			std::unique_ptr<boost::asio::deadline_timer> m_CleanupUDPTimer;

		public:
			// for HTTP
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
			const decltype(m_ClientTunnels)& GetClientTunnels () const { return m_ClientTunnels; };
			const decltype(m_ServerTunnels)& GetServerTunnels () const { return m_ServerTunnels; };
			const decltype(m_ClientForwards)& GetClientForwards () const { return m_ClientForwards; }
			const decltype(m_ServerForwards)& GetServerForwards () const { return m_ServerForwards; }
			const dotnet::proxy::HTTPProxy * GetHttpProxy () const { return m_HttpProxy; }
			const dotnet::proxy::SOCKSProxy * GetSocksProxy () const { return m_SocksProxy; }
	};

	extern ClientContext context;
}
}

#endif
