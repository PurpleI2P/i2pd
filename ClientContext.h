#ifndef CLIENT_CONTEXT_H__
#define CLIENT_CONTEXT_H__

#include <map>
#include <tuple>
#include <mutex>
#include <memory>
#include "Destination.h"
#include "HTTPProxy.h"
#include "SOCKS.h"
#include "I2PTunnel.h"
#include "SAM.h"
#include "BOB.h"
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
	const char I2P_CLIENT_TUNNEL_PORT[] = "port";
	const char I2P_CLIENT_TUNNEL_ADDRESS[] = "address";
	const char I2P_CLIENT_TUNNEL_DESTINATION[] = "destination";
	const char I2P_CLIENT_TUNNEL_KEYS[] = "keys";
	const char I2P_CLIENT_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char I2P_CLIENT_TUNNEL_DESTINATION_PORT[] = "destinationport";	
	const char I2P_SERVER_TUNNEL_HOST[] = "host";	
	const char I2P_SERVER_TUNNEL_HOST_OVERRIDE[] = "hostoverride";	
	const char I2P_SERVER_TUNNEL_PORT[] = "port";
	const char I2P_SERVER_TUNNEL_KEYS[] = "keys";
	const char I2P_SERVER_TUNNEL_SIGNATURE_TYPE[] = "signaturetype";
	const char I2P_SERVER_TUNNEL_INPORT[] = "inport";
	const char I2P_SERVER_TUNNEL_ACCESS_LIST[] = "accesslist";		
	const char I2P_SERVER_TUNNEL_GZIP[] = "gzip";	

	class ClientContext
	{
		public:

			ClientContext ();
			~ClientContext ();

			void Start ();
			void Stop ();

			std::shared_ptr<ClientDestination> GetSharedLocalDestination () const { return m_SharedLocalDestination; };
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (bool isPublic = false, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1,
			    const std::map<std::string, std::string> * params = nullptr); // transient
			std::shared_ptr<ClientDestination> CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true, 
				const std::map<std::string, std::string> * params = nullptr);
			void DeleteLocalDestination (std::shared_ptr<ClientDestination> destination);
			std::shared_ptr<ClientDestination> FindLocalDestination (const i2p::data::IdentHash& destination) const;		
			void LoadPrivateKeys (i2p::data::PrivateKeys& keys, const std::string& filename, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);

			AddressBook& GetAddressBook () { return m_AddressBook; };
			const SAMBridge * GetSAMBridge () const { return m_SamBridge; };
		
		private:

			void ReadTunnels ();
			template<typename Section, typename Type>
			std::string GetI2CPOption (const Section& section, const std::string& name, const Type& value) const;
			template<typename Section>
			void ReadI2CPOptions (const Section& section, std::map<std::string, std::string>& options) const;	

		private:

			std::mutex m_DestinationsMutex;
			std::map<i2p::data::IdentHash, std::shared_ptr<ClientDestination> > m_Destinations;
			std::shared_ptr<ClientDestination>  m_SharedLocalDestination;	

			AddressBook m_AddressBook;

			i2p::proxy::HTTPProxy * m_HttpProxy;
			i2p::proxy::SOCKSProxy * m_SocksProxy;
			std::map<int, std::unique_ptr<I2PClientTunnel> > m_ClientTunnels; // port->tunnel
			std::map<std::tuple<i2p::data::IdentHash, int>, std::unique_ptr<I2PServerTunnel> > m_ServerTunnels; // <destination,port>->tunnel
			SAMBridge * m_SamBridge;
			BOBCommandChannel * m_BOBCommandChannel;

		public:
			// for HTTP
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
			const decltype(m_ClientTunnels)& GetClientTunnels () const { return m_ClientTunnels; };
			const decltype(m_ServerTunnels)& GetServerTunnels () const { return m_ServerTunnels; };
	};
	
	extern ClientContext context;	
}		
}	

#endif
