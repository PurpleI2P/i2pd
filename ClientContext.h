#ifndef CLIENT_CONTEXT_H__
#define CLIENT_CONTEXT_H__

#include <map>
#include <mutex>
#include <memory>
#include "Destination.h"
#include "HTTPProxy.h"
#include "SOCKS.h"
#include "I2PTunnel.h"
#include "SAM.h"
#include "BOB.h"
#include "AddressBook.h"
#include "I2PControl.h"

namespace i2p
{
namespace client
{
	const char I2P_TUNNELS_SECTION_TYPE[] = "type";
	const char I2P_TUNNELS_SECTION_TYPE_CLIENT[] = "client";
	const char I2P_TUNNELS_SECTION_TYPE_SERVER[] = "server";
	const char I2P_CLIENT_TUNNEL_PORT[] = "port";
	const char I2P_CLIENT_TUNNEL_DESTINATION[] = "destination";
	const char I2P_CLIENT_TUNNEL_KEYS[] = "keys";
	const char I2P_CLIENT_TUNNEL_DESTINATION_PORT[] = "destinationport";	
	const char I2P_SERVER_TUNNEL_HOST[] = "host";	
	const char I2P_SERVER_TUNNEL_PORT[] = "port";
	const char I2P_SERVER_TUNNEL_KEYS[] = "keys";
	const char I2P_SERVER_TUNNEL_INPORT[] = "inport";
	const char I2P_SERVER_TUNNEL_ACCESS_LIST[] = "accesslist";		
	const char TUNNELS_CONFIG_FILENAME[] = "tunnels.cfg";

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
			std::shared_ptr<ClientDestination> LoadLocalDestination (const std::string& filename, bool isPublic);

			AddressBook& GetAddressBook () { return m_AddressBook; };
			const SAMBridge * GetSAMBridge () const { return m_SamBridge; };
		
		private:

			void ReadTunnels ();
	
		private:

			std::mutex m_DestinationsMutex;
			std::map<i2p::data::IdentHash, std::shared_ptr<ClientDestination> > m_Destinations;
			std::shared_ptr<ClientDestination>  m_SharedLocalDestination;	

			AddressBook m_AddressBook;

			i2p::proxy::HTTPProxy * m_HttpProxy;
			i2p::proxy::SOCKSProxy * m_SocksProxy;
			std::map<int, std::unique_ptr<I2PClientTunnel> > m_ClientTunnels; // port->tunnel
			std::map<i2p::data::IdentHash, std::unique_ptr<I2PServerTunnel> > m_ServerTunnels; // destination->tunnel
			SAMBridge * m_SamBridge;
			BOBCommandChannel * m_BOBCommandChannel;
			I2PControlService * m_I2PControlService;

		public:
			// for HTTP
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
	};
	
	extern ClientContext context;	
}		
}	

#endif
