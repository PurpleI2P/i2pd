#ifndef CLIENT_CONTEXT_H__
#define CLIENT_CONTEXT_H__

#include <mutex>
#include "Destination.h"
#include "HTTPProxy.h"
#include "SOCKS.h"
#include "I2PTunnel.h"
#include "SAM.h"

namespace i2p
{
namespace client
{
	class ClientContext
	{
		public:

			ClientContext ();
			~ClientContext ();

			void Start ();
			void Stop ();

			i2p::stream::StreamingDestination * GetSharedLocalDestination () const { return m_SharedLocalDestination; };
			i2p::stream::StreamingDestination * CreateNewLocalDestination (bool isPublic = true, i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1); // transient
			i2p::stream::StreamingDestination * CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true);
			void DeleteLocalDestination (i2p::stream::StreamingDestination * destination);
			i2p::stream::StreamingDestination * FindLocalDestination (const i2p::data::IdentHash& destination) const;		
			i2p::stream::StreamingDestination * LoadLocalDestination (const std::string& filename, bool isPublic);

		private:	

			void LoadLocalDestinations ();
			
		private:

			std::mutex m_DestinationsMutex;
			std::map<i2p::data::IdentHash, i2p::stream::StreamingDestination *> m_Destinations;
			i2p::stream::StreamingDestination * m_SharedLocalDestination;	

			i2p::proxy::HTTPProxy * m_HttpProxy;
			i2p::proxy::SOCKSProxy * m_SocksProxy;
			I2PClientTunnel * m_IrcTunnel;
			I2PServerTunnel * m_ServerTunnel;
			SAMBridge * m_SamBridge;

		public:
			// for HTTP
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
	};
	
	extern ClientContext context;	
}		
}	

#endif
