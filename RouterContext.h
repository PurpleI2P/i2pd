#ifndef ROUTER_CONTEXT_H__
#define ROUTER_CONTEXT_H__

#include <inttypes.h>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include "Identity.h"
#include "RouterInfo.h"

namespace i2p
{
	const char ROUTER_INFO[] = "router.info";
	const char ROUTER_KEYS[] = "router.keys";	
	
	class RouterContext: public i2p::data::LocalDestination 
	{
		public:

			RouterContext ();

			i2p::data::RouterInfo& GetRouterInfo () { return m_RouterInfo; };
			const uint8_t * GetPrivateKey () const { return m_Keys.GetPrivateKey (); };
			const uint8_t * GetSigningPrivateKey () const { return m_Keys.GetSigningPrivateKey (); };
			const i2p::data::Identity& GetRouterIdentity () const { return m_RouterInfo.GetRouterIdentity (); };
			const i2p::data::IdentHash& GetRouterIdentHash () const { return m_RouterInfo.GetIdentHash (); };
			CryptoPP::RandomNumberGenerator& GetRandomNumberGenerator () { return m_Rnd; };	

			void OverrideNTCPAddress (const char * host, int port); // temporary
			void UpdateAddress (const char * host);	// called from SSU
			
			// implements LocalDestination
			const i2p::data::IdentityEx& GetIdentity () const { return m_Keys.GetPublic (); };
			const uint8_t * GetEncryptionPrivateKey () const { return GetPrivateKey (); };
			const uint8_t * GetEncryptionPublicKey () const { return GetIdentity ().GetStandardIdentity ().publicKey; };
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;
			void SetLeaseSetUpdated () {};
			
		private:

			void CreateNewRouter ();
			void UpdateRouterInfo ();
			bool Load ();
			void Save (bool infoOnly = false);
			
		private:

			i2p::data::RouterInfo m_RouterInfo;
			i2p::data::PrivateKeys m_Keys; 
			CryptoPP::AutoSeededRandomPool m_Rnd;
	};

	extern RouterContext context;
}	

#endif
