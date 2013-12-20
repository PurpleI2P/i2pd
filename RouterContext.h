#ifndef ROUTER_CONTEXT_H__
#define ROUTER_CONTEXT_H__

#include <inttypes.h>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include "RouterInfo.h"

namespace i2p
{
	const char ROUTER_INFO[] = "router.info";
	const char ROUTER_KEYS[] = "router.keys";	
	
	class RouterContext
	{
		public:

			RouterContext ();

			i2p::data::RouterInfo& GetRouterInfo () { return m_RouterInfo; };
			const uint8_t * GetPrivateKey () const { return m_PrivateKey; };
			const uint8_t * GetSigningPrivateKey () const;
			const uint8_t * GetLeaseSetPrivateKey () const { return m_LeaseSetPrivateKey; };
			const uint8_t * GetLeaseSetPublicKey () const { return m_LeaseSetPublicKey; };
			const i2p::data::Identity& GetRouterIdentity () const { return m_RouterInfo.GetRouterIdentity (); };
			CryptoPP::RandomNumberGenerator& GetRandomNumberGenerator () { return m_Rnd; };	
			
			void Sign (uint8_t * buf, int len, uint8_t * signature);

			void OverrideNTCPAddress (const char * host, int port); // temporary
			
		private:

			void CreateNewRouter ();
			bool Load ();
			void Save ();
			
		private:

			i2p::data::RouterInfo m_RouterInfo;
			CryptoPP::DSA::PrivateKey m_SigningPrivateKey;
			uint8_t m_PrivateKey[256], m_SigningPrivateKeyStr[20], 
				m_LeaseSetPublicKey[256], m_LeaseSetPrivateKey[256];
			CryptoPP::AutoSeededRandomPool m_Rnd;
	};

	extern RouterContext context;
}	

#endif
