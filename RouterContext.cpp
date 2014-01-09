#include <fstream>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "RouterContext.h"

namespace i2p
{
	RouterContext context;

	RouterContext::RouterContext ()
	{
		if (!Load ())
			CreateNewRouter ();
		Save ();

		// we generate LeaseSet at every start-up
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(m_Rnd, m_LeaseSetPrivateKey, m_LeaseSetPublicKey);
	}	
	
	void RouterContext::CreateNewRouter ()
	{
		m_Keys = i2p::data::CreateRandomKeys ();
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));
		
		i2p::data::Identity ident;
		ident = m_Keys;
		m_RouterInfo.SetRouterIdentity (ident);

		m_RouterInfo.AddNTCPAddress ("127.0.0.1", 17007); // TODO:
		m_RouterInfo.SetProperty ("caps", "LR");
		m_RouterInfo.SetProperty ("coreVersion", "0.9.8.1");
		m_RouterInfo.SetProperty ("netId", "2");
		m_RouterInfo.SetProperty ("router.version", "0.9.8.1");
		m_RouterInfo.SetProperty ("start_uptime", "90m");

		m_RouterInfo.CreateBuffer ();
	}

	void RouterContext::OverrideNTCPAddress (const char * host, int port)
	{
		m_RouterInfo.CreateBuffer ();
		auto address = m_RouterInfo.GetNTCPAddress ();
		if (address)
		{
			address->host = host;
			address->port = port;
		}	

		m_RouterInfo.CreateBuffer ();
	}	
	
	void RouterContext::Sign (uint8_t * buf, int len, uint8_t * signature)
	{
		CryptoPP::DSA::Signer signer (m_SigningPrivateKey);
		signer.SignMessage (m_Rnd, buf, len, signature);
	}

	bool RouterContext::Load ()
	{
		std::ifstream fk (ROUTER_KEYS);
		if (!fk.is_open ())	return false;
			
		fk.read ((char *)&m_Keys, sizeof (m_Keys));
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));

		m_RouterInfo = i2p::data::RouterInfo (ROUTER_INFO); // TODO
		
		return true;
	}
	
	void RouterContext::Save ()
	{
		std::ofstream fk (ROUTER_KEYS);
		fk.write ((char *)&m_Keys, sizeof (m_Keys));
				
		std::ofstream fi (ROUTER_INFO);
		fi.write ((char *)m_RouterInfo.GetBuffer (), m_RouterInfo.GetBufferLen ());
	}	
}	