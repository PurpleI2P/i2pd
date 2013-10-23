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
	}	

	const uint8_t * RouterContext::GetSigningPrivateKey () const 
	{ 
		return m_SigningPrivateKeyStr; 
	}	
	
	void RouterContext::CreateNewRouter ()
	{
		i2p::data::RouterIdentity ident;
		
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(m_Rnd, m_PrivateKey, ident.publicKey);
		
		m_SigningPrivateKey.Initialize (m_Rnd, i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag);
		m_SigningPrivateKey.GetPrivateExponent ().Encode (m_SigningPrivateKeyStr, 20);

		CryptoPP::DSA::PublicKey publicKey;
		m_SigningPrivateKey.MakePublicKey (publicKey);
		publicKey.GetPublicElement ().Encode (ident.signingKey, 128);

		memset (ident.certificate, 0, sizeof (ident.certificate));
		
		m_RouterInfo.SetRouterIdentity (ident);

		m_RouterInfo.AddNTCPAddress ("127.0.0.1", 17007); // TODO:
		m_RouterInfo.SetProperty ("caps", "LR");
		m_RouterInfo.SetProperty ("coreVersion", "0.9.7");
		m_RouterInfo.SetProperty ("netId", "2");
		m_RouterInfo.SetProperty ("router.version", "0.9.7");
		m_RouterInfo.SetProperty ("start_uptime", "90m");

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
			
		fk.read ((char *)m_PrivateKey, 256);
		fk.read ((char *)m_SigningPrivateKeyStr, 20);
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_SigningPrivateKeyStr, 20));

		m_RouterInfo = i2p::data::RouterInfo (ROUTER_INFO); // TODO
		
		return true;
	}
	
	void RouterContext::Save ()
	{
		std::ofstream fk (ROUTER_KEYS);
		fk.write ((char *)m_PrivateKey, 256);
		fk.write ((char *)m_SigningPrivateKeyStr, 20);
		fk.write ((char *)m_RouterInfo.GetRouterIdentity ().publicKey, 256);
		fk.write ((char *)m_RouterInfo.GetRouterIdentity ().signingKey, 128);
				
		std::ofstream fi (ROUTER_INFO);
		fi.write ((char *)m_RouterInfo.GetBuffer (), m_RouterInfo.GetBufferLen ());
	}	
}	