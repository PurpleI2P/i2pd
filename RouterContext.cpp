#include <fstream>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "RouterContext.h"
#include "util.h"

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
		auto address = const_cast<i2p::data::RouterInfo::Address *>(m_RouterInfo.GetNTCPAddress ());
		if (address)
		{
			address->host = boost::asio::ip::address::from_string (host);
			address->port = port;
		}	

		m_RouterInfo.CreateBuffer ();
	}	

	void RouterContext::UpdateAddress (const char * host)
	{
		for (auto& address : m_RouterInfo.GetAddresses ())
			address.host = boost::asio::ip::address::from_string (host);	
		m_RouterInfo.CreateBuffer ();
	}	
	
	void RouterContext::Sign (uint8_t * buf, int len, uint8_t * signature)
	{
		CryptoPP::DSA::Signer signer (m_SigningPrivateKey);
		signer.SignMessage (m_Rnd, buf, len, signature);
	}

	bool RouterContext::Load ()
	{
		std::string dataDir = i2p::util::filesystem::GetDataDir ().string ();
#ifndef _WIN32
		dataDir.append ("/");
#else
		dataDir.append ("\\");
#endif
		std::string router_keys = dataDir;
		router_keys.append (ROUTER_KEYS);
		std::string router_info = dataDir;
		router_info.append (ROUTER_INFO);

		std::ifstream fk (router_keys.c_str (), std::ifstream::binary | std::ofstream::in);
		if (!fk.is_open ())	return false;
			
		fk.read ((char *)&m_Keys, sizeof (m_Keys));
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));

		m_RouterInfo = i2p::data::RouterInfo (router_info.c_str ()); // TODO
		
		return true;
	}
	
	void RouterContext::Save ()
	{
		std::string dataDir = i2p::util::filesystem::GetDataDir ().string ();
#ifndef _WIN32
		dataDir.append ("/");
#else
		dataDir.append ("\\");
#endif
		std::string router_keys = dataDir;
		router_keys.append (ROUTER_KEYS);
		std::string router_info = dataDir;
		router_info.append (ROUTER_INFO);

		std::ofstream fk (router_keys.c_str (), std::ofstream::binary | std::ofstream::out);
		fk.write ((char *)&m_Keys, sizeof (m_Keys));
				
		std::ofstream fi (router_info.c_str (), std::ofstream::binary | std::ofstream::out);
		fi.write ((char *)m_RouterInfo.GetBuffer (), m_RouterInfo.GetBufferLen ());
	}	
}	
