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
	}	
	
	void RouterContext::CreateNewRouter ()
	{
		m_Keys = i2p::data::CreateRandomKeys ();
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap(), i2p::crypto::dsaq(), i2p::crypto::dsag(), 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));
		UpdateRouterInfo ();
	}

	void RouterContext::UpdateRouterInfo ()
	{
		i2p::data::Identity ident;
		ident = m_Keys;

		i2p::data::RouterInfo routerInfo;
		routerInfo.SetRouterIdentity (ident);
		routerInfo.AddSSUAddress ("127.0.0.1", 17007, routerInfo.GetIdentHash ());
		routerInfo.AddNTCPAddress ("127.0.0.1", 17007); // TODO:
		routerInfo.SetProperty ("caps", "LR");
		routerInfo.SetProperty ("coreVersion", "0.9.8.1");
		routerInfo.SetProperty ("netId", "2");
		routerInfo.SetProperty ("router.version", "0.9.8.1");
		routerInfo.SetProperty ("start_uptime", "90m");
		routerInfo.CreateBuffer ();

		m_RouterInfo = routerInfo;
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
		Save (true);
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
		std::ifstream fk (i2p::util::filesystem::GetFullPath (ROUTER_KEYS).c_str (), std::ifstream::binary | std::ofstream::in);
		if (!fk.is_open ())	return false;
			
		fk.read ((char *)&m_Keys, sizeof (m_Keys));
		m_SigningPrivateKey.Initialize (i2p::crypto::dsap(), i2p::crypto::dsaq(), i2p::crypto::dsag(), 
			CryptoPP::Integer (m_Keys.signingPrivateKey, 20));

		m_RouterInfo = i2p::data::RouterInfo (i2p::util::filesystem::GetFullPath (ROUTER_INFO).c_str ()); // TODO
		
		return true;
	}
	
	void RouterContext::Save (bool infoOnly)
	{
		if (!infoOnly)
		{	
			std::ofstream fk (i2p::util::filesystem::GetFullPath (ROUTER_KEYS).c_str (), std::ofstream::binary | std::ofstream::out);
			fk.write ((char *)&m_Keys, sizeof (m_Keys));
		}
		
		std::ofstream fi (i2p::util::filesystem::GetFullPath (ROUTER_INFO).c_str (), std::ofstream::binary | std::ofstream::out);
		fi.write ((char *)m_RouterInfo.GetBuffer (), m_RouterInfo.GetBufferLen ());
	}	
}	
