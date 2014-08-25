#include <fstream>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "RouterContext.h"
#include "util.h"
#include "version.h"

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
		UpdateRouterInfo ();
	}

	void RouterContext::UpdateRouterInfo ()
	{
		i2p::data::RouterInfo routerInfo;
		routerInfo.SetRouterIdentity (GetIdentity ().GetStandardIdentity ());
		routerInfo.AddSSUAddress (i2p::util::config::GetCharArg("-host", "127.0.0.1"),
			i2p::util::config::GetArg("-port", 17007), routerInfo.GetIdentHash ());
		routerInfo.AddNTCPAddress (i2p::util::config::GetCharArg("-host", "127.0.0.1"),
			i2p::util::config::GetArg("-port", 17007));
		routerInfo.SetProperty ("caps", "LR");
		routerInfo.SetProperty ("coreVersion", I2P_VERSION);
		routerInfo.SetProperty ("netId", "2");
		routerInfo.SetProperty ("router.version", I2P_VERSION);
		routerInfo.SetProperty ("start_uptime", "90m");
		routerInfo.CreateBuffer ();
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
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

	void RouterContext::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		m_Keys.Sign(buf, len, signature);
	}

	bool RouterContext::Load ()
	{
		std::ifstream fk (i2p::util::filesystem::GetFullPath (ROUTER_KEYS).c_str (), std::ifstream::binary | std::ofstream::in);
		if (!fk.is_open ())	return false;
		
		i2p::data::Keys keys;	
		fk.read ((char *)&keys, sizeof (keys));
		m_Keys = keys;

		i2p::data::RouterInfo routerInfo(i2p::util::filesystem::GetFullPath (ROUTER_INFO)); // TODO
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
		
		return true;
	}

	void RouterContext::Save (bool infoOnly)
	{
		if (!infoOnly)
		{
			std::ofstream fk (i2p::util::filesystem::GetFullPath (ROUTER_KEYS).c_str (), std::ofstream::binary | std::ofstream::out);
			i2p::data::Keys keys;
			memcpy (keys.privateKey, m_Keys.GetPrivateKey (), sizeof (keys.privateKey));
			memcpy (keys.signingPrivateKey, m_Keys.GetSigningPrivateKey (), sizeof (keys.signingPrivateKey));
			auto& ident = GetIdentity ().GetStandardIdentity ();	
			memcpy (keys.publicKey, ident.publicKey, sizeof (keys.publicKey));
			memcpy (keys.signingKey, ident.signingKey, sizeof (keys.signingKey));

			fk.write ((char *)&keys, sizeof (keys));
		}

		m_RouterInfo.SaveToFile (i2p::util::filesystem::GetFullPath (ROUTER_INFO));
	}
}
