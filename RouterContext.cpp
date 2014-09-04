#include <fstream>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "RouterContext.h"
#include "Timestamp.h"
#include "util.h"
#include "version.h"

namespace i2p
{
	RouterContext context;

	RouterContext::RouterContext ():
		m_LastUpdateTime (0)
	{
	}

	void RouterContext::Init ()
	{
		if (!Load ())
			CreateNewRouter ();
		UpdateRouterInfo ();
	}

	void RouterContext::CreateNewRouter ()
	{
		m_Keys = i2p::data::CreateRandomKeys ();
		SaveKeys ();
		NewRouterInfo ();
	}

	void RouterContext::NewRouterInfo ()
	{
		i2p::data::RouterInfo routerInfo;
		routerInfo.SetRouterIdentity (GetIdentity ().GetStandardIdentity ());
		int port = i2p::util::config::GetArg("-port", 0);
		if (!port)
			port = m_Rnd.GenerateWord32 (9111, 30777); // I2P network ports range
		routerInfo.AddSSUAddress (i2p::util::config::GetCharArg("-host", "127.0.0.1"), port, routerInfo.GetIdentHash ());
		routerInfo.AddNTCPAddress (i2p::util::config::GetCharArg("-host", "127.0.0.1"), port);
		routerInfo.SetCaps (i2p::data::RouterInfo::eReachable); // LR
		routerInfo.SetProperty ("coreVersion", I2P_VERSION);
		routerInfo.SetProperty ("netId", "2");
		routerInfo.SetProperty ("router.version", I2P_VERSION);
		routerInfo.SetProperty ("stat_uptime", "90m");
		routerInfo.CreateBuffer (m_Keys);
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
	}

	void RouterContext::UpdateRouterInfo ()
	{
		m_RouterInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SaveToFile (i2p::util::filesystem::GetFullPath (ROUTER_INFO));
		m_LastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
	}	
		
	void RouterContext::OverrideNTCPAddress (const char * host, int port)
	{
		m_RouterInfo.CreateBuffer (m_Keys);
		auto address = const_cast<i2p::data::RouterInfo::Address *>(m_RouterInfo.GetNTCPAddress ());
		if (address)
		{
			address->host = boost::asio::ip::address::from_string (host);
			address->port = port;
		}
		UpdateRouterInfo ();
	}

	void RouterContext::UpdateAddress (const char * host)
	{
		bool updated = false;
		auto newAddress = boost::asio::ip::address::from_string (host);
		for (auto& address : m_RouterInfo.GetAddresses ())
		{
			if (address.host != newAddress)
			{	
				address.host = newAddress;
				updated = true;
			}	
		}	
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		if (updated || ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
			UpdateRouterInfo ();
	}

	void RouterContext::AddIntroducer (const i2p::data::RouterInfo& routerInfo, uint32_t tag)
	{
		auto address = routerInfo.GetSSUAddress ();
		if (address)
		{	
			if (m_RouterInfo.AddIntroducer (address, tag))
				UpdateRouterInfo ();
		}	
	}	

	void RouterContext::RemoveIntroducer (uint32_t tag)
	{
		if (m_RouterInfo.RemoveIntroducer (tag))
			UpdateRouterInfo ();
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
		m_RouterInfo.SetProperty ("coreVersion", I2P_VERSION);
		m_RouterInfo.SetProperty ("router.version", I2P_VERSION);
		
		return true;
	}

	void RouterContext::SaveKeys ()
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
}
