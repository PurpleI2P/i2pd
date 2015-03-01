#include <fstream>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "RouterContext.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "util.h"
#include "version.h"

namespace i2p
{
	RouterContext context;

	RouterContext::RouterContext ():
		m_LastUpdateTime (0), m_AcceptsTunnels (true), m_IsFloodfill (false), 
		m_StartupTime (0), m_Status (eRouterStatusOK )
	{
	}

	void RouterContext::Init ()
	{
		m_StartupTime = i2p::util::GetSecondsSinceEpoch ();
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
		routerInfo.SetRouterIdentity (GetIdentity ());
		int port = i2p::util::config::GetArg("-port", 0);
		if (!port)
			port = m_Rnd.GenerateWord32 (9111, 30777); // I2P network ports range
		routerInfo.AddSSUAddress (i2p::util::config::GetCharArg("-host", "127.0.0.1"), port, routerInfo.GetIdentHash ());
		routerInfo.AddNTCPAddress (i2p::util::config::GetCharArg("-host", "127.0.0.1"), port);
		routerInfo.SetCaps (i2p::data::RouterInfo::eReachable | 
			i2p::data::RouterInfo::eSSUTesting | i2p::data::RouterInfo::eSSUIntroducer); // LR, BC
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

	void RouterContext::UpdatePort (int port)
	{
		bool updated = false;
		for (auto& address : m_RouterInfo.GetAddresses ())
		{
			if (address.port != port)
			{	
				address.port = port;
				updated = true;
			}	
		}	
		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::UpdateAddress (const boost::asio::ip::address& host)
	{
		bool updated = false;
		for (auto& address : m_RouterInfo.GetAddresses ())
		{
			if (address.host != host && address.IsCompatible (host))
			{	
				address.host = host;
				updated = true;
			}	
		}	
		auto ts = i2p::util::GetSecondsSinceEpoch ();
		if (updated || ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
			UpdateRouterInfo ();
	}

	bool RouterContext::AddIntroducer (const i2p::data::RouterInfo& routerInfo, uint32_t tag)
	{
		bool ret = false;
		auto address = routerInfo.GetSSUAddress ();
		if (address)
		{	
			ret = m_RouterInfo.AddIntroducer (address, tag);
			if (ret)
				UpdateRouterInfo ();
		}	
		return ret;
	}	

	void RouterContext::RemoveIntroducer (const boost::asio::ip::udp::endpoint& e)
	{
		if (m_RouterInfo.RemoveIntroducer (e))
			UpdateRouterInfo ();
	}	
	
	void RouterContext::SetFloodfill (bool floodfill)
	{
		m_IsFloodfill = floodfill;
		if (floodfill)
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () | i2p::data::RouterInfo::eFloodfill);
		else
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () & ~i2p::data::RouterInfo::eFloodfill);
		UpdateRouterInfo ();
	}

	bool RouterContext::IsUnreachable () const
	{
		return m_RouterInfo.GetCaps () & i2p::data::RouterInfo::eUnreachable;
	}	
		
	void RouterContext::SetUnreachable ()
	{
		// set caps
		m_RouterInfo.SetCaps (i2p::data::RouterInfo::eUnreachable | i2p::data::RouterInfo::eSSUTesting); // LU, B
		// remove NTCP address
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (size_t i = 0; i < addresses.size (); i++)
		{
			if (addresses[i].transportStyle == i2p::data::RouterInfo::eTransportNTCP)
			{
				addresses.erase (addresses.begin () + i);
				break;
			}
		}	
		// delete previous introducers
		for (auto& addr : addresses)
			addr.introducers.clear ();
	
		// update
		UpdateRouterInfo ();
	}

	void RouterContext::SetReachable ()
	{
		// update caps
		uint8_t caps = m_RouterInfo.GetCaps ();
		caps &= ~i2p::data::RouterInfo::eUnreachable;
		caps |= i2p::data::RouterInfo::eReachable;
		caps |= i2p::data::RouterInfo::eSSUIntroducer;
		if (m_IsFloodfill)
			caps |= i2p::data::RouterInfo::eFloodfill;
		m_RouterInfo.SetCaps (caps);
		
		// insert NTCP back
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (size_t i = 0; i < addresses.size (); i++)
		{
			if (addresses[i].transportStyle == i2p::data::RouterInfo::eTransportSSU)
			{
				// insert NTCP address with host/port form SSU
				m_RouterInfo.AddNTCPAddress (addresses[i].host.to_string ().c_str (), addresses[i].port);
				break;
			}
		}		
		// delete previous introducers
		for (auto& addr : addresses)
			addr.introducers.clear ();
		
		// update
		UpdateRouterInfo ();
	}	
		
	void RouterContext::SetSupportsV6 (bool supportsV6)
	{
		if (supportsV6)
			m_RouterInfo.EnableV6 ();
		else
			m_RouterInfo.DisableV6 ();
		UpdateRouterInfo ();
	}	

	void RouterContext::UpdateNTCPV6Address (const boost::asio::ip::address& host)
	{
		bool updated = false, found = false;	
		int port = 0;
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto& addr : addresses)
		{
			if (addr.host.is_v6 () && addr.transportStyle == i2p::data::RouterInfo::eTransportNTCP)
			{
				if (addr.host != host)
				{
					addr.host = host;
					updated = true;
				}
				found = true;	
			}	
			else
				port = addr.port;	
		}	
		if (!found)
		{
			// create new address
			m_RouterInfo.AddNTCPAddress (host.to_string ().c_str (), port);
			auto mtu = i2p::util::net::GetMTU (host);
			if (mtu)
			{	
				LogPrint ("Our v6 MTU=", mtu);
				if (mtu > 1472) mtu = 1472; 
			}	
			m_RouterInfo.AddSSUAddress (host.to_string ().c_str (), port, GetIdentHash (), mtu ? mtu : 1472); // TODO
			updated = true;
		}
		if (updated)
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

		if (IsUnreachable ())
			SetReachable (); // we assume reachable until we discover firewall through peer tests
		
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

	void RouterContext::HandleI2NPMessage (const uint8_t * buf, size_t len, std::shared_ptr<i2p::tunnel::InboundTunnel> from)
	{
		i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from));
	}

	uint32_t RouterContext::GetUptime () const
	{
		return i2p::util::GetSecondsSinceEpoch () - m_StartupTime;
	}	
}
