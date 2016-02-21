#include <fstream>
#include <boost/lexical_cast.hpp>
#include "Config.h"
#include "Crypto.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "NetDb.h"
#include "util.h"
#include "version.h"
#include "Log.h"
#include "Family.h"
#include "RouterContext.h"

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
		srand (i2p::util::GetMillisecondsSinceEpoch () % 1000);
		m_StartupTime = i2p::util::GetSecondsSinceEpoch ();
		if (!Load ())
			CreateNewRouter ();
		UpdateRouterInfo ();
	}

	void RouterContext::CreateNewRouter ()
	{
#if defined(__x86_64__) || defined(__i386__) || defined(_MSC_VER)			
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
#else
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_DSA_SHA1);
#endif		
		SaveKeys ();
		NewRouterInfo ();
	}

	void RouterContext::NewRouterInfo ()
	{
		i2p::data::RouterInfo routerInfo;
		routerInfo.SetRouterIdentity (GetIdentity ());
		uint16_t port; i2p::config::GetOption("port", port);
		if (!port)
			port = rand () % (30777 - 9111) + 9111; // I2P network ports range
		std::string host; i2p::config::GetOption("host", host);
		if (i2p::config::IsDefault("host"))
			host = "127.0.0.1"; // replace default address with safe value
		routerInfo.AddSSUAddress  (host.c_str(), port, routerInfo.GetIdentHash ());
		routerInfo.AddNTCPAddress (host.c_str(), port);
		routerInfo.SetCaps (i2p::data::RouterInfo::eReachable | 
			i2p::data::RouterInfo::eSSUTesting | i2p::data::RouterInfo::eSSUIntroducer); // LR, BC
		routerInfo.SetProperty ("netId", std::to_string (I2PD_NET_ID));
		routerInfo.SetProperty ("router.version", I2P_VERSION);
		routerInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
	}

	void RouterContext::UpdateRouterInfo ()
	{
		m_RouterInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SaveToFile (i2p::util::filesystem::GetFullPath (ROUTER_INFO));
		m_LastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
	}	

	void RouterContext::SetStatus (RouterStatus status) 
	{ 
		if (status != m_Status)
		{	
			m_Status = status;
			switch (m_Status)
			{	
				case eRouterStatusOK:
					SetReachable ();
				break;
				case eRouterStatusFirewalled:
					SetUnreachable ();
				break;	
				default:
					;
			}
		}	
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

	bool RouterContext::AddIntroducer (const i2p::data::RouterInfo::Introducer& introducer)
	{
		bool ret = m_RouterInfo.AddIntroducer (introducer);
		if (ret)
			UpdateRouterInfo ();	
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
		{
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () & ~i2p::data::RouterInfo::eFloodfill);
			// we don't publish number of routers and leaseset for non-floodfill
			m_RouterInfo.DeleteProperty (i2p::data::ROUTER_INFO_PROPERTY_LEASESETS);
			m_RouterInfo.DeleteProperty (i2p::data::ROUTER_INFO_PROPERTY_ROUTERS);
		}
		UpdateRouterInfo ();
	}

	void RouterContext::SetFamily (const std::string& family)
	{
		std::string signature;
		if (family.length () > 0)
			signature = i2p::data::CreateFamilySignature (family, GetIdentHash ());
		if (signature.length () > 0)
		{
			m_RouterInfo.SetProperty (i2p::data::ROUTER_INFO_PROPERTY_FAMILY, family);
			m_RouterInfo.SetProperty (i2p::data::ROUTER_INFO_PROPERTY_FAMILY_SIG, signature);
		}	
		else
		{
			m_RouterInfo.DeleteProperty (i2p::data::ROUTER_INFO_PROPERTY_FAMILY);
			m_RouterInfo.DeleteProperty (i2p::data::ROUTER_INFO_PROPERTY_FAMILY_SIG);
		}	
	}	
		
	void RouterContext::SetHighBandwidth ()
	{
		if (!m_RouterInfo.IsHighBandwidth () || m_RouterInfo.IsExtraBandwidth ())
		{
			m_RouterInfo.SetCaps ((m_RouterInfo.GetCaps () | i2p::data::RouterInfo::eHighBandwidth) & ~i2p::data::RouterInfo::eExtraBandwidth);
			UpdateRouterInfo ();
		}
	}

	void RouterContext::SetLowBandwidth ()
	{
		if (m_RouterInfo.IsHighBandwidth () || m_RouterInfo.IsExtraBandwidth ())
		{
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () & ~i2p::data::RouterInfo::eHighBandwidth & ~i2p::data::RouterInfo::eExtraBandwidth);
			UpdateRouterInfo ();
		}
	}

	void RouterContext::SetExtraBandwidth ()
	{	
		if (!m_RouterInfo.IsExtraBandwidth () || !m_RouterInfo.IsHighBandwidth ())
		{
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () | i2p::data::RouterInfo::eExtraBandwidth | i2p::data::RouterInfo::eHighBandwidth);
			UpdateRouterInfo ();
		}
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
				// insert NTCP address with host/port from SSU
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
				LogPrint (eLogDebug, "Router: Our v6 MTU=", mtu);
				if (mtu > 1472) { // TODO: magic constant
					mtu = 1472;
					LogPrint(eLogWarning, "Router: MTU dropped to upper limit of 1472 bytes");
				}
			}	
			m_RouterInfo.AddSSUAddress (host.to_string ().c_str (), port, GetIdentHash (), mtu ? mtu : 1472); // TODO
			updated = true;
		}
		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::UpdateStats ()
	{
		if (m_IsFloodfill)
		{
			// update routers and leasesets
			m_RouterInfo.SetProperty (i2p::data::ROUTER_INFO_PROPERTY_LEASESETS, boost::lexical_cast<std::string>(i2p::data::netdb.GetNumLeaseSets ()));
			m_RouterInfo.SetProperty (i2p::data::ROUTER_INFO_PROPERTY_ROUTERS, boost::lexical_cast<std::string>(i2p::data::netdb.GetNumRouters ()));
			UpdateRouterInfo (); 
		}
	}
		
	bool RouterContext::Load ()
	{
		std::ifstream fk (i2p::util::filesystem::GetFullPath (ROUTER_KEYS).c_str (), std::ifstream::binary | std::ifstream::in);
		if (!fk.is_open ())	return false;
		fk.seekg (0, std::ios::end);
		size_t len = fk.tellg();
		fk.seekg (0, std::ios::beg);		

		if (len == sizeof (i2p::data::Keys)) // old keys file format
		{
			i2p::data::Keys keys;	
			fk.read ((char *)&keys, sizeof (keys));
			m_Keys = keys;
		}
		else // new keys file format
		{
			uint8_t * buf = new uint8_t[len];
			fk.read ((char *)buf, len);
			m_Keys.FromBuffer (buf, len);
			delete[] buf;
		}

		i2p::data::RouterInfo routerInfo(i2p::util::filesystem::GetFullPath (ROUTER_INFO)); // TODO
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
		m_RouterInfo.SetProperty ("coreVersion", I2P_VERSION);
		m_RouterInfo.SetProperty ("router.version", I2P_VERSION);

		// Migration to 0.9.24. TODO: remove later
		m_RouterInfo.DeleteProperty ("coreVersion");
		m_RouterInfo.DeleteProperty ("stat_uptime");
		
		if (IsUnreachable ())
			SetReachable (); // we assume reachable until we discover firewall through peer tests
		
		return true;
	}

	void RouterContext::SaveKeys ()
	{	
		// save in the same format as .dat files
		std::ofstream fk (i2p::util::filesystem::GetFullPath (ROUTER_KEYS).c_str (), std::ofstream::binary | std::ofstream::out);
		size_t len = m_Keys.GetFullLen ();
		uint8_t * buf = new uint8_t[len];
		m_Keys.ToBuffer (buf, len);
		fk.write ((char *)buf, len);
		delete[] buf;
	}

	std::shared_ptr<i2p::tunnel::TunnelPool> RouterContext::GetTunnelPool () const
	{
		return i2p::tunnel::tunnels.GetExploratoryPool (); 
	}	
		
	void RouterContext::HandleI2NPMessage (const uint8_t * buf, size_t len, std::shared_ptr<i2p::tunnel::InboundTunnel> from)
	{
		i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf), from));
	}

	void RouterContext::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		i2p::garlic::GarlicDestination::ProcessGarlicMessage (msg);
	}	
			
	void RouterContext::ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		i2p::garlic::GarlicDestination::ProcessDeliveryStatusMessage (msg);
	}	
		
	uint32_t RouterContext::GetUptime () const
	{
		return i2p::util::GetSecondsSinceEpoch () - m_StartupTime;
	}	
}
