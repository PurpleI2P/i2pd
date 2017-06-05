#include <fstream>
#include "Config.h"
#include "Crypto.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "NetDb.hpp"
#include "FS.h"
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
		m_StartupTime (0), m_ShareRatio (100), m_Status (eRouterStatusOK), 
		m_Error (eRouterErrorNone), m_NetID (I2PD_NET_ID)
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
		bool ipv4; i2p::config::GetOption("ipv4", ipv4);
		bool ipv6; i2p::config::GetOption("ipv6", ipv6);
		bool nat;  i2p::config::GetOption("nat", nat);
		std::string ifname; i2p::config::GetOption("ifname", ifname);
		std::string ifname4; i2p::config::GetOption("ifname4", ifname4);
		std::string ifname6; i2p::config::GetOption("ifname6", ifname6);
		if (ipv4)
		{
			std::string host = "127.0.0.1";
			if (!i2p::config::IsDefault("host"))
				i2p::config::GetOption("host", host);
			else if (!nat && !ifname.empty())
				/* bind to interface, we have no NAT so set external address too */
				host = i2p::util::net::GetInterfaceAddress(ifname, false).to_string(); // v4

			if(ifname4.size())
				host = i2p::util::net::GetInterfaceAddress(ifname4, false).to_string();

			routerInfo.AddSSUAddress (host.c_str(), port, routerInfo.GetIdentHash ());
			routerInfo.AddNTCPAddress (host.c_str(), port);
		}
		if (ipv6)
		{
			std::string host = "::";
			if (!i2p::config::IsDefault("host") && !ipv4) // override if v6 only
				i2p::config::GetOption("host", host);
			else if (!ifname.empty()) 
				host = i2p::util::net::GetInterfaceAddress(ifname, true).to_string(); // v6

			if(ifname6.size())
				host = i2p::util::net::GetInterfaceAddress(ifname6, true).to_string();

			routerInfo.AddSSUAddress (host.c_str(), port, routerInfo.GetIdentHash ());
			routerInfo.AddNTCPAddress (host.c_str(), port);
		}
		
		routerInfo.SetCaps (i2p::data::RouterInfo::eReachable | 
			i2p::data::RouterInfo::eSSUTesting | i2p::data::RouterInfo::eSSUIntroducer); // LR, BC
        routerInfo.SetProperty ("netId", std::to_string (m_NetID));
		routerInfo.SetProperty ("router.version", I2P_VERSION);
		routerInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
	}

	void RouterContext::UpdateRouterInfo ()
	{
		m_RouterInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SaveToFile (i2p::fs::DataDirPath (ROUTER_INFO));
		m_LastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
	}	

	void RouterContext::SetStatus (RouterStatus status) 
	{ 
		if (status != m_Status)
		{	
			m_Status = status;
			m_Error = eRouterErrorNone;
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
			if (address->port != port)
			{	
				address->port = port;
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
			if (address->host != host && address->IsCompatible (host))
			{	
				address->host = host;
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

	std::string RouterContext::GetFamily () const
	{
		return m_RouterInfo.GetProperty (i2p::data::ROUTER_INFO_PROPERTY_FAMILY);
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

	void RouterContext::SetBandwidth (char L) {
		uint16_t limit = 0;
		enum { low, high, extra, unlim } type = high;
		/* detect parameters */
		switch (L) 
		{
			case i2p::data::CAPS_FLAG_LOW_BANDWIDTH1   : limit =   12; type = low;   break;
			case i2p::data::CAPS_FLAG_LOW_BANDWIDTH2   : limit =   48; type = low;   break;
			case i2p::data::CAPS_FLAG_HIGH_BANDWIDTH1  : limit =   64; type = high;  break;
			case i2p::data::CAPS_FLAG_HIGH_BANDWIDTH2  : limit =  128; type = high;  break;
			case i2p::data::CAPS_FLAG_HIGH_BANDWIDTH3  : limit =  256; type = high;  break;
			case i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH1 : limit = 2048; type = extra; break;
			case i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH2 : limit = 9999; type = unlim; break;
			default:
				 limit =  48; type = low;
		}
		/* update caps & flags in RI */
		auto caps = m_RouterInfo.GetCaps ();
		caps &= ~i2p::data::RouterInfo::eHighBandwidth;
		caps &= ~i2p::data::RouterInfo::eExtraBandwidth;
		switch (type) 
		{
			case low   : /* not set */; break;
			case extra : caps |= i2p::data::RouterInfo::eExtraBandwidth; break; // 'P'
			case unlim : caps |= i2p::data::RouterInfo::eExtraBandwidth; //  no break here, extra + high means 'X'
			case high  : caps |= i2p::data::RouterInfo::eHighBandwidth;  break;
		}
		m_RouterInfo.SetCaps (caps);
		UpdateRouterInfo ();
		m_BandwidthLimit = limit;
	}

	void RouterContext::SetBandwidth (int limit) 
	{
		if      (limit > 2000) { SetBandwidth('X'); }
		else if (limit >  256) { SetBandwidth('P'); }
		else if (limit >  128) { SetBandwidth('O'); }
		else if (limit >   64) { SetBandwidth('N'); }
		else if (limit >   48) { SetBandwidth('M'); }
		else if (limit >   12) { SetBandwidth('L'); }
		else                   { SetBandwidth('K'); }
	}

	void RouterContext::SetShareRatio (int percents)
	{
		if (percents < 0) percents = 0;
		if (percents > 100) percents = 100;
		m_ShareRatio = percents;
	}

	bool RouterContext::IsUnreachable () const
	{
		return m_RouterInfo.GetCaps () & i2p::data::RouterInfo::eUnreachable;
	}	
		
	void RouterContext::SetUnreachable ()
	{
		// set caps
		uint8_t caps = m_RouterInfo.GetCaps ();
		caps &= ~i2p::data::RouterInfo::eReachable;
		caps |= i2p::data::RouterInfo::eUnreachable;
		caps &= ~i2p::data::RouterInfo::eFloodfill;	// can't be floodfill
		caps &= ~i2p::data::RouterInfo::eSSUIntroducer; // can't be introducer
		m_RouterInfo.SetCaps (caps); 
		// remove NTCP address
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto it = addresses.begin (); it != addresses.end (); ++it)
		{
			if ((*it)->transportStyle == i2p::data::RouterInfo::eTransportNTCP &&
				(*it)->host.is_v4 ())
			{
				addresses.erase (it);
				break;
			}
		}	
		// delete previous introducers
		for (auto& addr : addresses)	
			if (addr->ssu)
				addr->ssu->introducers.clear ();
	
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
		for (const auto& addr : addresses)
		{
			if (addr->transportStyle == i2p::data::RouterInfo::eTransportSSU &&
				addr->host.is_v4 ())
			{
				// insert NTCP address with host/port from SSU
				m_RouterInfo.AddNTCPAddress (addr->host.to_string ().c_str (), addr->port);
				break;
			}
		}		
		// delete previous introducers
		for (auto& addr : addresses)
			if (addr->ssu)
				addr->ssu->introducers.clear ();
		
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
  	
	void RouterContext::SetSupportsV4 (bool supportsV4)
	{
		if (supportsV4)
			m_RouterInfo.EnableV4 ();
		else
			m_RouterInfo.DisableV4 ();
		UpdateRouterInfo ();
	}
  

	void RouterContext::UpdateNTCPV6Address (const boost::asio::ip::address& host)
	{
		bool updated = false, found = false;	
		int port = 0;
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto& addr: addresses)
		{
			if (addr->host.is_v6 () && addr->transportStyle == i2p::data::RouterInfo::eTransportNTCP)
			{
				if (addr->host != host)
				{
					addr->host = host;
					updated = true;
				}
				found = true;	
			}	
			else
				port = addr->port;	
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
			m_RouterInfo.SetProperty (i2p::data::ROUTER_INFO_PROPERTY_LEASESETS, std::to_string(i2p::data::netdb.GetNumLeaseSets ()));
			m_RouterInfo.SetProperty (i2p::data::ROUTER_INFO_PROPERTY_ROUTERS,   std::to_string(i2p::data::netdb.GetNumRouters ()));
			UpdateRouterInfo (); 
		}
	}
		
	bool RouterContext::Load ()
	{
		std::ifstream fk (i2p::fs::DataDirPath (ROUTER_KEYS), std::ifstream::in | std::ifstream::binary);
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

		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		i2p::data::RouterInfo routerInfo(i2p::fs::DataDirPath (ROUTER_INFO)); 
		if (!routerInfo.IsUnreachable ()) // router.info looks good
		{
			m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
			m_RouterInfo.SetProperty ("coreVersion", I2P_VERSION);
			m_RouterInfo.SetProperty ("router.version", I2P_VERSION);

			// Migration to 0.9.24. TODO: remove later
			m_RouterInfo.DeleteProperty ("coreVersion");
			m_RouterInfo.DeleteProperty ("stat_uptime");
		}
		else
		{
			LogPrint (eLogError, ROUTER_INFO, " is malformed. Creating new");
			NewRouterInfo ();
		}			

		if (IsUnreachable ())
			SetReachable (); // we assume reachable until we discover firewall through peer tests
		
		return true;
	}

	void RouterContext::SaveKeys ()
	{	
		// save in the same format as .dat files
		std::ofstream fk (i2p::fs::DataDirPath (ROUTER_KEYS), std::ofstream::binary | std::ofstream::out);
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

	void RouterContext::CleanupDestination ()
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		i2p::garlic::GarlicDestination::CleanupExpiredTags ();
	}
		
	uint32_t RouterContext::GetUptime () const
	{
		return i2p::util::GetSecondsSinceEpoch () - m_StartupTime;
	}	
}
