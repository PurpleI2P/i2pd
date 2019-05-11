#include <fstream>
#include <openssl/rand.h>
#include "Config.h"
#include "Crypto.h"
#include "Ed25519.h"
#include "Timestamp.h"
#include "DNNPProtocol.h"
#include "NetDb.hpp"
#include "FS.h"
#include "util.h"
#include "version.h"
#include "Log.h"
#include "Family.h"
#include "RouterContext.h"

namespace dotnet
{
	RouterContext context;

	RouterContext::RouterContext ():
		m_LastUpdateTime (0), m_AcceptsTunnels (true), m_IsFloodfill (false),
		m_StartupTime (0), m_ShareRatio (100), m_Status (eRouterStatusOK),
		m_Error (eRouterErrorNone), m_NetID (DOTNET_NET_ID)
	{
	}

	void RouterContext::Init ()
	{
		srand (dotnet::util::GetMillisecondsSinceEpoch () % 1000);
		m_StartupTime = dotnet::util::GetSecondsSinceEpoch ();
		if (!Load ())
			CreateNewRouter ();
		m_Decryptor = m_Keys.CreateDecryptor (nullptr);
		UpdateRouterInfo ();
	}

	void RouterContext::CreateNewRouter ()
	{
		m_Keys = dotnet::data::PrivateKeys::CreateRandomKeys (dotnet::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
		SaveKeys ();
		NewRouterInfo ();
	}

	void RouterContext::NewRouterInfo ()
	{
		dotnet::data::RouterInfo routerInfo;
		routerInfo.SetRouterIdentity (GetIdentity ());
		uint16_t port; dotnet::config::GetOption("port", port);
		if (!port)
		{
			port = rand () % (30777 - 9111) + 9111; // DOTNET network ports range
			if (port == 9150) port = 9151; // Tor browser
		}
		bool ipv4;           dotnet::config::GetOption("ipv4", ipv4);
		bool ipv6;           dotnet::config::GetOption("ipv6", ipv6);
		bool ssu;            dotnet::config::GetOption("ssu", ssu);
		bool ntcp;           dotnet::config::GetOption("ntcp", ntcp);
		bool ntcp2;          dotnet::config::GetOption("ntcp2.enabled", ntcp2);
		bool nat;            dotnet::config::GetOption("nat", nat);
		std::string ifname;  dotnet::config::GetOption("ifname", ifname);
		std::string ifname4; dotnet::config::GetOption("ifname4", ifname4);
		std::string ifname6; dotnet::config::GetOption("ifname6", ifname6);
		if (ipv4)
		{
			std::string host = "127.0.0.1";
			if (!dotnet::config::IsDefault("host"))
				dotnet::config::GetOption("host", host);
			else if (!nat && !ifname.empty())
				/* bind to interface, we have no NAT so set external address too */
				host = dotnet::util::net::GetInterfaceAddress(ifname, false).to_string(); // v4

			if(ifname4.size())
				host = dotnet::util::net::GetInterfaceAddress(ifname4, false).to_string();

			if (ssu)
				routerInfo.AddSSUAddress (host.c_str(), port, routerInfo.GetIdentHash ());
			if (ntcp)
				routerInfo.AddNTCPAddress (host.c_str(), port);
		}
		if (ipv6)
		{
			std::string host = "::1";
			if (!dotnet::config::IsDefault("host") && !ipv4) // override if v6 only
				dotnet::config::GetOption("host", host);
			else if (!ifname.empty())
				host = dotnet::util::net::GetInterfaceAddress(ifname, true).to_string(); // v6

			if(ifname6.size())
				host = dotnet::util::net::GetInterfaceAddress(ifname6, true).to_string();

			if (ssu)
				routerInfo.AddSSUAddress (host.c_str(), port, routerInfo.GetIdentHash ());
			if (ntcp)
				routerInfo.AddNTCPAddress (host.c_str(), port);
		}

		routerInfo.SetCaps (dotnet::data::RouterInfo::eReachable |
			dotnet::data::RouterInfo::eSSUTesting | dotnet::data::RouterInfo::eSSUIntroducer); // LR, BC
		routerInfo.SetProperty ("netId", std::to_string (m_NetID));
		routerInfo.SetProperty ("router.version", DOTNET_VERSION);
		routerInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());

		if (ntcp2) // we don't store iv in the address if non published so we must update it from keys
		{
			if (!m_NTCP2Keys) NewNTCP2Keys ();
			UpdateNTCP2Address (true);
			if (!ntcp) // NTCP2 should replace NTCP
			{
				bool published; dotnet::config::GetOption("ntcp2.published", published);
				if (published)
					PublishNTCP2Address (port, true);
			}
		}
	}

	void RouterContext::UpdateRouterInfo ()
	{
		m_RouterInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SaveToFile (dotnet::fs::DataDirPath (ROUTER_INFO));
		m_LastUpdateTime = dotnet::util::GetSecondsSinceEpoch ();
	}

	void RouterContext::NewNTCP2Keys ()
	{
		m_StaticKeys.reset (new dotnet::crypto::X25519Keys ());
		m_StaticKeys->GenerateKeys ();
		m_NTCP2Keys.reset (new NTCP2PrivateKeys ());
		m_StaticKeys->GetPrivateKey (m_NTCP2Keys->staticPrivateKey);
		memcpy (m_NTCP2Keys->staticPublicKey, m_StaticKeys->GetPublicKey (), 32);
		RAND_bytes (m_NTCP2Keys->iv, 16);
		// save
		std::ofstream fk (dotnet::fs::DataDirPath (NTCP2_KEYS), std::ofstream::binary | std::ofstream::out);
		fk.write ((char *)m_NTCP2Keys.get (), sizeof (NTCP2PrivateKeys));
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
			if (!address->IsNTCP2 () && address->port != port)
			{
				address->port = port;
				updated = true;
			}
		}
		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::PublishNTCP2Address (int port, bool publish)
	{
		if (!m_NTCP2Keys) return;
		if (!port)
		{
			port = rand () % (30777 - 9111) + 9111; // DOTNET network ports range
			if (port == 9150) port = 9151; // Tor browser
		}
		bool updated = false;
		for (auto& address : m_RouterInfo.GetAddresses ())
		{
			if (address->IsNTCP2 () && (address->port != port || address->ntcp2->isPublished != publish))
			{
				address->port = port;
				address->cost = publish ? 3 : 14;
				address->ntcp2->isPublished = publish;
				address->ntcp2->iv = m_NTCP2Keys->iv;
				updated = true;
			}
		}
		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::UpdateNTCP2Address (bool enable)
	{
		auto& addresses = m_RouterInfo.GetAddresses ();
		bool found = false, updated = false;
		for (auto it = addresses.begin (); it != addresses.end (); ++it)
		{
			if ((*it)->IsNTCP2 ())
			{
				found = true;
				if (!enable)
				{
					addresses.erase (it);
					updated= true;
				}
				break;
			}
		}
		if (enable && !found)
		{
			m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv);
			updated = true;
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
		auto ts = dotnet::util::GetSecondsSinceEpoch ();
		if (updated || ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
			UpdateRouterInfo ();
	}

	bool RouterContext::AddIntroducer (const dotnet::data::RouterInfo::Introducer& introducer)
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
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () | dotnet::data::RouterInfo::eFloodfill);
		else
		{
			m_RouterInfo.SetCaps (m_RouterInfo.GetCaps () & ~dotnet::data::RouterInfo::eFloodfill);
			// we don't publish number of routers and leaseset for non-floodfill
			m_RouterInfo.DeleteProperty (dotnet::data::ROUTER_INFO_PROPERTY_LEASESETS);
			m_RouterInfo.DeleteProperty (dotnet::data::ROUTER_INFO_PROPERTY_ROUTERS);
		}
		UpdateRouterInfo ();
	}

	std::string RouterContext::GetFamily () const
	{
		return m_RouterInfo.GetProperty (dotnet::data::ROUTER_INFO_PROPERTY_FAMILY);
	}

	void RouterContext::SetFamily (const std::string& family)
	{
		std::string signature;
		if (family.length () > 0)
			signature = dotnet::data::CreateFamilySignature (family, GetIdentHash ());
		if (signature.length () > 0)
		{
			m_RouterInfo.SetProperty (dotnet::data::ROUTER_INFO_PROPERTY_FAMILY, family);
			m_RouterInfo.SetProperty (dotnet::data::ROUTER_INFO_PROPERTY_FAMILY_SIG, signature);
		}
		else
		{
			m_RouterInfo.DeleteProperty (dotnet::data::ROUTER_INFO_PROPERTY_FAMILY);
			m_RouterInfo.DeleteProperty (dotnet::data::ROUTER_INFO_PROPERTY_FAMILY_SIG);
		}
	}

	void RouterContext::SetBandwidth (char L)
	{
		uint32_t limit = 0;
		enum { low, high, extra, unlim } type = high;
		/* detect parameters */
		switch (L)
		{
			case dotnet::data::CAPS_FLAG_LOW_BANDWIDTH1   : limit =   12; type = low;   break;
			case dotnet::data::CAPS_FLAG_LOW_BANDWIDTH2   : limit =   48; type = low;   break;
			case dotnet::data::CAPS_FLAG_HIGH_BANDWIDTH1  : limit =   64; type = high;  break;
			case dotnet::data::CAPS_FLAG_HIGH_BANDWIDTH2  : limit =  128; type = high;  break;
			case dotnet::data::CAPS_FLAG_HIGH_BANDWIDTH3  : limit =  256; type = high;  break;
			case dotnet::data::CAPS_FLAG_EXTRA_BANDWIDTH1 : limit = 2048; type = extra; break;
			case dotnet::data::CAPS_FLAG_EXTRA_BANDWIDTH2 : limit = 1000000; type = unlim; break; // 1Gbyte/s
			default:
				 limit =  48; type = low;
		}
		/* update caps & flags in RI */
		auto caps = m_RouterInfo.GetCaps ();
		caps &= ~dotnet::data::RouterInfo::eHighBandwidth;
		caps &= ~dotnet::data::RouterInfo::eExtraBandwidth;
		switch (type)
		{
			case low   : /* not set */; break;
			case extra : caps |= dotnet::data::RouterInfo::eExtraBandwidth; break; // 'P'
			case unlim : caps |= dotnet::data::RouterInfo::eExtraBandwidth; //  no break here, extra + high means 'X'
			case high  : caps |= dotnet::data::RouterInfo::eHighBandwidth;  break;
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
		return m_RouterInfo.GetCaps () & dotnet::data::RouterInfo::eUnreachable;
	}

	void RouterContext::PublishNTCPAddress (bool publish, bool v4only)
	{
		auto& addresses = m_RouterInfo.GetAddresses ();
		if (publish)
		{
			for (const auto& addr : addresses) // v4
			{
				if (addr->transportStyle == dotnet::data::RouterInfo::eTransportSSU &&
					addr->host.is_v4 ())
				{
					// insert NTCP address with host/port from SSU
					m_RouterInfo.AddNTCPAddress (addr->host.to_string ().c_str (), addr->port);
					break;
				}
			}
			if (!v4only)
			{
				for (const auto& addr : addresses) // v6
				{
					if (addr->transportStyle == dotnet::data::RouterInfo::eTransportSSU &&
						addr->host.is_v6 ())
					{
						// insert NTCP address with host/port from SSU
						m_RouterInfo.AddNTCPAddress (addr->host.to_string ().c_str (), addr->port);
						break;
					}
				}
			}
		}
		else
		{
			for (auto it = addresses.begin (); it != addresses.end ();)
			{
				if ((*it)->transportStyle == dotnet::data::RouterInfo::eTransportNTCP && !(*it)->IsNTCP2 () &&
					(!v4only || (*it)->host.is_v4 ()))
				{
					it = addresses.erase (it);
					if (v4only) break; // otherwise might be more than one address
				}
				else
					++it;
			}
		}
	}

	void RouterContext::SetUnreachable ()
	{
		// set caps
		uint8_t caps = m_RouterInfo.GetCaps ();
		caps &= ~dotnet::data::RouterInfo::eReachable;
		caps |= dotnet::data::RouterInfo::eUnreachable;
		caps &= ~dotnet::data::RouterInfo::eFloodfill;	// can't be floodfill
		caps &= ~dotnet::data::RouterInfo::eSSUIntroducer; // can't be introducer
		m_RouterInfo.SetCaps (caps);
		// remove NTCP v4 address
		PublishNTCPAddress (false);
		// delete previous introducers
		auto& addresses = m_RouterInfo.GetAddresses ();
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
		caps &= ~dotnet::data::RouterInfo::eUnreachable;
		caps |= dotnet::data::RouterInfo::eReachable;
		caps |= dotnet::data::RouterInfo::eSSUIntroducer;
		if (m_IsFloodfill)
			caps |= dotnet::data::RouterInfo::eFloodfill;
		m_RouterInfo.SetCaps (caps);
		// insert NTCP back
		bool ntcp;   dotnet::config::GetOption("ntcp", ntcp);
		if (ntcp)
			PublishNTCPAddress (true);
		// delete previous introducers
		auto& addresses = m_RouterInfo.GetAddresses ();
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
			if (addr->host.is_v6 () && addr->transportStyle == dotnet::data::RouterInfo::eTransportNTCP)
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
			auto mtu = dotnet::util::net::GetMTU (host);
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

	void RouterContext::UpdateNTCP2V6Address (const boost::asio::ip::address& host)
	{
		bool updated = false, found = false;
		int port = 0;
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto& addr: addresses)
		{
			if (addr->IsPublishedNTCP2 ())
			{
				if (addr->host.is_v6 ())
				{
					if (addr->host != host)
					{
						addr->host = host;
						updated = true;
					}
					found = true;
					break;
				}
				else
					port = addr->port; // NTCP2 v4
			}
		}

		if (!found && port) // we have found NTCP2 v4 but not v6
		{
			m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, host, port);
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
			m_RouterInfo.SetProperty (dotnet::data::ROUTER_INFO_PROPERTY_LEASESETS, std::to_string(dotnet::data::netdb.GetNumLeaseSets ()));
			m_RouterInfo.SetProperty (dotnet::data::ROUTER_INFO_PROPERTY_ROUTERS,   std::to_string(dotnet::data::netdb.GetNumRouters ()));
			UpdateRouterInfo ();
		}
	}

	void RouterContext::UpdateTimestamp (uint64_t ts)
	{
		if (ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
			UpdateRouterInfo ();
	}

	bool RouterContext::Load ()
	{
		std::ifstream fk (dotnet::fs::DataDirPath (ROUTER_KEYS), std::ifstream::in | std::ifstream::binary);
		if (!fk.is_open ())	return false;
		fk.seekg (0, std::ios::end);
		size_t len = fk.tellg();
		fk.seekg (0, std::ios::beg);

		if (len == sizeof (dotnet::data::Keys)) // old keys file format
		{
			dotnet::data::Keys keys;
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
		// read NTCP2 keys if available
		std::ifstream n2k (dotnet::fs::DataDirPath (NTCP2_KEYS), std::ifstream::in | std::ifstream::binary);
		if (n2k)
		{
			n2k.seekg (0, std::ios::end);
			len = n2k.tellg();
			n2k.seekg (0, std::ios::beg);
			if (len == sizeof (NTCP2PrivateKeys))
			{
				m_NTCP2Keys.reset (new NTCP2PrivateKeys ());
				n2k.read ((char *)m_NTCP2Keys.get (), sizeof (NTCP2PrivateKeys));
			}
			n2k.close ();
		}
		// read RouterInfo
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		dotnet::data::RouterInfo routerInfo(dotnet::fs::DataDirPath (ROUTER_INFO));
		if (!routerInfo.IsUnreachable ()) // router.info looks good
		{
			m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
			m_RouterInfo.SetProperty ("coreVersion", DOTNET_VERSION);
			m_RouterInfo.SetProperty ("router.version", DOTNET_VERSION);

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

		// read NTCP2
		bool ntcp2;  dotnet::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
		{
			if (!m_NTCP2Keys) NewNTCP2Keys ();
			UpdateNTCP2Address (true); // enable NTCP2
		}
		else
			UpdateNTCP2Address (false);	 // disable NTCP2

		return true;
	}

	void RouterContext::SaveKeys ()
	{
		// save in the same format as .dat files
		std::ofstream fk (dotnet::fs::DataDirPath (ROUTER_KEYS), std::ofstream::binary | std::ofstream::out);
		size_t len = m_Keys.GetFullLen ();
		uint8_t * buf = new uint8_t[len];
		m_Keys.ToBuffer (buf, len);
		fk.write ((char *)buf, len);
		delete[] buf;
	}

	std::shared_ptr<dotnet::tunnel::TunnelPool> RouterContext::GetTunnelPool () const
	{
		return dotnet::tunnel::tunnels.GetExploratoryPool ();
	}

	void RouterContext::HandleDNNPMessage (const uint8_t * buf, size_t len, std::shared_ptr<dotnet::tunnel::InboundTunnel> from)
	{
		dotnet::HandleDNNPMessage (CreateDNNPMessage (buf, GetDNNPMessageLength (buf, len), from));
	}

	void RouterContext::ProcessGarlicMessage (std::shared_ptr<DNNPMessage> msg)
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		dotnet::garlic::GarlicDestination::ProcessGarlicMessage (msg);
	}

	void RouterContext::ProcessDeliveryStatusMessage (std::shared_ptr<DNNPMessage> msg)
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		dotnet::garlic::GarlicDestination::ProcessDeliveryStatusMessage (msg);
	}

	void RouterContext::CleanupDestination ()
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		dotnet::garlic::GarlicDestination::CleanupExpiredTags ();
	}

	uint32_t RouterContext::GetUptime () const
	{
		return dotnet::util::GetSecondsSinceEpoch () - m_StartupTime;
	}

	bool RouterContext::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx) const
	{
		return m_Decryptor ? m_Decryptor->Decrypt (encrypted, data, ctx, true) : false;
	}

	bool RouterContext::DecryptTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx) const
	{
		return m_Decryptor ? m_Decryptor->Decrypt (encrypted, data, ctx, false) : false;
	}

	dotnet::crypto::X25519Keys& RouterContext::GetStaticKeys ()
	{
		if (!m_StaticKeys)
		{
			if (!m_NTCP2Keys) NewNTCP2Keys ();
			auto x = new dotnet::crypto::X25519Keys (m_NTCP2Keys->staticPrivateKey, m_NTCP2Keys->staticPublicKey);
			if (!m_StaticKeys)
				m_StaticKeys.reset (x);
			else
				delete x;
		}
		return *m_StaticKeys;
	}
}
