/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <fstream>
#include <openssl/rand.h>
#include "Config.h"
#include "Crypto.h"
#include "Ed25519.h"
#include "Timestamp.h"
#include "I2NPProtocol.h"
#include "NetDb.hpp"
#include "FS.h"
#include "util.h"
#include "version.h"
#include "Log.h"
#include "Family.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "RouterContext.h"

namespace i2p
{
	RouterContext context;

	RouterContext::RouterContext ():
		m_LastUpdateTime (0), m_AcceptsTunnels (true), m_IsFloodfill (false),
		m_ShareRatio (100), m_Status (eRouterStatusOK),
		m_Error (eRouterErrorNone), m_NetID (I2PD_NET_ID)
	{
	}

	void RouterContext::Init ()
	{
		srand (i2p::util::GetMillisecondsSinceEpoch () % 1000);
		m_StartupTime = std::chrono::steady_clock::now();

		if (!Load ())
			CreateNewRouter ();
		m_Decryptor = m_Keys.CreateDecryptor (nullptr);
		UpdateRouterInfo ();
		if (IsECIES ())
		{	
			auto initState = new i2p::crypto::NoiseSymmetricState ();
			i2p::crypto::InitNoiseNState (*initState, GetIdentity ()->GetEncryptionPublicKey ());
			m_InitialNoiseState.reset (initState);	
		}	
	}

	void RouterContext::CreateNewRouter ()
	{
		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
			i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD);
		SaveKeys ();
		NewRouterInfo ();
	}

	void RouterContext::NewRouterInfo ()
	{
		i2p::data::RouterInfo routerInfo;
		routerInfo.SetRouterIdentity (GetIdentity ());
		uint16_t port; i2p::config::GetOption("port", port);
		if (!port)
		{
			port = rand () % (30777 - 9111) + 9111; // I2P network ports range
			if (port == 9150) port = 9151; // Tor browser
		}
		bool ipv4;           i2p::config::GetOption("ipv4", ipv4);
		bool ipv6;           i2p::config::GetOption("ipv6", ipv6);
		bool ssu;            i2p::config::GetOption("ssu", ssu);
		bool ntcp2;          i2p::config::GetOption("ntcp2.enabled", ntcp2);
		bool nat;            i2p::config::GetOption("nat", nat);
		std::string ifname;  i2p::config::GetOption("ifname", ifname);
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

			if (ssu)
				routerInfo.AddSSUAddress (host.c_str(), port, nullptr);
		}
		if (ipv6)
		{
			std::string host = "::1";
			if (!i2p::config::IsDefault("host") && !ipv4) // override if v6 only
				i2p::config::GetOption("host", host);
			else if (!ifname.empty())
				host = i2p::util::net::GetInterfaceAddress(ifname, true).to_string(); // v6

			if(ifname6.size())
				host = i2p::util::net::GetInterfaceAddress(ifname6, true).to_string();

			if (ssu)
				routerInfo.AddSSUAddress (host.c_str(), port, nullptr);
		}

		routerInfo.SetCaps (i2p::data::RouterInfo::eReachable |
			i2p::data::RouterInfo::eSSUTesting | i2p::data::RouterInfo::eSSUIntroducer); // LR, BC
		routerInfo.SetProperty ("netId", std::to_string (m_NetID));
		routerInfo.SetProperty ("router.version", I2P_VERSION);
		routerInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());

		if (ntcp2) // we don't store iv in the address if non published so we must update it from keys
		{
			if (!m_NTCP2Keys) NewNTCP2Keys ();
			UpdateNTCP2Address (true);
			bool published; i2p::config::GetOption("ntcp2.published", published);
			if (published)
			{
				PublishNTCP2Address (port, true);
				if (ipv6)
				{
					// add NTCP2 ipv6 address
					std::string host = "::1";
					if (!i2p::config::IsDefault ("ntcp2.addressv6"))
						i2p::config::GetOption ("ntcp2.addressv6", host);
					m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, boost::asio::ip::address_v6::from_string (host), port);
				}
			}
		}
	}

	void RouterContext::UpdateRouterInfo ()
	{
		m_RouterInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SaveToFile (i2p::fs::DataDirPath (ROUTER_INFO));
		m_LastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
	}

	void RouterContext::NewNTCP2Keys ()
	{
		m_StaticKeys.reset (new i2p::crypto::X25519Keys ());
		m_StaticKeys->GenerateKeys ();
		m_NTCP2Keys.reset (new NTCP2PrivateKeys ());
		m_StaticKeys->GetPrivateKey (m_NTCP2Keys->staticPrivateKey);
		memcpy (m_NTCP2Keys->staticPublicKey, m_StaticKeys->GetPublicKey (), 32);
		RAND_bytes (m_NTCP2Keys->iv, 16);
		// save
		std::ofstream fk (i2p::fs::DataDirPath (NTCP2_KEYS), std::ofstream::binary | std::ofstream::out);
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

	void RouterContext::PublishNTCP2Address (int port, bool publish, bool v4only)
	{
		if (!m_NTCP2Keys) return;
		bool updated = false;
		for (auto& address : m_RouterInfo.GetAddresses ())
		{
			if (address->IsNTCP2 () && (address->port != port || address->ntcp2->isPublished != publish) && (!v4only || address->host.is_v4 ()))
			{
				if (!port && !address->port)
				{
					// select random port only if address's port is not set
					port = rand () % (30777 - 9111) + 9111; // I2P network ports range
					if (port == 9150) port = 9151; // Tor browser
				}
				if (port) address->port = port;
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
				if (host.is_v6 () && address->transportStyle == i2p::data::RouterInfo::eTransportSSU)
				{
					// update MTU
					auto mtu = i2p::util::net::GetMTU (host);
					if (mtu)
					{
						LogPrint (eLogDebug, "Router: Our v6 MTU=", mtu);
						if (mtu > 1472) { // TODO: magic constant
							mtu = 1472;
							LogPrint(eLogWarning, "Router: MTU dropped to upper limit of 1472 bytes");
						}
						if (address->ssu) address->ssu->mtu = mtu;
					}
				}
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

	void RouterContext::SetBandwidth (char L)
	{
		uint32_t limit = 0;
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
			case i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH2 : limit = 1000000; type = unlim; break; // 1Gbyte/s
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
			case unlim : caps |= i2p::data::RouterInfo::eExtraBandwidth;
#if (__cplusplus >= 201703L) // C++ 17 or higher
			[[fallthrough]];
#endif
			//  no break here, extra + high means 'X'
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

	void RouterContext::RemoveNTCPAddress (bool v4only)
	{
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto it = addresses.begin (); it != addresses.end ();)
		{
			if ((*it)->transportStyle == i2p::data::RouterInfo::eTransportNTCP && !(*it)->IsNTCP2 () &&
				(!v4only || (*it)->host.is_v4 ()))
			{
				it = addresses.erase (it);
				if (v4only) break; // otherwise might be more than one address
			}
			else
				++it;
		}
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
		uint16_t port = 0;
		// delete previous introducers
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto& addr : addresses)
			if (addr->ssu)
			{
				addr->ssu->introducers.clear ();
				port = addr->port;
			}
		// remove NTCP2 v4 address
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
			PublishNTCP2Address (port, false, true);
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
		uint16_t port = 0;
		// delete previous introducers
		auto& addresses = m_RouterInfo.GetAddresses ();
		for (auto& addr : addresses)
			if (addr->ssu)
			{
				addr->ssu->introducers.clear ();
				port = addr->port;
			}
		// insert NTCP2 back
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
		{
			bool published; i2p::config::GetOption ("ntcp2.published", published);
			if (published)
			{
				uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
				if (!ntcp2Port) ntcp2Port = port;
				PublishNTCP2Address (ntcp2Port, true, true);
			}
		}
		// update
		UpdateRouterInfo ();
	}

	void RouterContext::SetSupportsV6 (bool supportsV6)
	{
		if (supportsV6)
		{
			m_RouterInfo.EnableV6 ();
			// insert v6 addresses if necessary
			bool foundSSU = false, foundNTCP2 = false;
			uint16_t port = 0;
			auto& addresses = m_RouterInfo.GetAddresses ();
			for (auto& addr: addresses)
			{
				if (addr->host.is_v6 ())
				{
					if (addr->transportStyle == i2p::data::RouterInfo::eTransportSSU)
						foundSSU = true;
					else if (addr->IsPublishedNTCP2 ())
						foundNTCP2 = true;
				}
				port = addr->port;
			}
			if (!port) i2p::config::GetOption("port", port);
			// SSU
			if (!foundSSU)
			{
				bool ssu; i2p::config::GetOption("ssu", ssu);
				if (ssu)
				{
					std::string host = "::1"; // TODO: read host
					m_RouterInfo.AddSSUAddress (host.c_str (), port, nullptr);
				}
			}
			// NTCP2
			if (!foundNTCP2)
			{
				bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
				bool ntcp2Published; i2p::config::GetOption("ntcp2.published", ntcp2Published);
				if (ntcp2 && ntcp2Published)
				{
					std::string ntcp2Host;
					if (!i2p::config::IsDefault ("ntcp2.addressv6"))
						i2p::config::GetOption ("ntcp2.addressv6", ntcp2Host);
					else
						ntcp2Host = "::1";
					uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
					if (!ntcp2Port) ntcp2Port = port;
					m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, boost::asio::ip::address::from_string (ntcp2Host), ntcp2Port);
				}
			}
		}
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

	void RouterContext::UpdateNTCP2V6Address (const boost::asio::ip::address& host)
	{
		bool updated = false;
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
					break;
				}
			}
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

	void RouterContext::UpdateTimestamp (uint64_t ts)
	{
		if (ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
			UpdateRouterInfo ();
	}

	bool RouterContext::Load ()
	{
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
		}
		std::shared_ptr<const i2p::data::IdentityEx> oldIdentity;
		if (m_Keys.GetPublic ()->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1)
		{
			// update keys
			LogPrint (eLogInfo, "Router: router keys are obsolete. Creating new");
			oldIdentity = m_Keys.GetPublic ();
			m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519,
				i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD);
			SaveKeys ();
		}	
		// read NTCP2 keys if available
		std::ifstream n2k (i2p::fs::DataDirPath (NTCP2_KEYS), std::ifstream::in | std::ifstream::binary);
		if (n2k)
		{
			n2k.seekg (0, std::ios::end);
			size_t len = n2k.tellg();
			n2k.seekg (0, std::ios::beg);
			if (len == sizeof (NTCP2PrivateKeys))
			{
				m_NTCP2Keys.reset (new NTCP2PrivateKeys ());
				n2k.read ((char *)m_NTCP2Keys.get (), sizeof (NTCP2PrivateKeys));
			}
			n2k.close ();
		}
		// read RouterInfo
		m_RouterInfo.SetRouterIdentity (oldIdentity ? oldIdentity : GetIdentity ());
		i2p::data::RouterInfo routerInfo(i2p::fs::DataDirPath (ROUTER_INFO));
		if (!routerInfo.IsUnreachable ()) // router.info looks good
		{
			m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
			if (oldIdentity)
				m_RouterInfo.SetRouterIdentity (GetIdentity ()); // from new keys
			m_RouterInfo.SetProperty ("coreVersion", I2P_VERSION);
			m_RouterInfo.SetProperty ("router.version", I2P_VERSION);
		}
		else
		{
			LogPrint (eLogError, ROUTER_INFO, " is malformed. Creating new");
			NewRouterInfo ();
		}

		if (IsUnreachable ())
			SetReachable (); // we assume reachable until we discover firewall through peer tests

		// read NTCP2
		bool ntcp2;  i2p::config::GetOption("ntcp2.enabled", ntcp2);
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

	void RouterContext::HandleI2NPMessage (const uint8_t * buf, size_t len)
	{
		i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf, len)));
	}

	bool RouterContext::HandleCloveI2NPMessage (I2NPMessageType typeID, const uint8_t * payload, size_t len) 
	{ 
		auto msg = CreateI2NPMessage (typeID, payload, len);
		if (!msg) return false;
		i2p::HandleI2NPMessage (msg);
		return true; 
	} 

		
	void RouterContext::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		if (IsECIES ())
		{
			uint8_t * buf = msg->GetPayload ();
			uint32_t len = bufbe32toh (buf);
			if (len > msg->GetLength ())
			{
				LogPrint (eLogWarning, "Router: garlic message length ", len, " exceeds I2NP message length ", msg->GetLength ());
				return;
			}
			buf += 4;
			auto session = std::make_shared<i2p::garlic::ECIESX25519AEADRatchetSession>(this, false);
			session->HandleNextMessageForRouter (buf, len);
		}	
		else	
			i2p::garlic::GarlicDestination::ProcessGarlicMessage (msg);
	}

	void RouterContext::ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (i2p::data::netdb.GetPublishReplyToken () == bufbe32toh (msg->GetPayload () + DELIVERY_STATUS_MSGID_OFFSET))
			i2p::data::netdb.PostI2NPMsg (msg);
		else
		{	
			std::unique_lock<std::mutex> l(m_GarlicMutex);
			i2p::garlic::GarlicDestination::ProcessDeliveryStatusMessage (msg);
		}	
	}

	void RouterContext::CleanupDestination ()
	{
		std::unique_lock<std::mutex> l(m_GarlicMutex);
		i2p::garlic::GarlicDestination::CleanupExpiredTags ();
	}

	uint32_t RouterContext::GetUptime () const
	{
		return std::chrono::duration_cast<std::chrono::seconds> (std::chrono::steady_clock::now() - m_StartupTime).count ();
	}

	bool RouterContext::Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, i2p::data::CryptoKeyType preferredCrypto) const
	{
		return m_Decryptor ? m_Decryptor->Decrypt (encrypted, data, ctx, true) : false;
	}

	bool RouterContext::DecryptTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx)
	{
		if (!m_Decryptor) return false;
		if (IsECIES ())
		{
			if (!m_InitialNoiseState) return false;
			// m_InitialNoiseState is h = SHA256(h || hepk)
			m_CurrentNoiseState.reset (new i2p::crypto::NoiseSymmetricState (*m_InitialNoiseState));		
			m_CurrentNoiseState->MixHash (encrypted, 32); // h = SHA256(h || sepk)
			uint8_t sharedSecret[32];
			if (!m_Decryptor->Decrypt (encrypted, sharedSecret, ctx, false))
			{
				LogPrint (eLogWarning, "Router: Incorrect ephemeral public key");
				return false;
			}	
			m_CurrentNoiseState->MixKey (sharedSecret); 
			encrypted += 32;
			uint8_t nonce[12];
			memset (nonce, 0, 12);
			if (!i2p::crypto::AEADChaCha20Poly1305 (encrypted, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE, 
				m_CurrentNoiseState->m_H, 32, m_CurrentNoiseState->m_CK + 32, nonce, data, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE, false)) // decrypt
			{
				LogPrint (eLogWarning, "Router: Tunnel record AEAD decryption failed");
				return false;
			}	
			m_CurrentNoiseState->MixHash (encrypted, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE + 16); // h = SHA256(h || ciphertext)
			return true;
		}	
		else	
			return m_Decryptor->Decrypt (encrypted, data, ctx, false);
	}

	i2p::crypto::X25519Keys& RouterContext::GetStaticKeys ()
	{
		if (!m_StaticKeys)
		{
			if (!m_NTCP2Keys) NewNTCP2Keys ();
			auto x = new i2p::crypto::X25519Keys (m_NTCP2Keys->staticPrivateKey, m_NTCP2Keys->staticPublicKey);
			if (!m_StaticKeys)
				m_StaticKeys.reset (x);
			else
				delete x;
		}
		return *m_StaticKeys;
	}
}
