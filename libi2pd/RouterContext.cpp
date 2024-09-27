/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
#include "Transports.h"
#include "Tunnel.h"
#include "RouterContext.h"

namespace i2p
{
	RouterContext context;

	RouterContext::RouterContext ():
		m_LastUpdateTime (0), m_AcceptsTunnels (true), m_IsFloodfill (false),
		m_ShareRatio (100), m_Status (eRouterStatusUnknown), m_StatusV6 (eRouterStatusUnknown),
		m_Error (eRouterErrorNone), m_ErrorV6 (eRouterErrorNone),
		m_Testing (false), m_TestingV6 (false), m_NetID (I2PD_NET_ID),
		m_PublishReplyToken (0), m_IsHiddenMode (false)
	{
	}

	void RouterContext::Init ()
	{
		srand (i2p::util::GetMillisecondsSinceEpoch () % 1000);
		m_StartupTime = i2p::util::GetMonotonicSeconds ();

		if (!Load ())
			CreateNewRouter ();
		m_Decryptor = m_Keys.CreateDecryptor (nullptr);
		m_TunnelDecryptor = m_Keys.CreateDecryptor (nullptr);
		UpdateRouterInfo ();
		i2p::crypto::InitNoiseNState (m_InitialNoiseState, GetIdentity ()->GetEncryptionPublicKey ());
		m_ECIESSession = std::make_shared<i2p::garlic::RouterIncomingRatchetSession>(m_InitialNoiseState);
	}

	void RouterContext::Start ()
	{
		if (!m_Service)
		{	
			m_Service.reset (new RouterService);
			m_Service->Start ();
			m_PublishTimer.reset (new boost::asio::deadline_timer (m_Service->GetService ()));
			ScheduleInitialPublish ();
			m_CongestionUpdateTimer.reset (new boost::asio::deadline_timer (m_Service->GetService ()));
			ScheduleCongestionUpdate ();
			m_CleanupTimer.reset (new boost::asio::deadline_timer (m_Service->GetService ()));
			ScheduleCleanupTimer ();
		}	
	}
	
	void RouterContext::Stop ()
	{
		if (m_Service)
		{	
			if (m_PublishTimer)
				m_PublishTimer->cancel ();	
			if (m_CongestionUpdateTimer)
				m_CongestionUpdateTimer->cancel ();
			m_Service->Stop ();
			CleanUp (); // GarlicDestination
		}	
	}	

	std::shared_ptr<i2p::data::RouterInfo::Buffer> RouterContext::CopyRouterInfoBuffer () const
	{
		std::lock_guard<std::mutex> l(m_RouterInfoMutex);
		return m_RouterInfo.CopyBuffer ();
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
		i2p::data::LocalRouterInfo routerInfo;
		routerInfo.SetRouterIdentity (GetIdentity ());
		uint16_t port; i2p::config::GetOption("port", port);
		if (!port) port = SelectRandomPort ();
		bool ipv4;  i2p::config::GetOption("ipv4", ipv4);
		bool ipv6;  i2p::config::GetOption("ipv6", ipv6);
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		bool ssu2;  i2p::config::GetOption("ssu2.enabled", ssu2);
		bool ygg;   i2p::config::GetOption("meshnets.yggdrasil", ygg);
		bool nat;   i2p::config::GetOption("nat", nat);

		if ((ntcp2 || ygg) && !m_NTCP2Keys)
			NewNTCP2Keys ();
		if (ssu2 && !m_SSU2Keys)
			NewSSU2Keys ();
		bool ntcp2Published = false;
		if (ntcp2)
		{
			i2p::config::GetOption("ntcp2.published", ntcp2Published);
			if (ntcp2Published)
			{
				std::string ntcp2proxy; i2p::config::GetOption("ntcp2.proxy", ntcp2proxy);
				if (!ntcp2proxy.empty ()) ntcp2Published = false;
			}
		}
		bool ssu2Published = false;
		if (ssu2)
			i2p::config::GetOption("ssu2.published", ssu2Published);
		uint8_t caps = 0;
		if (ipv4)
		{
			std::string host;
			if (!nat)
				// we have no NAT so set external address from local address
				i2p::config::GetOption("address4", host);
			if (host.empty ()) i2p::config::GetOption("host", host);

			if (ntcp2)
			{
				uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
				if (!ntcp2Port) ntcp2Port = port;
				if (ntcp2Published && ntcp2Port)
				{
					boost::asio::ip::address addr;
					if (!host.empty ())
						addr = boost::asio::ip::address::from_string (host);
					if (!addr.is_v4())
						addr = boost::asio::ip::address_v4 ();
					routerInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, addr, ntcp2Port);
				}
				else
				{
					// add non-published NTCP2 address
					uint8_t addressCaps = i2p::data::RouterInfo::AddressCaps::eV4;
					if (ipv6) addressCaps |= i2p::data::RouterInfo::AddressCaps::eV6;
					routerInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, ntcp2Port, addressCaps);
				}
			}
			if (ssu2)
			{
				uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
				if (!ssu2Port) ssu2Port = port;
				if (ssu2Published && ssu2Port)
				{
					boost::asio::ip::address addr;
					if (!host.empty ())
						addr = boost::asio::ip::address::from_string (host);
					if (!addr.is_v4())
						addr = boost::asio::ip::address_v4 ();
					routerInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, addr, ssu2Port);
				}
				else
				{
					uint8_t addressCaps = i2p::data::RouterInfo::AddressCaps::eV4;
					if (ipv6) addressCaps |= i2p::data::RouterInfo::AddressCaps::eV6;
					routerInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, ssu2Port, addressCaps);
				}
			}
		}
		if (ipv6)
		{
			std::string host; i2p::config::GetOption("address6", host);
			if (host.empty () && !ipv4) i2p::config::GetOption("host", host); // use host for ipv6 only if ipv4 is not presented

			if (ntcp2)
			{
				uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
				if (!ntcp2Port) ntcp2Port = port;
				if (ntcp2Published && ntcp2Port)
				{
					std::string ntcp2Host;
					if (!i2p::config::IsDefault ("ntcp2.addressv6"))
						i2p::config::GetOption ("ntcp2.addressv6", ntcp2Host);
					else
						ntcp2Host = host;
					boost::asio::ip::address addr;
					if (!ntcp2Host.empty ())
						addr = boost::asio::ip::address::from_string (ntcp2Host);
					if (!addr.is_v6())
						addr = boost::asio::ip::address_v6 ();
					routerInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, addr, ntcp2Port);
				}
				else
				{
					if (!ipv4) // no other ntcp2 addresses yet
						routerInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, ntcp2Port, i2p::data::RouterInfo::AddressCaps::eV6);
				}
			}
			if (ssu2)
			{
				uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
				if (!ssu2Port) ssu2Port = port;
				if (ssu2Published && ssu2Port)
				{
					boost::asio::ip::address addr;
					if (!host.empty ())
						addr = boost::asio::ip::address::from_string (host);
					if (!addr.is_v6())
						addr = boost::asio::ip::address_v6 ();
					routerInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, addr, ssu2Port);
				}
				else
				{
					if (!ipv4) // no other ssu2 addresses yet
						routerInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, ssu2Port, i2p::data::RouterInfo::AddressCaps::eV6);
				}
			}
		}
		if (ygg)
		{
			auto yggaddr = i2p::util::net::GetYggdrasilAddress ();
			if (!yggaddr.is_unspecified ())
				routerInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, yggaddr, port);
		}

		routerInfo.UpdateCaps (caps); // caps + L
		routerInfo.SetProperty ("netId", std::to_string (m_NetID));
		routerInfo.SetProperty ("router.version", I2P_VERSION);
		routerInfo.CreateBuffer (m_Keys);
		m_RouterInfo.SetRouterIdentity (GetIdentity ());
		m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
		m_RouterInfo.SetUnreachable (false);
	}

	uint16_t RouterContext::SelectRandomPort () const
	{
		uint16_t port;
		do
		{
			port = rand () % (30777 - 9111) + 9111; // I2P network ports range
		}
		while(i2p::util::net::IsPortInReservedRange(port));

		return port;
	}

	void RouterContext::UpdateRouterInfo ()
	{
		{
			std::lock_guard<std::mutex> l(m_RouterInfoMutex);
			m_RouterInfo.CreateBuffer (m_Keys);
		}
		m_RouterInfo.SaveToFile (i2p::fs::DataDirPath (ROUTER_INFO));
		m_LastUpdateTime = i2p::util::GetSecondsSinceEpoch ();
	}

	void RouterContext::NewNTCP2Keys ()
	{
		m_NTCP2StaticKeys.reset (new i2p::crypto::X25519Keys ());
		m_NTCP2StaticKeys->GenerateKeys ();
		m_NTCP2Keys.reset (new NTCP2PrivateKeys ());
		m_NTCP2StaticKeys->GetPrivateKey (m_NTCP2Keys->staticPrivateKey);
		memcpy (m_NTCP2Keys->staticPublicKey, m_NTCP2StaticKeys->GetPublicKey (), 32);
		RAND_bytes (m_NTCP2Keys->iv, 16);
		// save
		std::ofstream fk (i2p::fs::DataDirPath (NTCP2_KEYS), std::ofstream::binary | std::ofstream::out);
		fk.write ((char *)m_NTCP2Keys.get (), sizeof (NTCP2PrivateKeys));
	}

	void RouterContext::NewSSU2Keys ()
	{
		m_SSU2StaticKeys.reset (new i2p::crypto::X25519Keys ());
		m_SSU2StaticKeys->GenerateKeys ();
		m_SSU2Keys.reset (new SSU2PrivateKeys ());
		m_SSU2StaticKeys->GetPrivateKey (m_SSU2Keys->staticPrivateKey);
		memcpy (m_SSU2Keys->staticPublicKey, m_SSU2StaticKeys->GetPublicKey (), 32);
		RAND_bytes (m_SSU2Keys->intro, 32);
		// save
		std::ofstream fk (i2p::fs::DataDirPath (SSU2_KEYS), std::ofstream::binary | std::ofstream::out);
		fk.write ((char *)m_SSU2Keys.get (), sizeof (SSU2PrivateKeys));
	}

	void RouterContext::SetTesting (bool testing)
	{
		if (testing != m_Testing)
		{
			m_Testing = testing;
			if (m_Testing)
				m_Error = eRouterErrorNone;
		}
	}

	void RouterContext::SetTestingV6 (bool testing)
	{
		if (testing != m_TestingV6)
		{
			m_TestingV6 = testing;
			if (m_TestingV6)
				m_ErrorV6 = eRouterErrorNone;
		}
	}

	void RouterContext::SetStatus (RouterStatus status)
	{
		SetTesting (false);
		if (status != m_Status)
		{
			LogPrint(eLogInfo, "Router: network status v4 changed ",
				ROUTER_STATUS_NAMES[m_Status], " -> ", ROUTER_STATUS_NAMES[status]);
			m_Status = status;
			switch (m_Status)
			{
				case eRouterStatusOK:
					SetReachable (true, false); // ipv4
				break;
				case eRouterStatusFirewalled:
					SetUnreachable (true, false); // ipv4
				break;
				case eRouterStatusProxy:
					m_AcceptsTunnels = false;
					UpdateCongestion ();
				break;	
				default:
					;
			}
		}
	}

	void RouterContext::SetStatusV6 (RouterStatus status)
	{
		SetTestingV6 (false);
		if (status != m_StatusV6)
		{
			LogPrint(eLogInfo, "Router: network status v6 changed ",
				ROUTER_STATUS_NAMES[m_StatusV6], " -> ", ROUTER_STATUS_NAMES[status]);
			m_StatusV6 = status;
			switch (m_StatusV6)
			{
				case eRouterStatusOK:
					SetReachable (false, true); // ipv6
				break;
				case eRouterStatusFirewalled:
					SetUnreachable (false, true); // ipv6
				break;
				default:
					;
			}
		}
	}

	void RouterContext::UpdatePort (int port)
	{
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		bool updated = false;
		for (auto& address : *addresses)
		{
			if (address && address->port != port)
			{
				address->port = port;
				updated = true;
			}
		}
		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::PublishNTCP2Address (std::shared_ptr<i2p::data::RouterInfo::Address> address,
		int port, bool publish) const
	{
		if (!address) return;
		if (!port && !address->port) port = SelectRandomPort ();
		if (port) address->port = port;
		address->published = publish;
		memcpy (address->i, m_NTCP2Keys->iv, 16);
	}

	void RouterContext::PublishNTCP2Address (int port, bool publish, bool v4, bool v6, bool ygg)
	{
		if (!m_NTCP2Keys) return;
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		bool updated = false;
		if (v4)
		{
			auto addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V4Idx];
			if (addr && (addr->port != port || addr->published != publish))
			{
				PublishNTCP2Address (addr, port, publish);
				updated = true;
			}
		}
		if (v6)
		{
			auto addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V6Idx];
			if (addr && (addr->port != port || addr->published != publish))
			{
				PublishNTCP2Address (addr, port, publish);
				updated = true;
			}
		}
		if (ygg)
		{
			auto addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V6MeshIdx];
			if (addr && (addr->port != port || addr->published != publish))
			{
				PublishNTCP2Address (addr, port, publish);
				updated = true;
			}
		}

		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::UpdateNTCP2Keys ()
	{
		if (!m_NTCP2Keys) return;
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		for (auto& it: *addresses)
		{
			if (it && it->IsNTCP2 ())
			{
				it->s = m_NTCP2Keys->staticPublicKey;
				memcpy (it->i, m_NTCP2Keys->iv, 16);
			}
		}
	}

	void RouterContext::PublishSSU2Address (int port, bool publish, bool v4, bool v6)
	{
		if (!m_SSU2Keys) return;
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		int newPort = 0;
		if (!port)
		{
			for (const auto& address : *addresses)
				if (address && address->port)
				{
					newPort = address->port;
					break;
				}
			if (!newPort) newPort = SelectRandomPort ();
		}
		bool updated = false;
		for (auto& address : *addresses)
		{
			if (address && address->IsSSU2 () && (!address->port || address->port != port || address->published != publish) &&
				((v4 && address->IsV4 ()) || (v6 && address->IsV6 ())))
			{
				if (port) address->port = port;
				else if (!address->port) address->port = newPort;
				address->published = publish;
				if (publish)
					address->caps |= (i2p::data::RouterInfo::eSSUIntroducer | i2p::data::RouterInfo::eSSUTesting);
				else
					address->caps &= ~(i2p::data::RouterInfo::eSSUIntroducer | i2p::data::RouterInfo::eSSUTesting);
				updated = true;
			}
		}
		if (updated)
			UpdateRouterInfo ();
	}

	void RouterContext::UpdateSSU2Keys ()
	{
		if (!m_SSU2Keys) return;
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		for (auto& it: *addresses)
		{
			if (it && it->IsSSU2 ())
			{
				it->s = m_SSU2Keys->staticPublicKey;
				it->i = m_SSU2Keys->intro;
			}
		}
	}

	void RouterContext::UpdateAddress (const boost::asio::ip::address& host)
	{
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		bool updated = false;
		if (host.is_v4 ())
		{
			auto addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V4Idx];
			if (addr && addr->host != host)
			{
				addr->host = host;
				updated = true;
			}
			addr = (*addresses)[i2p::data::RouterInfo::eSSU2V4Idx];
			if (addr && addr->host != host)
			{
				addr->host = host;
				updated = true;
			}
		}
		else if (host.is_v6 ())
		{
			auto addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V6Idx];
			if (addr && addr->host != host)
			{
				addr->host = host;
				updated = true;
			}
			addr = (*addresses)[i2p::data::RouterInfo::eSSU2V6Idx];
			if (addr && (addr->host != host || !addr->ssu->mtu))
			{
				addr->host = host;
				if (m_StatusV6 != eRouterStatusProxy)
				{
					// update MTU
					auto mtu = i2p::util::net::GetMTU (host);
					if (mtu)
					{
						LogPrint (eLogDebug, "Router: Our v6 MTU=", mtu);
						int maxMTU = i2p::util::net::GetMaxMTU (host.to_v6 ());
						if (mtu > maxMTU)
						{
							mtu = maxMTU;
							LogPrint(eLogWarning, "Router: MTU dropped to upper limit of ", maxMTU, " bytes");
						}
						addr->ssu->mtu = mtu;
					}
				}
				updated = true;
			}
		}

		auto ts = i2p::util::GetSecondsSinceEpoch ();
		if (updated || ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
			UpdateRouterInfo ();
	}

	bool RouterContext::AddSSU2Introducer (const i2p::data::RouterInfo::Introducer& introducer, bool v4)
	{
		bool ret = m_RouterInfo.AddSSU2Introducer (introducer, v4);
		if (ret)
			UpdateRouterInfo ();
		return ret;
	}

	void RouterContext::RemoveSSU2Introducer (const i2p::data::IdentHash& h, bool v4)
	{
		if (m_RouterInfo.RemoveSSU2Introducer (h, v4))
			UpdateRouterInfo ();
	}

	void RouterContext::UpdateSSU2Introducer (const i2p::data::IdentHash& h, bool v4, uint32_t iTag, uint32_t iExp)
	{
		if (m_RouterInfo.UpdateSSU2Introducer (h, v4, iTag, iExp))
			UpdateRouterInfo ();
	}	
		
	void RouterContext::ClearSSU2Introducers (bool v4)
	{
		auto addr = m_RouterInfo.GetSSU2Address (v4);
		if (addr && !addr->ssu->introducers.empty ())
		{
			addr->ssu->introducers.clear ();
			UpdateRouterInfo ();
		}
	}

	void RouterContext::SetFloodfill (bool floodfill)
	{
		m_IsFloodfill = floodfill;
		if (floodfill)
			m_RouterInfo.UpdateFloodfillProperty (true);
		else
		{
			m_RouterInfo.UpdateFloodfillProperty (false);
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
			case i2p::data::CAPS_FLAG_LOW_BANDWIDTH1   : limit = 12; type = low;   break;
			case i2p::data::CAPS_FLAG_LOW_BANDWIDTH2   : limit = i2p::data::LOW_BANDWIDTH_LIMIT; type = low;   break; // 48
			case i2p::data::CAPS_FLAG_LOW_BANDWIDTH3  : limit = 64; type = low;  break;
			case i2p::data::CAPS_FLAG_LOW_BANDWIDTH4  : limit = 128; type = low;  break;
			case i2p::data::CAPS_FLAG_HIGH_BANDWIDTH  : limit = i2p::data::HIGH_BANDWIDTH_LIMIT; type = high;  break; // 256
			case i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH1 : limit = i2p::data::EXTRA_BANDWIDTH_LIMIT; type = extra; break; // 2048
			case i2p::data::CAPS_FLAG_EXTRA_BANDWIDTH2 : limit = 1000000; type = unlim; break; // 1Gbyte/s
			default:
				limit = i2p::data::LOW_BANDWIDTH_LIMIT; type = low; // 48
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
			[[fallthrough]];
			// no break here, extra + high means 'X'
			case high : caps |= i2p::data::RouterInfo::eHighBandwidth; break;
		}
		m_RouterInfo.UpdateCaps (caps);
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
		m_BandwidthLimit = limit; // set precise limit
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

	void RouterContext::SetUnreachable (bool v4, bool v6)
	{
		if (v4 || (v6 && !SupportsV4 ()))
		{
			// set caps
			uint8_t caps = m_RouterInfo.GetCaps ();
			caps &= ~i2p::data::RouterInfo::eReachable;
			caps |= i2p::data::RouterInfo::eUnreachable;
			if (v6 || !SupportsV6 ())
				caps &= ~i2p::data::RouterInfo::eFloodfill;	// can't be floodfill
			m_RouterInfo.UpdateCaps (caps);
		}
		uint16_t port = 0;
		// delete previous introducers
		auto addresses = m_RouterInfo.GetAddresses ();
		if (addresses)
		{
			for (auto& addr : *addresses)
				if (addr && addr->ssu && ((v4 && addr->IsV4 ()) || (v6 && addr->IsV6 ())))
				{
					addr->published = false;
					addr->caps &= ~i2p::data::RouterInfo::eSSUIntroducer; // can't be introducer
					addr->ssu->introducers.clear ();
					port = addr->port;
				}
		}
		// unpublish NTCP2 addreeses
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
			PublishNTCP2Address (port, false, v4, v6, false);
		// update
		m_RouterInfo.UpdateSupportedTransports ();
		UpdateRouterInfo ();
	}

	void RouterContext::SetReachable (bool v4, bool v6)
	{
		if (v4 || (v6 && !SupportsV4 ()))
		{
			// update caps
			uint8_t caps = m_RouterInfo.GetCaps ();
			caps &= ~i2p::data::RouterInfo::eUnreachable;
			caps |= i2p::data::RouterInfo::eReachable;
			if (m_IsFloodfill)
				caps |= i2p::data::RouterInfo::eFloodfill;
			m_RouterInfo.UpdateCaps (caps);
		}
		uint16_t port = 0;
		// delete previous introducers
		bool isSSU2Published; i2p::config::GetOption ("ssu2.published", isSSU2Published);
		auto addresses = m_RouterInfo.GetAddresses ();
		if (addresses)
		{
			for (auto& addr : *addresses)
				if (addr && addr->ssu && isSSU2Published && ((v4 && addr->IsV4 ()) || (v6 && addr->IsV6 ())))
				{
					addr->published = true;
					addr->caps |= i2p::data::RouterInfo::eSSUIntroducer;
					addr->ssu->introducers.clear ();
					if (addr->port) port = addr->port;
				}
		}
		// publish NTCP2
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		if (ntcp2)
		{
			bool published; i2p::config::GetOption ("ntcp2.published", published);
			if (published)
			{
				uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
				if (!ntcp2Port) ntcp2Port = port;
				PublishNTCP2Address (ntcp2Port, true, v4, v6, false);
			}
		}
		// update
		m_RouterInfo.UpdateSupportedTransports ();
		UpdateRouterInfo ();
	}

	void RouterContext::SetSupportsV6 (bool supportsV6)
	{
		if (supportsV6)
		{
			// insert v6 addresses if necessary
			bool foundNTCP2 = false, foundSSU2 = false;
			uint16_t port = 0;
			auto addresses = m_RouterInfo.GetAddresses ();
			if (addresses)
			{
				for (auto& addr: *addresses)
				{
					if (addr && addr->IsV6 () && !i2p::util::net::IsYggdrasilAddress (addr->host))
					{
						switch (addr->transportStyle)
						{
							case i2p::data::RouterInfo::eTransportNTCP2:
								foundNTCP2 = true;
							break;
							case i2p::data::RouterInfo::eTransportSSU2:
								foundSSU2 = true;
							break;
							default: ;
						}
					}
					if (addr) port = addr->port;
				}
			}
			if (!port)
			{
				i2p::config::GetOption("port", port);
				if (!port) port = SelectRandomPort ();
			}
			// NTCP2
			bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
			if (ntcp2)
			{
				if (!foundNTCP2)
				{
					uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
					if (!ntcp2Port) ntcp2Port = port;
					bool added = false;
					bool ntcp2Published; i2p::config::GetOption("ntcp2.published", ntcp2Published);
					if (ntcp2Published)
					{
						std::string ntcp2Host;
						if (!i2p::config::IsDefault ("ntcp2.addressv6"))
							i2p::config::GetOption ("ntcp2.addressv6", ntcp2Host);
						else
							i2p::config::GetOption("host", ntcp2Host);
						if (!ntcp2Host.empty () && ntcp2Port)
						{
							auto addr = boost::asio::ip::address::from_string (ntcp2Host);
							if (addr.is_v6 ())
							{
								m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, addr, ntcp2Port);
								added = true;
							}
						}
					}
					if (!added)
						m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, ntcp2Port, i2p::data::RouterInfo::eV6);
				}
			}
			else
				m_RouterInfo.RemoveNTCP2Address (false);
			// SSU2
			bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
			if (ssu2)
			{
				if (!foundSSU2)
				{
					uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
					if (!ssu2Port) ssu2Port = port;
					bool added = false;
					bool ssu2Published; i2p::config::GetOption("ssu2.published", ssu2Published);
					if (ssu2Published && ssu2Port)
					{
						std::string host; i2p::config::GetOption("host", host);
						if (!host.empty ())
						{
						    auto addr = boost::asio::ip::address::from_string (host);
							if (addr.is_v6 ())
							{
								m_RouterInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, addr, ssu2Port);
								added = true;
							}
						}
					}
					if (!added)
						m_RouterInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, ssu2Port, i2p::data::RouterInfo::eV6);
				}
			}
			else
				m_RouterInfo.RemoveSSU2Address (false);
			if (ntcp2 || ssu2)
				m_RouterInfo.EnableV6 ();
		}
		else
			m_RouterInfo.DisableV6 ();
		UpdateRouterInfo ();
	}

	void RouterContext::SetSupportsV4 (bool supportsV4)
	{
		if (supportsV4)
		{
			bool foundNTCP2 = false, foundSSU2 = false;
			uint16_t port = 0;
			auto addresses = m_RouterInfo.GetAddresses ();
			if (addresses)
			{
				for (auto& addr: *addresses)
				{
					if (addr && addr->IsV4 ())
					{
						switch (addr->transportStyle)
						{
							case i2p::data::RouterInfo::eTransportNTCP2:
								foundNTCP2 = true;
							break;
							case i2p::data::RouterInfo::eTransportSSU2:
								foundSSU2 = true;
							break;
							default: ;
						}
					}
					if (addr && addr->port) port = addr->port;
				}
			}
			if (!port)
			{
				i2p::config::GetOption("port", port);
				if (!port) port = SelectRandomPort ();
			}
			// NTCP2
			bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
			if (ntcp2)
			{
				if (!foundNTCP2)
				{
					uint16_t ntcp2Port; i2p::config::GetOption ("ntcp2.port", ntcp2Port);
					if (!ntcp2Port) ntcp2Port = port;
					bool added = false;
					bool ntcp2Published; i2p::config::GetOption("ntcp2.published", ntcp2Published);
					if (ntcp2Published && ntcp2Port)
					{
						std::string host; i2p::config::GetOption("host", host);
						if (!host.empty ())
						{
						    auto addr = boost::asio::ip::address::from_string (host);
							if (addr.is_v4 ())
							{
								m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, addr, ntcp2Port);
								added = true;
							}
						}
					}
					if (!added)
						m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, ntcp2Port, i2p::data::RouterInfo::eV4);
				}
			}
			else
				m_RouterInfo.RemoveNTCP2Address (true);
			// SSU2
			bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
			if (ssu2)
			{
				if (!foundSSU2)
				{
					uint16_t ssu2Port; i2p::config::GetOption ("ssu2.port", ssu2Port);
					if (!ssu2Port) ssu2Port = port;
					bool added = false;
					bool ssu2Published; i2p::config::GetOption("ssu2.published", ssu2Published);
					std::string host; i2p::config::GetOption("host", host);
					if (ssu2Published && ssu2Port)
					{
						std::string host; i2p::config::GetOption("host", host);
						if (!host.empty ())
						{
						    auto addr = boost::asio::ip::address::from_string (host);
							if (addr.is_v4 ())
							{
								m_RouterInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, addr, ssu2Port);
								added = true;
							}
						}
					}
					if (!added)
						m_RouterInfo.AddSSU2Address (m_SSU2Keys->staticPublicKey, m_SSU2Keys->intro, ssu2Port, i2p::data::RouterInfo::eV4);
				}
			}
			else
				m_RouterInfo.RemoveSSU2Address (true);
			if (ntcp2 || ssu2)
				m_RouterInfo.EnableV4 ();
		}
		else
			m_RouterInfo.DisableV4 ();
		UpdateRouterInfo ();
	}

	void RouterContext::SetSupportsMesh (bool supportsmesh, const boost::asio::ip::address_v6& host)
	{
		if (supportsmesh)
		{
			auto addresses = m_RouterInfo.GetAddresses ();
			if (!addresses) return;
			m_RouterInfo.EnableMesh ();
			if ((*addresses)[i2p::data::RouterInfo::eNTCP2V6MeshIdx]) return; // we have mesh address already
			uint16_t port = 0;
			i2p::config::GetOption ("ntcp2.port", port);
			if (!port) i2p::config::GetOption("port", port);
			if (!port)
			{
				for (auto& addr: *addresses)
				{
					if (addr && addr->port)
					{
						port = addr->port;
						break;
					}
				}
			}
			if (!port) port = SelectRandomPort ();
			m_RouterInfo.AddNTCP2Address (m_NTCP2Keys->staticPublicKey, m_NTCP2Keys->iv, host, port);
		}
		else
			m_RouterInfo.DisableMesh ();
		UpdateRouterInfo ();
	}

	void RouterContext::SetMTU (int mtu, bool v4)
	{
		if (mtu < 1280 || mtu > 1500) return;
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		for (auto& addr: *addresses)
		{
			if (addr && addr->ssu && ((v4 && addr->IsV4 ()) || (!v4 && addr->IsV6 ())))
			{
				addr->ssu->mtu = mtu;
				LogPrint (eLogDebug, "Router: MTU for ", v4 ? "ipv4" : "ipv6", " address ", addr->host.to_string(), " is set to ", mtu);
			}
		}
	}

	void RouterContext::UpdateNTCP2V6Address (const boost::asio::ip::address& host)
	{
		auto addresses = m_RouterInfo.GetAddresses ();
		if (!addresses) return;
		std::shared_ptr<i2p::data::RouterInfo::Address> addr;
		if (i2p::util::net::IsYggdrasilAddress (host)) // yggdrasil
			addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V6MeshIdx];
		else if (host.is_v6 ())
			addr = (*addresses)[i2p::data::RouterInfo::eNTCP2V6Idx];
		if (addr && addr->IsPublishedNTCP2 () && addr->host != host)
		{
			addr->host = host;
			UpdateRouterInfo ();
		}
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
		if (m_Keys.GetPublic ()->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1 ||
			m_Keys.GetPublic ()->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ELGAMAL)
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
		// read SSU2 keys if available
		std::ifstream s2k (i2p::fs::DataDirPath (SSU2_KEYS), std::ifstream::in | std::ifstream::binary);
		if (s2k)
		{
			s2k.seekg (0, std::ios::end);
			size_t len = s2k.tellg();
			s2k.seekg (0, std::ios::beg);
			if (len == sizeof (SSU2PrivateKeys))
			{
				m_SSU2Keys.reset (new SSU2PrivateKeys ());
				s2k.read ((char *)m_SSU2Keys.get (), sizeof (SSU2PrivateKeys));
			}
			s2k.close ();
		}
		// read RouterInfo
		m_RouterInfo.SetRouterIdentity (oldIdentity ? oldIdentity : GetIdentity ());
		i2p::data::RouterInfo routerInfo(i2p::fs::DataDirPath (ROUTER_INFO));
		if (!routerInfo.IsUnreachable ()) // router.info looks good
		{
			m_RouterInfo.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
			if (oldIdentity)
				m_RouterInfo.SetRouterIdentity (GetIdentity ()); // from new keys
			m_RouterInfo.SetProperty ("router.version", I2P_VERSION);
			m_RouterInfo.DeleteProperty ("coreVersion"); // TODO: remove later
		}
		else
		{
			LogPrint (eLogError, ROUTER_INFO, " is malformed. Creating new");
			NewRouterInfo ();
		}

		if (IsUnreachable ())
			SetReachable (true, true); // we assume reachable until we discover firewall through peer tests

		bool updated = false;
		// create new NTCP2 keys if required
		bool ntcp2; i2p::config::GetOption("ntcp2.enabled", ntcp2);
		bool ygg; i2p::config::GetOption("meshnets.yggdrasil", ygg);
		if ((ntcp2 || ygg) && !m_NTCP2Keys)
		{
			NewNTCP2Keys ();
			UpdateNTCP2Keys ();
			updated = true;
		}
		// create new SSU2 keys if required
		bool ssu2; i2p::config::GetOption("ssu2.enabled", ssu2);
		if (ssu2 && !m_SSU2Keys)
		{
			NewSSU2Keys ();
			UpdateSSU2Keys ();
			updated = true;
		}
		if (m_RouterInfo.UpdateCongestion (i2p::data::RouterInfo::eLowCongestion))
			updated = true;
		if (updated)
			UpdateRouterInfo ();

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

	int RouterContext::GetCongestionLevel (bool longTerm) const
	{
		return std::max (
			i2p::tunnel::tunnels.GetCongestionLevel (),
			i2p::transport::transports.GetCongestionLevel (longTerm)
		);
	}
	
	void RouterContext::HandleI2NPMessage (const uint8_t * buf, size_t len)
	{
		i2p::HandleI2NPMessage (CreateI2NPMessage (buf, GetI2NPMessageLength (buf, len)));
	}

	bool RouterContext::HandleCloveI2NPMessage (I2NPMessageType typeID, const uint8_t * payload, size_t len, uint32_t msgID)
	{
		if (typeID == eI2NPTunnelTest)
		{
			// try tunnel test
			auto pool = GetTunnelPool ();
			if (pool && pool->ProcessTunnelTest (bufbe32toh (payload + TUNNEL_TEST_MSGID_OFFSET), bufbe64toh (payload + TUNNEL_TEST_TIMESTAMP_OFFSET)))
				return true;
		}
		auto msg = CreateI2NPMessage (typeID, payload, len, msgID);
		if (!msg) return false;
		i2p::HandleI2NPMessage (msg);
		return true;
	}

	void RouterContext::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_Service)
			m_Service->GetService ().post (std::bind (&RouterContext::PostGarlicMessage, this, msg));
		else
			LogPrint (eLogError, "Router: service is NULL");
	}

	void RouterContext::PostGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		uint8_t * buf = msg->GetPayload ();
		uint32_t len = bufbe32toh (buf);
		if (len > msg->GetLength ())
		{
			LogPrint (eLogWarning, "Router: garlic message length ", len, " exceeds I2NP message length ", msg->GetLength ());
			return;
		}
		buf += 4;
		if (!HandleECIESx25519TagMessage (buf, len)) // try tag first
		{
			// then Noise_N one-time decryption
			if (m_ECIESSession)
				m_ECIESSession->HandleNextMessage (buf, len);
			else
				LogPrint (eLogError, "Router: Session is not set for ECIES router");
		}
	}	
	
	void RouterContext::ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_Service)
			m_Service->GetService ().post (std::bind (&RouterContext::PostDeliveryStatusMessage, this, msg));
		else
			LogPrint (eLogError, "Router: service is NULL");
	}

	void RouterContext::PostDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_PublishReplyToken == bufbe32toh (msg->GetPayload () + DELIVERY_STATUS_MSGID_OFFSET))
		{
			LogPrint (eLogInfo, "Router: Publishing confirmed. reply token=", m_PublishReplyToken);
			m_PublishExcluded.clear ();
			m_PublishReplyToken = 0;
			SchedulePublish ();
		}	
		else	              
			i2p::garlic::GarlicDestination::ProcessDeliveryStatusMessage (msg);
	}

	void RouterContext::SubmitECIESx25519Key (const uint8_t * key, uint64_t tag)
	{
		if (m_Service)
		{
			struct
			{
				uint8_t k[32];
				uint64_t t;
			} data;
			memcpy (data.k, key, 32);
			data.t = tag;
			m_Service->GetService ().post ([this,data](void)
				{
					AddECIESx25519Key (data.k, data.t);
				});
		}	
		else
			LogPrint (eLogError, "Router: service is NULL");
	}	

	uint32_t RouterContext::GetUptime () const
	{
		return i2p::util::GetMonotonicSeconds () - m_StartupTime;
	}

	bool RouterContext::Decrypt (const uint8_t * encrypted, uint8_t * data, i2p::data::CryptoKeyType preferredCrypto) const
	{
		return m_Decryptor ? m_Decryptor->Decrypt (encrypted, data) : false;
	}

	bool RouterContext::DecryptTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data)
	{
		return DecryptECIESTunnelBuildRecord (encrypted, data, ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE);
	}

	bool RouterContext::DecryptECIESTunnelBuildRecord (const uint8_t * encrypted, uint8_t * data, size_t clearTextSize)
	{
		// m_InitialNoiseState is h = SHA256(h || hepk)
		m_CurrentNoiseState = m_InitialNoiseState;
		m_CurrentNoiseState.MixHash (encrypted, 32); // h = SHA256(h || sepk)
		uint8_t sharedSecret[32];
		if (!m_TunnelDecryptor->Decrypt (encrypted, sharedSecret))
		{
			LogPrint (eLogWarning, "Router: Incorrect ephemeral public key");
			return false;
		}
		m_CurrentNoiseState.MixKey (sharedSecret);
		encrypted += 32;
		uint8_t nonce[12];
		memset (nonce, 0, 12);
		if (!i2p::crypto::AEADChaCha20Poly1305 (encrypted, clearTextSize, m_CurrentNoiseState.m_H, 32,
			m_CurrentNoiseState.m_CK + 32, nonce, data, clearTextSize, false)) // decrypt
		{
			LogPrint (eLogWarning, "Router: Tunnel record AEAD decryption failed");
			return false;
		}
		m_CurrentNoiseState.MixHash (encrypted, clearTextSize + 16); // h = SHA256(h || ciphertext)
		return true;
	}

	bool RouterContext::DecryptTunnelShortRequestRecord (const uint8_t * encrypted, uint8_t * data)
	{
		return DecryptECIESTunnelBuildRecord (encrypted, data, SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE);
	}

	i2p::crypto::X25519Keys& RouterContext::GetNTCP2StaticKeys ()
	{
		if (!m_NTCP2StaticKeys)
		{
			if (!m_NTCP2Keys) NewNTCP2Keys ();
			auto x = new i2p::crypto::X25519Keys (m_NTCP2Keys->staticPrivateKey, m_NTCP2Keys->staticPublicKey);
			if (!m_NTCP2StaticKeys)
				m_NTCP2StaticKeys.reset (x);
			else
				delete x;
		}
		return *m_NTCP2StaticKeys;
	}

	i2p::crypto::X25519Keys& RouterContext::GetSSU2StaticKeys ()
	{
		if (!m_SSU2StaticKeys)
		{
			if (!m_SSU2Keys) NewSSU2Keys ();
			auto x = new i2p::crypto::X25519Keys (m_SSU2Keys->staticPrivateKey, m_SSU2Keys->staticPublicKey);
			if (!m_SSU2StaticKeys)
				m_SSU2StaticKeys.reset (x);
			else
				delete x;
		}
		return *m_SSU2StaticKeys;
	}

	void RouterContext::ScheduleInitialPublish ()
	{
		if (m_PublishTimer)
		{	
			m_PublishTimer->expires_from_now (boost::posix_time::seconds(ROUTER_INFO_INITIAL_PUBLISH_INTERVAL));
			m_PublishTimer->async_wait (std::bind (&RouterContext::HandleInitialPublishTimer,
				this, std::placeholders::_1));
		}	
		else
			LogPrint (eLogError, "Router: Publish timer is NULL");
	}	

	void RouterContext::HandleInitialPublishTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{	
			if (m_RouterInfo.IsReachableBy (i2p::data::RouterInfo::eAllTransports))
			{
				UpdateCongestion ();
				HandlePublishTimer (ecode);
			}	
			else
			{	
				UpdateTimestamp (i2p::util::GetSecondsSinceEpoch ());	
				ScheduleInitialPublish ();
			}		
		}	
	}	
	
	void RouterContext::SchedulePublish ()
	{
		if (m_PublishTimer)
		{	
			m_PublishTimer->cancel ();
			m_PublishTimer->expires_from_now (boost::posix_time::seconds(ROUTER_INFO_PUBLISH_INTERVAL + 
				rand () % ROUTER_INFO_PUBLISH_INTERVAL_VARIANCE));
			m_PublishTimer->async_wait (std::bind (&RouterContext::HandlePublishTimer,
				this, std::placeholders::_1));
		}	
		else
			LogPrint (eLogError, "Router: Publish timer is NULL");
	}	

	void RouterContext::HandlePublishTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			UpdateTimestamp (i2p::util::GetSecondsSinceEpoch ());
			if (!m_IsHiddenMode)
			{	
				m_PublishExcluded.clear ();
				m_PublishReplyToken = 0;
				if (IsFloodfill ())
				{	
					UpdateStats (); // for floodfill
					m_PublishExcluded.insert (i2p::context.GetIdentHash ()); // don't publish to ourselves
				}		
				Publish ();	
				SchedulePublishResend ();
			}	
			else
				SchedulePublish ();
		}	
	}	
	
	void RouterContext::Publish ()
	{		
		if (!i2p::transport::transports.IsOnline ()) return;
		if (m_PublishExcluded.size () > ROUTER_INFO_MAX_PUBLISH_EXCLUDED_FLOODFILLS)
		{
			LogPrint (eLogError, "Router: Couldn't publish our RouterInfo to ", ROUTER_INFO_MAX_PUBLISH_EXCLUDED_FLOODFILLS, " closest routers. Try again");
			m_PublishExcluded.clear ();
			UpdateTimestamp (i2p::util::GetSecondsSinceEpoch ());
		}

		auto floodfill = i2p::data::netdb.GetClosestFloodfill (i2p::context.GetIdentHash (), m_PublishExcluded);
		if (floodfill)
		{
			uint32_t replyToken;
			RAND_bytes ((uint8_t *)&replyToken, 4);
			LogPrint (eLogInfo, "Router: Publishing our RouterInfo to ", i2p::data::GetIdentHashAbbreviation(floodfill->GetIdentHash ()), ". reply token=", replyToken);
			auto onDrop = [this]()
				{
					if (m_Service)
						m_Service->GetService ().post ([this]() { HandlePublishResendTimer (boost::system::error_code ()); });
				};
			if (i2p::transport::transports.IsConnected (floodfill->GetIdentHash ()) || // already connected
				(floodfill->IsReachableFrom (i2p::context.GetRouterInfo ()) && // are we able to connect
				 !i2p::transport::transports.RoutesRestricted ())) // and routes not restricted
			{	
				// send directly
				auto msg = CreateDatabaseStoreMsg (i2p::context.GetSharedRouterInfo (), replyToken);
				msg->onDrop = onDrop;
				i2p::transport::transports.SendMessage (floodfill->GetIdentHash (), msg);
			}	
			else
			{
				// otherwise through exploratory
				auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool ();
				auto outbound = exploratoryPool ? exploratoryPool->GetNextOutboundTunnel (nullptr, floodfill->GetCompatibleTransports (false)) : nullptr;
				auto inbound = exploratoryPool ? exploratoryPool->GetNextInboundTunnel (nullptr, floodfill->GetCompatibleTransports (true)) : nullptr;
				if (inbound && outbound)
				{		
					// encrypt for floodfill
					auto msg = CreateDatabaseStoreMsg (i2p::context.GetSharedRouterInfo (), replyToken, inbound);
					msg->onDrop = onDrop;
					outbound->SendTunnelDataMsgTo (floodfill->GetIdentHash (), 0, 
						i2p::garlic::WrapECIESX25519MessageForRouter (msg, floodfill->GetIdentity ()->GetEncryptionPublicKey ()));
				}	
				else
					LogPrint (eLogInfo, "Router: Can't publish our RouterInfo. No tunnles. Try again in ", ROUTER_INFO_CONFIRMATION_TIMEOUT, " seconds");
			}
			m_PublishExcluded.insert (floodfill->GetIdentHash ());
			m_PublishReplyToken = replyToken;
		}
		else
			LogPrint (eLogInfo, "Router: Can't find floodfill to publish our RouterInfo");
	}

	void RouterContext::SchedulePublishResend ()
	{
		if (m_PublishTimer)
		{
			m_PublishTimer->cancel ();
			m_PublishTimer->expires_from_now (boost::posix_time::seconds(ROUTER_INFO_CONFIRMATION_TIMEOUT));
			m_PublishTimer->async_wait (std::bind (&RouterContext::HandlePublishResendTimer,
				this, std::placeholders::_1));
		}	
		else
			LogPrint (eLogError, "Router: Publish timer is NULL");
	}
	
	void RouterContext::HandlePublishResendTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			i2p::context.UpdateTimestamp (i2p::util::GetSecondsSinceEpoch ());
			Publish ();	
			SchedulePublishResend ();
		}	
	}	

	void RouterContext::ScheduleCongestionUpdate ()
	{
		if (m_CongestionUpdateTimer)
		{	
			m_CongestionUpdateTimer->cancel ();
			m_CongestionUpdateTimer->expires_from_now (boost::posix_time::seconds(ROUTER_INFO_CONGESTION_UPDATE_INTERVAL));
			m_CongestionUpdateTimer->async_wait (std::bind (&RouterContext::HandleCongestionUpdateTimer,
				this, std::placeholders::_1));
		}	
		else
			LogPrint (eLogError, "Router: Congestion update timer is NULL");
	}
		
	void RouterContext::HandleCongestionUpdateTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			UpdateCongestion ();
			ScheduleCongestionUpdate ();
		}	
	}	

	void RouterContext::UpdateCongestion ()
	{
		auto c = i2p::data::RouterInfo::eLowCongestion;
		if (!AcceptsTunnels () || !m_ShareRatio)
			c = i2p::data::RouterInfo::eRejectAll;
		else
		{
			int congestionLevel = GetCongestionLevel (true);
			if (congestionLevel > CONGESTION_LEVEL_HIGH)
				c = i2p::data::RouterInfo::eHighCongestion;
			else if (congestionLevel > CONGESTION_LEVEL_MEDIUM)
				c = i2p::data::RouterInfo::eMediumCongestion;
		}
		if (m_RouterInfo.UpdateCongestion (c))
			UpdateRouterInfo ();
	}	
		
	void RouterContext::ScheduleCleanupTimer ()
	{
		if (m_CleanupTimer)
		{	
			m_CleanupTimer->cancel ();
			m_CleanupTimer->expires_from_now (boost::posix_time::minutes(ROUTER_INFO_CLEANUP_INTERVAL));
			m_CleanupTimer->async_wait (std::bind (&RouterContext::HandleCleanupTimer,
				this, std::placeholders::_1));
		}	
		else
			LogPrint (eLogError, "Router: Cleanup timer is NULL");
	}	

	void RouterContext::HandleCleanupTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			CleanupExpiredTags ();
			ScheduleCleanupTimer ();
		}	
	}	
}
