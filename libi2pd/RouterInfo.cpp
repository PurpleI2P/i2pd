/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <stdio.h>
#include <string.h>
#include "I2PEndian.h"
#include <fstream>
#include <boost/lexical_cast.hpp>
#include <boost/make_shared.hpp>
#if (BOOST_VERSION >= 105300)
#include <boost/atomic.hpp>
#endif
#include "version.h"
#include "util.h"
#include "Crypto.h"
#include "Base.h"
#include "Timestamp.h"
#include "Log.h"
#include "NetDb.hpp"
#include "RouterContext.h"
#include "RouterInfo.h"

namespace i2p
{
namespace data
{
	RouterInfo::Buffer::Buffer (const uint8_t * buf, size_t len)
	{
		if (len > size ()) len = size ();
		memcpy (data (), buf, len);
	}

	RouterInfo::RouterInfo (): m_Buffer (nullptr)
	{
		m_Addresses = boost::make_shared<Addresses>(); // create empty list
	}

	RouterInfo::RouterInfo (const std::string& fullPath):
		m_FamilyID (0), m_IsUpdated (false), m_IsUnreachable (false),
		m_SupportedTransports (0),m_ReachableTransports (0),
		m_Caps (0), m_Version (0)
	{
		m_Addresses = boost::make_shared<Addresses>(); // create empty list
		m_Buffer = NewBuffer (); // always RouterInfo's
		ReadFromFile (fullPath);
	}

	RouterInfo::RouterInfo (std::shared_ptr<Buffer>&& buf, size_t len):
		m_FamilyID (0), m_IsUpdated (true), m_IsUnreachable (false),
		m_SupportedTransports (0), m_ReachableTransports (0),
		m_Caps (0), m_Version (0)
	{
		if (len <= MAX_RI_BUFFER_SIZE)
		{
			m_Addresses = boost::make_shared<Addresses>(); // create empty list
			m_Buffer = buf;
			m_BufferLen = len;
			ReadFromBuffer (true);
		}
		else
		{
			LogPrint (eLogError, "RouterInfo: Buffer is too long ", len, ". Ignored");
			m_Buffer = nullptr;
			m_IsUnreachable = true;
		}
	}

	RouterInfo::RouterInfo (const uint8_t * buf, size_t len):
		RouterInfo (std::make_shared<Buffer> (buf, len), len)
	{
	}

	RouterInfo::~RouterInfo ()
	{
	}

	void RouterInfo::Update (const uint8_t * buf, size_t len)
	{
		if (len > MAX_RI_BUFFER_SIZE)
		{
			LogPrint (eLogError, "RouterInfo: Buffer is too long ", len);
			m_IsUnreachable = true;
			return;
		}
		// verify signature since we have identity already
		int l = len - m_RouterIdentity->GetSignatureLen ();
		if (m_RouterIdentity->Verify (buf, l, buf + l))
		{
			// clean up
			m_IsUpdated = true;
			m_IsUnreachable = false;
			m_SupportedTransports = 0;
			m_ReachableTransports = 0;
			m_Caps = 0;
			// don't clean up m_Addresses, it will be replaced in ReadFromStream
			ClearProperties ();
			// copy buffer
			UpdateBuffer (buf, len);
			// skip identity
			size_t identityLen = m_RouterIdentity->GetFullLen ();
			// read new RI
			std::stringstream str (std::string ((char *)m_Buffer->data () + identityLen, m_BufferLen - identityLen));
			ReadFromStream (str);
			// don't delete buffer until saved to the file
		}
		else
		{
			LogPrint (eLogError, "RouterInfo: Signature verification failed");
			m_IsUnreachable = true;
		}
	}

	void RouterInfo::SetRouterIdentity (std::shared_ptr<const IdentityEx> identity)
	{
		m_RouterIdentity = identity;
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch ();
	}

	bool RouterInfo::LoadFile (const std::string& fullPath)
	{
		std::ifstream s(fullPath, std::ifstream::binary);
		if (s.is_open ())
		{
			s.seekg (0,std::ios::end);
			m_BufferLen = s.tellg ();
			if (m_BufferLen < 40 || m_BufferLen > MAX_RI_BUFFER_SIZE)
			{
				LogPrint(eLogError, "RouterInfo: File", fullPath, " is malformed");
				return false;
			}
			s.seekg(0, std::ios::beg);
			if (!m_Buffer)
				m_Buffer = NewBuffer ();
			s.read((char *)m_Buffer->data (), m_BufferLen);
		}
		else
		{
			LogPrint (eLogError, "RouterInfo: Can't open file ", fullPath);
			return false;
		}
		return true;
	}

	void RouterInfo::ReadFromFile (const std::string& fullPath)
	{
		if (LoadFile (fullPath))
			ReadFromBuffer (false);
		else
			m_IsUnreachable = true;
	}

	void RouterInfo::ReadFromBuffer (bool verifySignature)
	{
		if (!m_Buffer)
		{
			m_IsUnreachable = true;
			return;
		}
		m_RouterIdentity = std::make_shared<IdentityEx>(m_Buffer->data (), m_BufferLen);
		size_t identityLen = m_RouterIdentity->GetFullLen ();
		if (identityLen >= m_BufferLen)
		{
			LogPrint (eLogError, "RouterInfo: Identity length ", identityLen, " exceeds buffer size ", m_BufferLen);
			m_IsUnreachable = true;
			return;
		}
		if (verifySignature)
		{
			// reject RSA signatures
			if (m_RouterIdentity->IsRSA ())
			{
				LogPrint (eLogError, "RouterInfo: RSA signature type is not allowed");
				m_IsUnreachable = true;
				return;
			}
			// verify signature
			int l = m_BufferLen - m_RouterIdentity->GetSignatureLen ();
			if (l < 0 || !m_RouterIdentity->Verify ((uint8_t *)m_Buffer->data (), l, (uint8_t *)m_Buffer->data () + l))
			{
				LogPrint (eLogError, "RouterInfo: Signature verification failed");
				m_IsUnreachable = true;
				return;
			}
			m_RouterIdentity->DropVerifier ();
		}
		// parse RI
		std::stringstream str;
		str.write ((const char *)m_Buffer->data () + identityLen, m_BufferLen - identityLen);
		ReadFromStream (str);
		if (!str)
		{
			LogPrint (eLogError, "RouterInfo: Malformed message");
			m_IsUnreachable = true;
		}
	}

	void RouterInfo::ReadFromStream (std::istream& s)
	{
		if (!s) return;
		m_Caps = 0;
		s.read ((char *)&m_Timestamp, sizeof (m_Timestamp));
		m_Timestamp = be64toh (m_Timestamp);
		// read addresses
		auto addresses = boost::make_shared<Addresses>();
		uint8_t numAddresses;
		s.read ((char *)&numAddresses, sizeof (numAddresses));
		addresses->reserve (numAddresses);
		for (int i = 0; i < numAddresses; i++)
		{
			uint8_t supportedTransports = 0;
			auto address = std::make_shared<Address> ();
			uint8_t cost; // ignore
			s.read ((char *)&cost, sizeof (cost));
			s.read ((char *)&address->date, sizeof (address->date));
			bool isHost = false, isIntroKey = false, isStaticKey = false, isV2 = false;
			Tag<32> iV2; // for 'i' field in SSU, TODO: remove later
			char transportStyle[6];
			ReadString (transportStyle, 6, s);
			if (!strncmp (transportStyle, "NTCP", 4)) // NTCP or NTCP2
				address->transportStyle = eTransportNTCP;
			else if (!strncmp (transportStyle, "SSU", 3)) // SSU or SSU2
			{
				address->transportStyle = (transportStyle[3] == '2') ? eTransportSSU2 : eTransportSSU;
				address->ssu.reset (new SSUExt ());
				address->ssu->mtu = 0;
			}
			else
				address->transportStyle = eTransportUnknown;
			address->caps = 0;
			address->port = 0;
			uint16_t size, r = 0;
			s.read ((char *)&size, sizeof (size)); if (!s) return;
			size = be16toh (size);
			if (address->transportStyle == eTransportUnknown)
			{
				// skip unknown address
				s.seekg (size, std::ios_base::cur);
				if (s) continue; else return;
			}
			while (r < size)
			{
				char key[255], value[255];
				r += ReadString (key, 255, s);
				s.seekg (1, std::ios_base::cur); r++; // =
				r += ReadString (value, 255, s);
				s.seekg (1, std::ios_base::cur); r++; // ;
				if (!s) return;
				if (!strcmp (key, "host"))
				{
					boost::system::error_code ecode;
					address->host = boost::asio::ip::address::from_string (value, ecode);
					if (!ecode && !address->host.is_unspecified ()) isHost = true;
				}
				else if (!strcmp (key, "port"))
					address->port = boost::lexical_cast<int>(value);
				else if (!strcmp (key, "mtu"))
				{
					if (address->ssu)
						address->ssu->mtu = boost::lexical_cast<int>(value);
					else
						LogPrint (eLogWarning, "RouterInfo: Unexpected field 'mtu' for NTCP");
				}
				else if (!strcmp (key, "key"))
				{
					if (address->ssu)
						isIntroKey = (Base64ToByteStream (value, strlen (value), address->i, 32) == 32);
					else
						LogPrint (eLogWarning, "RouterInfo: Unexpected field 'key' for NTCP");
				}
				else if (!strcmp (key, "caps"))
					address->caps = ExtractAddressCaps (value);
				else if (!strcmp (key, "s")) // ntcp2 or ssu2 static key
				{
					Base64ToByteStream (value, strlen (value), address->s, 32);
					isStaticKey = true;
				}
				else if (!strcmp (key, "i")) // ntcp2 iv or ssu2 intro
				{
					if (address->IsNTCP2 ())
					{
						Base64ToByteStream (value, strlen (value), address->i, 16);
						address->published = true; // presence of "i" means "published" NTCP2
					}
					else if (address->IsSSU2 ())
						Base64ToByteStream (value, strlen (value), address->i, 32);
					else
						Base64ToByteStream (value, strlen (value), iV2, 32);
				}
				else if (!strcmp (key, "v"))
				{
					if (!strcmp (value, "2"))
						isV2 = true;
					else
						LogPrint (eLogWarning, "RouterInfo: Unexpected value ", value, " for v");
				}
				else if (key[0] == 'i')
				{
					// introducers
					if (!address->ssu)
					{
						LogPrint (eLogError, "RouterInfo: Introducer is presented for non-SSU address. Skipped");
						continue;
					}
					size_t l = strlen(key);
					unsigned char index = key[l-1] - '0'; // TODO:
					key[l-1] = 0;
					if (index > 9)
					{
						LogPrint (eLogError, "RouterInfo: Unexpected introducer's index ", index, " skipped");
						if (s) continue; else return;
					}
					if (index >= address->ssu->introducers.size ())
					{
						if (address->ssu->introducers.empty ()) // first time
							address->ssu->introducers.reserve (3);
						address->ssu->introducers.resize (index + 1);
					}
					Introducer& introducer = address->ssu->introducers.at (index);
					if (!strcmp (key, "ihost"))
					{
						boost::system::error_code ecode;
						introducer.iHost = boost::asio::ip::address::from_string (value, ecode);
					}
					else if (!strcmp (key, "iport"))
						introducer.iPort = boost::lexical_cast<int>(value);
					else if (!strcmp (key, "itag"))
						introducer.iTag = boost::lexical_cast<uint32_t>(value);
					else if (!strcmp (key, "ikey") || !strcmp (key, "ih"))
						Base64ToByteStream (value, strlen (value), introducer.iKey, 32);
					else if (!strcmp (key, "iexp"))
						introducer.iExp = boost::lexical_cast<uint32_t>(value);
				}
				if (!s) return;
			}
			if (address->transportStyle == eTransportNTCP)
			{
				if (isStaticKey)
				{
					if (isHost)
					{
						if (address->host.is_v6 ())
							supportedTransports |= (i2p::util::net::IsYggdrasilAddress (address->host) ? eNTCP2V6Mesh : eNTCP2V6);
						else
							supportedTransports |= eNTCP2V4;
						m_ReachableTransports |= supportedTransports;
					}
					else if (!address->published)
					{
						if (address->caps)
						{
							if (address->caps & AddressCaps::eV4) supportedTransports |= eNTCP2V4;
							if (address->caps & AddressCaps::eV6) supportedTransports |= eNTCP2V6;
						}
						else
							supportedTransports |= eNTCP2V4; // most likely, since we don't have host
					}
				}
			}
			else if (address->transportStyle == eTransportSSU)
			{
				if (isIntroKey)
				{
					if (isHost)
						supportedTransports |= address->host.is_v4 () ? eSSUV4 : eSSUV6;
					else if (address->caps & AddressCaps::eV6)
					{
						supportedTransports |= eSSUV6;
						if (address->caps & AddressCaps::eV4) supportedTransports |= eSSUV4; // in additional to v6
					}
					else
						supportedTransports |= eSSUV4; // in case if host or 6 caps is not preasented, we assume 4
					if (address->ssu && !address->ssu->introducers.empty ())
					{
						// exclude invalid introducers
						uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
						int numValid = 0;
						for (auto& it: address->ssu->introducers)
						{
							if (!it.iExp) it.iExp = m_Timestamp/1000 + NETDB_INTRODUCEE_EXPIRATION_TIMEOUT;
							if (ts <= it.iExp && it.iPort > 0 &&
								((it.iHost.is_v4 () && address->IsV4 ()) || (it.iHost.is_v6 () && address->IsV6 ())))
								numValid++;
							else
								it.iPort = 0;
						}
						if (numValid)
							m_ReachableTransports |= supportedTransports;
						else
							address->ssu->introducers.resize (0);
					}
					else if (isHost && address->port)
					{
						address->published = true;
						m_ReachableTransports |= supportedTransports;
					}
				}
			}
			if (address->transportStyle == eTransportSSU2 || (isV2 && address->transportStyle == eTransportSSU))
			{
				if (address->IsV4 ()) supportedTransports |= eSSU2V4;
				if (address->IsV6 ()) supportedTransports |= eSSU2V6;
				if (address->port)
				{
					if (address->host.is_v4 ()) m_ReachableTransports |= eSSU2V4;
					if (address->host.is_v6 ()) m_ReachableTransports |= eSSU2V6;
				}
			}
			if (supportedTransports)
			{
				if (!(m_SupportedTransports & supportedTransports)) // avoid duplicates
				{
					addresses->push_back(address);
					if (address->transportStyle == eTransportSSU && isV2)
					{
						// create additional SSU2 address. TODO: remove later
						auto ssu2addr = std::make_shared<Address> ();
						ssu2addr->transportStyle = eTransportSSU2;
						ssu2addr->host = address->host; ssu2addr->port = address->port;
						ssu2addr->s = address->s; ssu2addr->i = iV2;
						ssu2addr->date = address->date; ssu2addr->caps = address->caps;
						ssu2addr->published = address->published;
						ssu2addr->ssu.reset (new SSUExt ()); ssu2addr->ssu->mtu = address->ssu->mtu;
						for (const auto& introducer: address->ssu->introducers)
							if (!introducer.iPort) // SSU2
								ssu2addr->ssu->introducers.push_back (introducer);
						addresses->push_back(ssu2addr);
					}
				}
				m_SupportedTransports |= supportedTransports;
			}
		}
#if (BOOST_VERSION >= 105300)
		boost::atomic_store (&m_Addresses, addresses);
#else
		m_Addresses = addresses; // race condition
#endif
		// read peers
		uint8_t numPeers;
		s.read ((char *)&numPeers, sizeof (numPeers)); if (!s) return;
		s.seekg (numPeers*32, std::ios_base::cur); // TODO: read peers
		// read properties
		m_Version = 0;
		bool isNetId = false;
		std::string family;
		uint16_t size, r = 0;
		s.read ((char *)&size, sizeof (size)); if (!s) return;
		size = be16toh (size);
		while (r < size)
		{
			char key[255], value[255];
			r += ReadString (key, 255, s);
			s.seekg (1, std::ios_base::cur); r++; // =
			r += ReadString (value, 255, s);
			s.seekg (1, std::ios_base::cur); r++; // ;
			if (!s) return;
			SetProperty (key, value);

			// extract caps
			if (!strcmp (key, "caps"))
				ExtractCaps (value);
			// extract version
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_VERSION))
			{
				m_Version = 0;
				char * ch = value;
				while (*ch)
				{
					if (*ch >= '0' && *ch <= '9')
					{
						m_Version *= 10;
						m_Version += (*ch - '0');
					}
					ch++;
				}
			}
			// check netId
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_NETID))
			{
				isNetId = true;
				if (atoi (value) != i2p::context.GetNetID ())
				{
					LogPrint (eLogError, "RouterInfo: Unexpected ", ROUTER_INFO_PROPERTY_NETID, "=", value);
					m_IsUnreachable = true;
				}
			}
			// family
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_FAMILY))
			{
				family = value;
				boost::to_lower (family);
			}
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_FAMILY_SIG))
			{
				if (netdb.GetFamilies ().VerifyFamily (family, GetIdentHash (), value))
					m_FamilyID = netdb.GetFamilies ().GetFamilyID (family);
				else
					LogPrint (eLogWarning, "RouterInfo: Family ", family, " signature verification failed");
			}

			if (!s) return;
		}

		if (!m_SupportedTransports || !isNetId || !m_Version)
			SetUnreachable (true);
	}

	bool RouterInfo::IsFamily (FamilyID famid) const
	{
		return m_FamilyID == famid;
	}

	void RouterInfo::ExtractCaps (const char * value)
	{
		const char * cap = value;
		while (*cap)
		{
			switch (*cap)
			{
				case CAPS_FLAG_FLOODFILL:
					m_Caps |= Caps::eFloodfill;
				break;
				case CAPS_FLAG_HIGH_BANDWIDTH1:
				case CAPS_FLAG_HIGH_BANDWIDTH2:
				case CAPS_FLAG_HIGH_BANDWIDTH3:
					m_Caps |= Caps::eHighBandwidth;
				break;
				case CAPS_FLAG_EXTRA_BANDWIDTH1:
				case CAPS_FLAG_EXTRA_BANDWIDTH2:
					m_Caps |= Caps::eExtraBandwidth | Caps::eHighBandwidth;
				break;
				case CAPS_FLAG_HIDDEN:
					m_Caps |= Caps::eHidden;
				break;
				case CAPS_FLAG_REACHABLE:
					m_Caps |= Caps::eReachable;
				break;
				case CAPS_FLAG_UNREACHABLE:
					m_Caps |= Caps::eUnreachable;
				break;
				default: ;
			}
			cap++;
		}
	}

	uint8_t RouterInfo::ExtractAddressCaps (const char * value) const
	{
		uint8_t caps = 0;
		const char * cap = value;
		while (*cap)
		{
			switch (*cap)
			{
				case CAPS_FLAG_V4:
					caps |= AddressCaps::eV4;
				break;
				case CAPS_FLAG_V6:
					caps |= AddressCaps::eV6;
				break;
				case CAPS_FLAG_SSU_TESTING:
					caps |= AddressCaps::eSSUTesting;
				break;
				case CAPS_FLAG_SSU_INTRODUCER:
					caps |= AddressCaps::eSSUIntroducer;
				break;
				default: ;
			}
			cap++;
		}
		return caps;
	}

	bool RouterInfo::IsNewer (const uint8_t * buf, size_t len) const
	{
		if (!m_RouterIdentity) return false;
		size_t size = m_RouterIdentity->GetFullLen ();
		if (size + 8 > len) return false;
		return bufbe64toh (buf + size) > m_Timestamp;
	}

	const uint8_t * RouterInfo::LoadBuffer (const std::string& fullPath)
	{
		if (!m_Buffer)
		{
			if (LoadFile (fullPath))
				LogPrint (eLogDebug, "RouterInfo: Buffer for ", GetIdentHashAbbreviation (GetIdentHash ()), " loaded from file");
		}
		return m_Buffer->data ();
	}

	bool RouterInfo::SaveToFile (const std::string& fullPath)
	{
		if (!m_Buffer)
		{
			LogPrint (eLogError, "RouterInfo: Can't save, m_Buffer == NULL");
			return false;
		}
		std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
		if (!f.is_open ()) {
			LogPrint(eLogError, "RouterInfo: Can't save to ", fullPath);
			return false;
		}
		f.write ((char *)m_Buffer->data (), m_BufferLen);
		return true;
	}

	size_t RouterInfo::ReadString (char * str, size_t len, std::istream& s) const
	{
		uint8_t l;
		s.read ((char *)&l, 1);
		if (l < len)
		{
			s.read (str, l);
			if (!s) l = 0; // failed, return empty string
			str[l] = 0;
		}
		else
		{
			LogPrint (eLogWarning, "RouterInfo: String length ", (int)l, " exceeds buffer size ", len);
			s.seekg (l, std::ios::cur); // skip
			str[0] = 0;
		}
		return l+1;
	}


	void RouterInfo::AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu)
	{
		auto addr = std::make_shared<Address>();
		addr->host = boost::asio::ip::address::from_string (host);
		addr->port = port;
		addr->transportStyle = eTransportSSU;
		addr->published = true;
		addr->caps = i2p::data::RouterInfo::eSSUTesting | i2p::data::RouterInfo::eSSUIntroducer; // BC;
		addr->date = 0;
		addr->ssu.reset (new SSUExt ());
		addr->ssu->mtu = mtu;
		if (key)
			memcpy (addr->i, key, 32);
		else
			RAND_bytes (addr->i, 32);
		for (const auto& it: *m_Addresses) // don't insert same address twice
			if (*it == *addr) return;
		m_SupportedTransports |= addr->host.is_v6 () ? eSSUV6 : eSSUV4;
		m_ReachableTransports |= addr->host.is_v6 () ? eSSUV6 : eSSUV4;
		m_Addresses->push_back(std::move(addr));
	}

	void RouterInfo::AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv,
		const boost::asio::ip::address& host, int port, uint8_t caps)
	{
		auto addr = std::make_shared<Address>();
		addr->host = host;
		addr->port = port;
		addr->transportStyle = eTransportNTCP;
		addr->caps = caps;
		addr->date = 0;
		if (port) addr->published = true;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, iv, 16);
		if (addr->IsV4 ())
		{
			m_SupportedTransports |= eNTCP2V4;
			if (addr->published) m_ReachableTransports |= eNTCP2V4;
		}
		if (addr->IsV6 ())
		{
			m_SupportedTransports |= eNTCP2V6;
			if (addr->published) m_ReachableTransports |= eNTCP2V6;
		}
		m_Addresses->push_back(std::move(addr));
	}

	void RouterInfo::AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey, uint8_t caps)
	{
		auto addr = std::make_shared<Address>();
		addr->transportStyle = eTransportSSU2;
		addr->caps = caps;
		addr->date = 0;
		addr->ssu.reset (new SSUExt ());
		addr->ssu->mtu = 0;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, introKey, 32);
		if (addr->IsV4 ()) m_SupportedTransports |= eSSU2V4;
		if (addr->IsV6 ()) m_SupportedTransports |= eSSU2V6;
		m_Addresses->push_back(std::move(addr));
	}

	void RouterInfo::AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey,
		const boost::asio::ip::address& host, int port)
	{
		auto addr = std::make_shared<Address>();
		addr->transportStyle = eTransportSSU2;
		addr->host = host;
		addr->port = port;
		addr->published = true;
		addr->caps = 0;
		addr->date = 0;
		addr->ssu.reset (new SSUExt ());
		addr->ssu->mtu = 0;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, introKey, 32);
		if (addr->IsV4 ())
		{
			m_SupportedTransports |= eSSU2V4;
			m_ReachableTransports |= eSSU2V4;
		}
		if (addr->IsV6 ())
		{
			m_SupportedTransports |= eSSU2V6;
			m_ReachableTransports |= eSSU2V6;
		}
		m_Addresses->push_back(std::move(addr));
	}

	bool RouterInfo::AddIntroducer (const Introducer& introducer)
	{
		for (auto& addr : *m_Addresses)
		{
			if (addr->transportStyle == eTransportSSU &&
				((addr->IsV4 () && introducer.iHost.is_v4 ()) || (addr->IsV6 () && introducer.iHost.is_v6 ())))
			{
				for (auto& intro: addr->ssu->introducers)
					if (intro.iTag == introducer.iTag) return false; // already presented
				addr->ssu->introducers.push_back (introducer);
				m_ReachableTransports |= (addr->IsV4 () ? eSSUV4 : eSSUV6);
				return true;
			}
		}
		return false;
	}

	bool RouterInfo::RemoveIntroducer (const boost::asio::ip::udp::endpoint& e)
	{
		for (auto& addr: *m_Addresses)
		{
			if (addr->transportStyle == eTransportSSU &&
				((addr->IsV4 () && e.address ().is_v4 ()) || (addr->IsV6 () && e.address ().is_v6 ())))
			{
				for (auto it = addr->ssu->introducers.begin (); it != addr->ssu->introducers.end (); ++it)
					if (boost::asio::ip::udp::endpoint (it->iHost, it->iPort) == e)
					{
						addr->ssu->introducers.erase (it);
						if (addr->ssu->introducers.empty ())
							m_ReachableTransports &= ~(addr->IsV4 () ? eSSUV4 : eSSUV6);
						return true;
					}
			}
		}
		return false;
	}

	bool RouterInfo::IsSSU (bool v4only) const
	{
		if (v4only)
			return m_SupportedTransports & eSSUV4;
		else
			return m_SupportedTransports & (eSSUV4 | eSSUV6);
	}

	bool RouterInfo::IsNTCP2 (bool v4only) const
	{
		if (v4only)
			return m_SupportedTransports & eNTCP2V4;
		else
			return m_SupportedTransports & (eNTCP2V4 | eNTCP2V6);
	}


	void RouterInfo::EnableV6 ()
	{
		if (!IsV6 ())
		{
			uint8_t addressCaps = AddressCaps::eV6;
			if (IsV4 ()) addressCaps |= AddressCaps::eV4;
			SetUnreachableAddressesTransportCaps (addressCaps);
			UpdateSupportedTransports ();
		}
	}

	void RouterInfo::EnableV4 ()
	{
		if (!IsV4 ())
		{
			uint8_t addressCaps = AddressCaps::eV4;
			if (IsV6 ()) addressCaps |= AddressCaps::eV6;
			SetUnreachableAddressesTransportCaps (addressCaps);
			UpdateSupportedTransports ();
		}
	}


	void RouterInfo::DisableV6 ()
	{
		if (IsV6 ())
		{
			for (auto it = m_Addresses->begin (); it != m_Addresses->end ();)
			{
				auto addr = *it;
				if (addr->IsV6 ())
				{
					if (addr->IsV4 ())
					{
						addr->caps &= ~AddressCaps::eV6;
						++it;
					}
					else
						it = m_Addresses->erase (it);
				}
				else
					++it;
			}
			UpdateSupportedTransports ();
		}
	}

	void RouterInfo::DisableV4 ()
	{
		if (IsV4 ())
		{
			for (auto it = m_Addresses->begin (); it != m_Addresses->end ();)
			{
				auto addr = *it;
				if (addr->IsV4 ())
				{
					if (addr->IsV6 ())
					{
						addr->caps &= ~AddressCaps::eV4;
						++it;
					}
					else
						it = m_Addresses->erase (it);
				}
				else
					++it;
			}
			UpdateSupportedTransports ();
		}
	}

	void RouterInfo::EnableMesh ()
	{
		if (!IsMesh ())
		{
			m_SupportedTransports |= eNTCP2V6Mesh;
			m_ReachableTransports |= eNTCP2V6Mesh;
		}
	}

	void RouterInfo::DisableMesh ()
	{
		if (IsMesh ())
		{
			m_SupportedTransports &= ~eNTCP2V6Mesh;
			m_ReachableTransports &= ~eNTCP2V6Mesh;
			for (auto it = m_Addresses->begin (); it != m_Addresses->end ();)
			{
				auto addr = *it;
				if (i2p::util::net::IsYggdrasilAddress (addr->host))
					it = m_Addresses->erase (it);
				else
					++it;
			}
		}
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSUAddress (bool v4only) const
	{
		return GetAddress (
			[v4only](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU) && (!v4only || address->IsV4 ());
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSUV6Address () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU) && address->IsV6();
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSU2V4Address () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU2) && address->IsV4();
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSU2V6Address () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU2) && address->IsV6();
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSU2Address (bool v4) const
	{
		if (v4)
		{	
			if (m_SupportedTransports & eSSU2V4)
				return GetSSU2V4Address ();
		}
		else
		{
			if (m_SupportedTransports & eSSU2V6)
				return GetSSU2V6Address ();
		}	
		return nullptr;
	}	
		
	template<typename Filter>
	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetAddress (Filter filter) const
	{
		// TODO: make it more generic using comparator
#if (BOOST_VERSION >= 105300)
		auto addresses = boost::atomic_load (&m_Addresses);
#else
		auto addresses = m_Addresses;
#endif
		for (const auto& address : *addresses)
			if (filter (address)) return address;

		return nullptr;
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetNTCP2AddressWithStaticKey (const uint8_t * key) const
	{
		if (!key) return nullptr;
		return GetAddress (
			[key](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return address->IsNTCP2 () && !memcmp (address->s, key, 32);
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSU2AddressWithStaticKey (const uint8_t * key, bool isV6) const
	{
		if (!key) return nullptr;
		return GetAddress (
			[key, isV6](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return address->IsSSU2 () && !memcmp (address->s, key, 32) && address->IsV6 () == isV6;
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetPublishedNTCP2V4Address () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return address->IsPublishedNTCP2 () && address->host.is_v4 ();
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetPublishedNTCP2V6Address () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return address->IsPublishedNTCP2 () && address->host.is_v6 () &&
					!i2p::util::net::IsYggdrasilAddress (address->host);
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetYggdrasilAddress () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return address->IsPublishedNTCP2 () && i2p::util::net::IsYggdrasilAddress (address->host);
			});
	}

	std::shared_ptr<RouterProfile> RouterInfo::GetProfile () const
	{
		if (!m_Profile)
			m_Profile = GetRouterProfile (GetIdentHash ());
		return m_Profile;
	}

	void RouterInfo::Encrypt (const uint8_t * data, uint8_t * encrypted) const
	{
		auto encryptor = m_RouterIdentity->CreateEncryptor (nullptr);
		if (encryptor)
			encryptor->Encrypt (data, encrypted);
	}

	bool RouterInfo::IsEligibleFloodfill () const
	{
		// floodfill must be reachable by ipv4, >= 0.9.38 and not DSA
		return IsReachableBy (eNTCP2V4 | eSSUV4) && m_Version >= NETDB_MIN_FLOODFILL_VERSION &&
			GetIdentity ()->GetSigningKeyType () != SIGNING_KEY_TYPE_DSA_SHA1;
	}

	bool RouterInfo::IsPeerTesting (bool v4) const
	{
		if (!(m_SupportedTransports & (v4 ? eSSUV4 : eSSUV6))) return false;
		return (bool)GetAddress (
			[v4](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU) && address->IsPeerTesting () &&
					((v4 && address->IsV4 ()) || (!v4 && address->IsV6 ())) && address->IsReachableSSU ();
			});
	}

	bool RouterInfo::IsSSU2PeerTesting (bool v4) const
	{
		if (!(m_SupportedTransports & (v4 ? eSSU2V4 : eSSU2V6))) return false;
		return (bool)GetAddress (
			[v4](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->IsSSU2 ()) && address->IsPeerTesting () &&
					((v4 && address->IsV4 ()) || (!v4 && address->IsV6 ())) && address->IsReachableSSU ();
			});
	}	
		
	bool RouterInfo::IsIntroducer (bool v4) const
	{
		if (!(m_SupportedTransports & (v4 ? eSSUV4 : eSSUV6))) return false;
		return (bool)GetAddress (
			[v4](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU) && address->IsIntroducer () &&
					((v4 && address->IsV4 ()) || (!v4 && address->IsV6 ())) && !address->host.is_unspecified ();
			});
	}

	void RouterInfo::SetUnreachableAddressesTransportCaps (uint8_t transports)
	{
		for (auto& addr: *m_Addresses)
		{
			// TODO: implement SSU
			if (!addr->published && (addr->transportStyle == eTransportNTCP || addr->transportStyle == eTransportSSU2))
			{
				addr->caps &= ~(eV4 | eV6);
				addr->caps |= transports;
			}
		}
	}

	void RouterInfo::UpdateSupportedTransports ()
	{
		m_SupportedTransports = 0;
		m_ReachableTransports = 0;
		for (const auto& addr: *m_Addresses)
		{
			uint8_t transports = 0;
			switch (addr->transportStyle)
			{        
				case eTransportNTCP:
					if (addr->IsV4 ()) transports |= eNTCP2V4;
					if (addr->IsV6 ())
						transports |= (i2p::util::net::IsYggdrasilAddress (addr->host) ? eNTCP2V6Mesh : eNTCP2V6);
					if (addr->IsPublishedNTCP2 ())
						m_ReachableTransports |= transports;
				break;
				case eTransportSSU:
					if (addr->IsV4 ()) transports |= eSSUV4;
					if (addr->IsV6 ()) transports |= eSSUV6;
					if (addr->IsReachableSSU ())
						m_ReachableTransports |= transports;
				break;
				case eTransportSSU2:
					if (addr->IsV4 ()) transports |= eSSU2V4;
					if (addr->IsV6 ()) transports |= eSSU2V6;
					if (addr->IsReachableSSU ())
						m_ReachableTransports |= transports;
				break;	
				default: ;	
			}	
			m_SupportedTransports |= transports;
		}
	}

	void RouterInfo::UpdateBuffer (const uint8_t * buf, size_t len)
	{
		if (!m_Buffer)
			m_Buffer = NewBuffer ();
		if (len > m_Buffer->size ()) len = m_Buffer->size ();
		memcpy (m_Buffer->data (), buf, len);
		m_BufferLen = len;
	}

	std::shared_ptr<RouterInfo::Buffer> RouterInfo::NewBuffer () const
	{
		return netdb.NewRouterInfoBuffer ();
	}

	void RouterInfo::RefreshTimestamp ()
	{
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch ();
	}

	void LocalRouterInfo::CreateBuffer (const PrivateKeys& privateKeys)
	{
		RefreshTimestamp ();
		std::stringstream s;
		uint8_t ident[1024];
		auto identLen = privateKeys.GetPublic ()->ToBuffer (ident, 1024);
		auto signatureLen = privateKeys.GetPublic ()->GetSignatureLen ();
		s.write ((char *)ident, identLen);
		WriteToStream (s);
		size_t len = s.str ().size ();
		if (len + signatureLen < MAX_RI_BUFFER_SIZE)
		{
			UpdateBuffer ((const uint8_t *)s.str ().c_str (), len);
			// signature
			privateKeys.Sign (GetBuffer (), len, GetBufferPointer (len));
			SetBufferLen (len + signatureLen);
		}
		else
			LogPrint (eLogError, "RouterInfo: Our RouterInfo is too long ", len + signatureLen);
	}

	void LocalRouterInfo::UpdateCaps (uint8_t caps)
	{
		SetCaps (caps);
		UpdateCapsProperty ();
	}

	void LocalRouterInfo::UpdateCapsProperty ()
	{
		std::string caps;
		uint8_t c = GetCaps ();
		if (c & eFloodfill)
		{
			if (c & eExtraBandwidth) caps += (c & eHighBandwidth) ?
				CAPS_FLAG_EXTRA_BANDWIDTH2 : // 'X'
				CAPS_FLAG_EXTRA_BANDWIDTH1; // 'P'
			else
				caps += CAPS_FLAG_HIGH_BANDWIDTH3; // 'O'
			caps += CAPS_FLAG_FLOODFILL; // floodfill
		}
		else
		{
			if (c & eExtraBandwidth)
				caps += (c & eHighBandwidth) ? CAPS_FLAG_EXTRA_BANDWIDTH2 /* 'X' */ : CAPS_FLAG_EXTRA_BANDWIDTH1; /*'P' */
			else
				caps += (c & eHighBandwidth) ? CAPS_FLAG_HIGH_BANDWIDTH3 /* 'O' */: CAPS_FLAG_LOW_BANDWIDTH2 /* 'L' */; // bandwidth
		}
		if (c & eHidden) caps += CAPS_FLAG_HIDDEN; // hidden
		if (c & eReachable) caps += CAPS_FLAG_REACHABLE; // reachable
		if (c & eUnreachable) caps += CAPS_FLAG_UNREACHABLE; // unreachable

		SetProperty ("caps", caps);
	}

	void LocalRouterInfo::WriteToStream (std::ostream& s) const
	{
		uint64_t ts = htobe64 (GetTimestamp ());
		s.write ((const char *)&ts, sizeof (ts));

		// addresses
		const Addresses& addresses = GetAddresses ();
		uint8_t numAddresses = addresses.size ();
		s.write ((char *)&numAddresses, sizeof (numAddresses));
		for (const auto& addr_ptr : addresses)
		{
			const Address& address = *addr_ptr;
			// calculate cost
			uint8_t cost = 0x7f;
			if (address.transportStyle == eTransportNTCP)
				cost = address.published ? COST_NTCP2_PUBLISHED : COST_NTCP2_NON_PUBLISHED;
			else if (address.transportStyle == eTransportSSU)
				cost = address.published ? COST_SSU_DIRECT : COST_SSU_THROUGH_INTRODUCERS;
			else if (address.transportStyle == eTransportSSU2)
				cost = address.published ? COST_SSU2_DIRECT : COST_SSU2_NON_PUBLISHED;
			s.write ((const char *)&cost, sizeof (cost));
			s.write ((const char *)&address.date, sizeof (address.date));
			std::stringstream properties;
			bool isPublished = false;
			if (address.transportStyle == eTransportNTCP)
			{
				if (address.IsNTCP2 ())
				{
					WriteString ("NTCP2", s);
					if (address.IsPublishedNTCP2 () && !address.host.is_unspecified () && address.port)
						isPublished = true;
					else
					{
						WriteString ("caps", properties);
						properties << '=';
						std::string caps;
						if (address.IsV4 ()) caps += CAPS_FLAG_V4;
						if (address.IsV6 ()) caps += CAPS_FLAG_V6;
						if (caps.empty ()) caps += CAPS_FLAG_V4;
						WriteString (caps, properties);
						properties << ';';
					}
				}
				else
					continue; // don't write NTCP address
			}
			else if (address.transportStyle == eTransportSSU)
			{
				WriteString ("SSU", s);
				// caps
				WriteString ("caps", properties);
				properties << '=';
				std::string caps;
				if (address.IsPeerTesting ()) caps += CAPS_FLAG_SSU_TESTING;
				if (address.host.is_v4 ())
				{
					if (address.published)
					{
						isPublished = true;
						if (address.IsIntroducer ()) caps += CAPS_FLAG_SSU_INTRODUCER;
					}
					else
						caps += CAPS_FLAG_V4;
				}
				else if (address.host.is_v6 ())
				{
					if (address.published)
					{
						isPublished = true;
						if (address.IsIntroducer ()) caps += CAPS_FLAG_SSU_INTRODUCER;
					}
					else
						caps += CAPS_FLAG_V6;
				}
				else
				{
					if (address.IsV4 ()) caps += CAPS_FLAG_V4;
					if (address.IsV6 ()) caps += CAPS_FLAG_V6;
					if (caps.empty ()) caps += CAPS_FLAG_V4;
				}
				WriteString (caps, properties);
				properties << ';';
			}
			else if (address.transportStyle == eTransportSSU2)
			{
				WriteString ("SSU2", s);
				// caps
				std::string caps;
				if (address.published)
				{
					isPublished = true;
					if (address.IsPeerTesting ()) caps += CAPS_FLAG_SSU_TESTING;
					if (address.IsIntroducer ()) caps += CAPS_FLAG_SSU_INTRODUCER;
				}
				else
				{
					if (address.IsV4 ()) caps += CAPS_FLAG_V4;
					if (address.IsV6 ()) caps += CAPS_FLAG_V6;
					if (caps.empty ()) caps += CAPS_FLAG_V4;
				}
				if (!caps.empty ())
				{
					WriteString ("caps", properties);
					properties << '=';
					WriteString (caps, properties);
					properties << ';';
				}
			}
			else
				WriteString ("", s);

			if (isPublished)
			{
				WriteString ("host", properties);
				properties << '=';
				WriteString (address.host.to_string (), properties);
				properties << ';';
			}
			if ((address.IsNTCP2 () && isPublished) || address.IsSSU2 ())
			{
				// publish i for NTCP2 or SSU2
				WriteString ("i", properties); properties << '=';
				size_t len = address.IsSSU2 () ? 32 : 16;
				WriteString (address.i.ToBase64 (len), properties); properties << ';';
			}
			if (address.transportStyle == eTransportSSU || address.IsSSU2 ())
			{
				// write introducers if any
				if (address.ssu && !address.ssu->introducers.empty())
				{
					int i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						if (introducer.iExp) // expiration is specified
						{
							WriteString ("iexp" + boost::lexical_cast<std::string>(i), properties);
							properties << '=';
							WriteString (boost::lexical_cast<std::string>(introducer.iExp), properties);
							properties << ';';
						}
						i++;
					}
					if (address.transportStyle == eTransportSSU)
					{
						i = 0;
						for (const auto& introducer: address.ssu->introducers)
						{
							WriteString ("ihost" + boost::lexical_cast<std::string>(i), properties);
							properties << '=';
							WriteString (introducer.iHost.to_string (), properties);
							properties << ';';
							i++;
						}
					}
					i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						if (address.IsSSU2 ())
							WriteString ("ih" + boost::lexical_cast<std::string>(i), properties);
						else
							WriteString ("ikey" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						char value[64];
						size_t l = ByteStreamToBase64 (introducer.iKey, 32, value, 64);
						value[l] = 0;
						WriteString (value, properties);
						properties << ';';
						i++;
					}
					if (address.transportStyle == eTransportSSU)
					{
						i = 0;
						for (const auto& introducer: address.ssu->introducers)
						{
							WriteString ("iport" + boost::lexical_cast<std::string>(i), properties);
							properties << '=';
							WriteString (boost::lexical_cast<std::string>(introducer.iPort), properties);
							properties << ';';
							i++;
						}
					}
					i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						WriteString ("itag" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (boost::lexical_cast<std::string>(introducer.iTag), properties);
						properties << ';';
						i++;
					}
				}
			}
			if (address.transportStyle == eTransportSSU)
			{
				// write intro key
				WriteString ("key", properties);
				properties << '=';
				char value[64];
				size_t l = ByteStreamToBase64 (address.i, 32, value, 64);
				value[l] = 0;
				WriteString (value, properties);
				properties << ';';
			}
			if (address.transportStyle == eTransportSSU || address.IsSSU2 ())
			{
				// write mtu
				if (address.ssu && address.ssu->mtu)
				{
					WriteString ("mtu", properties);
					properties << '=';
					WriteString (boost::lexical_cast<std::string>(address.ssu->mtu), properties);
					properties << ';';
				}
			}
			if (isPublished || (address.ssu && !address.IsSSU2 ()))
			{
				WriteString ("port", properties);
				properties << '=';
				WriteString (boost::lexical_cast<std::string>(address.port), properties);
				properties << ';';
			}
			if (address.IsNTCP2 () || address.IsSSU2 ())
			{
				// publish s and v for NTCP2 or SSU2
				WriteString ("s", properties); properties << '=';
				WriteString (address.s.ToBase64 (), properties); properties << ';';
				WriteString ("v", properties); properties << '=';
				WriteString ("2", properties); properties << ';';
			}

			uint16_t size = htobe16 (properties.str ().size ());
			s.write ((char *)&size, sizeof (size));
			s.write (properties.str ().c_str (), properties.str ().size ());
		}

		// peers
		uint8_t numPeers = 0;
		s.write ((char *)&numPeers, sizeof (numPeers));

		// properties
		std::stringstream properties;
		for (const auto& p : m_Properties)
		{
			WriteString (p.first, properties);
			properties << '=';
			WriteString (p.second, properties);
			properties << ';';
		}
		uint16_t size = htobe16 (properties.str ().size ());
		s.write ((char *)&size, sizeof (size));
		s.write (properties.str ().c_str (), properties.str ().size ());
	}

	void LocalRouterInfo::SetProperty (const std::string& key, const std::string& value)
	{
		m_Properties[key] = value;
	}

	void LocalRouterInfo::DeleteProperty (const std::string& key)
	{
		m_Properties.erase (key);
	}

	std::string LocalRouterInfo::GetProperty (const std::string& key) const
	{
		auto it = m_Properties.find (key);
		if (it != m_Properties.end ())
			return it->second;
		return "";
	}

	void LocalRouterInfo::WriteString (const std::string& str, std::ostream& s) const
	{
		uint8_t len = str.size ();
		s.write ((char *)&len, 1);
		s.write (str.c_str (), len);
	}

	std::shared_ptr<RouterInfo::Buffer> LocalRouterInfo::NewBuffer () const
	{
		return std::make_shared<Buffer> ();
	}
}
}
