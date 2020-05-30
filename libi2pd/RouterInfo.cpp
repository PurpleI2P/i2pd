/*
* Copyright (c) 2013-2020, The PurpleI2P Project
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
	RouterInfo::RouterInfo (): m_Buffer (nullptr)
	{
		m_Addresses = boost::make_shared<Addresses>(); // create empty list
	}

	RouterInfo::RouterInfo (const std::string& fullPath):
		m_FullPath (fullPath), m_IsUpdated (false), m_IsUnreachable (false),
		m_SupportedTransports (0), m_Caps (0), m_Version (0)
	{
		m_Addresses = boost::make_shared<Addresses>(); // create empty list
		m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		ReadFromFile ();
	}

	RouterInfo::RouterInfo (const uint8_t * buf, int len):
		m_IsUpdated (true), m_IsUnreachable (false), m_SupportedTransports (0),
		m_Caps (0), m_Version (0)
	{
		m_Addresses = boost::make_shared<Addresses>(); // create empty list
		if (len <= MAX_RI_BUFFER_SIZE)
		{
			m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
			memcpy (m_Buffer, buf, len);
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

	RouterInfo::~RouterInfo ()
	{
		delete[] m_Buffer;
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
			m_Caps = 0;
			// don't clean up m_Addresses, it will be replaced in ReadFromStream
			m_Properties.clear ();
			// copy buffer
			if (!m_Buffer)
				m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
			memcpy (m_Buffer, buf, len);
			m_BufferLen = len;
			// skip identity
			size_t identityLen = m_RouterIdentity->GetFullLen ();
			// read new RI
			std::stringstream str (std::string ((char *)m_Buffer + identityLen, m_BufferLen - identityLen));
			ReadFromStream (str);
			// don't delete buffer until saved to the file
		}
		else
		{
			LogPrint (eLogError, "RouterInfo: signature verification failed");
			m_IsUnreachable = true;
		}
	}

	void RouterInfo::SetRouterIdentity (std::shared_ptr<const IdentityEx> identity)
	{
		m_RouterIdentity = identity;
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch ();
	}

	bool RouterInfo::LoadFile ()
	{
		std::ifstream s(m_FullPath, std::ifstream::binary);
		if (s.is_open ())
		{
			s.seekg (0,std::ios::end);
			m_BufferLen = s.tellg ();
			if (m_BufferLen < 40 || m_BufferLen > MAX_RI_BUFFER_SIZE)
			{
				LogPrint(eLogError, "RouterInfo: File", m_FullPath, " is malformed");
				return false;
			}
			s.seekg(0, std::ios::beg);
			if (!m_Buffer) m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
			s.read((char *)m_Buffer, m_BufferLen);
		}
		else
		{
			LogPrint (eLogError, "RouterInfo: Can't open file ", m_FullPath);
			return false;
		}
		return true;
	}

	void RouterInfo::ReadFromFile ()
	{
		if (LoadFile ())
			ReadFromBuffer (false);
		else
			m_IsUnreachable = true;
	}

	void RouterInfo::ReadFromBuffer (bool verifySignature)
	{
		m_RouterIdentity = std::make_shared<IdentityEx>(m_Buffer, m_BufferLen);
		size_t identityLen = m_RouterIdentity->GetFullLen ();
		if (identityLen >= m_BufferLen)
		{
			LogPrint (eLogError, "RouterInfo: identity length ", identityLen, " exceeds buffer size ", m_BufferLen);
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
			if (l < 0 || !m_RouterIdentity->Verify ((uint8_t *)m_Buffer, l, (uint8_t *)m_Buffer + l))
			{
				LogPrint (eLogError, "RouterInfo: signature verification failed");
				m_IsUnreachable = true;
				return;
			}
			m_RouterIdentity->DropVerifier ();
		}
		// parse RI
		std::stringstream str;
		str.write ((const char *)m_Buffer + identityLen, m_BufferLen - identityLen);
		ReadFromStream (str);
		if (!str)
		{
			LogPrint (eLogError, "RouterInfo: malformed message");
			m_IsUnreachable = true;
		}
	}

	void RouterInfo::ReadFromStream (std::istream& s)
	{
		s.read ((char *)&m_Timestamp, sizeof (m_Timestamp));
		m_Timestamp = be64toh (m_Timestamp);
		// read addresses
		auto addresses = boost::make_shared<Addresses>();
		uint8_t numAddresses;
		s.read ((char *)&numAddresses, sizeof (numAddresses)); if (!s) return;
		bool introducers = false;
		for (int i = 0; i < numAddresses; i++)
		{
			uint8_t supportedTransports = 0;
			auto address = std::make_shared<Address>();
			s.read ((char *)&address->cost, sizeof (address->cost));
			s.read ((char *)&address->date, sizeof (address->date));
			bool isNTCP2Only = false;
			char transportStyle[6];
			auto transportStyleLen = ReadString (transportStyle, 6, s) - 1;
			if (!strncmp (transportStyle, "NTCP", 4)) // NTCP or NTCP2
			{
				address->transportStyle = eTransportNTCP;
				if (transportStyleLen > 4 && transportStyle[4] == '2') isNTCP2Only= true;
			}
			else if (!strcmp (transportStyle, "SSU"))
			{
				address->transportStyle = eTransportSSU;
				address->ssu.reset (new SSUExt ());
				address->ssu->mtu = 0;
			}
			else
				address->transportStyle = eTransportUnknown;
			address->port = 0;
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
				if (!strcmp (key, "host"))
				{
					boost::system::error_code ecode;
					address->host = boost::asio::ip::address::from_string (value, ecode);
					if (!ecode)
					{
#if BOOST_VERSION >= 104900
						if (!address->host.is_unspecified ()) // check if address is valid
#else
						address->host.to_string (ecode);
						if (!ecode)
#endif
						{
							// add supported protocol
							if (address->host.is_v4 ())
								supportedTransports |= (address->transportStyle == eTransportNTCP) ? eNTCPV4 : eSSUV4;
							else
								supportedTransports |= (address->transportStyle == eTransportNTCP) ? eNTCPV6 : eSSUV6;
						}
					}
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
						Base64ToByteStream (value, strlen (value), address->ssu->key, 32);
					else
						LogPrint (eLogWarning, "RouterInfo: Unexpected field 'key' for NTCP");
				}
				else if (!strcmp (key, "caps"))
					ExtractCaps (value);
				else if (!strcmp (key, "s")) // ntcp2 static key
				{
					if (!address->ntcp2) address->ntcp2.reset (new NTCP2Ext ());
					supportedTransports |= (address->host.is_v4 ()) ? eNTCP2V4 : eNTCP2V6;
					Base64ToByteStream (value, strlen (value), address->ntcp2->staticKey, 32);
				}
				else if (!strcmp (key, "i")) // ntcp2 iv
				{
					if (!address->ntcp2) address->ntcp2.reset (new NTCP2Ext ());
					supportedTransports |= (address->host.is_v4 ()) ? eNTCP2V4 : eNTCP2V6;
					Base64ToByteStream (value, strlen (value), address->ntcp2->iv, 16);
					address->ntcp2->isPublished = true; // presence if "i" means "published"
				}
				else if (key[0] == 'i')
				{
					// introducers
					if (!address->ssu)
					{
						LogPrint (eLogError, "RouterInfo: Introducer is presented for non-SSU address. Skipped");
						continue;
					}
					introducers = true;
					size_t l = strlen(key);
					unsigned char index = key[l-1] - '0'; // TODO:
					key[l-1] = 0;
					if (index > 9)
					{
						LogPrint (eLogError, "RouterInfo: Unexpected introducer's index ", index, " skipped");
						if (s) continue; else return;
					}
					if (index >= address->ssu->introducers.size ())
						address->ssu->introducers.resize (index + 1);
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
					else if (!strcmp (key, "ikey"))
						Base64ToByteStream (value, strlen (value), introducer.iKey, 32);
					else if (!strcmp (key, "iexp"))
						introducer.iExp = boost::lexical_cast<uint32_t>(value);
				}
				if (!s) return;
			}
			if (introducers) supportedTransports |= eSSUV4; // in case if host is not presented
			if (isNTCP2Only && address->ntcp2) address->ntcp2->isNTCP2Only = true;
			if (supportedTransports)
			{
				addresses->push_back(address);
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
			m_Properties[key] = value;

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
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_NETID) && atoi (value) != i2p::context.GetNetID ())
			{
				LogPrint (eLogError, "RouterInfo: Unexpected ", ROUTER_INFO_PROPERTY_NETID, "=", value);
				m_IsUnreachable = true;
			}
			// family
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_FAMILY))
			{
				m_Family = value;
				boost::to_lower (m_Family);
			}
			else if (!strcmp (key, ROUTER_INFO_PROPERTY_FAMILY_SIG))
			{
				if (!netdb.GetFamilies ().VerifyFamily (m_Family, GetIdentHash (), value))
				{
					LogPrint (eLogWarning, "RouterInfo: family signature verification failed");
					m_Family.clear ();
				}
			}

			if (!s) return;
		}

		if (!m_SupportedTransports || !m_Addresses->size() || (UsesIntroducer () && !introducers))
			SetUnreachable (true);
	}

	bool RouterInfo::IsFamily(const std::string & fam) const
	{
		return m_Family == fam;
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
				case CAPS_FLAG_SSU_TESTING:
					m_Caps |= Caps::eSSUTesting;
				break;
				case CAPS_FLAG_SSU_INTRODUCER:
					m_Caps |= Caps::eSSUIntroducer;
				break;
				default: ;
			}
			cap++;
		}
	}

	void RouterInfo::UpdateCapsProperty ()
	{
		std::string caps;
		if (m_Caps & eFloodfill)
		{
			if (m_Caps & eExtraBandwidth) caps += (m_Caps & eHighBandwidth) ?
				CAPS_FLAG_EXTRA_BANDWIDTH2 : // 'X'
				CAPS_FLAG_EXTRA_BANDWIDTH1; // 'P'
			else
				caps += CAPS_FLAG_HIGH_BANDWIDTH3; // 'O'
			caps += CAPS_FLAG_FLOODFILL; // floodfill
		}
		else
		{
			if (m_Caps & eExtraBandwidth)
				caps += (m_Caps & eHighBandwidth) ? CAPS_FLAG_EXTRA_BANDWIDTH2 /* 'X' */ : CAPS_FLAG_EXTRA_BANDWIDTH1; /*'P' */
			else
				caps += (m_Caps & eHighBandwidth) ? CAPS_FLAG_HIGH_BANDWIDTH3 /* 'O' */: CAPS_FLAG_LOW_BANDWIDTH2 /* 'L' */; // bandwidth
		}
		if (m_Caps & eHidden) caps += CAPS_FLAG_HIDDEN; // hidden
		if (m_Caps & eReachable) caps += CAPS_FLAG_REACHABLE; // reachable
		if (m_Caps & eUnreachable) caps += CAPS_FLAG_UNREACHABLE; // unreachable

		SetProperty ("caps", caps);
	}

	void RouterInfo::WriteToStream (std::ostream& s) const
	{
		uint64_t ts = htobe64 (m_Timestamp);
		s.write ((const char *)&ts, sizeof (ts));

		// addresses
		uint8_t numAddresses = m_Addresses->size ();
		s.write ((char *)&numAddresses, sizeof (numAddresses));
		for (const auto& addr_ptr : *m_Addresses)
		{
			const Address& address = *addr_ptr;
			s.write ((const char *)&address.cost, sizeof (address.cost));
			s.write ((const char *)&address.date, sizeof (address.date));
			std::stringstream properties;
			if (address.transportStyle == eTransportNTCP)
				WriteString (address.IsNTCP2 () ? "NTCP2" : "NTCP", s);
			else if (address.transportStyle == eTransportSSU)
			{
				WriteString ("SSU", s);
				// caps
				WriteString ("caps", properties);
				properties << '=';
				std::string caps;
				if (IsPeerTesting ()) caps += CAPS_FLAG_SSU_TESTING;
				if (IsIntroducer ()) caps += CAPS_FLAG_SSU_INTRODUCER;
				WriteString (caps, properties);
				properties << ';';
			}
			else
				WriteString ("", s);

			if (!address.IsNTCP2 () || address.IsPublishedNTCP2 ())
			{
				WriteString ("host", properties);
				properties << '=';
				WriteString (address.host.to_string (), properties);
				properties << ';';
			}
			if (address.transportStyle == eTransportSSU)
			{
				// write introducers if any
				if (address.ssu->introducers.size () > 0)
				{
					int i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						WriteString ("ihost" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (introducer.iHost.to_string (), properties);
						properties << ';';
						i++;
					}
					i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						WriteString ("ikey" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						char value[64];
						size_t l = ByteStreamToBase64 (introducer.iKey, 32, value, 64);
						value[l] = 0;
						WriteString (value, properties);
						properties << ';';
						i++;
					}
					i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						WriteString ("iport" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (boost::lexical_cast<std::string>(introducer.iPort), properties);
						properties << ';';
						i++;
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
					i = 0;
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
				}
				// write intro key
				WriteString ("key", properties);
				properties << '=';
				char value[64];
				size_t l = ByteStreamToBase64 (address.ssu->key, 32, value, 64);
				value[l] = 0;
				WriteString (value, properties);
				properties << ';';
				// write mtu
				if (address.ssu->mtu)
				{
					WriteString ("mtu", properties);
					properties << '=';
					WriteString (boost::lexical_cast<std::string>(address.ssu->mtu), properties);
					properties << ';';
				}
			}

			if (address.IsPublishedNTCP2 ())
			{
				// publish i for NTCP2
				WriteString ("i", properties); properties << '=';
				WriteString (address.ntcp2->iv.ToBase64 (), properties); properties << ';';
			}

			if (!address.IsNTCP2 () || address.IsPublishedNTCP2 ())
			{
				WriteString ("port", properties);
				properties << '=';
				WriteString (boost::lexical_cast<std::string>(address.port), properties);
				properties << ';';
			}
			if (address.IsNTCP2 ())
			{
				// publish s and v for NTCP2
				WriteString ("s", properties); properties << '=';
				WriteString (address.ntcp2->staticKey.ToBase64 (), properties); properties << ';';
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

	bool RouterInfo::IsNewer (const uint8_t * buf, size_t len) const
	{
		if (!m_RouterIdentity) return false;
		size_t size = m_RouterIdentity->GetFullLen ();
		if (size + 8 > len) return false;
		return bufbe64toh (buf + size) > m_Timestamp;
	}

	const uint8_t * RouterInfo::LoadBuffer ()
	{
		if (!m_Buffer)
		{
			if (LoadFile ())
				LogPrint (eLogDebug, "RouterInfo: Buffer for ", GetIdentHashAbbreviation (GetIdentHash ()), " loaded from file");
		}
		return m_Buffer;
	}

	void RouterInfo::CreateBuffer (const PrivateKeys& privateKeys)
	{
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch (); // refresh timstamp
		std::stringstream s;
		uint8_t ident[1024];
		auto identLen = privateKeys.GetPublic ()->ToBuffer (ident, 1024);
		auto signatureLen = privateKeys.GetPublic ()->GetSignatureLen ();
		s.write ((char *)ident, identLen);
		WriteToStream (s);
		m_BufferLen = s.str ().size ();
		if (!m_Buffer)
			m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		if (m_BufferLen + signatureLen < MAX_RI_BUFFER_SIZE)
		{
			memcpy (m_Buffer, s.str ().c_str (), m_BufferLen);
			// signature
			privateKeys.Sign ((uint8_t *)m_Buffer, m_BufferLen, (uint8_t *)m_Buffer + m_BufferLen);
			m_BufferLen += signatureLen;
		}
		else
			LogPrint (eLogError, "RouterInfo: Our RouterInfo is too long ", m_BufferLen + signatureLen);
	}

	bool RouterInfo::SaveToFile (const std::string& fullPath)
	{
		m_FullPath = fullPath;
		if (!m_Buffer) {
			LogPrint (eLogError, "RouterInfo: Can't save, m_Buffer == NULL");
			return false;
		}
		std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
		if (!f.is_open ()) {
			LogPrint(eLogError, "RouterInfo: Can't save to ", fullPath);
			return false;
		}
		f.write ((char *)m_Buffer, m_BufferLen);
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
			LogPrint (eLogWarning, "RouterInfo: string length ", (int)l, " exceeds buffer size ", len);
			s.seekg (l, std::ios::cur); // skip
			str[0] = 0;
		}
		return l+1;
	}

	void RouterInfo::WriteString (const std::string& str, std::ostream& s) const
	{
		uint8_t len = str.size ();
		s.write ((char *)&len, 1);
		s.write (str.c_str (), len);
	}

	void RouterInfo::AddNTCPAddress (const char * host, int port)
	{
		auto addr = std::make_shared<Address>();
		addr->host = boost::asio::ip::address::from_string (host);
		addr->port = port;
		addr->transportStyle = eTransportNTCP;
		addr->cost = 6;
		addr->date = 0;
		for (const auto& it: *m_Addresses) // don't insert same address twice
			if (*it == *addr) return;
		m_SupportedTransports |= addr->host.is_v6 () ? eNTCPV6 : eNTCPV4;
		m_Addresses->push_front(std::move(addr)); // always make NTCP first
	}

	void RouterInfo::AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu)
	{
		auto addr = std::make_shared<Address>();
		addr->host = boost::asio::ip::address::from_string (host);
		addr->port = port;
		addr->transportStyle = eTransportSSU;
		addr->cost = 10; // NTCP should have priority over SSU
		addr->date = 0;
		addr->ssu.reset (new SSUExt ());
		addr->ssu->mtu = mtu;
		memcpy (addr->ssu->key, key, 32);
		for (const auto& it: *m_Addresses) // don't insert same address twice
			if (*it == *addr) return;
		m_SupportedTransports |= addr->host.is_v6 () ? eSSUV6 : eSSUV4;
		m_Addresses->push_back(std::move(addr));

		m_Caps |= eSSUTesting;
		m_Caps |= eSSUIntroducer;
	}

	void RouterInfo::AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv, const boost::asio::ip::address& host, int port)
	{
		auto addr = std::make_shared<Address>();
		addr->host = host;
		addr->port = port;
		addr->transportStyle = eTransportNTCP;
		addr->cost = port ? 3 : 14; // override from RouterContext::PublishNTCP2Address
		addr->date = 0;
		addr->ntcp2.reset (new NTCP2Ext ());
		addr->ntcp2->isNTCP2Only = true; // NTCP2 only address
		if (port) addr->ntcp2->isPublished = true;
		memcpy (addr->ntcp2->staticKey, staticKey, 32);
		memcpy (addr->ntcp2->iv, iv, 16);
		m_Addresses->push_back(std::move(addr));
	}

	bool RouterInfo::AddIntroducer (const Introducer& introducer)
	{
		for (auto& addr : *m_Addresses)
		{
			if (addr->transportStyle == eTransportSSU && addr->host.is_v4 ())
			{
				for (auto& intro: addr->ssu->introducers)
					if (intro.iTag == introducer.iTag) return false; // already presented
				addr->ssu->introducers.push_back (introducer);
				return true;
			}
		}
		return false;
	}

	bool RouterInfo::RemoveIntroducer (const boost::asio::ip::udp::endpoint& e)
	{
		for (auto& addr: *m_Addresses)
		{
			if (addr->transportStyle == eTransportSSU && addr->host.is_v4 ())
			{
				for (auto it = addr->ssu->introducers.begin (); it != addr->ssu->introducers.end (); ++it)
					if ( boost::asio::ip::udp::endpoint (it->iHost, it->iPort) == e)
					{
						addr->ssu->introducers.erase (it);
						return true;
					}
			}
		}
		return false;
	}

	void RouterInfo::SetCaps (uint8_t caps)
	{
		m_Caps = caps;
		UpdateCapsProperty ();
	}

	void RouterInfo::SetCaps (const char * caps)
	{
		SetProperty ("caps", caps);
		m_Caps = 0;
		ExtractCaps (caps);
	}

	void RouterInfo::SetProperty (const std::string& key, const std::string& value)
	{
		m_Properties[key] = value;
	}

	void RouterInfo::DeleteProperty (const std::string& key)
	{
		m_Properties.erase (key);
	}

	std::string RouterInfo::GetProperty (const std::string& key) const
	{
		auto it = m_Properties.find (key);
		if (it != m_Properties.end ())
			return it->second;
		return "";
	}

	bool RouterInfo::IsNTCP (bool v4only) const
	{
		if (v4only)
			return m_SupportedTransports & eNTCPV4;
		else
			return m_SupportedTransports & (eNTCPV4 | eNTCPV6);
	}

	bool RouterInfo::IsSSU (bool v4only) const
	{
		if (v4only)
			return m_SupportedTransports & eSSUV4;
		else
			return m_SupportedTransports & (eSSUV4 | eSSUV6);
	}

	bool RouterInfo::IsSSUV6 () const
	{
		return m_SupportedTransports & eSSUV6;
	}

	bool RouterInfo::IsNTCP2 (bool v4only) const
	{
		if (v4only)
			return m_SupportedTransports & eNTCP2V4;
		else
			return m_SupportedTransports & (eNTCP2V4 | eNTCP2V6);
	}

	bool RouterInfo::IsV6 () const
	{
		return m_SupportedTransports & (eNTCPV6 | eSSUV6 | eNTCP2V6);
	}

	bool RouterInfo::IsV4 () const
	{
		return m_SupportedTransports & (eNTCPV4 | eSSUV4 | eNTCP2V4);
	}

	void RouterInfo::EnableV6 ()
	{
		if (!IsV6 ())
			m_SupportedTransports |= eNTCPV6 | eSSUV6 | eNTCP2V6;
	}

	void RouterInfo::EnableV4 ()
	{
		if (!IsV4 ())
			m_SupportedTransports |= eNTCPV4 | eSSUV4 | eNTCP2V4;
	}


	void RouterInfo::DisableV6 ()
	{
		if (IsV6 ())
		{
			m_SupportedTransports &= ~(eNTCPV6 | eSSUV6 | eNTCP2V6);
			for (auto it = m_Addresses->begin (); it != m_Addresses->end ();)
			{
				auto addr = *it;
				if (addr->host.is_v6 ())
					it = m_Addresses->erase (it);
				else
					++it;
			}
		}
	}

	void RouterInfo::DisableV4 ()
	{
		if (IsV4 ())
		{
			m_SupportedTransports &= ~(eNTCPV4 | eSSUV4 | eNTCP2V4);
			for (auto it = m_Addresses->begin (); it != m_Addresses->end ();)
			{
				auto addr = *it;
				if (addr->host.is_v4 ())
					it = m_Addresses->erase (it);
				else
					++it;
			}
		}
	}


	bool RouterInfo::UsesIntroducer () const
	{
		return m_Caps & Caps::eUnreachable; // non-reachable
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetNTCPAddress (bool v4only) const
	{
		return GetAddress (
			[v4only](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportNTCP) && !address->IsNTCP2Only () && (!v4only || address->host.is_v4 ());
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSUAddress (bool v4only) const
	{
		return GetAddress (
			[v4only](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU) && (!v4only || address->host.is_v4 ());
			});
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSUV6Address () const
	{
		return GetAddress (
			[](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return (address->transportStyle == eTransportSSU) && address->host.is_v6 ();
			});
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

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetNTCP2Address (bool publishedOnly, bool v4only) const
	{
		return GetAddress (
			[publishedOnly, v4only](std::shared_ptr<const RouterInfo::Address> address)->bool
			{
				return address->IsNTCP2 () && (!publishedOnly || address->IsPublishedNTCP2 ()) && (!v4only || address->host.is_v4 ());
			});
	}

	std::shared_ptr<RouterProfile> RouterInfo::GetProfile () const
	{
		if (!m_Profile)
			m_Profile = GetRouterProfile (GetIdentHash ());
		return m_Profile;
	}

	void RouterInfo::Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const
	{
		auto encryptor = m_RouterIdentity->CreateEncryptor (nullptr);
		if (encryptor)
			encryptor->Encrypt (data, encrypted, ctx, true);
	}
}
}
