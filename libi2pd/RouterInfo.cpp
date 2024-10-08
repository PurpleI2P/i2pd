/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <stdio.h>
#include <string.h>
#include "I2PEndian.h"
#include <fstream>
#include <memory>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp> // for boost::to_lower
#ifndef __cpp_lib_atomic_shared_ptr
#include <boost/atomic.hpp>
#endif
#include "version.h"
#include "util.h"
#include "Crypto.h"
#include "Base.h"
#include "Timestamp.h"
#include "Log.h"
#include "Transports.h"
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
		m_BufferLen = len;
	}

	RouterInfo::RouterInfo (): m_Buffer (nullptr)
	{
		m_Addresses = AddressesPtr(new Addresses ()); // create empty list
	}

	RouterInfo::RouterInfo (const std::string& fullPath):
		m_FamilyID (0), m_IsUpdated (false), m_IsUnreachable (false), m_IsFloodfill (false),
		m_SupportedTransports (0),m_ReachableTransports (0), m_PublishedTransports (0),
		m_Caps (0), m_Version (0), m_Congestion (eLowCongestion)
	{
		m_Addresses = AddressesPtr(new Addresses ()); // create empty list
		m_Buffer = RouterInfo::NewBuffer (); // always RouterInfo's
		ReadFromFile (fullPath);
	}

	RouterInfo::RouterInfo (std::shared_ptr<Buffer>&& buf, size_t len):
		m_FamilyID (0), m_IsUpdated (true), m_IsUnreachable (false), m_IsFloodfill (false),
		m_SupportedTransports (0), m_ReachableTransports (0), m_PublishedTransports (0),
		m_Caps (0), m_Version (0), m_Congestion (eLowCongestion)
	{
		if (len <= MAX_RI_BUFFER_SIZE)
		{
			m_Addresses = AddressesPtr(new Addresses ()); // create empty list
			m_Buffer = buf;
			if (m_Buffer) m_Buffer->SetBufferLen (len);
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
		RouterInfo (netdb.NewRouterInfoBuffer (buf, len), len)
	{
	}

	RouterInfo::~RouterInfo ()
	{
	}

	bool RouterInfo::Update (const uint8_t * buf, size_t len)
	{
		if (len > MAX_RI_BUFFER_SIZE)
		{
			LogPrint (eLogWarning, "RouterInfo: Updated buffer is too long ", len, ". Not changed");
			return false;
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
			m_PublishedTransports = 0;	
			m_Caps = 0; m_IsFloodfill = false;
			// don't clean up m_Addresses, it will be replaced in ReadFromStream
			ClearProperties ();
			// skip identity
			size_t identityLen = m_RouterIdentity->GetFullLen ();
			// read new RI
			std::stringstream str (std::string ((char *)buf + identityLen, len - identityLen));
			ReadFromStream (str);
			if (!m_IsUnreachable)
				UpdateBuffer (buf, len); // save buffer	
			// don't delete buffer until saved to the file
		}
		else
		{	
			LogPrint (eLogWarning, "RouterInfo: Updated signature verification failed. Not changed");
			return false;
		}	
		return true;
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
			size_t bufferLen = s.tellg ();
			if (bufferLen < 40 || bufferLen > MAX_RI_BUFFER_SIZE)
			{
				LogPrint(eLogError, "RouterInfo: File ", fullPath, " is malformed");
				return false;
			}
			s.seekg(0, std::ios::beg);
			if (!m_Buffer)
				m_Buffer = NewBuffer ();
			s.read((char *)m_Buffer->data (), bufferLen);
			m_Buffer->SetBufferLen (bufferLen);
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
		size_t bufferLen = m_Buffer->GetBufferLen ();
		m_RouterIdentity = NewIdentity (m_Buffer->data (), bufferLen);
		size_t identityLen = m_RouterIdentity->GetFullLen ();
		if (identityLen >= bufferLen)
		{
			LogPrint (eLogError, "RouterInfo: Identity length ", identityLen, " exceeds buffer size ", bufferLen);
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
			int l = bufferLen - m_RouterIdentity->GetSignatureLen ();
			if (l < 0 || !m_RouterIdentity->Verify ((uint8_t *)m_Buffer->data (), l, (uint8_t *)m_Buffer->data () + l))
			{
				LogPrint (eLogError, "RouterInfo: Signature verification failed");
				m_IsUnreachable = true;
				return;
			}
		}
		// parse RI
		std::stringstream str;
		str.write ((const char *)m_Buffer->data () + identityLen, bufferLen - identityLen);
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
		m_Caps = 0; m_Congestion = eLowCongestion;
		s.read ((char *)&m_Timestamp, sizeof (m_Timestamp));
		m_Timestamp = be64toh (m_Timestamp);
		// read addresses
		auto addresses = NewAddresses ();
		uint8_t numAddresses;
		s.read ((char *)&numAddresses, sizeof (numAddresses));
		for (int i = 0; i < numAddresses; i++)
		{
			uint8_t supportedTransports = 0;
			auto address = NewAddress ();
			uint8_t cost; // ignore
			s.read ((char *)&cost, sizeof (cost));
			s.read ((char *)&address->date, sizeof (address->date));
			bool isHost = false, isStaticKey = false, isV2 = false, isIntroKey = false;
			char transportStyle[6];
			ReadString (transportStyle, 6, s);
			if (!strncmp (transportStyle, "NTCP", 4)) // NTCP or NTCP2
				address->transportStyle = eTransportNTCP2;
			else if (!strncmp (transportStyle, "SSU", 3)) // SSU or SSU2
			{
				address->transportStyle = eTransportSSU2;
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
					if (!ecode && !address->host.is_unspecified ())
					{
						if (!i2p::transport::transports.IsInReservedRange (address->host) ||
						    i2p::util::net::IsYggdrasilAddress (address->host))
							isHost = true;
						else
							// we consider such address as invalid
							address->transportStyle = eTransportUnknown;
					}
				}
				else if (!strcmp (key, "port"))
				{
					try
					{
						address->port = boost::lexical_cast<int>(value);
					}
					catch (std::exception& ex)
					{
						LogPrint (eLogWarning, "RouterInfo: 'port' exception ", ex.what ());
					}
				}
				else if (!strcmp (key, "mtu"))
				{
					if (address->ssu)
					{
						try
						{
							address->ssu->mtu = boost::lexical_cast<int>(value);
						}
						catch (std::exception& ex)
						{
							LogPrint (eLogWarning, "RouterInfo: 'mtu' exception ", ex.what ());
						}
					}
					else
						LogPrint (eLogWarning, "RouterInfo: Unexpected field 'mtu' for NTCP2");
				}
				else if (!strcmp (key, "caps"))
					address->caps = ExtractAddressCaps (value);
				else if (!strcmp (key, "s")) // ntcp2 or ssu2 static key
				{
					if (Base64ToByteStream (value, strlen (value), address->s, 32) == 32 &&
						!(address->s[31] & 0x80)) // check if x25519 public key
							isStaticKey = true;
					else
						address->transportStyle = eTransportUnknown; // invalid address
				}
				else if (!strcmp (key, "i")) // ntcp2 iv or ssu2 intro
				{
					if (address->IsNTCP2 ())
					{
						if (Base64ToByteStream (value, strlen (value), address->i, 16) == 16)
							address->published = true; // presence of "i" means "published" NTCP2
						else
							address->transportStyle = eTransportUnknown; // invalid address
					}
					else if (address->IsSSU2 ())
					{	
						if (Base64ToByteStream (value, strlen (value), address->i, 32) == 32)
							isIntroKey = true;
						else
							address->transportStyle = eTransportUnknown; // invalid address
					}	
				}
				else if (!strcmp (key, "v"))
				{
					if (!strcmp (value, "2"))
						isV2 = true;
					else
					{	
						LogPrint (eLogWarning, "RouterInfo: Unexpected value ", value, " for v");
						address->transportStyle = eTransportUnknown; // invalid address
					}	
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
					if (!strcmp (key, "itag"))
					{
						try
						{
							introducer.iTag = boost::lexical_cast<uint32_t>(value);
						}
						catch (std::exception& ex)
						{
							LogPrint (eLogWarning, "RouterInfo: 'itag' exception ", ex.what ());
						}
					}
					else if (!strcmp (key, "ih"))
						Base64ToByteStream (value, strlen (value), introducer.iH, 32);
					else if (!strcmp (key, "iexp"))
					{
						try
						{
							introducer.iExp = boost::lexical_cast<uint32_t>(value);
						}
						catch (std::exception& ex)
						{
							LogPrint (eLogWarning, "RouterInfo: 'iexp' exception ", ex.what ());
						}
					}
				}
				if (!s) return;
			}
			
			if (address->transportStyle == eTransportNTCP2)
			{
				if (isStaticKey)
				{
					if (isHost && address->port)
					{
						if (address->host.is_v6 ())
							supportedTransports |= (i2p::util::net::IsYggdrasilAddress (address->host) ? eNTCP2V6Mesh : eNTCP2V6);
						else
							supportedTransports |= eNTCP2V4;
						m_PublishedTransports |= supportedTransports;
					}
					else
					{
						address->published = false;
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
			else if (address->transportStyle == eTransportSSU2 && isV2 && isStaticKey && isIntroKey)
			{
				if (address->IsV4 ()) supportedTransports |= eSSU2V4;
				if (address->IsV6 ()) supportedTransports |= eSSU2V6;
				if (isHost && address->port)
				{
					if (address->host.is_v4 ()) m_PublishedTransports |= eSSU2V4;
					if (address->host.is_v6 ()) m_PublishedTransports |= eSSU2V6;
					address->published = true;
				}
				else if (address->ssu && !address->ssu->introducers.empty ())
				{
					// exclude invalid introducers
					uint32_t ts = i2p::util::GetSecondsSinceEpoch ();
					UpdateIntroducers (address, ts);
					if (!address->ssu->introducers.empty ()) // still has something
						m_ReachableTransports |= supportedTransports;
				}
			}
			if (supportedTransports)
			{
				if (!(m_SupportedTransports & supportedTransports)) // avoid duplicates
				{
					for (uint8_t i = 0; i < eNumTransports; i++)
						if ((1 << i) & supportedTransports)
							(*addresses)[i] = address;
				}
				m_SupportedTransports |= supportedTransports;
			}
		}
		m_ReachableTransports |= m_PublishedTransports;
		// update addresses
#ifdef __cpp_lib_atomic_shared_ptr
		m_Addresses = addresses;
#else		
		boost::atomic_store (&m_Addresses, addresses);
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
			{	
				ExtractCaps (value);
				m_IsFloodfill = IsDeclaredFloodfill ();
			}	
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
				{	
					LogPrint (eLogWarning, "RouterInfo: Family ", family, " signature verification failed");
					SetUnreachable (true);	
				}		
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
				case CAPS_FLAG_LOW_BANDWIDTH1:
				case CAPS_FLAG_LOW_BANDWIDTH2:
				case CAPS_FLAG_LOW_BANDWIDTH3:
				case CAPS_FLAG_LOW_BANDWIDTH4:
					m_BandwidthCap = *cap;
				break;
				case CAPS_FLAG_HIGH_BANDWIDTH:
					m_Caps |= Caps::eHighBandwidth;
					m_BandwidthCap = *cap;
				break;
				case CAPS_FLAG_EXTRA_BANDWIDTH1:
				case CAPS_FLAG_EXTRA_BANDWIDTH2:
					m_Caps |= Caps::eExtraBandwidth | Caps::eHighBandwidth;
					m_BandwidthCap = *cap;
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
				case CAPS_FLAG_MEDIUM_CONGESTION:
					m_Congestion = eMediumCongestion;
				break;
				case CAPS_FLAG_HIGH_CONGESTION:
					m_Congestion = eHighCongestion;
				break;
				case CAPS_FLAG_REJECT_ALL_CONGESTION:
					m_Congestion = eRejectAll;
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
				case CAPS_FLAG_SSU2_TESTING:
					caps |= AddressCaps::eSSUTesting;
				break;
				case CAPS_FLAG_SSU2_INTRODUCER:
					caps |= AddressCaps::eSSUIntroducer;
				break;
				default: ;
			}
			cap++;
		}
		return caps;
	}

	void RouterInfo::UpdateIntroducers (std::shared_ptr<Address> address, uint64_t ts)
	{
		if (!address || !address->ssu) return;
		int numValid = 0;
		for (auto& it: address->ssu->introducers)
		{
			if (it.iTag && ts < it.iExp && !it.iH.IsZero ())
				numValid++;
			else
				it.iTag = 0;
		}
		if (!numValid)
			address->ssu->introducers.resize (0);
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
			else
				return nullptr;
		}
		return m_Buffer->data ();
	}

	bool RouterInfo::SaveToFile (const std::string& fullPath, std::shared_ptr<Buffer> buf)
	{
		if (!buf) return false;
		std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
		if (!f.is_open ()) 
		{
			LogPrint (eLogError, "RouterInfo: Can't save to ", fullPath);
			return false;
		}
		f.write ((char *)buf->data (), buf->GetBufferLen ());
		return true;
	}	
		
	bool RouterInfo::SaveToFile (const std::string& fullPath)
	{
		if (m_IsUnreachable) return false; // don't save bad router
		if (!m_Buffer)
		{
			LogPrint (eLogWarning, "RouterInfo: Can't save, m_Buffer == NULL");
			return false;
		}
		return SaveToFile (fullPath, m_Buffer);
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

	void RouterInfo::AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv,int port, uint8_t caps)
	{
		auto addr = std::make_shared<Address>();
		addr->port = port;
		addr->transportStyle = eTransportNTCP2;
		addr->caps = caps;
		addr->date = 0;
		addr->published = false;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, iv, 16);
		if (addr->IsV4 ())
		{
			m_SupportedTransports |= eNTCP2V4;
			(*GetAddresses ())[eNTCP2V4Idx] = addr;
		}
		if (addr->IsV6 ())
		{
			m_SupportedTransports |= eNTCP2V6;
			(*GetAddresses ())[eNTCP2V6Idx] = addr;
		}
	}

	void RouterInfo::AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv,
		const boost::asio::ip::address& host, int port)
	{
		auto addr = std::make_shared<Address>();
		addr->host = host;
		addr->port = port;
		addr->transportStyle = eTransportNTCP2;
		addr->date = 0;
		addr->published = true;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, iv, 16);
		addr->caps = 0;
		if (host.is_unspecified ())
		{	
			if (host.is_v4 ()) addr->caps |= eV4;
			if (host.is_v6 ()) addr->caps |= eV6;
		}	
		auto addresses = GetAddresses ();
		if (addr->IsV4 ())
		{
			m_SupportedTransports |= eNTCP2V4;
			m_ReachableTransports |= eNTCP2V4;
			(*addresses)[eNTCP2V4Idx] = addr;
		}
		if (addr->IsV6 ())
		{
			if (i2p::util::net::IsYggdrasilAddress (addr->host))
			{
				m_SupportedTransports |= eNTCP2V6Mesh;
				m_ReachableTransports |= eNTCP2V6Mesh;
				(*addresses)[eNTCP2V6MeshIdx] = addr;
			}
			else
			{
				m_SupportedTransports |= eNTCP2V6;
				m_ReachableTransports |= eNTCP2V6;
				(*addresses)[eNTCP2V6Idx] = addr;
			}
		}
	}

	void RouterInfo::RemoveNTCP2Address (bool v4)
	{
		auto addresses = GetAddresses ();
		if (v4)
		{
			if ((*addresses)[eNTCP2V6Idx])
				(*addresses)[eNTCP2V6Idx]->caps &= ~AddressCaps::eV4;
			(*addresses)[eNTCP2V4Idx].reset ();
		}
		else
		{
			if ((*addresses)[eNTCP2V4Idx])
				(*addresses)[eNTCP2V4Idx]->caps &= ~AddressCaps::eV6;
			(*addresses)[eNTCP2V6Idx].reset ();
		}
		UpdateSupportedTransports ();
	}

	void RouterInfo::AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey, int port, uint8_t caps)
	{
		auto addr = std::make_shared<Address>();
		addr->transportStyle = eTransportSSU2;
		addr->port = port;
		addr->caps = caps;
		addr->date = 0;
		addr->ssu.reset (new SSUExt ());
		addr->ssu->mtu = 0;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, introKey, 32);
		auto addresses = GetAddresses ();
		if (addr->IsV4 ())
		{
			m_SupportedTransports |= eSSU2V4;
			(*addresses)[eSSU2V4Idx] = addr;
		}
		if (addr->IsV6 ())
		{
			m_SupportedTransports |= eSSU2V6;
			(*addresses)[eSSU2V6Idx] = addr;
		}
	}

	void RouterInfo::AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey,
		const boost::asio::ip::address& host, int port)
	{
		auto addr = std::make_shared<Address>();
		addr->transportStyle = eTransportSSU2;
		addr->host = host;
		addr->port = port;
		addr->published = true;
		addr->date = 0;
		addr->ssu.reset (new SSUExt ());
		addr->ssu->mtu = 0;
		memcpy (addr->s, staticKey, 32);
		memcpy (addr->i, introKey, 32);
		if (!host.is_unspecified ())
			addr->caps = i2p::data::RouterInfo::eSSUTesting | i2p::data::RouterInfo::eSSUIntroducer; // BC;
		else
		{	
			addr->caps = 0;
			if (host.is_v4 ()) addr->caps |= eV4;
			if (host.is_v6 ()) addr->caps |= eV6;
		}
		auto addresses = GetAddresses ();
		if (addr->IsV4 ())
		{
			m_SupportedTransports |= eSSU2V4;
			m_ReachableTransports |= eSSU2V4;
			(*addresses)[eSSU2V4Idx] = addr;
		}
		if (addr->IsV6 ())
		{
			m_SupportedTransports |= eSSU2V6;
			m_ReachableTransports |= eSSU2V6;
			(*addresses)[eSSU2V6Idx] = addr;
		}
	}

	void RouterInfo::RemoveSSU2Address (bool v4)
	{
		auto addresses = GetAddresses ();
		if (v4)
		{
			if ((*addresses)[eSSU2V6Idx])
				(*addresses)[eSSU2V6Idx]->caps &= ~AddressCaps::eV4;
			(*addresses)[eSSU2V4Idx].reset ();
		}
		else
		{
			if ((*addresses)[eSSU2V4Idx])
				(*addresses)[eSSU2V4Idx]->caps &= ~AddressCaps::eV6;
			(*addresses)[eSSU2V6Idx].reset ();
		}
		UpdateSupportedTransports ();
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
			auto addresses = GetAddresses ();
			if ((*addresses)[eNTCP2V6Idx])
			{
				if ((*addresses)[eNTCP2V6Idx]->IsV4 () && (*addresses)[eNTCP2V4Idx])
					(*addresses)[eNTCP2V4Idx]->caps &= ~AddressCaps::eV6;
				(*addresses)[eNTCP2V6Idx].reset ();
			}
			if ((*addresses)[eSSU2V6Idx])
			{
				if ((*addresses)[eSSU2V6Idx]->IsV4 () && (*addresses)[eSSU2V4Idx])
					(*addresses)[eSSU2V4Idx]->caps &= ~AddressCaps::eV6;
				(*addresses)[eSSU2V6Idx].reset ();
			}
			UpdateSupportedTransports ();
		}
	}

	void RouterInfo::DisableV4 ()
	{
		if (IsV4 ())
		{
			auto addresses = GetAddresses ();
			if ((*addresses)[eNTCP2V4Idx])
			{
				if ((*addresses)[eNTCP2V4Idx]->IsV6 () && (*addresses)[eNTCP2V6Idx])
					(*addresses)[eNTCP2V6Idx]->caps &= ~AddressCaps::eV4;
				(*addresses)[eNTCP2V4Idx].reset ();
			}
			if ((*addresses)[eSSU2V4Idx])
			{
				if ((*addresses)[eSSU2V4Idx]->IsV6 () && (*addresses)[eSSU2V6Idx])
					(*addresses)[eSSU2V6Idx]->caps &= ~AddressCaps::eV4;
				(*addresses)[eSSU2V4Idx].reset ();
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
			(*GetAddresses ())[eNTCP2V6MeshIdx].reset ();
		}
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSU2V4Address () const
	{
		return (*GetAddresses ())[eSSU2V4Idx];
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetSSU2V6Address () const
	{
		return (*GetAddresses ())[eSSU2V6Idx];
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

	RouterInfo::AddressesPtr RouterInfo::GetAddresses () const
	{
#ifdef __cpp_lib_atomic_shared_ptr
		return m_Addresses;
#else		
		return boost::atomic_load (&m_Addresses);
#endif
	}

	template<typename Filter>
	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetAddress (Filter filter) const
	{
		// TODO: make it more generic using comparator
#ifdef __cpp_lib_atomic_shared_ptr
		AddressesPtr addresses = m_Addresses;
#else		
		auto addresses = boost::atomic_load (&m_Addresses);
#endif
		for (const auto& address : *addresses)
			if (address && filter (address)) return address;

		return nullptr;
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetNTCP2V4Address () const
	{
		return (*GetAddresses ())[eNTCP2V4Idx];
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetNTCP2V6Address () const
	{
		return (*GetAddresses ())[eNTCP2V6Idx];
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetPublishedNTCP2V4Address () const
	{
		auto addr = (*GetAddresses ())[eNTCP2V4Idx];
		if (addr && addr->IsPublishedNTCP2 ()) return addr;
		return nullptr;
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetPublishedNTCP2V6Address () const
	{
		auto addr = (*GetAddresses ())[eNTCP2V6Idx];
		if (addr && addr->IsPublishedNTCP2 ()) return addr;
		return nullptr;
	}

	std::shared_ptr<const RouterInfo::Address> RouterInfo::GetYggdrasilAddress () const
	{
		return (*GetAddresses ())[eNTCP2V6MeshIdx];
	}

	std::shared_ptr<RouterProfile> RouterInfo::GetProfile () const
	{
		auto profile = m_Profile;
		if (!profile)
		{	
			profile = GetRouterProfile (GetIdentHash ());
			m_Profile = profile;
		}	
		return profile;
	}

	void RouterInfo::Encrypt (const uint8_t * data, uint8_t * encrypted) const
	{
		auto encryptor = m_RouterIdentity->CreateEncryptor (nullptr);
		if (encryptor)
			encryptor->Encrypt (data, encrypted);
	}

	bool RouterInfo::IsEligibleFloodfill () const
	{
		// floodfill must have published ipv4 or reachable ipv4 and published ipv6
		// >= 0.9.59 and not DSA
		return m_Version >= NETDB_MIN_FLOODFILL_VERSION && (IsPublished (true) ||
			(IsReachableBy (eNTCP2V4 | eSSU2V4) && IsPublished (false))) &&
			GetIdentity ()->GetSigningKeyType () != SIGNING_KEY_TYPE_DSA_SHA1;
	}

	bool RouterInfo::IsPublished (bool v4) const
	{
		if (m_Caps & (eUnreachable | eHidden)) return false; // if router sets U or H we assume that all addresses are not published
		return IsPublishedOn (v4 ? (eNTCP2V4 | eSSU2V4) : (eNTCP2V6 | eSSU2V6));
	}	

	bool RouterInfo::IsPublishedOn (CompatibleTransports transports) const
	{
		return m_PublishedTransports & transports;
	}
	
	bool RouterInfo::IsNAT2NATOnly (const RouterInfo& other) const
	{
		return !(m_PublishedTransports & other.m_SupportedTransports) &&
			!(other.m_PublishedTransports & m_SupportedTransports); 	
	}	
		
	bool RouterInfo::IsSSU2PeerTesting (bool v4) const
	{
		if (!(m_SupportedTransports & (v4 ? eSSU2V4 : eSSU2V6))) return false;
		auto addr = (*GetAddresses ())[v4 ? eSSU2V4Idx : eSSU2V6Idx];
		return addr && addr->IsPeerTesting () && addr->IsReachableSSU ();
	}

	bool RouterInfo::IsSSU2Introducer (bool v4) const
	{
		if (!(m_SupportedTransports & (v4 ? eSSU2V4 : eSSU2V6))) return false;
		auto addr = (*GetAddresses ())[v4 ? eSSU2V4Idx : eSSU2V6Idx];
		return addr && addr->IsIntroducer () && !addr->host.is_unspecified () && addr->port;
	}

	void RouterInfo::SetUnreachableAddressesTransportCaps (uint8_t transports)
	{
		for (auto& addr: *GetAddresses ())
		{
			if (addr && !addr->published)
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
		for (const auto& addr: *GetAddresses ())
		{
			if (!addr) continue;
			uint8_t transports = 0;
			switch (addr->transportStyle)
			{
				case eTransportNTCP2:
					if (addr->IsV4 ()) transports |= eNTCP2V4;
					if (addr->IsV6 ())
						transports |= (i2p::util::net::IsYggdrasilAddress (addr->host) ? eNTCP2V6Mesh : eNTCP2V6);
					if (addr->IsPublishedNTCP2 ())
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

	void RouterInfo::UpdateIntroducers (uint64_t ts)
	{
		if (ts*1000 < m_Timestamp + INTRODUCER_UPDATE_INTERVAL) return;
		if (m_ReachableTransports & eSSU2V4)
		{
			auto addr = (*GetAddresses ())[eSSU2V4Idx];
			if (addr && addr->UsesIntroducer ())
			{
				UpdateIntroducers (addr, ts);
				if (!addr->UsesIntroducer ()) // no more valid introducers
					m_ReachableTransports &= ~eSSU2V4;
			}	
		}	
		if (m_ReachableTransports & eSSU2V6)
		{
			auto addr = (*GetAddresses ())[eSSU2V6Idx];
			if (addr && addr->UsesIntroducer ())
			{
				UpdateIntroducers (addr, ts);
				if (!addr->UsesIntroducer ()) // no more valid introducers
					m_ReachableTransports &= ~eSSU2V6;
			}	
		}	
	}	
		
	void RouterInfo::UpdateBuffer (const uint8_t * buf, size_t len)
	{
		if (!m_Buffer)
			m_Buffer = NewBuffer ();
		if (len > m_Buffer->size ()) len = m_Buffer->size ();
		memcpy (m_Buffer->data (), buf, len);
		m_Buffer->SetBufferLen (len);
	}

	std::shared_ptr<RouterInfo::Buffer> RouterInfo::CopyBuffer () const
	{
		if (!m_Buffer) return nullptr;
		return netdb.NewRouterInfoBuffer (*m_Buffer);
	}	
		
	std::shared_ptr<RouterInfo::Buffer> RouterInfo::NewBuffer () const
	{
		return netdb.NewRouterInfoBuffer ();
	}

	std::shared_ptr<RouterInfo::Address> RouterInfo::NewAddress () const
	{
		return netdb.NewRouterInfoAddress ();
	}

	RouterInfo::AddressesPtr RouterInfo::NewAddresses () const
	{
		return netdb.NewRouterInfoAddresses ();
	}

	std::shared_ptr<IdentityEx> RouterInfo::NewIdentity (const uint8_t * buf, size_t len) const
	{
		return netdb.NewIdentity (buf, len);
	}	
		
	void RouterInfo::RefreshTimestamp ()
	{
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch ();
	}

	bool RouterInfo::IsHighCongestion (bool highBandwidth) const
	{
		switch (m_Congestion)
		{
			case eLowCongestion:
				return false;
			break;
			case eMediumCongestion:
				return highBandwidth;
			break;
			case eHighCongestion:
				return i2p::util::GetMillisecondsSinceEpoch () < m_Timestamp + HIGH_CONGESTION_INTERVAL*1000LL;
			break;	
			case eRejectAll:
				return true;
			break;	
			default:
				return false;
		}
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
				caps += CAPS_FLAG_HIGH_BANDWIDTH; // 'O'
			caps += CAPS_FLAG_FLOODFILL; // floodfill
		}
		else
		{
			if (c & eExtraBandwidth)
				caps += (c & eHighBandwidth) ? CAPS_FLAG_EXTRA_BANDWIDTH2 /* 'X' */ : CAPS_FLAG_EXTRA_BANDWIDTH1; /*'P' */
			else
				caps += (c & eHighBandwidth) ? CAPS_FLAG_HIGH_BANDWIDTH /* 'O' */: CAPS_FLAG_LOW_BANDWIDTH2 /* 'L' */; // bandwidth
		}
		if (c & eHidden) caps += CAPS_FLAG_HIDDEN; // hidden
		if (c & eReachable) caps += CAPS_FLAG_REACHABLE; // reachable
		if (c & eUnreachable) caps += CAPS_FLAG_UNREACHABLE; // unreachable

		switch (GetCongestion ())
		{
			case eMediumCongestion:
				caps += CAPS_FLAG_MEDIUM_CONGESTION;
			break;	
			case eHighCongestion:
				caps += CAPS_FLAG_HIGH_CONGESTION;
			break;		
			case eRejectAll:
				caps += CAPS_FLAG_REJECT_ALL_CONGESTION;
			break;	
			default: ;	
		};	
		
		SetProperty ("caps", caps);
	}

	bool LocalRouterInfo::UpdateCongestion (Congestion c)
	{
		if (c != GetCongestion ())
		{
			SetCongestion (c);
			UpdateCapsProperty ();
			return true;
		}	
		return false;
 	}	
		
	void LocalRouterInfo::WriteToStream (std::ostream& s) const
	{
		auto addresses = GetAddresses ();
		if (!addresses) return;

		uint64_t ts = htobe64 (GetTimestamp ());
		s.write ((const char *)&ts, sizeof (ts));
		// addresses
		uint8_t numAddresses = 0;
		for (size_t idx = 0; idx < addresses->size(); idx++)
		{
			auto addr_ptr = (*addresses)[idx];
			if (!addr_ptr) continue;
			if (idx == eNTCP2V6Idx && addr_ptr == (*addresses)[eNTCP2V4Idx]) continue;
			if (idx == eSSU2V6Idx && addr_ptr == (*addresses)[eSSU2V4Idx]) continue;
			numAddresses++;
		}
		s.write ((char *)&numAddresses, sizeof (numAddresses));
		for (size_t idx = 0; idx < addresses->size(); idx++)
		{
			auto addr_ptr = (*addresses)[idx];
			if (!addr_ptr) continue;
			if (idx == eNTCP2V6Idx && addr_ptr == (*addresses)[eNTCP2V4Idx]) continue;
			if (idx == eSSU2V6Idx && addr_ptr == (*addresses)[eSSU2V4Idx]) continue;
			const Address& address = *addr_ptr;
			// calculate cost
			uint8_t cost = 0x7f;
			if (address.transportStyle == eTransportNTCP2)
				cost = address.published ? COST_NTCP2_PUBLISHED : COST_NTCP2_NON_PUBLISHED;
			else if (address.transportStyle == eTransportSSU2)
				cost = address.published ? COST_SSU2_DIRECT : COST_SSU2_NON_PUBLISHED;
			else
				continue; // skip unknown address
			s.write ((const char *)&cost, sizeof (cost));
			s.write ((const char *)&address.date, sizeof (address.date));
			std::stringstream properties;
			bool isPublished = address.published && !address.host.is_unspecified () && address.port;
			if (address.transportStyle == eTransportNTCP2)
			{
				WriteString ("NTCP2", s);
				// caps
				if (!isPublished)
				{
					WriteString ("caps", properties);
					properties << '=';
					std::string caps;
					if (address.IsV4 ()) caps += CAPS_FLAG_V4;
					if (address.IsV6 () || address.host.is_v6 ()) caps += CAPS_FLAG_V6; // we set 6 for unspecified ipv6
					if (caps.empty ()) caps += CAPS_FLAG_V4;
					WriteString (caps, properties);
					properties << ';';
				}
			}
			else if (address.transportStyle == eTransportSSU2)
			{
				WriteString ("SSU2", s);
				// caps
				std::string caps;
				if (isPublished)
				{
					if (address.IsPeerTesting ()) caps += CAPS_FLAG_SSU2_TESTING;
					if (address.IsIntroducer ()) caps += CAPS_FLAG_SSU2_INTRODUCER;
				}
				else
				{
					if (address.IsV4 ()) caps += CAPS_FLAG_V4;
					if (address.IsV6 () || address.host.is_v6 ()) caps += CAPS_FLAG_V6; // we set 6 for unspecified ipv6
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

			if (isPublished && !address.host.is_unspecified ())
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
			if (address.transportStyle == eTransportSSU2)
			{
				// write introducers if any
				if (address.ssu && !address.ssu->introducers.empty())
				{
					int i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						if (!introducer.iTag) continue;
						if (introducer.iExp) // expiration is specified
						{
							WriteString ("iexp" + boost::lexical_cast<std::string>(i), properties);
							properties << '=';
							WriteString (boost::lexical_cast<std::string>(introducer.iExp), properties);
							properties << ';';
						}
						i++;
					}
					i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						if (!introducer.iTag) continue;
						WriteString ("ih" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						char value[64];
						size_t l = ByteStreamToBase64 (introducer.iH, 32, value, 64);
						value[l] = 0;
						WriteString (value, properties);
						properties << ';';
						i++;
					}
					i = 0;
					for (const auto& introducer: address.ssu->introducers)
					{
						if (!introducer.iTag) continue;
						WriteString ("itag" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (boost::lexical_cast<std::string>(introducer.iTag), properties);
						properties << ';';
						i++;
					}
				}
			}

			if (address.transportStyle == eTransportSSU2)
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
			if (isPublished && address.port)
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

	void LocalRouterInfo::UpdateFloodfillProperty (bool floodfill)
	{
		if (floodfill)
		{	
			UpdateCaps (GetCaps () | i2p::data::RouterInfo::eFloodfill);
			SetFloodfill ();
		}	
		else
		{	
			UpdateCaps (GetCaps () & ~i2p::data::RouterInfo::eFloodfill);
			ResetFloodfill ();
		}	
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

	std::shared_ptr<RouterInfo::Address> LocalRouterInfo::NewAddress () const
	{
		return std::make_shared<Address> ();
	}

	RouterInfo::AddressesPtr LocalRouterInfo::NewAddresses () const
	{
		return RouterInfo::AddressesPtr(new RouterInfo::Addresses ());
	}

	std::shared_ptr<IdentityEx> LocalRouterInfo::NewIdentity (const uint8_t * buf, size_t len) const
	{
		return std::make_shared<IdentityEx> (buf, len);
	}	
		
	bool LocalRouterInfo::AddSSU2Introducer (const Introducer& introducer, bool v4)
	{
		auto addresses = GetAddresses ();
		if (!addresses) return false;
		auto addr = (*addresses)[v4 ? eSSU2V4Idx : eSSU2V6Idx];
		if (addr)
		{
			for (auto& intro: addr->ssu->introducers)
				if (intro.iTag == introducer.iTag) return false; // already presented
			addr->ssu->introducers.push_back (introducer);
			SetReachableTransports (GetReachableTransports () | ((addr->IsV4 () ? eSSU2V4 : eSSU2V6)));
			return true;
		}
		return false;
	}

	bool LocalRouterInfo::RemoveSSU2Introducer (const IdentHash& h, bool v4)
	{
		auto addresses = GetAddresses ();
		if (!addresses) return false;
		auto addr = (*addresses)[v4 ? eSSU2V4Idx : eSSU2V6Idx];
		if (addr)
		{
			for (auto it = addr->ssu->introducers.begin (); it != addr->ssu->introducers.end (); ++it)
				if (h == it->iH)
				{
					addr->ssu->introducers.erase (it);
					if (addr->ssu->introducers.empty ())
						SetReachableTransports (GetReachableTransports () & ~(addr->IsV4 () ? eSSU2V4 : eSSU2V6));
					return true;
				}
		}
		return false;
	}

	bool LocalRouterInfo::UpdateSSU2Introducer (const IdentHash& h, bool v4, uint32_t iTag, uint32_t iExp)
	{
		auto addresses = GetAddresses ();
		if (!addresses) return false;
		auto addr = (*addresses)[v4 ? eSSU2V4Idx : eSSU2V6Idx];
		if (addr)
		{
			for (auto& it: addr->ssu->introducers)
				if (h == it.iH)
				{
					it.iTag = iTag;
					it.iExp = iExp;
					return true;
				}	
		}
		return false;
	}	
}
}
