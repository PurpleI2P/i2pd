#include <stdio.h>
#include <string.h>
#include "I2PEndian.h"
#include <fstream>
#include <boost/lexical_cast.hpp>
#include <cryptopp/sha.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "base64.h"
#include "Timestamp.h"
#include "Log.h"
#include "RouterInfo.h"
#include "RouterContext.h"


namespace i2p
{
namespace data
{		
	RouterInfo::RouterInfo (const std::string& fullPath):
		m_FullPath (fullPath), m_IsUpdated (false), m_IsUnreachable (false), 
		m_SupportedTransports (0), m_Caps (0)
	{
		m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		ReadFromFile ();
	}	

	RouterInfo::RouterInfo (const uint8_t * buf, int len):
		m_IsUpdated (true), m_IsUnreachable (false), m_SupportedTransports (0), m_Caps (0)
	{
		m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer (true);
	}	

	RouterInfo::~RouterInfo ()
	{
		delete m_Buffer;
	}	
		
	void RouterInfo::Update (const uint8_t * buf, int len)
	{
		if (!m_Buffer)	
			m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		m_IsUpdated = true;
		m_IsUnreachable = false;
		m_SupportedTransports = 0;
		m_Caps = 0;
		m_Addresses.clear ();
		m_Properties.clear ();
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer (true);
		// don't delete buffer until save to file
	}	
		
	void RouterInfo::SetRouterIdentity (const IdentityEx& identity)
	{	
		m_RouterIdentity = identity;
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch ();
	}
	
	bool RouterInfo::LoadFile ()
	{
		std::ifstream s(m_FullPath.c_str (), std::ifstream::binary);
		if (s.is_open ())	
		{	
			s.seekg (0,std::ios::end);
			m_BufferLen = s.tellg ();
			if (m_BufferLen < 40)
			{
				LogPrint(eLogError, "File", m_FullPath, " is malformed");
				return false;
			}
			s.seekg(0, std::ios::beg);
			if (!m_Buffer)
				m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
			s.read((char *)m_Buffer, m_BufferLen);
		}	
		else
		{
			LogPrint (eLogError, "Can't open file ", m_FullPath);
			return false;		
		}
		return true;
	}	

	void RouterInfo::ReadFromFile ()
	{
		if (LoadFile ())
			ReadFromBuffer (false); 
	}	

	void RouterInfo::ReadFromBuffer (bool verifySignature)
	{
		size_t identityLen = m_RouterIdentity.FromBuffer (m_Buffer, m_BufferLen);
		std::stringstream str (std::string ((char *)m_Buffer + identityLen, m_BufferLen - identityLen));
		ReadFromStream (str);
		if (verifySignature)
		{	
			// verify signature
			int l = m_BufferLen - m_RouterIdentity.GetSignatureLen ();
			if (!m_RouterIdentity.Verify ((uint8_t *)m_Buffer, l, (uint8_t *)m_Buffer + l))
			{	
				LogPrint (eLogError, "signature verification failed");	
				m_IsUnreachable = true;
			}
			m_RouterIdentity.DropVerifier ();
		}	
	}	
	
	void RouterInfo::ReadFromStream (std::istream& s)
	{
		s.read ((char *)&m_Timestamp, sizeof (m_Timestamp));
		m_Timestamp = be64toh (m_Timestamp);
		// read addresses
		uint8_t numAddresses;
		s.read ((char *)&numAddresses, sizeof (numAddresses));
		bool introducers = false;
		for (int i = 0; i < numAddresses; i++)
		{
			bool isValidAddress = true;
			Address address;
			s.read ((char *)&address.cost, sizeof (address.cost));
			s.read ((char *)&address.date, sizeof (address.date));
			char transportStyle[5];
			ReadString (transportStyle, s);
			if (!strcmp (transportStyle, "NTCP"))
				address.transportStyle = eTransportNTCP;
			else if (!strcmp (transportStyle, "SSU"))
				address.transportStyle = eTransportSSU;
			else
				address.transportStyle = eTransportUnknown;
			address.port = 0;
			address.mtu = 0;
			uint16_t size, r = 0;
			s.read ((char *)&size, sizeof (size));
			size = be16toh (size);
			while (r < size)
			{
				char key[500], value[500];
				r += ReadString (key, s);
				s.seekg (1, std::ios_base::cur); r++; // =
				r += ReadString (value, s); 
				s.seekg (1, std::ios_base::cur); r++; // ;
				if (!strcmp (key, "host"))
				{	
					boost::system::error_code ecode;
					address.host = boost::asio::ip::address::from_string (value, ecode);
					if (ecode)
					{	
						if (address.transportStyle == eTransportNTCP)
						{
							m_SupportedTransports |= eNTCPV4; // TODO:
							address.addressString = value;
						}
						else
						{	
							// TODO: resolve address for SSU
							LogPrint (eLogWarning, "Unexpected SSU address ", value);
							isValidAddress = false;
						}	
					}	
					else
					{
						// add supported protocol
						if (address.host.is_v4 ())
							m_SupportedTransports |= (address.transportStyle == eTransportNTCP) ? eNTCPV4 : eSSUV4;	
						else
							m_SupportedTransports |= (address.transportStyle == eTransportNTCP) ? eNTCPV6 : eSSUV6;
 					}	
				}	
				else if (!strcmp (key, "port"))
					address.port = boost::lexical_cast<int>(value);
				else if (!strcmp (key, "mtu"))
					address.mtu = boost::lexical_cast<int>(value);
				else if (!strcmp (key, "key"))
					Base64ToByteStream (value, strlen (value), address.key, 32);
				else if (!strcmp (key, "caps"))
					ExtractCaps (value);
				else if (key[0] == 'i')
				{	
					// introducers
					introducers = true;
					size_t l = strlen(key); 	
					unsigned char index = key[l-1] - '0'; // TODO:
					key[l-1] = 0;
					if (index >= address.introducers.size ())
						address.introducers.resize (index + 1); 
					Introducer& introducer = address.introducers.at (index);
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
				}
			}	
			if (isValidAddress)
				m_Addresses.push_back(address);
		}	
		// read peers
		uint8_t numPeers;
		s.read ((char *)&numPeers, sizeof (numPeers));
		s.seekg (numPeers*32, std::ios_base::cur); // TODO: read peers
		// read properties
		uint16_t size, r = 0;
		s.read ((char *)&size, sizeof (size));
		size = be16toh (size);
		while (r < size)
		{
#ifdef _WIN32			
			char key[500], value[500];
			// TODO: investigate why properties get read as one long string under Windows
			// length should not be more than 44
#else
			char key[50], value[50];
#endif			
			r += ReadString (key, s);
			s.seekg (1, std::ios_base::cur); r++; // =
			r += ReadString (value, s); 
			s.seekg (1, std::ios_base::cur); r++; // ;
			m_Properties[key] = value;
			
			// extract caps	
			if (!strcmp (key, "caps"))
				ExtractCaps (value);
		}		

		if (!m_SupportedTransports || !m_Addresses.size() || (UsesIntroducer () && !introducers))
			SetUnreachable (true);
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
			caps += CAPS_FLAG_HIGH_BANDWIDTH3; // highest bandwidth
			caps += CAPS_FLAG_FLOODFILL; // floodfill  
		}	
		else
			caps += (m_Caps & eHighBandwidth) ? CAPS_FLAG_HIGH_BANDWIDTH3 : CAPS_FLAG_LOW_BANDWIDTH2; // bandwidth		
		if (m_Caps & eHidden) caps += CAPS_FLAG_HIDDEN; // hidden
		if (m_Caps & eReachable) caps += CAPS_FLAG_REACHABLE; // reachable
		if (m_Caps & eUnreachable) caps += CAPS_FLAG_UNREACHABLE; // unreachable

		SetProperty ("caps", caps.c_str ());
	}
		
	void RouterInfo::WriteToStream (std::ostream& s)
	{
		uint64_t ts = htobe64 (m_Timestamp);
		s.write ((char *)&ts, sizeof (ts));

		// addresses
		uint8_t numAddresses = m_Addresses.size ();
		s.write ((char *)&numAddresses, sizeof (numAddresses));
		for (auto& address : m_Addresses)
		{
			s.write ((char *)&address.cost, sizeof (address.cost));
			s.write ((char *)&address.date, sizeof (address.date));
			std::stringstream properties;
			if (address.transportStyle == eTransportNTCP)
				WriteString ("NTCP", s);
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

			WriteString ("host", properties);
			properties << '=';
			WriteString (address.host.to_string (), properties);
			properties << ';';
			if (address.transportStyle == eTransportSSU)
			{
				// write introducers if any
				if (address.introducers.size () > 0)
				{	
					int i = 0;
					for (auto introducer: address.introducers)
					{
						WriteString ("ihost" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (introducer.iHost.to_string (), properties);
						properties << ';';
						i++;
					}	
					i = 0;
					for (auto introducer: address.introducers)
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
					for (auto introducer: address.introducers)
					{
						WriteString ("iport" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (boost::lexical_cast<std::string>(introducer.iPort), properties);
						properties << ';';
						i++;
					}	
					i = 0;
					for (auto introducer: address.introducers)
					{
						WriteString ("itag" + boost::lexical_cast<std::string>(i), properties);
						properties << '=';
						WriteString (boost::lexical_cast<std::string>(introducer.iTag), properties);
						properties << ';';
						i++;
					}	
				}	
				// write intro key
				WriteString ("key", properties);
				properties << '=';
				char value[64];
				size_t l = ByteStreamToBase64 (address.key, 32, value, 64);
				value[l] = 0;
				WriteString (value, properties);
				properties << ';';
				// write mtu
				if (address.mtu)
				{
					WriteString ("mtu", properties);
					properties << '=';
					WriteString (boost::lexical_cast<std::string>(address.mtu), properties);
					properties << ';';
				}	
			}	
			WriteString ("port", properties);
			properties << '=';
			WriteString (boost::lexical_cast<std::string>(address.port), properties);
			properties << ';';
			
			uint16_t size = htobe16 (properties.str ().size ());
			s.write ((char *)&size, sizeof (size));
			s.write (properties.str ().c_str (), properties.str ().size ());
		}	

		// peers
		uint8_t numPeers = 0;
		s.write ((char *)&numPeers, sizeof (numPeers));

		// properties
		std::stringstream properties;
		for (auto& p : m_Properties)
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

	const uint8_t * RouterInfo::LoadBuffer ()
	{
		if (!m_Buffer)
		{
			if (LoadFile ())
				LogPrint ("Buffer for ", GetIdentHashAbbreviation (), " loaded from file");
		} 
		return m_Buffer; 
	}

	void RouterInfo::CreateBuffer (const PrivateKeys& privateKeys)
	{
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch (); // refresh timstamp
		std::stringstream s;
		uint8_t ident[1024];
		auto identLen = privateKeys.GetPublic ().ToBuffer (ident, 1024);
		s.write ((char *)ident, identLen);			
		WriteToStream (s);
		m_BufferLen = s.str ().size ();
		if (!m_Buffer)
			m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		memcpy (m_Buffer, s.str ().c_str (), m_BufferLen);
		// signature
		privateKeys.Sign ((uint8_t *)m_Buffer, m_BufferLen, (uint8_t *)m_Buffer + m_BufferLen);
		m_BufferLen += privateKeys.GetPublic ().GetSignatureLen ();
	}	

	void RouterInfo::SaveToFile (const std::string& fullPath)
	{
		m_FullPath = fullPath;
		if (m_Buffer)
		{	
			std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
			f.write ((char *)m_Buffer, m_BufferLen);
		}	
		else
			LogPrint (eLogError, "Can't save to file");
	}
	
	size_t RouterInfo::ReadString (char * str, std::istream& s)
	{
		uint8_t len;
		s.read ((char *)&len, 1);
		s.read (str, len);
		str[len] = 0;
		return len+1;
	}	

	void RouterInfo::WriteString (const std::string& str, std::ostream& s)
	{
		uint8_t len = str.size ();
		s.write ((char *)&len, 1);
		s.write (str.c_str (), len);
	}	

	void RouterInfo::AddNTCPAddress (const char * host, int port)
	{
		Address addr;
		addr.host = boost::asio::ip::address::from_string (host);
		addr.port = port;
		addr.transportStyle = eTransportNTCP;
		addr.cost = 2;
		addr.date = 0;
		addr.mtu = 0;
		m_Addresses.push_back(addr);	
		m_SupportedTransports |= addr.host.is_v6 () ? eNTCPV6 : eNTCPV4;
	}	

	void RouterInfo::AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu)
	{
		Address addr;
		addr.host = boost::asio::ip::address::from_string (host);
		addr.port = port;
		addr.transportStyle = eTransportSSU;
		addr.cost = 10; // NTCP should have priority over SSU
		addr.date = 0;
		addr.mtu = mtu; 
		memcpy (addr.key, key, 32);
		m_Addresses.push_back(addr);	
		m_SupportedTransports |= addr.host.is_v6 () ? eNTCPV6 : eSSUV4;
		m_Caps |= eSSUTesting; 
		m_Caps |= eSSUIntroducer; 
	}	

	bool RouterInfo::AddIntroducer (const Address * address, uint32_t tag)
	{
		for (auto& addr : m_Addresses)
		{
			if (addr.transportStyle == eTransportSSU && addr.host.is_v4 ())
			{	
				for (auto intro: addr.introducers)
					if (intro.iTag == tag) return false; // already presented
				Introducer x;
				x.iHost = address->host;
				x.iPort = address->port;
				x.iTag = tag;
				memcpy (x.iKey, address->key, 32); // TODO: replace to Tag<32>
				addr.introducers.push_back (x);
				return true;
			}	
		}	
		return false;
	}	

	bool RouterInfo::RemoveIntroducer (const boost::asio::ip::udp::endpoint& e)
	{		
		for (auto& addr : m_Addresses)
		{
			if (addr.transportStyle == eTransportSSU && addr.host.is_v4 ())
			{	
				for (std::vector<Introducer>::iterator it = addr.introducers.begin (); it != addr.introducers.end (); it++)
					if ( boost::asio::ip::udp::endpoint (it->iHost, it->iPort) == e) 
					{
						addr.introducers.erase (it);
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

	bool RouterInfo::IsFloodfill () const
	{
		return m_Caps & Caps::eFloodfill;
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

	bool RouterInfo::IsV6 () const
	{
		return m_SupportedTransports & (eNTCPV6 | eSSUV6);
	}

	void RouterInfo::EnableV6 ()
	{
		if (!IsV6 ())
			m_SupportedTransports |= eNTCPV6 | eSSUV6;
	}
		
	void RouterInfo::DisableV6 ()
	{		
		if (IsV6 ())
		{	
			// NTCP
			m_SupportedTransports &= ~eNTCPV6; 
			for (size_t i = 0; i < m_Addresses.size (); i++)
			{
				if (m_Addresses[i].transportStyle == i2p::data::RouterInfo::eTransportNTCP &&
					m_Addresses[i].host.is_v6 ())
				{
					m_Addresses.erase (m_Addresses.begin () + i);
					break;
				}
			}	
			
			// SSU
			m_SupportedTransports &= ~eSSUV6; 
			for (size_t i = 0; i < m_Addresses.size (); i++)
			{
				if (m_Addresses[i].transportStyle == i2p::data::RouterInfo::eTransportSSU &&
					m_Addresses[i].host.is_v6 ())
				{
					m_Addresses.erase (m_Addresses.begin () + i);
					break;
				}
			}	
		}	
	}
		
	bool RouterInfo::UsesIntroducer () const
	{
		return m_Caps & Caps::eUnreachable; // non-reachable
	}		
		
	const RouterInfo::Address * RouterInfo::GetNTCPAddress (bool v4only) const
	{
		return GetAddress (eTransportNTCP, v4only);
	}	

	const RouterInfo::Address * RouterInfo::GetSSUAddress (bool v4only) const 
	{
		return GetAddress (eTransportSSU, v4only);
	}	

	const RouterInfo::Address * RouterInfo::GetSSUV6Address () const 
	{
		return GetAddress (eTransportSSU, false, true);
	}	
		
	const RouterInfo::Address * RouterInfo::GetAddress (TransportStyle s, bool v4only, bool v6only) const
	{
		for (auto& address : m_Addresses)
		{
			if (address.transportStyle == s)
			{	
				if ((!v4only || address.host.is_v4 ()) && (!v6only || address.host.is_v6 ()))
					return &address;
			}	
		}	
		return nullptr;
	}	
}
}
