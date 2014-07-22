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
	RouterInfo::RouterInfo (const char * filename):
		m_IsUpdated (false), m_IsUnreachable (false), m_SupportedTransports (0), m_Caps (0)
	{
		m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		ReadFromFile (filename);
	}	

	RouterInfo::RouterInfo (const uint8_t * buf, int len):
		m_IsUpdated (true), m_IsUnreachable (false), m_SupportedTransports (0), m_Caps (0)
	{
		m_Buffer = new uint8_t[MAX_RI_BUFFER_SIZE];
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
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
		ReadFromBuffer ();
		// don't delete buffer until save to file
	}	
		
	void RouterInfo::SetRouterIdentity (const Identity& identity)
	{	
		m_RouterIdentity = identity;
		m_IdentHash = m_RouterIdentity.Hash ();
		UpdateIdentHashBase64 ();
		UpdateRoutingKey ();
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch ();
	}
	
	void RouterInfo::ReadFromFile (const char * filename)
	{
		std::ifstream s(filename, std::ifstream::binary);
		if (s.is_open ())	
		{	
			s.seekg (0,std::ios::end);
			m_BufferLen = s.tellg ();
			if (m_BufferLen < 40)
			{
				LogPrint("File", filename, " is malformed");
				return;
			}
			s.seekg(0, std::ios::beg);
			s.read((char *)m_Buffer, m_BufferLen);
			ReadFromBuffer ();
		}	
		else
			LogPrint ("Can't open file ", filename);
	}	

	void RouterInfo::ReadFromBuffer ()
	{
		std::stringstream str (std::string ((char *)m_Buffer, m_BufferLen));
		ReadFromStream (str);
		// verify signature
		CryptoPP::DSA::PublicKey pubKey;
		pubKey.Initialize (i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag, CryptoPP::Integer (m_RouterIdentity.signingKey, 128));
		CryptoPP::DSA::Verifier verifier (pubKey);
		int l = m_BufferLen - 40;
		if (!verifier.VerifyMessage ((uint8_t *)m_Buffer, l, (uint8_t *)m_Buffer + l, 40))
		{	
			LogPrint ("signature verification failed");
		}	
	}	
	
	void RouterInfo::ReadFromStream (std::istream& s)
	{
		s.read ((char *)&m_RouterIdentity, sizeof (m_RouterIdentity));
		s.read ((char *)&m_Timestamp, sizeof (m_Timestamp));
		m_Timestamp = be64toh (m_Timestamp);
		// read addresses
		uint8_t numAddresses;
		s.read ((char *)&numAddresses, sizeof (numAddresses));
		for (int i = 0; i < numAddresses; i++)
		{
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
						// TODO: we should try to resolve address here
						LogPrint ("Unexpected address ", value);
						SetUnreachable (true);
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
				else if (!strcmp (key, "key"))
					Base64ToByteStream (value, strlen (value), address.key, 32);
				else if (!strcmp (key, "caps"))
					ExtractCaps (value);
				else if (key[0] == 'i')
				{	
					// introducers
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
		
		CryptoPP::SHA256().CalculateDigest(m_IdentHash, (uint8_t *)&m_RouterIdentity, sizeof (m_RouterIdentity));
		UpdateIdentHashBase64 ();
		UpdateRoutingKey ();

		if (!m_SupportedTransports)
			SetUnreachable (true);
	}	

	void RouterInfo::ExtractCaps (const char * value)
	{
		const char * cap = value;
		while (*cap)
		{
			switch (*cap)
			{
				case 'f':
					m_Caps |= Caps::eFloodfill;
				break;
				case 'M':
				case 'N':
				case 'O':
					m_Caps |= Caps::eHighBandwidth;
				break;
				case 'R':
					m_Caps |= Caps::eReachable;
				break;
				case 'B':
					m_Caps |= Caps::eSSUTesting;
				break;	
				case 'C':
					m_Caps |= Caps::eSSUIntroducer;
				break;	
				case 'H':
					m_Caps |= Caps::eHidden;
				break;	
				default: ;
			}	
			cap++;
		}
	}

	void RouterInfo::UpdateIdentHashBase64 ()
	{
		size_t l = i2p::data::ByteStreamToBase64 (m_IdentHash, 32, m_IdentHashBase64, 48);
		m_IdentHashBase64[l] = 0;
		memcpy (m_IdentHashAbbreviation, m_IdentHashBase64, 4);
		m_IdentHashAbbreviation[4] = 0;
	}	

	void RouterInfo::UpdateRoutingKey ()
	{		
		m_RoutingKey = CreateRoutingKey (m_IdentHash);
	}
		
	void RouterInfo::WriteToStream (std::ostream& s)
	{
		s.write ((char *)&m_RouterIdentity, sizeof (m_RouterIdentity));
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
				if (IsPeerTesting ()) caps += 'B';
				if (IsIntroducer ()) caps += 'C';
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
				// wtite intro key
				WriteString ("key", properties);
				properties << '=';
				char value[64];
				size_t l = ByteStreamToBase64 (address.key, 32, value, 64);
				value[l] = 0;
				WriteString (value, properties);
				properties << ';';
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

	void RouterInfo::CreateBuffer ()
	{
		m_Timestamp = i2p::util::GetMillisecondsSinceEpoch (); // refresh timstamp
		std::stringstream s;
		WriteToStream (s);
		m_BufferLen = s.str ().size ();
		memcpy (m_Buffer, s.str ().c_str (), m_BufferLen);
		// signature
		i2p::context.Sign ((uint8_t *)m_Buffer, m_BufferLen, (uint8_t *)m_Buffer + m_BufferLen);
		m_BufferLen += 40;
	}	

	void RouterInfo::SaveToFile (const std::string& fullPath)
	{
		if (m_Buffer)
		{	
			std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
			f.write ((char *)m_Buffer, m_BufferLen);
		}	
		else
			LogPrint ("Can't save to file");
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
		m_Addresses.push_back(addr);	
		m_SupportedTransports |= eNTCPV4;
	}	

	void RouterInfo::AddSSUAddress (const char * host, int port, const uint8_t * key)
	{
		Address addr;
		addr.host = boost::asio::ip::address::from_string (host);
		addr.port = port;
		addr.transportStyle = eTransportSSU;
		addr.cost = 10; // NTCP should have priority over SSU
		addr.date = 0;
		memcpy (addr.key, key, 32);
		m_Addresses.push_back(addr);	
		m_SupportedTransports |= eSSUV4;
		m_Caps |= eSSUTesting; 
		m_Caps |= eSSUIntroducer; 
	}	
		
	void RouterInfo::SetProperty (const char * key, const char * value)
	{
		m_Properties[key] = value;
	}	

	const char * RouterInfo::GetProperty (const char * key) const
	{
		auto it = m_Properties.find (key);
		if (it != m_Properties.end ())
			return it->second.c_str ();
		return 0;
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

	bool RouterInfo::UsesIntroducer () const
	{
		return !(m_Caps & Caps::eReachable); // non-reachable
	}		
		
	const RouterInfo::Address * RouterInfo::GetNTCPAddress (bool v4only) const
	{
		return GetAddress (eTransportNTCP, v4only);
	}	

	const RouterInfo::Address * RouterInfo::GetSSUAddress (bool v4only) const 
	{
		return GetAddress (eTransportSSU, v4only);
	}	

	const RouterInfo::Address * RouterInfo::GetAddress (TransportStyle s, bool v4only) const
	{
		for (auto& address : m_Addresses)
		{
			if (address.transportStyle == s)
			{	
				if (!v4only || address.host.is_v4 ())
					return &address;
			}	
		}	
		return nullptr;
	}	
}
}
