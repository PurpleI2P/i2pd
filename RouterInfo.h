#ifndef ROUTER_INFO_H__
#define ROUTER_INFO_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <boost/asio.hpp>
#include "Identity.h"

namespace i2p
{
namespace data
{
	const char CAPS_FLAG_FLOODFILL = 'f';
	const char CAPS_FLAG_HIDDEN = 'H';
	const char CAPS_FLAG_REACHABLE = 'R';
	const char CAPS_FLAG_UNREACHABLE = 'U';	
	const char CAPS_FLAG_LOW_BANDWIDTH1 = 'K';		
	const char CAPS_FLAG_LOW_BANDWIDTH2 = 'L';	
	const char CAPS_FLAG_HIGH_BANDWIDTH1 = 'M';	
	const char CAPS_FLAG_HIGH_BANDWIDTH2 = 'N';
	const char CAPS_FLAG_HIGH_BANDWIDTH3 = 'O';

	const char CAPS_FLAG_SSU_TESTING = 'B';
	const char CAPS_FLAG_SSU_INTRODUCER = 'C';

	const int MAX_RI_BUFFER_SIZE = 2048;
	class RouterInfo: public RoutingDestination
	{
		public:

			enum SupportedTranports
			{	
				eNTCPV4 = 0x01,
				eNTCPV6 = 0x02,
				eSSUV4 = 0x04,
				eSSUV6 = 0x08
			};
			
			enum Caps
			{
				eFloodfill = 0x01,
				eHighBandwidth = 0x02,
				eReachable = 0x04,
				eSSUTesting = 0x08,
				eSSUIntroducer = 0x10,
				eHidden = 0x20,
				eUnreachable = 0x40
			};

			enum TransportStyle
			{
				eTransportUnknown = 0,
				eTransportNTCP,
				eTransportSSU
			};

			struct Introducer			
			{
				boost::asio::ip::address iHost;
				int iPort;
				Tag<32> iKey;
				uint32_t iTag;
			};

			struct Address
			{
				TransportStyle transportStyle;
				boost::asio::ip::address host;
				std::string addressString;
				int port, mtu;
				uint64_t date;
				uint8_t cost;
				// SSU only
				Tag<32> key; // intro key for SSU
				std::vector<Introducer> introducers;

				bool IsCompatible (const boost::asio::ip::address& other) const 
				{
					return (host.is_v4 () && other.is_v4 ()) ||
						(host.is_v6 () && other.is_v6 ());
				}	
			};
			
			RouterInfo (const std::string& fullPath);
			RouterInfo (): m_Buffer (nullptr) { };
			RouterInfo (const RouterInfo& ) = default;
			RouterInfo& operator=(const RouterInfo& ) = default;
			RouterInfo (const uint8_t * buf, int len);
			~RouterInfo ();
			
			const IdentityEx& GetRouterIdentity () const { return m_RouterIdentity; };
			void SetRouterIdentity (const IdentityEx& identity);
			std::string GetIdentHashBase64 () const { return GetIdentHash ().ToBase64 (); };
			std::string GetIdentHashAbbreviation () const { return GetIdentHash ().ToBase64 ().substr (0, 4); };
			uint64_t GetTimestamp () const { return m_Timestamp; };
			std::vector<Address>& GetAddresses () { return m_Addresses; };
			const Address * GetNTCPAddress (bool v4only = true) const;
			const Address * GetSSUAddress (bool v4only = true) const;
			const Address * GetSSUV6Address () const;
			
			void AddNTCPAddress (const char * host, int port);
			void AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu = 0);
			bool AddIntroducer (const Address * address, uint32_t tag);
			bool RemoveIntroducer (const boost::asio::ip::udp::endpoint& e);
			void SetProperty (const char * key, const char * value);
			const char * GetProperty (const char * key) const;
			bool IsFloodfill () const;
			bool IsNTCP (bool v4only = true) const;
			bool IsSSU (bool v4only = true) const;
			bool IsV6 () const;
			void EnableV6 ();
			void DisableV6 ();
			bool IsCompatible (const RouterInfo& other) const { return m_SupportedTransports & other.m_SupportedTransports; };
			bool UsesIntroducer () const;
			bool IsIntroducer () const { return m_Caps & eSSUIntroducer; };
			bool IsPeerTesting () const { return m_Caps & eSSUTesting; };
			bool IsHidden () const { return m_Caps & eHidden; };

			uint8_t GetCaps () const { return m_Caps; };	
			void SetCaps (uint8_t caps);
			void SetCaps (const char * caps);

			void SetUnreachable (bool unreachable) { m_IsUnreachable = unreachable; }; 
			bool IsUnreachable () const { return m_IsUnreachable; };

			const uint8_t * GetBuffer () const { return m_Buffer; };
			const uint8_t * LoadBuffer (); // load if necessary
			int GetBufferLen () const { return m_BufferLen; };			
			void CreateBuffer (const PrivateKeys& privateKeys);

			bool IsUpdated () const { return m_IsUpdated; };
			void SetUpdated (bool updated) { m_IsUpdated = updated; }; 
			void SaveToFile (const std::string& fullPath);

			void Update (const uint8_t * buf, int len);
			void DeleteBuffer () { delete m_Buffer; m_Buffer = nullptr; };
			
			// implements RoutingDestination
			const IdentHash& GetIdentHash () const { return m_RouterIdentity.GetIdentHash (); };
			const uint8_t * GetEncryptionPublicKey () const { return m_RouterIdentity.GetStandardIdentity ().publicKey; };
			bool IsDestination () const { return false; };

			
		private:

			bool LoadFile ();
			void ReadFromFile ();
			void ReadFromStream (std::istream& s);
			void ReadFromBuffer (bool verifySignature);
			void WriteToStream (std::ostream& s);
			size_t ReadString (char * str, std::istream& s);
			void WriteString (const std::string& str, std::ostream& s);
			void ExtractCaps (const char * value);
			const Address * GetAddress (TransportStyle s, bool v4only, bool v6only = false) const;
			void UpdateCapsProperty ();			

		private:

			std::string m_FullPath;
			IdentityEx m_RouterIdentity;
			uint8_t * m_Buffer;
			int m_BufferLen;
			uint64_t m_Timestamp;
			std::vector<Address> m_Addresses;
			std::map<std::string, std::string> m_Properties;
			bool m_IsUpdated, m_IsUnreachable;
			uint8_t m_SupportedTransports, m_Caps;
	};	
}	
}

#endif
