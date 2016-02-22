#ifndef ROUTER_INFO_H__
#define ROUTER_INFO_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Profiling.h"

namespace i2p
{
namespace data
{
	const char ROUTER_INFO_PROPERTY_LEASESETS[] = "netdb.knownLeaseSets";
	const char ROUTER_INFO_PROPERTY_ROUTERS[] = "netdb.knownRouters";	
	const char ROUTER_INFO_PROPERTY_NETID[] = "netId";
	const char ROUTER_INFO_PROPERTY_FAMILY[] = "family";	
	const char ROUTER_INFO_PROPERTY_FAMILY_SIG[] = "family.sig";
	
	const char CAPS_FLAG_FLOODFILL = 'f';
	const char CAPS_FLAG_HIDDEN = 'H';
	const char CAPS_FLAG_REACHABLE = 'R';
	const char CAPS_FLAG_UNREACHABLE = 'U';	
	const char CAPS_FLAG_LOW_BANDWIDTH1 = 'K';		
	const char CAPS_FLAG_LOW_BANDWIDTH2 = 'L';	
	const char CAPS_FLAG_HIGH_BANDWIDTH1 = 'M';	
	const char CAPS_FLAG_HIGH_BANDWIDTH2 = 'N';
	const char CAPS_FLAG_HIGH_BANDWIDTH3 = 'O';
	const char CAPS_FLAG_EXTRA_BANDWIDTH1 = 'P';
	const char CAPS_FLAG_EXTRA_BANDWIDTH2 = 'X';
	
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
				eExtraBandwidth = 0x04,
				eReachable = 0x08,
				eSSUTesting = 0x10,
				eSSUIntroducer = 0x20,
				eHidden = 0x40,
				eUnreachable = 0x80
			};

			enum TransportStyle
			{
				eTransportUnknown = 0,
				eTransportNTCP,
				eTransportSSU
			};

			typedef Tag<32> IntroKey; // should be castable to MacKey and AESKey
			struct Introducer			
			{
				boost::asio::ip::address iHost;
				int iPort;
				IntroKey iKey;
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
				IntroKey key; // intro key for SSU
				std::vector<Introducer> introducers;

				bool IsCompatible (const boost::asio::ip::address& other) const 
				{
					return (host.is_v4 () && other.is_v4 ()) ||
						(host.is_v6 () && other.is_v6 ());
				}	

				bool operator==(const Address& other) const
				{
					return transportStyle == other.transportStyle && host == other.host && port == other.port;
				}	

				bool operator!=(const Address& other) const
				{
					return !(*this == other);
				}	
			};
			
			RouterInfo (const std::string& fullPath);
			RouterInfo (): m_Buffer (nullptr) { };
			RouterInfo (const RouterInfo& ) = default;
			RouterInfo& operator=(const RouterInfo& ) = default;
			RouterInfo (const uint8_t * buf, int len);
			~RouterInfo ();
			
			std::shared_ptr<const IdentityEx> GetRouterIdentity () const { return m_RouterIdentity; };
			void SetRouterIdentity (std::shared_ptr<const IdentityEx> identity);
			std::string GetIdentHashBase64 () const { return GetIdentHash ().ToBase64 (); };
			uint64_t GetTimestamp () const { return m_Timestamp; };
			std::vector<Address>& GetAddresses () { return m_Addresses; };
			const Address * GetNTCPAddress (bool v4only = true) const;
			const Address * GetSSUAddress (bool v4only = true) const;
			const Address * GetSSUV6Address () const;
			
			void AddNTCPAddress (const char * host, int port);
			void AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu = 0);
			bool AddIntroducer (const Introducer& introducer);
			bool RemoveIntroducer (const boost::asio::ip::udp::endpoint& e);
			void SetProperty (const std::string& key, const std::string& value); // called from RouterContext only
			void DeleteProperty (const std::string& key); // called from RouterContext only
			void ClearProperties () { m_Properties.clear (); };
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
			bool IsHighBandwidth () const { return m_Caps & RouterInfo::eHighBandwidth; };
			bool IsExtraBandwidth () const { return m_Caps & RouterInfo::eExtraBandwidth; };	
			
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

			std::shared_ptr<RouterProfile> GetProfile () const;
			void SaveProfile () { if (m_Profile) m_Profile->Save (); };
			
			void Update (const uint8_t * buf, int len);
			void DeleteBuffer () { delete[] m_Buffer; m_Buffer = nullptr; };
			bool IsNewer (const uint8_t * buf, size_t len) const;			

			// implements RoutingDestination
			const IdentHash& GetIdentHash () const { return m_RouterIdentity->GetIdentHash (); };
			const uint8_t * GetEncryptionPublicKey () const { return m_RouterIdentity->GetStandardIdentity ().publicKey; };
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

			std::string m_FullPath, m_Family;
			std::shared_ptr<const IdentityEx> m_RouterIdentity;
			uint8_t * m_Buffer;
			size_t m_BufferLen;
			uint64_t m_Timestamp;
			std::vector<Address> m_Addresses;
			std::map<std::string, std::string> m_Properties;
			bool m_IsUpdated, m_IsUnreachable;
			uint8_t m_SupportedTransports, m_Caps;
			mutable std::shared_ptr<RouterProfile> m_Profile;
	};	
}	
}

#endif
