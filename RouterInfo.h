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
				eHighBanwidth = 0x02,
				eReachable = 0x04
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
				uint8_t iKey[32];
				uint32_t iTag;
			};

			struct Address
			{
				TransportStyle transportStyle;
				boost::asio::ip::address host;
				int port;
				uint64_t date;
				uint8_t cost;
				// SSU only
				uint8_t key[32]; // intro key for SSU
				std::vector<Introducer> introducers;
			};
			
			RouterInfo (const char * filename);
			RouterInfo () = default;
			RouterInfo (const RouterInfo& ) = default;
			RouterInfo& operator=(const RouterInfo& ) = default;
			RouterInfo (const uint8_t * buf, int len);
			
			const Identity& GetRouterIdentity () const { return m_RouterIdentity; };
			void SetRouterIdentity (const Identity& identity);
			const char * GetIdentHashBase64 () const { return m_IdentHashBase64; };
			const char * GetIdentHashAbbreviation () const { return m_IdentHashAbbreviation; };
			uint64_t GetTimestamp () const { return m_Timestamp; };
			std::vector<Address>& GetAddresses () { return m_Addresses; };
			const Address * GetNTCPAddress (bool v4only = true) const;
			const Address * GetSSUAddress (bool v4only = true) const;
			const RoutingKey& GetRoutingKey () const { return m_RoutingKey; };
			
			void AddNTCPAddress (const char * host, int port);
			void AddSSUAddress (const char * host, int port, const uint8_t * key);
			void SetProperty (const char * key, const char * value);
			const char * GetProperty (const char * key) const;
			bool IsFloodfill () const;
			bool IsNTCP (bool v4only = true) const;
			bool IsSSU (bool v4only = true) const;
			bool IsCompatible (const RouterInfo& other) const { return m_SupportedTransports & other.m_SupportedTransports; };
			bool UsesIntroducer () const;
			
			void SetUnreachable (bool unreachable) { m_IsUnreachable = unreachable; }; 
			bool IsUnreachable () const { return m_IsUnreachable; };
			
			void CreateBuffer ();
			void UpdateRoutingKey ();
			const char * GetBuffer () const  { return m_Buffer; };
			int GetBufferLen () const { return m_BufferLen; };

			bool IsUpdated () const { return m_IsUpdated; };
			void SetUpdated (bool updated) { m_IsUpdated = updated; }; 

			// implements RoutingDestination
			const IdentHash& GetIdentHash () const { return m_IdentHash; };
			const uint8_t * GetEncryptionPublicKey () const { return m_RouterIdentity.publicKey; };
			bool IsDestination () const { return false; };
			
		private:

			void ReadFromFile (const char * filename);
			void ReadFromStream (std::istream& s);
			void ReadFromBuffer ();
			void WriteToStream (std::ostream& s);
			size_t ReadString (char * str, std::istream& s);
			void WriteString (const std::string& str, std::ostream& s);
			void ExtractCaps (const char * value);
			void UpdateIdentHashBase64 ();
			const Address * GetAddress (TransportStyle s, bool v4only) const;
			
		private:

			Identity m_RouterIdentity;
			IdentHash m_IdentHash;
			RoutingKey m_RoutingKey;
			char m_IdentHashBase64[48], m_IdentHashAbbreviation[5];
			char m_Buffer[2048];
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
