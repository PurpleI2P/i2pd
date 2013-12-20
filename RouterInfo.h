#ifndef ROUTER_INFO_H__
#define ROUTER_INFO_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <boost/asio.hpp>
#include "LeaseSet.h"

namespace i2p
{
namespace data
{			
	class RouterInfo: public RoutingDestination
	{
		public:

			enum TransportStyle
			{
				eTransportUnknown = 0,
				eTransportNTCP,
				eTransportSSU
			};

			struct Address
			{
				TransportStyle transportStyle;
				std::string host;
				int port;
				uint64_t date;
				uint8_t cost;
			};
			
			RouterInfo (const char * filename);
			RouterInfo () = default;
			RouterInfo (const RouterInfo& ) = default;
			RouterInfo (const uint8_t * buf, int len);
			
			const Identity& GetRouterIdentity () const { return m_RouterIdentity; };
			void SetRouterIdentity (const Identity& identity);
			const char * GetIdentHashBase64 () const { return m_IdentHashBase64; };
			const char * GetIdentHashAbbreviation () const { return m_IdentHashAbbreviation; };
			uint64_t GetTimestamp () const { return m_Timestamp; };
			const std::vector<Address>& GetAddresses () const { return m_Addresses; };
			Address * GetNTCPAddress ();
			
			void AddNTCPAddress (const char * host, int port);
			void SetProperty (const char * key, const char * value);
			const char * GetProperty (const char * key) const;
			bool IsFloodfill () const;
			bool IsNTCP () const;
			void SetUnreachable (bool unreachable) { m_IsUnreachable = unreachable; }; 
			bool IsUnreachable () const { return m_IsUnreachable; };
			
			void CreateBuffer ();
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
			
		private:

			Identity m_RouterIdentity;
			IdentHash m_IdentHash;
			char m_IdentHashBase64[48], m_IdentHashAbbreviation[5];
			char m_Buffer[2048];
			int m_BufferLen;
			uint64_t m_Timestamp;
			std::vector<Address> m_Addresses;
			std::map<std::string, std::string> m_Properties;
			bool m_IsUpdated, m_IsUnreachable;
	};	
}	
}

#endif
