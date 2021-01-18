/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef ROUTER_INFO_H__
#define ROUTER_INFO_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <vector>
#include <list>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include "Identity.h"
#include "Profiling.h"

namespace i2p
{
namespace data
{
	const char ROUTER_INFO_PROPERTY_LEASESETS[] = "netdb.knownLeaseSets";
	const char ROUTER_INFO_PROPERTY_ROUTERS[] = "netdb.knownRouters";
	const char ROUTER_INFO_PROPERTY_NETID[] = "netId";
	const char ROUTER_INFO_PROPERTY_VERSION[] = "router.version";
	const char ROUTER_INFO_PROPERTY_FAMILY[] = "family";
	const char ROUTER_INFO_PROPERTY_FAMILY_SIG[] = "family.sig";

	const char CAPS_FLAG_FLOODFILL = 'f';
	const char CAPS_FLAG_HIDDEN = 'H';
	const char CAPS_FLAG_REACHABLE = 'R';
	const char CAPS_FLAG_UNREACHABLE = 'U';
	/* bandwidth flags */
	const char CAPS_FLAG_LOW_BANDWIDTH1   = 'K'; /*   < 12 KBps */
	const char CAPS_FLAG_LOW_BANDWIDTH2   = 'L'; /*  12-48 KBps */
	const char CAPS_FLAG_HIGH_BANDWIDTH1  = 'M'; /*  48-64 KBps */
	const char CAPS_FLAG_HIGH_BANDWIDTH2  = 'N'; /*  64-128 KBps */
	const char CAPS_FLAG_HIGH_BANDWIDTH3  = 'O'; /* 128-256 KBps */
	const char CAPS_FLAG_EXTRA_BANDWIDTH1 = 'P'; /* 256-2000 KBps */
	const char CAPS_FLAG_EXTRA_BANDWIDTH2 = 'X'; /*   > 2000 KBps */

	const char CAPS_FLAG_SSU_TESTING = 'B';
	const char CAPS_FLAG_SSU_INTRODUCER = 'C';

	const int MAX_RI_BUFFER_SIZE = 2048; // if RouterInfo exceeds 2048 we consider it as malformed, might be changed later
	class RouterInfo: public RoutingDestination
	{
		public:

			enum SupportedTranports
			{
				eNTCPV4 = 0x01,
				eNTCPV6 = 0x02,
				eSSUV4 = 0x04,
				eSSUV6 = 0x08,
				eNTCP2V4 = 0x10,
				eNTCP2V6 = 0x20
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
				Introducer (): iExp (0) {};
				boost::asio::ip::address iHost;
				int iPort;
				IntroKey iKey;
				uint32_t iTag;
				uint32_t iExp;
			};

			struct SSUExt
			{
				int mtu;
				IntroKey key; // intro key for SSU
				std::vector<Introducer> introducers;
			};

			struct NTCP2Ext
			{
				Tag<32> staticKey;
				Tag<16> iv;
				bool isPublished = false;
				bool isNTCP2Only = false;
			};

			struct Address
			{
				TransportStyle transportStyle;
				boost::asio::ip::address host;
				int port;
				uint64_t date;
				uint8_t cost;
				std::unique_ptr<SSUExt> ssu; // not null for SSU
				std::unique_ptr<NTCP2Ext> ntcp2; // not null for NTCP2

				bool IsCompatible (const boost::asio::ip::address& other) const
				{
					return (host.is_v4 () && other.is_v4 ()) ||
						(host.is_v6 () && other.is_v6 ());
				}

				bool operator==(const Address& other) const
				{
					return transportStyle == other.transportStyle && IsNTCP2 () == other.IsNTCP2 () &&
						host == other.host && port == other.port;
				}

				bool operator!=(const Address& other) const
				{
					return !(*this == other);
				}

				bool IsNTCP2 () const { return (bool)ntcp2; };
				bool IsPublishedNTCP2 () const { return IsNTCP2 () && ntcp2->isPublished; };
				bool IsNTCP2Only () const { return ntcp2 && ntcp2->isNTCP2Only; };
			};
			typedef std::list<std::shared_ptr<Address> > Addresses;

			RouterInfo ();
			RouterInfo (const std::string& fullPath);
			RouterInfo (const RouterInfo& ) = default;
			RouterInfo& operator=(const RouterInfo& ) = default;
			RouterInfo (const uint8_t * buf, int len);
			~RouterInfo ();

			std::shared_ptr<const IdentityEx> GetRouterIdentity () const { return m_RouterIdentity; };
			void SetRouterIdentity (std::shared_ptr<const IdentityEx> identity);
			std::string GetIdentHashBase64 () const { return GetIdentHash ().ToBase64 (); };
			uint64_t GetTimestamp () const { return m_Timestamp; };
			int GetVersion () const { return m_Version; };
			Addresses& GetAddresses () { return *m_Addresses; }; // should be called for local RI only, otherwise must return shared_ptr
			std::shared_ptr<const Address> GetNTCP2Address (bool publishedOnly,  bool v4only = true) const;
			std::shared_ptr<const Address> GetPublishedNTCP2V4Address () const; 
			std::shared_ptr<const Address> GetPublishedNTCP2V6Address () const; 
			std::shared_ptr<const Address> GetSSUAddress (bool v4only = true) const;
			std::shared_ptr<const Address> GetSSUV6Address () const;

			void AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu = 0);
			void AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv, const boost::asio::ip::address& host = boost::asio::ip::address(), int port = 0);
			bool AddIntroducer (const Introducer& introducer);
			bool RemoveIntroducer (const boost::asio::ip::udp::endpoint& e);
			void SetProperty (const std::string& key, const std::string& value); // called from RouterContext only
			void DeleteProperty (const std::string& key); // called from RouterContext only
			std::string GetProperty (const std::string& key) const; // called from RouterContext only
			void ClearProperties () { m_Properties.clear (); };
			bool IsFloodfill () const { return m_Caps & Caps::eFloodfill; };
			bool IsReachable () const { return m_Caps & Caps::eReachable; };
			bool IsSSU (bool v4only = true) const;
			bool IsSSUV6 () const;
			bool IsNTCP2 (bool v4only = true) const;
			bool IsV6 () const;
			bool IsV4 () const;
			void EnableV6 ();
			void DisableV6 ();
			void EnableV4 ();
			void DisableV4 ();
			bool IsCompatible (const RouterInfo& other) const { return m_SupportedTransports & other.m_SupportedTransports; };
			bool HasValidAddresses () const { return m_SupportedTransports; };
			bool UsesIntroducer () const;
			bool IsIntroducer () const { return m_Caps & eSSUIntroducer; };
			bool IsPeerTesting () const { return m_Caps & eSSUTesting; };
			bool IsHidden () const { return m_Caps & eHidden; };
			bool IsHighBandwidth () const { return m_Caps & RouterInfo::eHighBandwidth; };
			bool IsExtraBandwidth () const { return m_Caps & RouterInfo::eExtraBandwidth; };
			bool IsEligibleFloodfill () const;
		
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
			bool SaveToFile (const std::string& fullPath);

			std::shared_ptr<RouterProfile> GetProfile () const;
			void SaveProfile () { if (m_Profile) m_Profile->Save (GetIdentHash ()); };

			void Update (const uint8_t * buf, size_t len);
			void DeleteBuffer () { delete[] m_Buffer; m_Buffer = nullptr; };
			bool IsNewer (const uint8_t * buf, size_t len) const;

			/** return true if we are in a router family and the signature is valid */
			bool IsFamily(const std::string & fam) const;

			// implements RoutingDestination
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_RouterIdentity; };
			void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const;

			bool IsDestination () const { return false; };

		private:

			bool LoadFile ();
			void ReadFromFile ();
			void ReadFromStream (std::istream& s);
			void ReadFromBuffer (bool verifySignature);
			void WriteToStream (std::ostream& s) const;
			size_t ReadString (char* str, size_t len, std::istream& s) const;
			void WriteString (const std::string& str, std::ostream& s) const;
			void ExtractCaps (const char * value);
			template<typename Filter>
			std::shared_ptr<const Address> GetAddress (Filter filter) const;
			void UpdateCapsProperty ();

		private:

			std::string m_FullPath, m_Family;
			std::shared_ptr<const IdentityEx> m_RouterIdentity;
			uint8_t * m_Buffer;
			size_t m_BufferLen;
			uint64_t m_Timestamp;
			boost::shared_ptr<Addresses> m_Addresses; // TODO: use std::shared_ptr and std::atomic_store for gcc >= 4.9
			std::map<std::string, std::string> m_Properties;
			bool m_IsUpdated, m_IsUnreachable;
			uint8_t m_SupportedTransports, m_Caps;
			int m_Version;
			mutable std::shared_ptr<RouterProfile> m_Profile;
	};
}
}

#endif
