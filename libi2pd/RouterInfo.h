/*
* Copyright (c) 2013-2022, The PurpleI2P Project
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
#include <array>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include "Identity.h"
#include "Profiling.h"
#include "Family.h"

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

	const char CAPS_FLAG_V4 = '4';
	const char CAPS_FLAG_V6 = '6';
	const char CAPS_FLAG_SSU_TESTING = 'B';
	const char CAPS_FLAG_SSU_INTRODUCER = 'C';

	const uint8_t COST_NTCP2_PUBLISHED = 3;
	const uint8_t COST_NTCP2_NON_PUBLISHED = 14;
	const uint8_t COST_SSU2_DIRECT = 8;
	const uint8_t COST_SSU_DIRECT = 9;
	const uint8_t COST_SSU_THROUGH_INTRODUCERS = 11;
	const uint8_t COST_SSU2_NON_PUBLISHED = 15;

	const size_t MAX_RI_BUFFER_SIZE = 3072; // if RouterInfo exceeds 3K we consider it as malformed, might extend later
	class RouterInfo: public RoutingDestination
	{
		public:

			enum SupportedTransports
			{
				eNTCP2V4 = 0x01,
				eNTCP2V6 = 0x02,
				eSSUV4 = 0x04,
				eSSUV6 = 0x08,
				eNTCP2V6Mesh = 0x10,
				eSSU2V4 = 0x20,
				eSSU2V6 = 0x40,
				eAllTransports = 0xFF
			};
			typedef uint8_t CompatibleTransports;

			enum Caps
			{
				eFloodfill = 0x01,
				eHighBandwidth = 0x02,
				eExtraBandwidth = 0x04,
				eReachable = 0x08,
				eHidden = 0x10,
				eUnreachable = 0x20
			};

			enum AddressCaps
			{
				eV4 = 0x01,
				eV6 = 0x02,
				eSSUTesting = 0x04,
				eSSUIntroducer = 0x08
			};

			enum TransportStyle
			{
				eTransportUnknown = 0,
				eTransportNTCP,
				eTransportSSU,
				eTransportSSU2
			};

			typedef Tag<32> IntroKey; // should be castable to MacKey and AESKey
			struct Introducer
			{
				Introducer (): iPort (0), iExp (0) {};
				boost::asio::ip::address iHost;
				int iPort;
				IntroKey iKey; // or ih for SSU2
				uint32_t iTag;
				uint32_t iExp;
			};

			struct SSUExt
			{
				int mtu;
				std::vector<Introducer> introducers;
			};

			struct Address
			{
				TransportStyle transportStyle;
				boost::asio::ip::address host;
				Tag<32> s, i; // keys, i is first 16 bytes for NTCP2 and 32 bytes intro key for SSU
				int port;
				uint64_t date;
				uint8_t caps;
				bool published = false;
				std::unique_ptr<SSUExt> ssu; // not null for SSU

				bool IsCompatible (const boost::asio::ip::address& other) const
				{
					return (IsV4 () && other.is_v4 ()) ||
						(IsV6 () && other.is_v6 ());
				}

				bool operator==(const Address& other) const
				{
					return transportStyle == other.transportStyle &&
						host == other.host && port == other.port;
				}

				bool operator!=(const Address& other) const
				{
					return !(*this == other);
				}

				bool IsNTCP2 () const { return transportStyle == eTransportNTCP; };
				bool IsSSU2 () const { return transportStyle == eTransportSSU2; };
				bool IsPublishedNTCP2 () const { return IsNTCP2 () && published; };
				bool IsReachableSSU () const { return (bool)ssu && (published || UsesIntroducer ()); };
				bool UsesIntroducer () const { return (bool)ssu && !ssu->introducers.empty (); };

				bool IsIntroducer () const { return caps & eSSUIntroducer; };
				bool IsPeerTesting () const { return caps & eSSUTesting; };

				bool IsV4 () const { return (caps & AddressCaps::eV4) || (host.is_v4 () && !host.is_unspecified ()); };
				bool IsV6 () const { return (caps & AddressCaps::eV6) || (host.is_v6 () && !host.is_unspecified ()); };
			};

			class Buffer: public std::array<uint8_t, MAX_RI_BUFFER_SIZE>
			{
				public:

					Buffer () = default;
					Buffer (const uint8_t * buf, size_t len);
			};

			typedef std::vector<std::shared_ptr<Address> > Addresses;

			RouterInfo (const std::string& fullPath);
			RouterInfo (const RouterInfo& ) = default;
			RouterInfo& operator=(const RouterInfo& ) = default;
			RouterInfo (std::shared_ptr<Buffer>&& buf, size_t len);
			RouterInfo (const uint8_t * buf, size_t len);
			virtual ~RouterInfo ();

			std::shared_ptr<const IdentityEx> GetRouterIdentity () const { return m_RouterIdentity; };
			void SetRouterIdentity (std::shared_ptr<const IdentityEx> identity);
			std::string GetIdentHashBase64 () const { return GetIdentHash ().ToBase64 (); };
			uint64_t GetTimestamp () const { return m_Timestamp; };
			int GetVersion () const { return m_Version; };
			virtual void SetProperty (const std::string& key, const std::string& value) {};
			virtual void ClearProperties () {};
			Addresses& GetAddresses () { return *m_Addresses; }; // should be called for local RI only, otherwise must return shared_ptr
			std::shared_ptr<const Address> GetNTCP2AddressWithStaticKey (const uint8_t * key) const;
			std::shared_ptr<const Address> GetSSU2AddressWithStaticKey (const uint8_t * key, bool isV6) const;
			std::shared_ptr<const Address> GetPublishedNTCP2V4Address () const;
			std::shared_ptr<const Address> GetPublishedNTCP2V6Address () const;
			std::shared_ptr<const Address> GetSSUAddress (bool v4only = true) const;
			std::shared_ptr<const Address> GetSSUV6Address () const;
			std::shared_ptr<const Address> GetYggdrasilAddress () const;
			std::shared_ptr<const Address> GetSSU2V4Address () const;
			std::shared_ptr<const Address> GetSSU2V6Address () const;
			std::shared_ptr<const Address> GetSSU2Address (bool v4) const;

			void AddSSUAddress (const char * host, int port, const uint8_t * key, int mtu = 0);
			void AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv,
				const boost::asio::ip::address& host = boost::asio::ip::address(), int port = 0, uint8_t caps = 0);
			void AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey, uint8_t caps = 0); // non published
			void AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey,
				const boost::asio::ip::address& host, int port); // published
			bool AddIntroducer (const Introducer& introducer);
			bool RemoveIntroducer (const boost::asio::ip::udp::endpoint& e);
			void SetUnreachableAddressesTransportCaps (uint8_t transports); // bitmask of AddressCaps
			void UpdateSupportedTransports ();
			bool IsFloodfill () const { return m_Caps & Caps::eFloodfill; };
			bool IsReachable () const { return m_Caps & Caps::eReachable; };
			bool IsECIES () const { return m_RouterIdentity->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD; };
			bool IsSSU (bool v4only = true) const;
			bool IsSSUV6 () const { return m_SupportedTransports & eSSUV6; };
			bool IsNTCP2 (bool v4only = true) const;
			bool IsNTCP2V6 () const { return m_SupportedTransports & eNTCP2V6; };
			bool IsSSU2V4 () const { return m_SupportedTransports & eSSU2V4; };
			bool IsSSU2V6 () const { return m_SupportedTransports & eSSU2V6; };
			bool IsV6 () const { return m_SupportedTransports & (eSSUV6 | eNTCP2V6 | eSSU2V6); };
			bool IsV4 () const { return m_SupportedTransports & (eSSUV4 | eNTCP2V4 | eSSU2V4); };
			bool IsMesh () const { return m_SupportedTransports & eNTCP2V6Mesh; };
			void EnableV6 ();
			void DisableV6 ();
			void EnableV4 ();
			void DisableV4 ();
			void EnableMesh ();
			void DisableMesh ();
			bool IsCompatible (const RouterInfo& other) const { return m_SupportedTransports & other.m_SupportedTransports; };
			bool IsReachableFrom (const RouterInfo& other) const { return m_ReachableTransports & other.m_SupportedTransports; };
			bool IsReachableBy (CompatibleTransports transports) const { return m_ReachableTransports & transports; };
			CompatibleTransports GetCompatibleTransports (bool incoming) const { return incoming ? m_ReachableTransports : m_SupportedTransports; };
			bool HasValidAddresses () const { return m_SupportedTransports; };
			bool IsHidden () const { return m_Caps & eHidden; };
			bool IsHighBandwidth () const { return m_Caps & RouterInfo::eHighBandwidth; };
			bool IsExtraBandwidth () const { return m_Caps & RouterInfo::eExtraBandwidth; };
			bool IsEligibleFloodfill () const;
			bool IsPeerTesting (bool v4) const;
			bool IsSSU2PeerTesting (bool v4) const;
			bool IsIntroducer (bool v4) const;

			uint8_t GetCaps () const { return m_Caps; };
			void SetCaps (uint8_t caps) { m_Caps = caps; };

			void SetUnreachable (bool unreachable) { m_IsUnreachable = unreachable; };
			bool IsUnreachable () const { return m_IsUnreachable; };

			const uint8_t * GetBuffer () const { return m_Buffer->data (); };
			const uint8_t * LoadBuffer (const std::string& fullPath); // load if necessary
			size_t GetBufferLen () const { return m_BufferLen; };

			bool IsUpdated () const { return m_IsUpdated; };
			void SetUpdated (bool updated) { m_IsUpdated = updated; };
			bool SaveToFile (const std::string& fullPath);

			std::shared_ptr<RouterProfile> GetProfile () const;
			void SaveProfile () { if (m_Profile) m_Profile->Save (GetIdentHash ()); };

			void Update (const uint8_t * buf, size_t len);
			void DeleteBuffer () { m_Buffer = nullptr; };
			bool IsNewer (const uint8_t * buf, size_t len) const;

			/** return true if we are in a router family and the signature is valid */
			bool IsFamily (FamilyID famid) const;

			// implements RoutingDestination
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_RouterIdentity; };
			void Encrypt (const uint8_t * data, uint8_t * encrypted) const;

			bool IsDestination () const { return false; };

		protected:

			RouterInfo ();
			uint8_t * GetBufferPointer (size_t offset = 0 ) { return m_Buffer->data () + offset; };
			void UpdateBuffer (const uint8_t * buf, size_t len);
			void SetBufferLen (size_t len) { m_BufferLen = len; };
			void RefreshTimestamp ();
			const Addresses& GetAddresses () const { return *m_Addresses; };

		private:

			bool LoadFile (const std::string& fullPath);
			void ReadFromFile (const std::string& fullPath);
			void ReadFromStream (std::istream& s);
			void ReadFromBuffer (bool verifySignature);
			size_t ReadString (char* str, size_t len, std::istream& s) const;
			void ExtractCaps (const char * value);
			uint8_t ExtractAddressCaps (const char * value) const;
			template<typename Filter>
			std::shared_ptr<const Address> GetAddress (Filter filter) const;
			virtual std::shared_ptr<Buffer> NewBuffer () const;

		private:

			FamilyID m_FamilyID;
			std::shared_ptr<const IdentityEx> m_RouterIdentity;
			std::shared_ptr<Buffer> m_Buffer;
			size_t m_BufferLen;
			uint64_t m_Timestamp;
			boost::shared_ptr<Addresses> m_Addresses; // TODO: use std::shared_ptr and std::atomic_store for gcc >= 4.9
			bool m_IsUpdated, m_IsUnreachable;
			CompatibleTransports m_SupportedTransports, m_ReachableTransports;
			uint8_t m_Caps;
			int m_Version;
			mutable std::shared_ptr<RouterProfile> m_Profile;
	};

	class LocalRouterInfo: public RouterInfo
	{
		public:

			LocalRouterInfo () = default;
			void CreateBuffer (const PrivateKeys& privateKeys);
			void UpdateCaps (uint8_t caps);

			void SetProperty (const std::string& key, const std::string& value) override;
			void DeleteProperty (const std::string& key);
			std::string GetProperty (const std::string& key) const;
			void ClearProperties () override { m_Properties.clear (); };

		private:

			void WriteToStream (std::ostream& s) const;
			void UpdateCapsProperty ();
			void WriteString (const std::string& str, std::ostream& s) const;
			std::shared_ptr<Buffer> NewBuffer () const override;

		private:

			std::map<std::string, std::string> m_Properties;
	};
}
}

#endif
