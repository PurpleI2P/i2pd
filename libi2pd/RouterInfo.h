/*
* Copyright (c) 2013-2024, The PurpleI2P Project
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
#include <memory>
#include <boost/asio.hpp>
#ifndef __cpp_lib_atomic_shared_ptr
#include <boost/shared_ptr.hpp>
#endif
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
	const char CAPS_FLAG_LOW_BANDWIDTH3  = 'M'; /*  48-64 KBps */
	const char CAPS_FLAG_LOW_BANDWIDTH4  = 'N'; /*  64-128 KBps */
	const char CAPS_FLAG_HIGH_BANDWIDTH  = 'O'; /* 128-256 KBps */
	const char CAPS_FLAG_EXTRA_BANDWIDTH1 = 'P'; /* 256-2048 KBps */
	const char CAPS_FLAG_EXTRA_BANDWIDTH2 = 'X'; /*   > 2048 KBps */
	// bandwidth limits in kBps
	const uint32_t LOW_BANDWIDTH_LIMIT = 48;
	const uint32_t HIGH_BANDWIDTH_LIMIT = 256;
	const uint32_t EXTRA_BANDWIDTH_LIMIT = 2048;	
	// congesion flags
	const char CAPS_FLAG_MEDIUM_CONGESTION = 'D';
	const char CAPS_FLAG_HIGH_CONGESTION = 'E';
	const char CAPS_FLAG_REJECT_ALL_CONGESTION = 'G';
	
	const char CAPS_FLAG_V4 = '4';
	const char CAPS_FLAG_V6 = '6';
	const char CAPS_FLAG_SSU2_TESTING = 'B';
	const char CAPS_FLAG_SSU2_INTRODUCER = 'C';

	const uint8_t COST_NTCP2_PUBLISHED = 3;
	const uint8_t COST_NTCP2_NON_PUBLISHED = 14;
	const uint8_t COST_SSU2_DIRECT = 8;
	const uint8_t COST_SSU2_NON_PUBLISHED = 15;

	const size_t MAX_RI_BUFFER_SIZE = 3072; // if RouterInfo exceeds 3K we consider it as malformed, might extend later
	const int HIGH_CONGESTION_INTERVAL = 15*60; // in seconds, 15 minutes
	const int INTRODUCER_UPDATE_INTERVAL = 20*60*1000; // in milliseconds, 20 minutes
		
	class RouterInfo: public RoutingDestination
	{
		public:

			enum SupportedTransportsIdx
			{
				eNTCP2V4Idx = 0,
				eNTCP2V6Idx,
				eSSU2V4Idx,
				eSSU2V6Idx,
				eNTCP2V6MeshIdx,
				eNumTransports
			};

#define TransportBit(tr) e##tr = (1 << e##tr##Idx)

			enum SupportedTransports
			{
				TransportBit(NTCP2V4), // 0x01
				TransportBit(NTCP2V6), // 0x02
				TransportBit(SSU2V4),  // 0x04
				TransportBit(SSU2V6),  // 0x08
				TransportBit(NTCP2V6Mesh), // 0x10
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

			enum Congestion
			{
				eLowCongestion = 0,
				eMediumCongestion,
				eHighCongestion,
				eRejectAll
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
				eTransportNTCP2,
				eTransportSSU2
			};

			struct Introducer
			{
				Introducer (): iTag (0), iExp (0) { iH.Fill(0); };
				IdentHash iH;
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

				bool IsNTCP2 () const { return transportStyle == eTransportNTCP2; };
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
					Buffer (const Buffer& other): Buffer (other.data (), other.m_BufferLen) {};

					size_t GetBufferLen () const { return m_BufferLen; };
					void SetBufferLen (size_t len) { m_BufferLen = len; };
					
				private:

					size_t m_BufferLen = 0;
			};

			typedef std::array<std::shared_ptr<Address>, eNumTransports> Addresses;
#ifdef __cpp_lib_atomic_shared_ptr
			typedef std::shared_ptr<Addresses> AddressesPtr;
#else
			typedef boost::shared_ptr<Addresses> AddressesPtr;
#endif			
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
			AddressesPtr GetAddresses () const; // should be called for local RI only, otherwise must return shared_ptr
			std::shared_ptr<const Address> GetNTCP2V4Address () const;
			std::shared_ptr<const Address> GetNTCP2V6Address () const;
			std::shared_ptr<const Address> GetPublishedNTCP2V4Address () const;
			std::shared_ptr<const Address> GetPublishedNTCP2V6Address () const;
			std::shared_ptr<const Address> GetYggdrasilAddress () const;
			std::shared_ptr<const Address> GetSSU2V4Address () const;
			std::shared_ptr<const Address> GetSSU2V6Address () const;
			std::shared_ptr<const Address> GetSSU2Address (bool v4) const;

			void AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv,int port, uint8_t caps); // non published
			void AddNTCP2Address (const uint8_t * staticKey, const uint8_t * iv,
				const boost::asio::ip::address& host, int port); // published
			void RemoveNTCP2Address (bool v4);
			void AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey, int port, uint8_t caps); // non published
			void AddSSU2Address (const uint8_t * staticKey, const uint8_t * introKey,
				const boost::asio::ip::address& host, int port); // published
			void RemoveSSU2Address (bool v4);
			void SetUnreachableAddressesTransportCaps (uint8_t transports); // bitmask of AddressCaps
			void UpdateSupportedTransports ();
			void UpdateIntroducers (uint64_t ts); // ts in seconds
			bool IsFloodfill () const { return m_IsFloodfill; };
			void SetFloodfill () { m_IsFloodfill = true; };
			void ResetFloodfill () { m_IsFloodfill = false; };
			bool IsECIES () const { return m_RouterIdentity->GetCryptoKeyType () == i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD; };
			bool IsNTCP2 (bool v4only = true) const;
			bool IsNTCP2V6 () const { return m_SupportedTransports & eNTCP2V6; };
			bool IsSSU2V4 () const { return m_SupportedTransports & eSSU2V4; };
			bool IsSSU2V6 () const { return m_SupportedTransports & eSSU2V6; };
			bool IsV6 () const { return m_SupportedTransports & (eNTCP2V6 | eSSU2V6); };
			bool IsV4 () const { return m_SupportedTransports & (eNTCP2V4 | eSSU2V4); };
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
			CompatibleTransports GetPublishedTransports () const { return m_PublishedTransports; };	
			bool HasValidAddresses () const { return m_SupportedTransports; };
			bool IsHidden () const { return m_Caps & eHidden; };
			bool IsHighBandwidth () const { return m_Caps & RouterInfo::eHighBandwidth; };
			bool IsExtraBandwidth () const { return m_Caps & RouterInfo::eExtraBandwidth; };
			bool IsEligibleFloodfill () const;
			bool IsDeclaredFloodfill () const { return m_Caps & RouterInfo::eFloodfill; };
			bool IsPublished (bool v4) const;
			bool IsPublishedOn (CompatibleTransports transports) const;
			bool IsNAT2NATOnly (const RouterInfo& other) const; // only NAT-to-NAT connection is possible
			bool IsSSU2PeerTesting (bool v4) const;
			bool IsSSU2Introducer (bool v4) const;
			bool IsHighCongestion (bool highBandwidth) const;

			uint8_t GetCaps () const { return m_Caps; };
			char GetBandwidthCap() const { return m_BandwidthCap; };
			void SetCaps (uint8_t caps) { m_Caps = caps; };

			Congestion GetCongestion () const { return m_Congestion; };
		
			void SetUnreachable (bool unreachable) { m_IsUnreachable = unreachable; };
			bool IsUnreachable () const { return m_IsUnreachable; };
			void ExcludeReachableTransports (CompatibleTransports transports) { m_ReachableTransports &= ~transports; };

			const uint8_t * GetBuffer () const { return m_Buffer ? m_Buffer->data () : nullptr; };
			const uint8_t * LoadBuffer (const std::string& fullPath); // load if necessary
			size_t GetBufferLen () const { return m_Buffer ? m_Buffer->GetBufferLen () : 0; };
			void DeleteBuffer () { m_Buffer = nullptr; };
			std::shared_ptr<Buffer> GetSharedBuffer () const { return m_Buffer; };	
			std::shared_ptr<Buffer> CopyBuffer () const;

			bool IsUpdated () const { return m_IsUpdated; };
			void SetUpdated (bool updated) { m_IsUpdated = updated; };
			bool SaveToFile (const std::string& fullPath);
			static bool SaveToFile (const std::string& fullPath, std::shared_ptr<Buffer> buf);
		
			std::shared_ptr<RouterProfile> GetProfile () const;
			void DropProfile () { m_Profile = nullptr; };
			bool HasProfile () const { return (bool)m_Profile; }; 

			bool Update (const uint8_t * buf, size_t len);
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
			void SetBufferLen (size_t len) { if (m_Buffer) m_Buffer->SetBufferLen (len); };
			void RefreshTimestamp ();
			CompatibleTransports GetReachableTransports () const { return m_ReachableTransports; };
			void SetReachableTransports (CompatibleTransports transports) { m_ReachableTransports = transports; };
			void SetCongestion (Congestion c) { m_Congestion = c; };
		
		private:

			bool LoadFile (const std::string& fullPath);
			void ReadFromFile (const std::string& fullPath);
			void ReadFromStream (std::istream& s);
			void ReadFromBuffer (bool verifySignature);
			size_t ReadString (char* str, size_t len, std::istream& s) const;
			void ExtractCaps (const char * value);
			uint8_t ExtractAddressCaps (const char * value) const;
			void UpdateIntroducers (std::shared_ptr<Address> address, uint64_t ts); 
			template<typename Filter>
			std::shared_ptr<const Address> GetAddress (Filter filter) const;
			virtual std::shared_ptr<Buffer> NewBuffer () const;
			virtual std::shared_ptr<Address> NewAddress () const;
			virtual AddressesPtr NewAddresses () const;
			virtual std::shared_ptr<IdentityEx> NewIdentity (const uint8_t * buf, size_t len) const;

		private:

			FamilyID m_FamilyID;
			std::shared_ptr<const IdentityEx> m_RouterIdentity;
			std::shared_ptr<Buffer> m_Buffer;
			uint64_t m_Timestamp; // in milliseconds
#ifdef __cpp_lib_atomic_shared_ptr
			std::atomic<AddressesPtr> m_Addresses;
#else		
			AddressesPtr m_Addresses;
#endif		
			bool m_IsUpdated, m_IsUnreachable, m_IsFloodfill;
			CompatibleTransports m_SupportedTransports, m_ReachableTransports, m_PublishedTransports;
			uint8_t m_Caps;
			char m_BandwidthCap;
			int m_Version;
			Congestion m_Congestion;
			mutable std::shared_ptr<RouterProfile> m_Profile;
	};

	class LocalRouterInfo: public RouterInfo
	{
		public:

			LocalRouterInfo () = default;
			void CreateBuffer (const PrivateKeys& privateKeys);
			void UpdateCaps (uint8_t caps);
			bool UpdateCongestion (Congestion c); // returns true if updated

			void SetProperty (const std::string& key, const std::string& value) override;
			void DeleteProperty (const std::string& key);
			std::string GetProperty (const std::string& key) const;
			void ClearProperties () override { m_Properties.clear (); };
			void UpdateFloodfillProperty (bool floodfill);
			
			bool AddSSU2Introducer (const Introducer& introducer, bool v4);
			bool RemoveSSU2Introducer (const IdentHash& h, bool v4);
			bool UpdateSSU2Introducer (const IdentHash& h, bool v4, uint32_t iTag, uint32_t iExp);

		private:

			void WriteToStream (std::ostream& s) const;
			void UpdateCapsProperty ();
			void WriteString (const std::string& str, std::ostream& s) const;
			std::shared_ptr<Buffer> NewBuffer () const override;
			std::shared_ptr<Address> NewAddress () const override;
			RouterInfo::AddressesPtr NewAddresses () const override;
			std::shared_ptr<IdentityEx> NewIdentity (const uint8_t * buf, size_t len) const override;

		private:

			std::map<std::string, std::string> m_Properties;
	};
}
}

#endif
