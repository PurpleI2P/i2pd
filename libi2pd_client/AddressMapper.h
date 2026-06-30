/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef ADDRESS_MAPPER_H__
#define ADDRESS_MAPPER_H__

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <boost/asio.hpp>

namespace i2p
{
namespace client
{
	// Bi-directional, thread-safe mapping between .i2p host names and virtual
	// IPv4 addresses drawn from a configurable network V/p.
	//
	// This is the shared "automap" mechanism factored out of the SOCKS proxy.
	// The DNS resolver allocates a virtual IP for a name (forward direction);
	// the TPROXY transparent proxy recovers the name from the destination IP
	// of an intercepted connection (reverse direction). Sharing one instance
	// between the two services is what makes resolve-then-connect work across
	// DNS and TPROXY.
	//
	// The legacy SOCKS torsocks path keeps its own instance bound to the
	// unroutable 255.0.0.0/8 range (that IP is rewritten locally and never put
	// on the wire). Gateway consumers use a separate instance bound to a
	// routable range (transproxy.virtualnet, e.g. 10.192.0.0/10) so the virtual
	// IPs can actually be routed across a LAN to the i2pd box.
	class AddressMapper
	{
		public:

			// Construct from an explicit base address and prefix length.
			// `base` is masked to the network address; `prefix` must be in [1,31].
			AddressMapper (boost::asio::ip::address_v4 base, int prefix);

			// Construct from a "base/prefix" CIDR string (e.g. "10.192.0.0/10").
			// Throws std::runtime_error on a malformed or out-of-range value.
			explicit AddressMapper (const std::string& cidr);

			// Parse "base/prefix" into its components. Returns false on malformed
			// input or a prefix outside [1,31]. Does not validate routability.
			static bool ParseCIDR (const std::string& cidr, boost::asio::ip::address_v4& base, int& prefix);

			// Return the virtual IP for `name`, allocating the next free address
			// in V/p (LRU-evicting the oldest entry when the range is exhausted)
			// if it is not already mapped. Refreshes the entry timestamp so that
			// recently-used mappings survive Cleanup().
			boost::asio::ip::address_v4 Resolve (std::string_view name);

			// Reverse lookup: return the .i2p name mapped to `addr`, or an empty
			// string if `addr` is not in the table (or not in V/p).
			std::string GetName (const boost::asio::ip::address_v4& addr) const;

			// True if `addr` lies within V/p (mask compare against the base).
			bool IsVirtual (const boost::asio::ip::address_v4& addr) const
			{
				return (addr.to_uint () & m_Mask) == m_Base;
			}

			// Evict entries whose timestamp is older than `olderThanMs`
			// (wall-clock milliseconds) from both maps.
			void Cleanup (uint64_t olderThanMs);

			bool IsEmpty () const;

			boost::asio::ip::address_v4 GetBase () const { return boost::asio::ip::address_v4 (m_Base); }
			int GetPrefix () const { return m_Prefix; }

		private:

			using NameTS = std::pair<std::string, uint64_t>; // name, wall-clock ms timestamp

			uint32_t m_Base;   // network address (masked)
			uint32_t m_Mask;   // netmask
			uint64_t m_Size;   // number of addresses in V/p (2^(32-prefix))
			int m_Prefix;
			uint32_t m_Cursor; // next offset within V/p to try when allocating
			mutable std::mutex m_Mutex;
			std::map<uint32_t, NameTS> m_Reverse;       // virtual IP -> (name, ts)
			std::map<std::string, uint32_t, std::less<>> m_Forward; // name -> virtual IP
	};
}
}

#endif
