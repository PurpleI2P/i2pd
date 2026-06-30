/*
* Unit tests for the shared AddressMapper (virtual-IP automap).
*/
#include <cassert>
#include <chrono>
#include <string>
#include <thread>
#include <boost/asio.hpp>

#include "AddressMapper.h"

using boost::asio::ip::address_v4;
using boost::asio::ip::make_address;

static address_v4 v4 (uint32_t u) { return address_v4 (u); }

static void test_roundtrip_and_stability ()
{
	i2p::client::AddressMapper m ("10.192.0.0/24");
	auto a = m.Resolve ("foo.i2p");
	assert (m.IsVirtual (a));
	assert (m.GetName (a) == "foo.i2p");
	// repeating the lookup returns the same vip
	auto a2 = m.Resolve ("foo.i2p");
	assert (a2 == a);
	// a different name gets a different vip
	auto b = m.Resolve ("bar.b32.i2p");
	assert (b != a);
	assert (m.IsVirtual (b));
	assert (m.GetName (b) == "bar.b32.i2p");
	// reverse of an unmapped in-range address is empty
	assert (m.GetName (v4 (0x0AC000FE)).empty ()); // 10.192.0.254, in range, not allocated
}

static void test_isvirtual_bounds ()
{
	i2p::client::AddressMapper m ("10.192.0.0/10");
	assert (m.IsVirtual (v4 (0x0AC00000))); // 10.192.0.0  (network, still "virtual")
	assert (m.IsVirtual (v4 (0x0AFFFFFF))); // 10.255.255.255 (broadcast, in range)
	assert (!m.IsVirtual (v4 (0x0ABFFFFF))); // 10.191.255.255 (just below range)
	assert (!m.IsVirtual (v4 (0x0B000000))); // 11.0.0.0 (just above)
	assert (!m.IsVirtual (make_address ("8.8.8.8").to_v4 ()));
	assert (!m.IsVirtual (make_address ("255.0.0.5").to_v4 ())); // not our range
}

static void test_sequential_distinct ()
{
	i2p::client::AddressMapper m ("10.192.0.0/24");
	address_v4 prev = m.Resolve ("n0.i2p");
	for (int i = 1; i < 50; i++)
	{
		auto cur = m.Resolve (("n" + std::to_string (i) + ".i2p").c_str ());
		assert (cur != prev);
		assert (m.IsVirtual (cur));
		prev = cur;
	}
}

static void test_cleanup ()
{
	i2p::client::AddressMapper m ("10.192.0.0/24");
	auto a = m.Resolve ("keep.i2p");
	assert (m.GetName (a) == "keep.i2p");
	// a huge threshold must not evict fresh entries
	m.Cleanup (UINT64_MAX / 2);
	assert (m.GetName (a) == "keep.i2p");
	// after a small sleep, a tiny threshold evicts everything
	std::this_thread::sleep_for (std::chrono::milliseconds (5));
	m.Cleanup (1);
	assert (m.GetName (a).empty ());
	assert (m.IsEmpty ());
	// re-resolving works after cleanup (re-allocates)
	auto a2 = m.Resolve ("again.i2p");
	assert (m.GetName (a2) == "again.i2p");
}

static void test_exhaustion_eviction ()
{
	// /30 -> 4 addresses, only offsets 1 and 2 are allocatable (skip network/broadcast)
	i2p::client::AddressMapper m ("10.0.0.0/30");
	auto a = m.Resolve ("first.i2p");
	auto b = m.Resolve ("second.i2p");
	assert (a != b);
	assert (m.IsVirtual (a) && m.IsVirtual (b));
	assert (m.GetName (a) == "first.i2p");
	assert (m.GetName (b) == "second.i2p");
	// range is now full; a third name must evict the LRU (first.i2p) and reuse its address
	auto c = m.Resolve ("third.i2p");
	assert (m.IsVirtual (c));
	assert (m.GetName (c) == "third.i2p");
	// first.i2p was evicted, its address now belongs to third.i2p
	assert (m.GetName (a) == "third.i2p");
	// second.i2p survived
	assert (m.GetName (b) == "second.i2p");
}

static void test_parse_cidr ()
{
	boost::asio::ip::address_v4 base;
	int prefix;
	assert (i2p::client::AddressMapper::ParseCIDR ("10.192.0.0/10", base, prefix));
	assert (prefix == 10);
	assert (base.to_uint () == 0x0AC00000);
	assert (!i2p::client::AddressMapper::ParseCIDR ("10.192.0.0", base, prefix));   // no prefix
	assert (!i2p::client::AddressMapper::ParseCIDR ("10.192.0.0/0", base, prefix));  // prefix too small
	assert (!i2p::client::AddressMapper::ParseCIDR ("10.192.0.0/32", base, prefix)); // prefix too big
	assert (!i2p::client::AddressMapper::ParseCIDR ("not-an-ip/10", base, prefix));
	bool threw = false;
	try { i2p::client::AddressMapper bad ("garbage"); } catch (const std::runtime_error&) { threw = true; }
	assert (threw);
}

int main ()
{
	test_parse_cidr ();
	test_roundtrip_and_stability ();
	test_isvirtual_bounds ();
	test_sequential_distinct ();
	test_exhaustion_eviction ();
	test_cleanup ();
	return 0;
}
