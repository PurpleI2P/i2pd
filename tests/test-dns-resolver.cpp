/*
* Unit tests for I2PDNSResolver::ProcessQuery (stateless DNS wire handling).
*
* Exercises the A/AAAA/PTR/refusal logic against a real AddressMapper without
* needing a running destination or io_context.
*/
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <boost/asio.hpp>

#include "AddressMapper.h"
#include "I2PDNSResolver.h"

using boost::asio::ip::address_v4;

static void put16 (std::vector<uint8_t>& v, uint16_t x)
{
	uint16_t b = htons (x);
	v.insert (v.end (), (uint8_t*)&b, (uint8_t*)&b + 2);
}
static uint16_t get16 (const uint8_t* p) { return ntohs (*(const uint16_t*)p); }
static uint32_t get32 (const uint8_t* p) { return ntohl (*(const uint32_t*)p); }

static std::vector<uint8_t> MakeQuery (uint16_t id, const std::string& name, uint16_t qtype)
{
	std::vector<uint8_t> q;
	put16 (q, id);
	put16 (q, 0x0100); // standard query, RD=1
	put16 (q, 1);      // qdcount
	put16 (q, 0); put16 (q, 0); put16 (q, 0);
	std::size_t i = 0;
	while (i < name.size ())
	{
		auto dot = name.find ('.', i);
		auto len = (dot == std::string::npos) ? (name.size () - i) : (dot - i);
		q.push_back ((uint8_t)len);
		q.insert (q.end (), name.begin () + i, name.begin () + i + len);
		if (dot == std::string::npos) break;
		i = dot + 1;
	}
	q.push_back (0);
	put16 (q, qtype);
	put16 (q, 1); // IN
	return q;
}

// Follow DNS names (incl. compression pointers) and return the offset just past
// the name in the original stream, filling `out` (lowercased).
static int ReadName (const uint8_t* buf, std::size_t len, std::size_t off, std::string& out)
{
	out.clear ();
	std::size_t pos = off, end = off; bool endSet = false; unsigned hops = 0;
	while (true)
	{
		if (pos >= len || hops++ > 255) return -1;
		uint8_t c = buf[pos];
		if (c == 0) { if (!endSet) end = pos + 1; break; }
		if ((c & 0xC0) == 0xC0)
		{
			if (pos + 1 >= len) return -1;
			if (!endSet) { end = pos + 2; endSet = true; }
			pos = (((std::size_t)(c & 0x3F)) << 8) | buf[pos + 1];
			continue;
		}
		pos++;
		if (pos + c > len) return -1;
		if (!out.empty ()) out += '.';
		out.append ((const char*)(buf + pos), c);
		pos += c;
	}
	return (int)end;
}

struct Resp
{
	uint16_t id, flags, qd, an, rcode;
	bool hasAnswer = false;
	uint16_t rrType = 0, rrClass = 0;
	std::vector<uint8_t> rdata;
};

static Resp Parse (const std::vector<uint8_t>& r)
{
	Resp p;
	assert (r.size () >= 12);
	p.id = get16 (r.data ());
	p.flags = get16 (r.data () + 2);
	p.qd = get16 (r.data () + 4);
	p.an = get16 (r.data () + 6);
	p.rcode = p.flags & 0x0F;
	std::string nm;
	int qe = ReadName (r.data (), r.size (), 12, nm);
	assert (qe >= 0);
	std::size_t off = (std::size_t)qe + 4; // skip qtype/qclass of the question
	if (p.an >= 1 && off + 12 <= r.size ())
	{
		std::string aname;
		int ae = ReadName (r.data (), r.size (), off, aname);
		assert (ae >= 0);
		std::size_t o = (std::size_t)ae;
		p.hasAnswer = true;
		p.rrType = get16 (r.data () + o); o += 2;
		p.rrClass = get16 (r.data () + o); o += 2;
		o += 4; // TTL
		uint16_t rdlen = get16 (r.data () + o); o += 2;
		assert (o + rdlen <= r.size ());
		p.rdata.assign (r.begin () + o, r.begin () + o + rdlen);
	}
	return p;
}

int main ()
{
	i2p::client::AddressMapper mapper ("10.192.0.0/24");

	// A for foo.i2p -> an A record with a virtual IP in range
	auto q = MakeQuery (0x1234, "foo.i2p", 1);
	auto r = i2p::client::I2PDNSResolver::ProcessQuery (mapper, q.data (), q.size ());
	assert (!r.empty ());
	auto pr = Parse (r);
	assert (pr.id == 0x1234);
	assert ((pr.flags & 0x8000) != 0); // QR
	assert ((pr.flags & 0x0080) != 0); // RA
	assert (pr.rcode == 0);
	assert (pr.qd == 1);
	assert (pr.an == 1);
	assert (pr.hasAnswer);
	assert (pr.rrType == 1); // A
	assert (pr.rrClass == 1); // IN
	assert (pr.rdata.size () == 4);
	uint32_t ip = get32 (pr.rdata.data ());
	auto vip = address_v4 (ip);
	assert (mapper.IsVirtual (vip));
	assert (mapper.GetName (vip) == "foo.i2p");
	// equals what Resolve() would return
	assert (vip == mapper.Resolve ("foo.i2p"));

	// Repeated A query returns the SAME vip (stability)
	auto r2 = i2p::client::I2PDNSResolver::ProcessQuery (mapper, q.data (), q.size ());
	assert (get32 (Parse (r2).rdata.data ()) == ip);

	// A distinct name gets a distinct vip
	auto q2 = MakeQuery (0x2222, "bar.b32.i2p", 1);
	auto pr2 = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, q2.data (), q2.size ()));
	assert (pr2.rcode == 0 && pr2.an == 1);
	assert (get32 (pr2.rdata.data ()) != ip);

	// Non-.i2p A query -> REFUSED, 0 answers
	auto qc = MakeQuery (0x3333, "example.com", 1);
	auto prc = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, qc.data (), qc.size ()));
	assert (prc.rcode == 5); // REFUSED
	assert (prc.an == 0);

	// AAAA for .i2p -> NOERROR, 0 answers (no IPv6 mapping)
	auto q6 = MakeQuery (0x4444, "foo.i2p", 28);
	auto pr6 = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, q6.data (), q6.size ()));
	assert (pr6.rcode == 0);
	assert (pr6.an == 0);

	// AAAA for non-.i2p -> REFUSED
	auto q6c = MakeQuery (0x4545, "example.com", 28);
	auto pr6c = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, q6c.data (), q6c.size ()));
	assert (pr6c.rcode == 5);

	// PTR for the allocated vip -> returns "foo.i2p"
	uint8_t a = (ip) & 0xFF, b = (ip >> 8) & 0xFF, c = (ip >> 16) & 0xFF, d = (ip >> 24) & 0xFF;
	std::string rev = std::to_string (a) + "." + std::to_string (b) + "." +
	                  std::to_string (c) + "." + std::to_string (d) + ".in-addr.arpa";
	auto qp = MakeQuery (0x5555, rev, 12);
	auto prp = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, qp.data (), qp.size ()));
	assert (prp.rcode == 0);
	assert (prp.an == 1);
	assert (prp.hasAnswer);
	assert (prp.rrType == 12); // PTR
	// decode rdata name
	std::string pname;
	assert (ReadName (prp.rdata.data (), prp.rdata.size (), 0, pname) >= 0);
	assert (pname == "foo.i2p");

	// PTR for an in-range but unmapped address -> NXDOMAIN
	auto unmapped = address_v4 (0x0AC000FE); // 10.192.0.254, in /24, not allocated
	uint8_t ua = unmapped.to_uint () & 0xFF, ub = (unmapped.to_uint () >> 8) & 0xFF,
	        uc = (unmapped.to_uint () >> 16) & 0xFF, ud = (unmapped.to_uint () >> 24) & 0xFF;
	std::string urev = std::to_string (ua) + "." + std::to_string (ub) + "." +
	                   std::to_string (uc) + "." + std::to_string (ud) + ".in-addr.arpa";
	auto qu = MakeQuery (0x6666, urev, 12);
	auto pru = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, qu.data (), qu.size ()));
	assert (pru.rcode == 3); // NXDOMAIN

	// PTR for an out-of-range address -> NXDOMAIN
	auto qu2 = MakeQuery (0x7777, "8.8.8.8.in-addr.arpa", 12);
	auto pru2 = Parse (i2p::client::I2PDNSResolver::ProcessQuery (mapper, qu2.data (), qu2.size ()));
	assert (pru2.rcode == 3);

	// A response received as a query is dropped (empty result)
	std::vector<uint8_t> fakeResp = r;
	fakeResp[2] |= 0x80; // set QR
	assert (i2p::client::I2PDNSResolver::ProcessQuery (mapper, fakeResp.data (), fakeResp.size ()).empty ());

	// Too-short message is dropped
	uint8_t tiny[8] = {0};
	assert (i2p::client::I2PDNSResolver::ProcessQuery (mapper, tiny, sizeof (tiny)).empty ());

	return 0;
}
