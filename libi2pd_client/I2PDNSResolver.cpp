/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "I2PDNSResolver.h"
#include <algorithm>
#include <cstring>
#include "Log.h"
#include "I2PEndian.h"

namespace i2p
{
namespace client
{
	namespace
	{
		// DNS record types / classes
		constexpr uint16_t QTYPE_A    = 1;
		constexpr uint16_t QTYPE_PTR  = 12;
		constexpr uint16_t QTYPE_AAAA = 28;
		constexpr uint16_t QCLASS_IN  = 1;

		// DNS RCODEs
		constexpr uint8_t RCODE_NOERROR  = 0;
		constexpr uint8_t RCODE_FORMERR   = 1;
		constexpr uint8_t RCODE_SERVFAIL  = 2;
		constexpr uint8_t RCODE_NXDOMAIN  = 3;
		constexpr uint8_t RCODE_NOTIMP    = 4;
		constexpr uint8_t RCODE_REFUSED   = 5;

		constexpr uint32_t DNS_MAPPER_TTL = 60; // seconds

		// DNS flags layout (big-endian uint16):
		// QR(1) Opcode(4) AA(1) TC(1) RD(1) | RA(1) Z(3) RCODE(4)
		uint16_t MakeFlags (bool qr, uint8_t opcode, bool aa, bool tc, bool rd,
			bool ra, uint8_t rcode)
		{
			return (qr ? 0x8000 : 0) | ((opcode & 0x0F) << 11) | (aa ? 0x0400 : 0) |
			       (tc ? 0x0200 : 0) | (rd ? 0x0100 : 0) | (ra ? 0x0080 : 0) | (rcode & 0x0F);
		}

		void PutU16 (std::vector<uint8_t>& v, uint16_t x) { uint16_t b = htobe16 (x); v.insert (v.end (), (uint8_t*)&b, (uint8_t*)&b + 2); }
		void PutU32 (std::vector<uint8_t>& v, uint32_t x) { uint32_t b = htobe32 (x); v.insert (v.end (), (uint8_t*)&b, (uint8_t*)&b + 4); }

		uint16_t GetU16 (const uint8_t* p) { return be16toh (*(const uint16_t*)p); }

		// Decode a DNS name beginning at `offset`, following compression pointers.
		// On success returns the offset just past the name in the original stream
		// (where qtype/qclass follow) and fills `name` (lowercased). Returns -1 on
		// malformed input or runaway pointers.
		int ReadName (const uint8_t* buf, std::size_t len, std::size_t offset, std::string& name)
		{
			name.clear ();
			std::size_t pos = offset, endOffset = offset;
			bool endSet = false;
			unsigned hops = 0;
			while (true)
			{
				if (pos >= len || hops++ > 255) return -1;
				uint8_t c = buf[pos];
				if (c == 0)
				{
					if (!endSet) endOffset = pos + 1;
					break;
				}
				if ((c & 0xC0) == 0xC0)
				{
					if (pos + 1 >= len) return -1;
					if (!endSet) { endOffset = pos + 2; endSet = true; }
					pos = (((std::size_t)(c & 0x3F)) << 8) | buf[pos + 1];
					continue;
				}
				if ((c & 0xC0) != 0) return -1; // reserved
				pos++;
				if (pos + c > len) return -1;
				if (!name.empty ()) name += '.';
				name.append ((const char*)(buf + pos), c);
				pos += c;
			}
			std::transform (name.begin (), name.end (), name.begin (), ::tolower);
			return (int)endOffset;
		}

		// Encode a dotted name as DNS labels (no compression), appending to `out`.
		void PutName (std::vector<uint8_t>& out, const std::string& name)
		{
			std::size_t i = 0;
			while (i < name.size ())
			{
				std::size_t dot = name.find ('.', i);
				std::size_t labLen = (dot == std::string::npos) ? (name.size () - i) : (dot - i);
				if (labLen > 63) labLen = 63; // clamp
				out.push_back ((uint8_t)labLen);
				out.insert (out.end (), name.begin () + i, name.begin () + i + labLen);
				if (dot == std::string::npos) break;
				i = dot + 1;
			}
			out.push_back (0); // terminator
		}

		bool EndsWithI2P (const std::string& name)
		{
			constexpr const char* suffix = ".i2p";
			constexpr std::size_t suflen = 4;
			return name.size () > suflen && name.compare (name.size () - suflen, suflen, suffix) == 0;
		}

		// Parse "d.c.b.a.in-addr.arpa" into a.b.c.d. Returns true on success.
		bool ParseInAddrArpa (const std::string& name, uint32_t& addr)
		{
			constexpr const char* suffix = ".in-addr.arpa";
			constexpr std::size_t suflen = 13;
			if (name.size () <= suflen || name.compare (name.size () - suflen, suflen, suffix) != 0)
				return false;
			std::string s = name.substr (0, name.size () - suflen); // "d.c.b.a"
			uint8_t oct[4] = {0,0,0,0};
			int idx = 0;
			std::size_t pos = 0;
			while (idx < 4 && pos < s.size ())
			{
				std::size_t dot = s.find ('.', pos);
				std::string tok = (dot == std::string::npos) ? s.substr (pos) : s.substr (pos, dot - pos);
				if (tok.empty ()) return false;
				for (char c : tok) if (c < '0' || c > '9') return false;
				int v = 0;
				try { v = std::stoi (tok); } catch (...) { return false; }
				if (v < 0 || v > 255) return false;
				oct[idx] = (uint8_t)v;
				idx++;
				if (dot == std::string::npos) break;
				pos = dot + 1;
			}
			if (idx != 4) return false;
			// reverse DNS order: d.c.b.a -> a.b.c.d
			addr = ((uint32_t)oct[3] << 24) | ((uint32_t)oct[2] << 16) | ((uint32_t)oct[1] << 8) | oct[0];
			return true;
		}
	}

	I2PDNSResolver::I2PDNSResolver (const std::string& address, uint16_t port, bool enableTCP,
			std::shared_ptr<AddressMapper> mapper, std::shared_ptr<ClientDestination> localDestination):
		I2PService (localDestination ? localDestination : i2p::client::context.GetSharedLocalDestination ()),
		m_Address (address), m_Port (port), m_EnableTCP (enableTCP), m_AddressMapper (mapper)
	{
	}

	void I2PDNSResolver::Start ()
	{
		I2PService::Start ();
		try
		{
			auto addr = boost::asio::ip::make_address (m_Address);
			boost::asio::ip::udp::endpoint uep (addr, m_Port);
			m_UDPSocket.reset (new boost::asio::ip::udp::socket (GetService ()));
			m_UDPSocket->open (uep.protocol ());
			m_UDPSocket->set_option (boost::asio::socket_base::reuse_address (true));
			m_UDPSocket->bind (uep);
			LogPrint (eLogInfo, "I2PDNS: UDP listener on ", m_Address, ":", m_Port);
			ReceiveUDP ();

			if (m_EnableTCP)
			{
				boost::asio::ip::tcp::endpoint tep (addr, m_Port);
				m_TCPAcceptor.reset (new boost::asio::ip::tcp::acceptor (GetService ()));
				m_TCPAcceptor->open (tep.protocol ());
				m_TCPAcceptor->set_option (boost::asio::socket_base::reuse_address (true));
				m_TCPAcceptor->bind (tep);
				m_TCPAcceptor->listen ();
				LogPrint (eLogInfo, "I2PDNS: TCP listener on ", m_Address, ":", m_Port);
				AcceptTCP ();
			}
		}
		catch (std::exception& e)
		{
			LogPrint (eLogError, "I2PDNS: Failed to bind on ", m_Address, ":", m_Port, ": ", e.what ());
			m_UDPSocket.reset (nullptr);
			m_TCPAcceptor.reset (nullptr);
		}
	}

	void I2PDNSResolver::Stop ()
	{
		if (m_TCPAcceptor) { m_TCPAcceptor->close (); m_TCPAcceptor.reset (nullptr); }
		if (m_UDPSocket) { m_UDPSocket->close (); m_UDPSocket.reset (nullptr); }
		I2PService::Stop ();
	}

	void I2PDNSResolver::ReceiveUDP ()
	{
		if (!m_UDPSocket) return;
		auto self = std::static_pointer_cast<I2PDNSResolver> (shared_from_this ());
		m_UDPSocket->async_receive_from (boost::asio::buffer (m_RecvBuffer),
			m_Sender, [self](const boost::system::error_code& ecode, std::size_t len)
			{ self->HandleUDPReceive (ecode, len); });
	}

	void I2PDNSResolver::HandleUDPReceive (const boost::system::error_code& ecode, std::size_t len)
	{
		if (ecode == boost::asio::error::operation_aborted) return;
		if (!ecode)
		{
			auto resp = ProcessQuery (m_RecvBuffer.data (), len);
			if (!resp.empty () && m_UDPSocket)
			{
				auto self = std::static_pointer_cast<I2PDNSResolver> (shared_from_this ());
				auto buf = std::make_shared<std::vector<uint8_t>> (std::move (resp));
				m_UDPSocket->async_send_to (boost::asio::buffer (*buf), m_Sender,
					[self, buf](const boost::system::error_code& ec, std::size_t)
					{ self->HandleUDPSend (ec); });
				return;
			}
		}
		else
			LogPrint (eLogWarning, "I2PDNS: UDP receive error: ", ecode.message ());
		ReceiveUDP ();
	}

	void I2PDNSResolver::HandleUDPSend (const boost::system::error_code& ecode)
	{
		if (ecode)
			LogPrint (eLogWarning, "I2PDNS: UDP send error: ", ecode.message ());
		ReceiveUDP ();
	}

	// --- DNS over TCP -------------------------------------------------------

	class DNSResolverTCPConnection: public std::enable_shared_from_this<DNSResolverTCPConnection>
	{
		public:
			DNSResolverTCPConnection (std::shared_ptr<boost::asio::ip::tcp::socket> sock, const I2PDNSResolver* resolver)
				: m_Socket (sock), m_Resolver (resolver) {}

			void Start () { ReadLength (); }

		private:
			void ReadLength ()
			{
				auto self = shared_from_this ();
				boost::asio::async_read (*m_Socket, boost::asio::buffer (&m_LenBuf, 2),
					[self](const boost::system::error_code& ec, std::size_t)
					{
						if (ec) { self->Close (); return; }
						uint16_t len = be16toh (*(uint16_t*)self->m_LenBuf);
						if (len < 12 || len > 4096) { self->Close (); return; }
						self->m_Msg.assign (len, 0);
						self->ReadMessage (len);
					});
			}

			void ReadMessage (uint16_t len)
			{
				auto self = shared_from_this ();
				boost::asio::async_read (*m_Socket, boost::asio::buffer (m_Msg.data (), len),
					[self, len](const boost::system::error_code& ec, std::size_t)
					{
						if (ec) { self->Close (); return; }
						auto resp = self->m_Resolver->ProcessQuery (self->m_Msg.data (), len);
						if (resp.empty ()) { self->Close (); return; }
						self->Send (std::move (resp));
					});
			}

			void Send (std::vector<uint8_t> resp)
			{
				auto self = shared_from_this ();
				m_OutLen = htobe16 ((uint16_t)resp.size ());
				m_OutBuf = std::make_shared<std::vector<uint8_t>> (std::move (resp));
				std::array<boost::asio::const_buffer, 2> bufs {{
					boost::asio::buffer (&m_OutLen, 2), boost::asio::buffer (*m_OutBuf) }};
				boost::asio::async_write (*m_Socket, bufs,
					[self](const boost::system::error_code& ec, std::size_t)
					{
						if (ec) { self->Close (); return; }
						self->ReadLength ();
					});
			}

			void Close () { if (m_Socket && m_Socket->is_open ()) m_Socket->close (); }

		private:
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			const I2PDNSResolver* m_Resolver;
			uint8_t m_LenBuf[2];
			std::vector<uint8_t> m_Msg;
			uint16_t m_OutLen;
			std::shared_ptr<std::vector<uint8_t>> m_OutBuf;
	};

	void I2PDNSResolver::AcceptTCP ()
	{
		if (!m_TCPAcceptor) return;
		auto self = std::static_pointer_cast<I2PDNSResolver> (shared_from_this ());
		auto sock = std::make_shared<boost::asio::ip::tcp::socket> (GetService ());
		m_TCPAcceptor->async_accept (*sock, [self, sock](const boost::system::error_code& ecode)
			{ self->HandleTCPAccept (ecode, sock); });
	}

	void I2PDNSResolver::HandleTCPAccept (const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> sock)
	{
		if (ecode == boost::asio::error::operation_aborted) return;
		if (!ecode)
		{
			auto conn = std::make_shared<DNSResolverTCPConnection> (sock, this);
			conn->Start ();
		}
		else
			LogPrint (eLogWarning, "I2PDNS: TCP accept error: ", ecode.message ());
		AcceptTCP ();
	}

	// --- Query processing ---------------------------------------------------

	std::vector<uint8_t> I2PDNSResolver::BuildResponse (uint16_t id, uint16_t reqFlags, uint8_t rcode,
		const uint8_t* req, std::size_t reqlen, std::vector<uint8_t> answer, std::size_t questionEnd)
	{
		std::vector<uint8_t> out;
		out.reserve (12 + (questionEnd > 12 ? questionEnd - 12 : 0) + answer.size ());
		bool rd = reqFlags & 0x0100;
		uint8_t opcode = (reqFlags >> 11) & 0x0F;
		uint16_t flags = MakeFlags (true, opcode, false, false, rd, true, rcode);
		uint16_t qd = (questionEnd > 12 && questionEnd <= reqlen) ? 1 : 0;
		uint16_t an = answer.empty () ? 0 : 1;
		PutU16 (out, id);
		PutU16 (out, flags);
		PutU16 (out, qd);
		PutU16 (out, an);
		PutU16 (out, 0); // nscount
		PutU16 (out, 0); // arcount
		if (qd)
			out.insert (out.end (), req + 12, req + questionEnd); // echo the question verbatim
		if (an)
			out.insert (out.end (), answer.begin (), answer.end ());
		return out;
	}

	std::vector<uint8_t> I2PDNSResolver::ProcessQuery (const uint8_t* buf, std::size_t len) const
	{
		return ProcessQuery (*m_AddressMapper, buf, len);
	}

	std::vector<uint8_t> I2PDNSResolver::ProcessQuery (AddressMapper& mapper, const uint8_t* buf, std::size_t len)
	{
		if (len < 12) return {};
		uint16_t id = GetU16 (buf);
		uint16_t reqFlags = GetU16 (buf + 2);
		uint16_t qdcount = GetU16 (buf + 4);

		bool qr = reqFlags & 0x8000;
		uint8_t opcode = (reqFlags >> 11) & 0x0F;

		// Drop responses and anything that isn't a standard query with a question.
		if (qr) return {};
		if (opcode != 0) return BuildResponse (id, reqFlags, RCODE_NOTIMP, buf, len, {});
		if (qdcount < 1) return BuildResponse (id, reqFlags, RCODE_FORMERR, buf, len, {});

		std::string name;
		int off = ReadName (buf, len, 12, name);
		if (off < 0 || (std::size_t)off + 4 > len) return BuildResponse (id, reqFlags, RCODE_FORMERR, buf, len, {});
		uint16_t qtype = GetU16 (buf + off);
		uint16_t qclass = GetU16 (buf + off + 2);
		std::size_t questionEnd = off + 4;

		if (qclass != QCLASS_IN)
			return BuildResponse (id, reqFlags, RCODE_REFUSED, buf, len, {}, questionEnd);

		std::vector<uint8_t> answer;
		uint8_t rcode = RCODE_NOERROR;

		switch (qtype)
		{
			case QTYPE_A:
				if (EndsWithI2P (name))
				{
					auto vip = mapper.Resolve (name);
					answer.reserve (2 + 2 + 2 + 4 + 2 + 4);
					answer.push_back (0xC0); answer.push_back (0x0C); // ptr to question name
					PutU16 (answer, QTYPE_A);
					PutU16 (answer, QCLASS_IN);
					PutU32 (answer, DNS_MAPPER_TTL);
					PutU16 (answer, 4);
					PutU32 (answer, vip.to_uint ());
				}
				else
					rcode = RCODE_REFUSED;
				break;

			case QTYPE_AAAA:
				// No IPv6 mapping: empty NOERROR for .i2p, REFUSED otherwise.
				if (!EndsWithI2P (name)) rcode = RCODE_REFUSED;
				break;

			case QTYPE_PTR:
			{
				uint32_t ip;
				if (ParseInAddrArpa (name, ip))
				{
					auto v4 = boost::asio::ip::address_v4 (ip);
					if (mapper.IsVirtual (v4))
					{
						std::string host = mapper.GetName (v4);
						if (!host.empty ())
						{
							answer.push_back (0xC0); answer.push_back (0x0C);
							PutU16 (answer, QTYPE_PTR);
							PutU16 (answer, QCLASS_IN);
							PutU32 (answer, DNS_MAPPER_TTL);
							std::vector<uint8_t> rdata;
							PutName (rdata, host);
							PutU16 (answer, (uint16_t)rdata.size ());
							answer.insert (answer.end (), rdata.begin (), rdata.end ());
						}
						else
							rcode = RCODE_NXDOMAIN;
					}
					else
						rcode = RCODE_NXDOMAIN;
				}
				else
					rcode = RCODE_REFUSED;
				break;
			}

			default:
				// Unknown type: empty NOERROR.
				break;
		}

		return BuildResponse (id, reqFlags, rcode, buf, len, std::move (answer), questionEnd);
	}
}
}
