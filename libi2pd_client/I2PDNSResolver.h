/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2P_DNS_RESOLVER_H__
#define I2P_DNS_RESOLVER_H__

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include "I2PService.h"
#include "AddressMapper.h"
#include "ClientContext.h"

namespace i2p
{
namespace client
{
	// Minimal DNS server that answers A/AAAA/PTR for .i2p names by mapping
	// them to virtual IPv4 addresses from a shared AddressMapper (the same
	// instance the TPROXY transparent proxy reverses on connect).
	//
	// Mirrors Tor's DNSPort + automap behaviour: a name resolves to a virtual
	// IP; a later transparent connection to that IP is mapped back to the name
	// before the I2P stream is built. Only .i2p (+ in-range PTR) is answered;
	// other queries are refused so no DNS is leaked upstream by default.
	//
	// Name handling is synchronous: any well-formed *.i2p name is allocated a
	// virtual IP immediately (matching the SOCKS automap), and the later I2P
	// stream attempt fails if the name is bogus. This avoids blocking the DNS
	// reply on a netDb lookup.
	class I2PDNSResolver: public I2PService
	{
		public:

			I2PDNSResolver (const std::string& address, uint16_t port, bool enableTCP,
				std::shared_ptr<AddressMapper> mapper,
				std::shared_ptr<ClientDestination> localDestination = nullptr);
			~I2PDNSResolver () { Stop (); }

			void Start () override;
			void Stop () override;

			const char* GetName () const override { return "I2P DNS Resolver"; }

			// Build a DNS response for a wire-format query. Returns an empty
			// vector to silently drop the query (e.g. a response received as a
			// query, or a too-short message). Public so the TCP connection helper
			// can reuse the same logic as the UDP path.
			std::vector<uint8_t> ProcessQuery (const uint8_t* buf, std::size_t len) const;

			// Stateless query processing backed by `mapper`. Exposed statically so
			// it can be unit-tested without a running destination/io_context.
			static std::vector<uint8_t> ProcessQuery (AddressMapper& mapper, const uint8_t* buf, std::size_t len);

		private:

			void ReceiveUDP ();
			void HandleUDPReceive (const boost::system::error_code& ecode, std::size_t len);
			void HandleUDPSend (const boost::system::error_code& ecode);

			void AcceptTCP ();
			void HandleTCPAccept (const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> sock);

			// Assemble a DNS response: mirrors the request id/question, sets QR/RA,
			// and applies `rcode`. `answer` carries a single pre-built RR (or is
			// empty for a 0-answer response). `questionEnd` is the offset just past
			// the echoed question (0 to echo no question, used for malformed input).
			static std::vector<uint8_t> BuildResponse (uint16_t id, uint16_t reqFlags, uint8_t rcode,
				const uint8_t* req, std::size_t reqlen, std::vector<uint8_t> answer,
				std::size_t questionEnd = 0);

		private:

			std::string m_Address;
			uint16_t m_Port;
			bool m_EnableTCP;
			std::shared_ptr<AddressMapper> m_AddressMapper;

			std::unique_ptr<boost::asio::ip::udp::socket> m_UDPSocket;
			std::array<uint8_t, 4096> m_RecvBuffer;
			boost::asio::ip::udp::endpoint m_Sender;

			std::unique_ptr<boost::asio::ip::tcp::acceptor> m_TCPAcceptor;
	};
}
}

#endif
