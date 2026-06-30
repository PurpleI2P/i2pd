/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SOCKS_H__
#define SOCKS_H__

#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <boost/asio.hpp>
#include <mutex>
#include "I2PService.h"
#include "AddressMapper.h"

namespace i2p
{
namespace proxy
{
	class SOCKSServer: public i2p::client::TCPIPAcceptor
	{
		public:

			SOCKSServer(const std::string& name, const std::string& address, uint16_t port, bool outEnable, const std::string& outAddress, uint16_t outPort,
				std::shared_ptr<i2p::client::ClientDestination> localDestination = nullptr);
			~SOCKSServer() {};

			void SetUpstreamProxy(const std::string & addr, const uint16_t port);
			boost::asio::ip::udp::endpoint GetNextLocalUDPEndpoint ();
			void ReleaseLocalUDPPort (uint16_t port);

			std::string GetResolvedAddress (const boost::asio::ip::address_v4& addr) const;
			boost::asio::ip::address_v4 ResolveAddress (std::string_view resolved);
			bool HasResolvedAddresses () const { return m_AddressMapper && !m_AddressMapper->IsEmpty (); }

			std::shared_ptr<i2p::client::AddressMapper> GetAddressMapper () const { return m_AddressMapper; }

		protected:

			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket) override;
			const char* GetName()const override { return m_Name.c_str (); }

		private:

			std::string m_Name;
			std::string m_UpstreamProxyAddress;
			uint16_t m_UpstreamProxyPort;
			bool m_UseUpstreamProxy;
			std::set<uint16_t> m_UDPPorts;
			// Automap table for the torsocks path. Bound to the unroutable
			// 255.0.0.0/8 range; the virtual IP is rewritten locally and never
			// put on the wire, so the reserved range is fine here.
			std::shared_ptr<i2p::client::AddressMapper> m_AddressMapper;
	};

	typedef SOCKSServer SOCKSProxy;
}
}
#endif
