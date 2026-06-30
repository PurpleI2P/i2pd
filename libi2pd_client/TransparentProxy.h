/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TRANSPARENT_PROXY_H__
#define TRANSPARENT_PROXY_H__

#include <memory>
#include <string>
#include <boost/asio.hpp>
#include "I2PService.h"
#include "AddressMapper.h"

namespace i2p
{
namespace client
{
	enum class TransProxyType { tproxy, redirect };

	// Transparent proxy: a TCP listener that recovers the *original* destination
	// of connections diverted to it (Linux TPROXY or NAT REDIRECT), maps the
	// destination IPv4 back to a .i2p name via the shared AddressMapper, and
	// bridges the connection to an I2P stream — Tor's TransPort for I2P.
	//
	// Only destinations inside the configured virtual range with a live mapping
	// are accepted; anything else is closed, so i2pd cannot be used as an open
	// relay to arbitrary IPs.
	//
	// TPROXY is Linux-only (IP_TRANSPARENT). On other platforms the service
	// compiles to a stub that logs "not supported".
	class TransparentProxyServer: public I2PService
	{
		public:

			TransparentProxyServer (const std::string& name, const std::string& address, uint16_t port,
				TransProxyType type, std::shared_ptr<AddressMapper> mapper,
				std::shared_ptr<ClientDestination> localDestination = nullptr);
			~TransparentProxyServer () { Stop (); }

			void Start () override;
			void Stop () override;

			const char* GetName () const override { return m_Name.c_str (); }
			TransProxyType GetType () const { return m_Type; }
			std::shared_ptr<AddressMapper> GetAddressMapper () const { return m_AddressMapper; }

		private:

			void Accept ();
			std::shared_ptr<I2PServiceHandler> CreateHandler (std::shared_ptr<boost::asio::ip::tcp::socket> socket);

			std::string m_Name;
			boost::asio::ip::tcp::endpoint m_LocalEndpoint;
			std::unique_ptr<boost::asio::ip::tcp::acceptor> m_Acceptor;
			std::shared_ptr<AddressMapper> m_AddressMapper;
			TransProxyType m_Type;
	};
}
}

#endif
