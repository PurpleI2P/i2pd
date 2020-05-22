/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SOCKS_H__
#define SOCKS_H__

#include <memory>
#include <set>
#include <boost/asio.hpp>
#include <mutex>
#include "I2PService.h"

namespace i2p
{
namespace proxy
{
	class SOCKSServer: public i2p::client::TCPIPAcceptor
	{
		public:

			SOCKSServer(const std::string& name, const std::string& address, int port, bool outEnable, const std::string& outAddress, uint16_t outPort,
				std::shared_ptr<i2p::client::ClientDestination> localDestination = nullptr);
			~SOCKSServer() {};

			void SetUpstreamProxy(const std::string & addr, const uint16_t port);

		protected:

			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			const char* GetName() { return m_Name.c_str (); }

		private:

			std::string m_Name;
			std::string m_UpstreamProxyAddress;
			uint16_t m_UpstreamProxyPort;
			bool m_UseUpstreamProxy;
	};

	typedef SOCKSServer SOCKSProxy;
}
}
#endif
