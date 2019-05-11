#ifndef SOCKS_H__
#define SOCKS_H__

#include <memory>
#include <set>
#include <boost/asio.hpp>
#include <mutex>
#include "DotNetService.h"

namespace dotnet
{
namespace proxy
{
	class SOCKSServer: public dotnet::client::TCPIPAcceptor
	{
		public:
			SOCKSServer(const std::string& name, const std::string& address, int port, bool outEnable, const std::string& outAddress, uint16_t outPort,
				std::shared_ptr<dotnet::client::ClientDestination> localDestination = nullptr);
			~SOCKSServer() {};

			void SetUpstreamProxy(const std::string & addr, const uint16_t port);

		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<dotnet::client::DotNetServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
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
