#ifndef WEBSOCKS_H_
#define WEBSOCKS_H_
#include <string>
#include <memory>
#include "I2PService.h"
#include "Destination.h"

namespace i2p
{
namespace client
{

	class WebSocksImpl;

	/** @brief websocket socks proxy server */
	class WebSocks : public i2p::client::I2PService
	{
	public:
		WebSocks(const std::string & addr, int port, std::shared_ptr<ClientDestination> localDestination);
		~WebSocks();

		void Start();
		void Stop();

		boost::asio::ip::tcp::endpoint GetLocalEndpoint() const;

		const char * GetName() { return "WebSOCKS Proxy"; }

	private:
		WebSocksImpl * m_Impl;
	};
}
}
#endif
