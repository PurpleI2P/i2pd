#ifndef WEBSOCKS_H_
#define WEBSOCKS_H_
#include <string>
#include <memory>
#include "DotNetService.h"
#include "Destination.h"

namespace dotnet
{
namespace client
{

	class WebSocksImpl;

	/** @brief websocket socks proxy server */
	class WebSocks : public dotnet::client::DotNetService
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
