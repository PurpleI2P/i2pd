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
	class SOCKSHandler;
	class SOCKSServer: public i2p::client::I2PService
	{
		private:
			std::set<std::shared_ptr<SOCKSHandler> > m_Handlers;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
			std::mutex m_HandlersMutex;

		private:

			void Accept();
			void HandleAccept(const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);

		public:
			SOCKSServer(int port) : I2PService(nullptr),
				m_Acceptor (GetService (), boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
				m_Timer (GetService ()) {};
			~SOCKSServer() { Stop(); }

			void Start ();
			void Stop ();
	};

	typedef SOCKSServer SOCKSProxy;
}
}


#endif
