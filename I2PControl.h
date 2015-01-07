#ifndef I2P_CONTROL_H__
#define I2P_CONTROL_H__

#include <thread>
#include <boost/asio.hpp>

namespace i2p
{
namespace client
{
	class I2PControlService
	{
		public:

			I2PControlService (int port);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	

			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;			
	};
}
}

#endif

