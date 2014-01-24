#ifndef SSU_H__
#define SSU_H__

#include <inttypes.h>
#include <boost/asio.hpp>

namespace i2p
{
namespace ssu
{
	const int SSU_MTU = 1484;

	class SSUServer
	{
		public:

			SSUServer (boost::asio::io_service& service, int port);
			void Start ();
			void Stop ();

		private:

			void Receive ();
			void HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred);

		private:
			
			boost::asio::ip::udp::socket m_Socket;
			boost::asio::ip::udp::endpoint m_SenderEndpoint;
			uint8_t m_ReceiveBuffer[SSU_MTU];
	};
}
}

#endif

