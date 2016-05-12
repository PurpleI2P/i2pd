#ifndef I2CP_H__
#define I2CP_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <boost/asio.hpp>

namespace i2p
{
namespace client
{
	const uint8_t I2CP_PRTOCOL_BYTE = 0x2A;
	const size_t I2CP_SESSION_BUFFER_SIZE = 8192;

	class I2CPSession: public std::enable_shared_from_this<I2CPSession>
	{
		public:

			I2CPSession (std::shared_ptr<boost::asio::ip::tcp::socket> socket);

		private:
			
			void ReadProtocolByte ();
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void Terminate ();

		private:

			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			uint8_t m_Buffer[I2CP_SESSION_BUFFER_SIZE];
	};

	class I2CPServer
	{
		public:

			I2CPServer (const std::string& interface, int port);
	};	
}
}

#endif

