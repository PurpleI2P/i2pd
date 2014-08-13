#ifndef I2PTUNNEL_H__
#define I2PTUNNEL_H__

#include <inttypes.h>
#include <string>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	class I2PTunnelConnection
	{
		public:

			I2PTunnelConnection (boost::asio::ip::tcp::socket * socket,
				const i2p::data::LeaseSet * leaseSet);
			~I2PTunnelConnection ();
			
		private:

			boost::asio::ip::tcp::socket * m_Socket;
			Stream * m_Stream;
	};	
	
	class I2PClientTunnel
	{
		public:

			I2PClientTunnel (boost::asio::io_service& service, const std::string& destination, int port);
				
		private:

			void Accept ();
			void HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);
			
		private:

			boost::asio::io_service& m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			std::string m_Destination;
			i2p::data::IdentHash m_DestinationIdentHash;
			const i2p::data::LeaseSet * m_RemoteLeaseSet;
	};	
}		
}	

#endif
