#ifndef UPNP_H__
#define UPNP_H__

#include <boost/asio.hpp>

namespace i2p
{
	const int UPNP_MAX_PACKET_LEN = 1500;
	const char UPNP_GROUP[] = "239.255.255.250";
	const int UPNP_PORT = 1900;
	const int UPNP_REPLY_PORT = 1901;
	const char UPNP_ROUTER[] = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";	
	
	class UPnP
	{
		public:

			UPnP ();
			~UPnP ();

			void Run ();
			

		private:

			void DiscoverRouter ();
			void Receive ();
			void HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred);
			void HandleTimer (const boost::system::error_code& ecode);
			
		private:

			boost::asio::io_service m_Service;
			boost::asio::deadline_timer m_Timer;
			boost::asio::ip::udp::endpoint m_Endpoint, m_MulticastEndpoint, m_SenderEndpoint;
			boost::asio::ip::udp::socket m_Socket;
			char m_ReceiveBuffer[UPNP_MAX_PACKET_LEN];
	};	
}

#endif
