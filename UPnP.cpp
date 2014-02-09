#include <string>
#include <boost/lexical_cast.hpp>
#include <boost/bind.hpp>
#include "Log.h"
#include "UPnP.h"

namespace i2p
{
	UPnP::UPnP (): m_Timer (m_Service),
		m_Endpoint (boost::asio::ip::udp::v4 (), UPNP_REPLY_PORT),
		m_MulticastEndpoint (boost::asio::ip::address::from_string (UPNP_GROUP), UPNP_PORT),		
		m_Socket (m_Service, m_Endpoint.protocol ())
	{
		m_Socket.set_option (boost::asio::socket_base::receive_buffer_size (65535));
		m_Socket.set_option (boost::asio::socket_base::send_buffer_size (65535));
		m_Socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
	}
	
	UPnP::~UPnP ()
	{
	}	

	void UPnP::Run ()
	{
		DiscoverRouter ();
		m_Service.run ();
	}	
		
	void UPnP::DiscoverRouter ()
	{
		m_Timer.expires_from_now (boost::posix_time::seconds(5)); // 5 seconds
		m_Timer.async_wait (boost::bind (&UPnP::HandleTimer, this, boost::asio::placeholders::error));

		std::string address = UPNP_GROUP;
		address += ":" + boost::lexical_cast<std::string>(UPNP_PORT);
		std::string request = "M-SEARCH * HTTP/1.1\r\n"
			"HOST: " + address + "\r\n"
			"ST:" + UPNP_ROUTER + "\r\n"
			"MAN:\"ssdp:discover\"\r\n"
			"MX:3\r\n"
			"\r\n\r\n";
		m_Socket.send_to (boost::asio::buffer (request.c_str (), request.length ()), m_MulticastEndpoint);
		Receive ();
	}	

	void UPnP::Receive ()
	{
		m_Socket.async_receive_from (boost::asio::buffer (m_ReceiveBuffer, UPNP_MAX_PACKET_LEN), m_SenderEndpoint,
			boost::bind (&UPnP::HandleReceivedFrom, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}
		
	void UPnP::HandleReceivedFrom (const boost::system::error_code& ecode, size_t bytes_transferred)
	{		
		LogPrint ("UPnP: ", bytes_transferred, " received from ", m_SenderEndpoint.address ());
		std::string str (m_ReceiveBuffer, bytes_transferred);
		LogPrint (str);
		m_Timer.cancel ();
	}

	void UPnP::HandleTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			LogPrint ("UPnP: timeout expired");
			m_Service.stop ();
		}	
	}	
}
