#include <boost/bind.hpp>
#include "Log.h"
#include "hmac.h"
#include "SSU.h"

namespace i2p
{
namespace ssu
{
	SSUServer::SSUServer (boost::asio::io_service& service, int port):
		m_Socket (service, boost::asio::ip::udp::v4 (), port)
	{
	}
	
	void SSUServer::Start ()
	{
		Receive ();
	}

	void SSUServer::Stop ()
	{
		m_Socket.close ();
	}

	void SSUServer::Receive ()
	{
		m_Socket.async_receive_from (boost::asio::buffer (m_ReceiveBuffer, SSU_MTU), m_SenderEndpoint,
			boost::bind (&SSUServer::HandleReceivedFrom, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}

	void SSUServer::HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			LogPrint ("SSU received ", bytes_transferred, " bytes");
			// Handle
			Receive ();
		}
		else
			LogPrint ("SSU receive error: ", ecode.message ());
	}
}
}

