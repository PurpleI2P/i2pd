#include <boost/bind.hpp>
#include "Log.h"
#include "hmac.h"
#include "SSU.h"

namespace i2p
{
namespace ssu
{

	SSUSession::SSUSession (): m_State (eSessionStateUnknown)
	{
	}

	void SSUSession::ProcessNextMessage (uint8_t * buf, std::size_t len)
	{
	}

	SSUServer::SSUServer (boost::asio::io_service& service, int port):
		m_Socket (service, boost::asio::ip::udp::v4 (), port)
	{
	}
	
	SSUServer::~SSUServer ()
	{
		for (auto it: m_Sessions)
			delete it.second;
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
			SSUSession * session = nullptr;
			auto it = m_Sessions.find (m_SenderEndpoint);
			if (it != m_Sessions.end ())
				session = it->second;
			if (session)
			{
				session = new SSUSession ();
				m_Sessions[m_SenderEndpoint] = session;
				LogPrint ("New SSU session from ", m_SenderEndpoint.address ().to_string (), ":", m_SenderEndpoint.port (), " created");
			}
			session->ProcessNextMessage (m_ReceiveBuffer, bytes_transferred);
			Receive ();
		}
		else
			LogPrint ("SSU receive error: ", ecode.message ());
	}
}
}

