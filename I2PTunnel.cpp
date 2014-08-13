#include <boost/bind.hpp>
#include "I2PTunnel.h"

namespace i2p
{
namespace stream
{
	I2PTunnelConnection::I2PTunnelConnection (boost::asio::ip::tcp::socket * socket,
		const i2p::data::LeaseSet * leaseSet): m_Socket (socket)
	{
		m_Stream = i2p::stream::CreateStream (*leaseSet);
	}	

	I2PTunnelConnection::~I2PTunnelConnection ()
	{
		if (m_Stream)
		{
			m_Stream->Close ();
			DeleteStream (m_Stream);
		}
		
		delete m_Socket;
	}	

	I2PClientTunnel::I2PClientTunnel (boost::asio::io_service& service, const std::string& destination, int port):
		m_Service (service), m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_Destination (destination), m_RemoteLeaseSet (nullptr)
	{
	}	

	
	void I2PClientTunnel::Accept ()
	{
		auto newSocket = new boost::asio::ip::tcp::socket (m_Service);
		m_Acceptor.async_accept (*newSocket, boost::bind (&I2PClientTunnel::HandleAccept, this,
			boost::asio::placeholders::error, newSocket));
	}	

	void I2PClientTunnel::HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket)
	{
		if (!ecode)
		{
			if (m_RemoteLeaseSet)
				new I2PTunnelConnection (socket, m_RemoteLeaseSet);
			else
				delete socket;
			Accept ();
		}
		else
			delete socket;
	}
}		
}	
