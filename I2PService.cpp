#include "Destination.h"
#include "Identity.h"
#include "ClientContext.h"
#include "I2PService.h"


namespace i2p
{
namespace client
{
	static const i2p::data::SigningKeyType I2P_SERVICE_DEFAULT_KEY_TYPE = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256;

	I2PService::I2PService (std::shared_ptr<ClientDestination> localDestination):
		m_LocalDestination (localDestination ? localDestination :
					i2p::client::context.CreateNewLocalDestination (false, I2P_SERVICE_DEFAULT_KEY_TYPE))
	{
	}
	
	I2PService::I2PService (i2p::data::SigningKeyType kt):
		m_LocalDestination (i2p::client::context.CreateNewLocalDestination (false, kt))
	{
	}
	
	void I2PService::CreateStream (StreamRequestComplete streamRequestComplete, const std::string& dest, int port) {
		assert(streamRequestComplete);
		i2p::data::IdentHash identHash;
		if (i2p::client::context.GetAddressBook ().GetIdentHash (dest, identHash))
			m_LocalDestination->CreateStream (streamRequestComplete, identHash, port);
		else
		{
			LogPrint (eLogWarning, "I2PService: Remote destination ", dest, " not found");
			streamRequestComplete (nullptr);
		}
	}

	void TCPIPAcceptor::Start ()
	{
		m_Acceptor.listen ();
		Accept ();
	}

	void TCPIPAcceptor::Stop ()
	{
		m_Acceptor.close();
		m_Timer.cancel ();
		ClearHandlers();
	}

	void TCPIPAcceptor::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (GetService ());
		m_Acceptor.async_accept (*newSocket, std::bind (&TCPIPAcceptor::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void TCPIPAcceptor::HandleAccept (const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (!ecode)
		{
			LogPrint(eLogDebug, "I2PService: ", GetName(), " accepted");
			auto handler = CreateHandler(socket);
			if (handler) 
			{
				AddHandler(handler);
				handler->Handle();
			} 
			else 
				socket->close();
			Accept();
		}
		else
		{
			if (ecode != boost::asio::error::operation_aborted)
				LogPrint (eLogError, "I2PService: ", GetName(), " closing socket on accept because: ", ecode.message ());
		}
	}

}
}
