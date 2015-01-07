#include "Destination.h"
#include "Identity.h"
#include "ClientContext.h"
#include "I2PService.h"


namespace i2p
{
namespace client
{
	static const i2p::data::SigningKeyType I2P_SERVICE_DEFAULT_KEY_TYPE = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256;

	I2PService::I2PService (ClientDestination * localDestination):
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
			LogPrint (eLogWarning, "Remote destination ", dest, " not found");
			streamRequestComplete (nullptr);
		}
	}
}
}
