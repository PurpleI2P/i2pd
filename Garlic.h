#ifndef GARLIC_H__
#define GARLIC_H__

#include <inttypes.h>
#include <map>
#include <string>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include "I2NPProtocol.h"
#include "LeaseSet.h"

namespace i2p
{	
namespace garlic
{
	
	enum GarlicDeliveryType 
	{ 
		eGarlicDeliveryTypeLocal = 0, 
		eGarlicDeliveryTypeDestination = 1,
		eGarlicDeliveryTypeRouter = 2,	
		eGarlicDeliveryTypeTunnel = 3
	};	

#pragma pack(1)
	struct ElGamalBlock
	{
		uint8_t sessionKey[32];
		uint8_t preIV[32];
		uint8_t padding[158];
	};		
#pragma pack()	

	
	class GarlicRoutingSession
	{
		public:

			GarlicRoutingSession (const i2p::data::RoutingDestination * destination, int numTags);
			~GarlicRoutingSession ();
			I2NPMessage * WrapSingleMessage (I2NPMessage * msg);
			int GetNumRemainingSessionTags () const { return m_NumTags - m_NextTag; };

		private:

			size_t CreateAESBlock (uint8_t * buf, I2NPMessage * msg);
			size_t CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg);
			
		private:

			const i2p::data::RoutingDestination * m_Destination;
			uint8_t m_SessionKey[32];
			int m_NumTags, m_NextTag;
			uint8_t * m_SessionTags; // m_NumTags*32 bytes
			
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_Encryption;
			CryptoPP::AutoSeededRandomPool m_Rnd;
	};	

	class GarlicRouting
	{
		public:

			GarlicRouting ();
			~GarlicRouting ();

			I2NPMessage * WrapSingleMessage (const i2p::data::RoutingDestination * destination, I2NPMessage * msg);
			
		private:

			std::map<i2p::data::IdentHash, GarlicRoutingSession *> m_Sessions;
	};	

	extern GarlicRouting routing;
}	
}

#endif
