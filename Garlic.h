#ifndef GARLIC_H__
#define GARLIC_H__

#include <inttypes.h>
#include <map>
#include <set>
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
			I2NPMessage * WrapSingleMessage (I2NPMessage * msg, I2NPMessage * leaseSet);
			int GetNumRemainingSessionTags () const { return m_NumTags - m_NextTag; };

		private:

			size_t CreateAESBlock (uint8_t * buf, I2NPMessage * msg, I2NPMessage * leaseSet);
			size_t CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg, I2NPMessage * leaseSet);
			size_t CreateGarlicClove (uint8_t * buf, I2NPMessage * msg, bool isDestination);
			
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

			void HandleGarlicMessage (uint8_t * buf, size_t len);
			
			I2NPMessage * WrapSingleMessage (const i2p::data::RoutingDestination * destination, 
				I2NPMessage * msg, I2NPMessage * leaseSet = nullptr);

		private:

			void HandleAESBlock (uint8_t * buf, size_t len);
			void HandleGarlicPayload (uint8_t * buf, size_t len);
			
		private:

			// outgoing sessions
			std::map<i2p::data::IdentHash, GarlicRoutingSession *> m_Sessions;
			// incoming session
			uint8_t m_SessionKey[32];
			std::set<std::string> m_SessionTags;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_Decryption;
	};	

	extern GarlicRouting routing;
}	
}

#endif
