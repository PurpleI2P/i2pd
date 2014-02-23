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

			GarlicRoutingSession (const i2p::data::RoutingDestination& destination, int numTags);
			~GarlicRoutingSession ();
			I2NPMessage * WrapSingleMessage (I2NPMessage * msg, I2NPMessage * leaseSet);
			int GetNextTag () const { return m_NextTag; };
			uint32_t GetFirstMsgID () const { return m_FirstMsgID; };

			bool IsAcknowledged () const { return m_IsAcknowledged; };
			void SetAcknowledged (bool acknowledged) { m_IsAcknowledged = acknowledged; };
			
		private:

			size_t CreateAESBlock (uint8_t * buf, I2NPMessage * msg, I2NPMessage * leaseSet);
			size_t CreateGarlicPayload (uint8_t * payload, I2NPMessage * msg, I2NPMessage * leaseSet);
			size_t CreateGarlicClove (uint8_t * buf, I2NPMessage * msg, bool isDestination);
			size_t CreateDeliveryStatusClove (uint8_t * buf, uint32_t msgID);
			
			void GenerateSessionTags ();

		private:

			const i2p::data::RoutingDestination& m_Destination;
			uint8_t m_SessionKey[32];
			uint32_t m_FirstMsgID; // first message ID
			bool m_IsAcknowledged;
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

			void HandleGarlicMessage (uint8_t * buf, size_t len, bool isFromTunnel);
			void HandleDeliveryStatusMessage (uint8_t * buf, size_t len);
			
			I2NPMessage * WrapSingleMessage (const i2p::data::RoutingDestination& destination, I2NPMessage * msg);
			I2NPMessage * WrapMessage (const i2p::data::RoutingDestination& destination, 
			    I2NPMessage * msg, I2NPMessage * leaseSet = nullptr);

		private:

			void HandleAESBlock (uint8_t * buf, size_t len, uint8_t * sessionKey);
			void HandleGarlicPayload (uint8_t * buf, size_t len);
			
		private:

			// outgoing sessions
			std::map<i2p::data::IdentHash, GarlicRoutingSession *> m_Sessions;
			std::map<uint32_t, GarlicRoutingSession *> m_CreatedSessions; // msgID -> session
			// incoming session
			std::map<std::string, std::string> m_SessionTags; // tag -> key
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_Decryption;
	};	

	extern GarlicRouting routing;
}	
}

#endif
