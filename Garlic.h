#ifndef GARLIC_H__
#define GARLIC_H__

#include <inttypes.h>
#include <map>
#include <list>
#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include <cryptopp/osrng.h>
#include "aes.h"
#include "I2NPProtocol.h"
#include "LeaseSet.h"
#include "Queue.h"
#include "Identity.h"

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

	const int TAGS_EXPIRATION_TIMEOUT = 900; // 15 minutes			

	typedef i2p::data::Tag<32> SessionTag;	
	class GarlicDestination;
	class GarlicRoutingSession
	{
		public:

			GarlicRoutingSession (GarlicDestination * owner, const i2p::data::RoutingDestination * destination, int numTags);
			GarlicRoutingSession (const uint8_t * sessionKey, const SessionTag& sessionTag); // one time encryption
			~GarlicRoutingSession ();
			I2NPMessage * WrapSingleMessage (I2NPMessage * msg);
			int GetNextTag () const { return m_NextTag; };
			
			bool IsAcknowledged () const { return m_IsAcknowledged; };
			void SetAcknowledged (bool acknowledged) { m_IsAcknowledged = acknowledged; };

			void SetLeaseSetUpdated () { m_LeaseSetUpdated = true; };
			
		private:

			size_t CreateAESBlock (uint8_t * buf, const I2NPMessage * msg);
			size_t CreateGarlicPayload (uint8_t * payload, const I2NPMessage * msg);
			size_t CreateGarlicClove (uint8_t * buf, const I2NPMessage * msg, bool isDestination);
			size_t CreateDeliveryStatusClove (uint8_t * buf, uint32_t msgID);
			
			void GenerateSessionTags ();

		private:

			GarlicDestination * m_Owner;
			const i2p::data::RoutingDestination * m_Destination;
			uint8_t m_SessionKey[32];
			bool m_IsAcknowledged;
			int m_NumTags, m_NextTag;
			SessionTag * m_SessionTags; // m_NumTags*32 bytes
			uint32_t m_TagsCreationTime; // seconds since epoch		
			bool m_LeaseSetUpdated;

			i2p::crypto::CBCEncryption m_Encryption;
			CryptoPP::AutoSeededRandomPool m_Rnd;
	};	

	class GarlicDestination: public i2p::data::LocalDestination
	{
		public:

			GarlicDestination () {};
			~GarlicDestination ();

			GarlicRoutingSession * GetRoutingSession (const i2p::data::RoutingDestination& destination, int numTags);	
			I2NPMessage * WrapMessage (const i2p::data::RoutingDestination& destination, 
			    I2NPMessage * msg, bool attachLeaseSet = false);

			void AddSessionKey (const uint8_t * key, const uint8_t * tag); // one tag
			void DeliveryStatusSent (GarlicRoutingSession * session, uint32_t msgID);
			
			virtual void ProcessGarlicMessage (I2NPMessage * msg);
			virtual void ProcessDeliveryStatusMessage (I2NPMessage * msg);			
			virtual void SetLeaseSetUpdated ();

			virtual const i2p::data::LeaseSet * GetLeaseSet () = 0; // TODO

		protected:

			void HandleGarlicMessage (I2NPMessage * msg);
			void HandleDeliveryStatusMessage (I2NPMessage * msg);			
	
		private:

			void HandleAESBlock (uint8_t * buf, size_t len, std::shared_ptr<i2p::crypto::CBCDecryption> decryption, 
				i2p::tunnel::InboundTunnel * from);
			void HandleGarlicPayload (uint8_t * buf, size_t len, i2p::tunnel::InboundTunnel * from);

		private:
			
			// outgoing sessions
			std::mutex m_SessionsMutex;
			std::map<i2p::data::IdentHash, GarlicRoutingSession *> m_Sessions;
			// incoming
			std::map<SessionTag, std::shared_ptr<i2p::crypto::CBCDecryption>> m_Tags;	
			// DeliveryStatus
			std::map<uint32_t, GarlicRoutingSession *> m_CreatedSessions; // msgID -> session
	};	
}	
}

#endif
