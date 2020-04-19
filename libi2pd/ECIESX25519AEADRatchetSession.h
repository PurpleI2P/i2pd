#ifndef ECIES_X25519_AEAD_RATCHET_SESSION_H__
#define ECIES_X25519_AEAD_RATCHET_SESSION_H__

#include <string.h>
#include <inttypes.h>
#include <functional>
#include <memory>
#include <vector>
#include <list>
#include <unordered_map>
#include "Identity.h"
#include "Crypto.h"
#include "Garlic.h"
#include "Tag.h"

namespace i2p
{
namespace garlic
{
    class RatchetTagSet
    {
        public:
            
            void DHInitialize (const uint8_t * rootKey, const uint8_t * k);
            void NextSessionTagRatchet ();
            uint64_t GetNextSessionTag ();
			int GetNextIndex () const { return m_NextIndex; }; 
			void GetSymmKey (int index, uint8_t * key);
				
		private:
			
           union
           {
               uint64_t ll[8]; 
               uint8_t buf[64];

               const uint8_t * GetSessTagCK () const { return buf; }; // sessTag_chainKey = keydata[0:31]
               const uint8_t * GetSessTagConstant () const { return buf + 32; }; // SESSTAG_CONSTANT = keydata[32:63] 
               uint64_t GetTag () const { return ll[4]; }; // tag = keydata[32:39]            
             
           } m_KeyData;  
           uint8_t m_SessTagConstant[32], m_SymmKeyCK[32], m_CurrentSymmKeyCK[64];   
		   int m_NextIndex, m_NextSymmKeyIndex;
		   std::unordered_map<int, i2p::data::Tag<32> > m_ItermediateSymmKeys;
    };       

    enum ECIESx25519BlockType
	{
		eECIESx25519BlkDateTime = 0,
		eECIESx25519BlkSessionID = 1, 
		eECIESx25519BlkTermination = 4,
		eECIESx25519BlkOptions = 5,
		eECIESx25519BlkNextSessionKey = 7,
		eECIESx25519BlkAck = 8,
		eECIESx25519BlkAckRequest = 9,
		eECIESx25519BlkGalicClove = 11,
		eECIESx25519BlkPadding = 254	
	};	


	const int ECIESX25519_RESTART_TIMEOUT = 120; // number of second of inactivity we should restart after
	const int ECIESX25519_EXPIRATION_TIMEOUT = 600; // in seconds

    class ECIESX25519AEADRatchetSession: public GarlicRoutingSession, public std::enable_shared_from_this<ECIESX25519AEADRatchetSession>
    {
        enum SessionState
        {
            eSessionStateNew =0,
            eSessionStateNewSessionReceived,
			eSessionStateNewSessionSent,
			eSessionStateNewSessionReplySent,
			eSessionStateEstablished		
        };

        public:

            ECIESX25519AEADRatchetSession (GarlicDestination * owner, bool attachLeaseSet);
            ~ECIESX25519AEADRatchetSession ();

			bool HandleNextMessage (const uint8_t * buf, size_t len, int index = 0);
            std::shared_ptr<I2NPMessage> WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg);

            const uint8_t * GetRemoteStaticKey () const { return m_RemoteStaticKey; }
			void SetRemoteStaticKey (const uint8_t * key) { memcpy (m_RemoteStaticKey, key, 32); }

			void SetDestination (const i2p::data::IdentHash& dest) // TODO:
			{
				if (!m_Destination) m_Destination.reset (new i2p::data::IdentHash (dest));
			}
			
			bool CheckExpired (uint64_t ts); // true is expired
			bool CanBeRestarted (uint64_t ts) const { return ts > m_LastActivityTimestamp + ECIESX25519_RESTART_TIMEOUT; }

        private:

			void ResetKeys ();
            void MixHash (const uint8_t * buf, size_t len);
			void CreateNonce (uint64_t seqn, uint8_t * nonce);
            bool GenerateEphemeralKeysAndEncode (uint8_t * buf); // buf is 32 bytes
            uint64_t CreateNewSessionTag () const;

			bool HandleNewIncomingSession (const uint8_t * buf, size_t len);
            bool HandleNewOutgoingSessionReply (const uint8_t * buf, size_t len);
			bool HandleExistingSessionMessage (const uint8_t * buf, size_t len, int index);
            void HandlePayload (const uint8_t * buf, size_t len, int index = 0);

            bool NewOutgoingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
            bool NewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
			bool NextNewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
			bool NewExistingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
	
            std::vector<uint8_t> CreatePayload (std::shared_ptr<const I2NPMessage> msg, bool first);
            size_t CreateGarlicClove (std::shared_ptr<const I2NPMessage> msg, uint8_t * buf, size_t len, bool isDestination = false);
			size_t CreateDeliveryStatusClove (std::shared_ptr<const I2NPMessage> msg, uint8_t * buf, size_t len);

			void GenerateMoreReceiveTags (int numTags);
			
        private:

            uint8_t m_H[32], m_CK[64] /* [chainkey, key] */, m_RemoteStaticKey[32];
			uint8_t m_Aepk[32]; // Alice's ephemeral keys, for incoming only
			uint8_t m_NSRHeader[56], m_NSRKey[32]; // new session reply, for incoming only
            i2p::crypto::X25519Keys m_EphemeralKeys;
            SessionState m_State = eSessionStateNew;
			uint64_t m_LastActivityTimestamp = 0; // incoming
            RatchetTagSet m_SendTagset, m_ReceiveTagset;
			std::unique_ptr<i2p::data::IdentHash> m_Destination;// TODO: might not need it 
			std::list<std::pair<uint16_t, int> > m_AckRequests; // (tagsetid, index)
    };

	std::shared_ptr<I2NPMessage> WrapECIESX25519AEADRatchetMessage (std::shared_ptr<const I2NPMessage> msg, const uint8_t * key, uint64_t tag);
}
}

#endif
