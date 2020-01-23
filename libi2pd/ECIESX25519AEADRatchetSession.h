#ifndef ECIES_X25519_AEAD_RATCHET_SESSION_H__
#define ECIES_X25519_AEAD_RATCHET_SESSION_H__

#include <string.h>
#include <inttypes.h>
#include <functional>
#include <memory>
#include <vector>
#include "Identity.h"
#include "Crypto.h"
#include "Garlic.h"

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

        private:
        
           union
           {
               uint64_t ll[8]; 
               uint8_t buf[64];

               const uint8_t * GetSessTagCK () const { return buf; }; // sessTag_chainKey = keydata[0:31]
               const uint8_t * GetSessTagConstant () const { return buf + 32; }; // SESSTAG_CONSTANT = keydata[32:63] 
               uint64_t GetTag () const { return ll[4]; }; // tag = keydata[32:39]            
             
           } m_KeyData;  
           uint8_t m_SessTagConstant[32];   
    };       

    enum ECIESx25519BlockType
	{
		eECIESx25519BlkDateTime = 0,
		eECIESx25519BlkSessionID = 1, 
		eECIESx25519BlkTermination = 4,
		eECIESx25519BlkOptions = 5,
		eECIESx25519BlkNextSessionKey = 7,
		eECIESx25519BlkGalicClove = 11,
		eECIESx25519BlkPadding = 254	
	};	

    class ECIESX25519AEADRatchetSession: public GarlicRoutingSession, public std::enable_shared_from_this<ECIESX25519AEADRatchetSession>
    {
        enum SessionState
        {
            eSessionStateNew =0,
            eSessionStateNewSessionReceived
        };

        public:

            typedef std::function<void (const uint8_t * buf, size_t len)> CloveHandler;

            ECIESX25519AEADRatchetSession (GarlicDestination * owner);
            ~ECIESX25519AEADRatchetSession ();

            std::shared_ptr<I2NPMessage> WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg);

            bool NewIncomingSession (const uint8_t * buf, size_t len, CloveHandler handleClove);
            bool NewOutgoingSessionReply (const uint8_t * buf, size_t len, CloveHandler handleClove);
            const uint8_t * GetRemoteStaticKey () const { return m_RemoteStaticKey; }
			void SetRemoteStaticKey (const uint8_t * key) { memcpy (m_RemoteStaticKey, key, 32); }

        private:

			void ResetKeys ();
            void MixHash (const uint8_t * buf, size_t len);
            bool GenerateEphemeralKeysAndEncode (uint8_t * buf); // buf is 32 bytes
            uint64_t CreateNewSessionTag () const;

            void HandlePayload (const uint8_t * buf, size_t len,  CloveHandler& handleClove);

            bool NewOutgoingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
            bool NewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
            std::vector<uint8_t> CreatePayload (std::shared_ptr<const I2NPMessage> msg);
            size_t CreateGarlicClove (std::shared_ptr<const I2NPMessage> msg, uint8_t * buf, size_t len);

        private:

            uint8_t m_H[32], m_CK[64] /* [chainkey, key] */, m_RemoteStaticKey[32];
            i2p::crypto::X25519Keys m_EphemeralKeys;
            SessionState m_State = eSessionStateNew;
            RatchetTagSet m_TagsetAB, m_TagsetBA;
    };
}
}

#endif
