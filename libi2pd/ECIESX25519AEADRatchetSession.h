#ifndef ECIES_X25519_AEAD_RATCHET_SESSION_H__
#define ECIES_X25519_AEAD_RATCHET_SESSION_H__

#include <inttypes.h>
#include <functional>
#include "Identity.h"

namespace i2p
{
namespace garlic
{
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

    class ECIESX25519AEADRatchetSession
    {
        public:

            typedef std::function<void (uint8_t typeID, const uint8_t * payload, size_t len)> CloveI2NPMsgHandler;

            ECIESX25519AEADRatchetSession ();
            ~ECIESX25519AEADRatchetSession ();

            bool NewIncomingSession (const i2p::data::LocalDestination& dest, const uint8_t * buf, size_t len, 
                CloveI2NPMsgHandler handleCloveI2NPMsg);

        private:

            void MixHash (const uint8_t * buf, size_t len);

            void HandlePayload (const uint8_t * buf, size_t len,  CloveI2NPMsgHandler& handleCloveI2NPMsg);
            void HandleClove (const uint8_t * buf, size_t len,  CloveI2NPMsgHandler& handleCloveI2NPMsg);

        private:

            uint8_t m_H[32], m_CK[32];
    };
}
}

#endif
