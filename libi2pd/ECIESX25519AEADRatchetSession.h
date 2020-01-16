#ifndef ECIES_X25519_AEAD_RATCHET_SESSION_H__
#define ECIES_X25519_AEAD_RATCHET_SESSION_H__

#include <inttypes.h>
#include <functional>
#include "Identity.h"
#include "Garlic.h"

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

    class ECIESX25519AEADRatchetSession: public GarlicRoutingSession
    {
        public:

            typedef std::function<void (const uint8_t * buf, size_t len)> CloveHandler;

            ECIESX25519AEADRatchetSession (GarlicDestination * owner);
            ~ECIESX25519AEADRatchetSession ();

            std::shared_ptr<I2NPMessage> WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg);

            bool NewIncomingSession (const uint8_t * buf, size_t len, CloveHandler handleClove);
            const uint8_t * GetStaticKey () const { return m_StaticKey; };

        private:

            void MixHash (const uint8_t * buf, size_t len);

            void HandlePayload (const uint8_t * buf, size_t len,  CloveHandler& handleClove);

        private:

            uint8_t m_H[32], m_CK[32], m_StaticKey[32];
    };
}
}

#endif
