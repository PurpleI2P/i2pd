#include <string.h>
#include <openssl/sha.h>
#include "Log.h"
#include "Crypto.h"
#include "Elligator.h"
#include "Tag.h"
#include "I2PEndian.h"
#include "Garlic.h"
#include "ECIESX25519AEADRatchetSession.h"

namespace i2p
{
namespace garlic
{

    ECIESX25519AEADRatchetSession::ECIESX25519AEADRatchetSession ()
    {
        // TODO : use precalculated hashes
		static const char protocolName[41] = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"; // 40 bytes
		SHA256 ((const uint8_t *)protocolName, 40, m_H);
		memcpy (m_CK, m_H, 32);
		SHA256 (m_H, 32, m_H);
    }

    ECIESX25519AEADRatchetSession::~ECIESX25519AEADRatchetSession ()
    {
    }

    void ECIESX25519AEADRatchetSession::MixHash (const uint8_t * buf, size_t len)
    {
        SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, m_H, 32);
		SHA256_Update (&ctx, buf, len);
		SHA256_Final (m_H, &ctx);
    }

    bool ECIESX25519AEADRatchetSession::NewIncomingSession (const i2p::data::LocalDestination& dest, 
        const uint8_t * buf, size_t len,  CloveI2NPMsgHandler handleCloveI2NPMsg)
    {
        // we are Bob
        // KDF1
        MixHash (dest.GetEncryptionPublicKey (), 32); // h = SHA256(h || bpk)    

        uint8_t aepk[32]; // Alice's ephemeral key
		if (!i2p::crypto::GetElligator ()->Decode (buf, aepk))
		{ 
			LogPrint (eLogError, "Garlic: Can't decode elligator");
			return false;	
		}
        buf += 32; len -= 32;
        MixHash (aepk, 32); // h = SHA256(h || aepk)  
    
        uint8_t sharedSecret[32], keyData[64];
		dest.Decrypt (aepk, sharedSecret, nullptr); // x25519(bsk, aepk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", keyData); // keydata = HKDF(chainKey, sharedSecret, "", 64)
		memcpy (m_CK, keyData, 32); // chainKey = keydata[0:31] 

        // decrypt flags/static    
		uint8_t nonce[12], fs[32];
		memset (nonce, 0, 12); // n = 0
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, 32, m_H, 32, keyData + 32, nonce, fs, 32, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Flags/static section AEAD verification failed ");
			return false;
		}
		MixHash (buf, 48); // h = SHA256(h || ciphertext)
		buf += 48; len -= 48; // 32 data + 16 poly

        // decrypt payload
		std::vector<uint8_t> payload (len - 16);
		// KDF2 for payload
		bool isStatic = !i2p::data::Tag<32> (fs).IsZero (); 
		if (isStatic)
		{
			// static key, fs is apk
			dest.Decrypt (fs, sharedSecret, nullptr); // x25519(bsk, apk)
			i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", keyData); // keydata = HKDF(chainKey, sharedSecret, "", 64)
			memcpy (m_CK, keyData, 32); // chainKey = keydata[0:31] 
		}
		else // all zeros flags
			htole64buf (nonce + 4, 1); // n = 1 
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, len - 16, m_H, 32, keyData + 32, nonce, payload.data (), len - 16, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD verification failed");
			return false;
		}
		if (isStatic) MixHash (buf, len); // h = SHA256(h || ciphertext)
            
        HandlePayload (payload.data (), len - 16, handleCloveI2NPMsg);    

        return true;
    }

    void ECIESX25519AEADRatchetSession::HandlePayload (const uint8_t * buf, size_t len, CloveI2NPMsgHandler& handleCloveI2NPMsg)
    {
        size_t offset = 0;
		while (offset < len)
		{
			uint8_t blk = buf[offset];
			offset++;
			auto size = bufbe16toh (buf + offset);
			offset += 2;
			LogPrint (eLogDebug, "Garlic: Block type ", (int)blk, " of size ", size);
			if (size > len)
			{
				LogPrint (eLogError, "Garlic: Unexpected block length ", size);
				break;
			}
			switch (blk)
			{
				case eECIESx25519BlkGalicClove:
					HandleClove (buf + offset, size, handleCloveI2NPMsg);
				break;
				case eECIESx25519BlkDateTime:
					LogPrint (eLogDebug, "Garlic: datetime");
				break;	
				case eECIESx25519BlkOptions:
					LogPrint (eLogDebug, "Garlic: options");
				break;
				case eECIESx25519BlkPadding:
					LogPrint (eLogDebug, "NTCP2: padding");
				break;
				default:
					LogPrint (eLogWarning, "Garlic: Unknown block type ", (int)blk);
			}
			offset += size;
		}
    }    

    void ECIESX25519AEADRatchetSession::HandleClove (const uint8_t * buf, size_t len,  CloveI2NPMsgHandler& handleCloveI2NPMsg)
    {   
        const uint8_t * buf1 = buf;	
		uint8_t flag = buf[0]; buf++; // flag
		GarlicDeliveryType deliveryType = (GarlicDeliveryType)((flag >> 5) & 0x03);
		switch (deliveryType)
		{
			case eGarlicDeliveryTypeDestination:
				buf += 32; // TODO: check destination
			// no break here
			case eGarlicDeliveryTypeLocal:
			{
				uint8_t typeID = buf[0]; buf++; // typeid
				buf += (4 + 4); // msgID + expiration
				ptrdiff_t offset = buf - buf1;
				if (offset <= (int)len)
					handleCloveI2NPMsg (typeID, buf, len - offset);
				else
					LogPrint (eLogError, "Garlic: clove is too long");
				break;
			}
			//  TODO: tunnel
			default:
				LogPrint (eLogWarning, "Garlic: unexpected delivery type ", (int)deliveryType);
		} 
    }
}
}


