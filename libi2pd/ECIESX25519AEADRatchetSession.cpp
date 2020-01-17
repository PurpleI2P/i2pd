#include <string.h>
#include <openssl/sha.h>
#include "Log.h"
#include "Crypto.h"
#include "Elligator.h"
#include "Tag.h"
#include "I2PEndian.h"
#include "ECIESX25519AEADRatchetSession.h"

namespace i2p
{
namespace garlic
{

    ECIESX25519AEADRatchetSession::ECIESX25519AEADRatchetSession (GarlicDestination * owner):
        GarlicRoutingSession (owner, true)
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
		
    bool ECIESX25519AEADRatchetSession::NewIncomingSession (const uint8_t * buf, size_t len,  CloveHandler handleClove)
    {
        if (!GetOwner ()) return false;
        // we are Bob
        // KDF1
        MixHash (GetOwner ()->GetEncryptionPublicKey (), 32); // h = SHA256(h || bpk)    

        uint8_t aepk[32]; // Alice's ephemeral key
		if (!i2p::crypto::GetElligator ()->Decode (buf, aepk))
		{ 
			LogPrint (eLogError, "Garlic: Can't decode elligator");
			return false;	
		}
        buf += 32; len -= 32;
        MixHash (aepk, 32); // h = SHA256(h || aepk)  
    
        uint8_t sharedSecret[32];
		GetOwner ()->Decrypt (aepk, sharedSecret, nullptr); // x25519(bsk, aepk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		
        // decrypt flags/static    
		uint8_t nonce[12], fs[32];
		memset (nonce, 0, 12); // n = 0
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, 32, m_H, 32, m_CK + 32, nonce, fs, 32, false)) // decrypt
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
            memcpy (m_RemoteStaticKey, fs, 32);
			GetOwner ()->Decrypt (fs, sharedSecret, nullptr); // x25519(bsk, apk)
			i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		}
		else // all zeros flags
			htole64buf (nonce + 4, 1); // n = 1 
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, len - 16, m_H, 32, m_CK + 32, nonce, payload.data (), len - 16, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD verification failed");
			return false;
		}
		if (isStatic) MixHash (buf, len); // h = SHA256(h || ciphertext)
        m_State = eSessionStateNewSessionReceived;            

        HandlePayload (payload.data (), len - 16, handleClove);    

        return true;
    }

    void ECIESX25519AEADRatchetSession::HandlePayload (const uint8_t * buf, size_t len, CloveHandler& handleClove)
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
					handleClove (buf + offset, size);
				break;
				case eECIESx25519BlkDateTime:
					LogPrint (eLogDebug, "Garlic: datetime");
				break;	
				case eECIESx25519BlkOptions:
					LogPrint (eLogDebug, "Garlic: options");
				break;
				case eECIESx25519BlkPadding:
					LogPrint (eLogDebug, "Garlic: padding");
				break;
				default:
					LogPrint (eLogWarning, "Garlic: Unknown block type ", (int)blk);
			}
			offset += size;
		}
    }    

    bool ECIESX25519AEADRatchetSession::NewOutgoingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen)
    {
        m_EphemeralKeys.GenerateKeys ();    
        // we are Alice, bpk is m_RemoteStaticKey
        size_t offset = 0;
        if (!i2p::crypto::GetElligator ()->Encode (m_EphemeralKeys.GetPublicKey (), out + offset))
		{ 
			LogPrint (eLogError, "Garlic: Can't encode elligator");
			return false;	
		}         
        offset += 32;   

        // KDF1
        MixHash (m_RemoteStaticKey, 32); // h = SHA256(h || bpk) 
        MixHash (m_EphemeralKeys.GetPublicKey (), 32); // h = SHA256(h || aepk)          
        uint8_t sharedSecret[32];
		m_EphemeralKeys.Agree (m_RemoteStaticKey, nullptr); // x25519(aesk, bpk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)    
        // encrypt static key section
        uint8_t nonce[12];
		memset (nonce, 0, 12); // n = 0
		if (!i2p::crypto::AEADChaCha20Poly1305 (GetOwner ()->GetEncryptionPublicKey (), 32, m_H, 32, m_CK + 32, nonce, out + offset, 48, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Static section AEAD encryption failed ");
			return false;
		}
        MixHash (out + offset, 48); // h = SHA256(h || ciphertext)
        offset += 48;
        // KDF2 
        GetOwner ()->Decrypt (m_RemoteStaticKey, sharedSecret, nullptr); // x25519 (ask, bpk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		// encrypt payload
		if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len, m_H, 32, m_CK + 32, nonce, out + offset, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD encryption failed");
			return false;
		}
		MixHash (out + offset, len + 16); // h = SHA256(h || ciphertext)
		
        return true;
    }

    std::shared_ptr<I2NPMessage> ECIESX25519AEADRatchetSession::WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg)
    { 
        auto m = NewI2NPMessage ();
		m->Align (12); // in order to get buf aligned to 16 (12 + 4)
		uint8_t * buf = m->GetPayload () + 4; // 4 bytes for length
        auto payload = CreatePayload (msg);  
        size_t len = payload.size ();

        switch (m_State)
        {
            case eSessionStateNew:
                if (!NewOutgoingSessionMessage (payload.data (), payload.size (), buf, m->maxLen))
                    return nullptr;
                len += 96;
            break;
            default:
                return nullptr;
        }
       
        htobe32buf (m->GetPayload (), len);
		m->len += len + 4;
		m->FillI2NPMessageHeader (eI2NPGarlic);
		return m;
    }

    std::vector<uint8_t> ECIESX25519AEADRatchetSession::CreatePayload (std::shared_ptr<const I2NPMessage> msg)
    {
        uint16_t cloveSize = msg->GetPayloadLength () + 9 + 1;
        std::vector<uint8_t> v(cloveSize + 3);
        uint8_t * payload = v.data ();
        payload[0] = eECIESx25519BlkGalicClove; // clove type
        htobe16buf (payload + 1, cloveSize); // size        
        payload[3] = 0; // flag and delivery instructions
        payload[4] = msg->GetTypeID (); // I2NP msg type
        htobe32buf (payload + 5, msg->GetMsgID ()); // msgID     
        htobe32buf (payload + 9, msg->GetExpiration ()/1000); // expiration in seconds     
        memcpy (payload + 13, msg->GetPayload (), msg->GetPayloadLength ());
        return v;
    }    
}
}


