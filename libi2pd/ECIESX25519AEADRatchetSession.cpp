#include <string.h>
#include <openssl/sha.h>
#include "Log.h"
#include "Crypto.h"
#include "Elligator.h"
#include "Tag.h"
#include "I2PEndian.h"
#include "Timestamp.h"
#include "ECIESX25519AEADRatchetSession.h"

namespace i2p
{
namespace garlic
{

    void RatchetTagSet::DHInitialize (const uint8_t * rootKey, const uint8_t * k)
    {
        // DH_INITIALIZE(rootKey, k)
        uint8_t keydata[64];
        i2p::crypto::HKDF (rootKey, k, 32, "KDFDHRatchetStep", keydata); // keydata = HKDF(rootKey, k, "KDFDHRatchetStep", 64)
        // nextRootKey = keydata[0:31]
        i2p::crypto::HKDF (keydata + 32, nullptr, 0, "TagAndKeyGenKeys", m_KeyData.buf); 
        // [sessTag_ck, symmKey_ck] = HKDF(keydata[32:63], ZEROLEN, "TagAndKeyGenKeys", 64) 
    }

    void RatchetTagSet::NextSessionTagRatchet ()
    {
        i2p::crypto::HKDF (m_KeyData.GetSessTagCK (), nullptr, 0, "STInitialization", m_KeyData.buf); // [sessTag_ck, sesstag_constant] = HKDF(sessTag_ck, ZEROLEN, "STInitialization", 64)
        memcpy (m_SessTagConstant, m_KeyData.GetSessTagConstant (), 32);
    }

    uint64_t RatchetTagSet::GetNextSessionTag ()
    {
         i2p::crypto::HKDF (m_KeyData.GetSessTagCK (), m_SessTagConstant, 32, "SessionTagKeyGen", m_KeyData.buf); // [sessTag_ck, tag] = HKDF(sessTag_chainkey, SESSTAG_CONSTANT, "SessionTagKeyGen", 64)
        return m_KeyData.GetTag ();
    }


    ECIESX25519AEADRatchetSession::ECIESX25519AEADRatchetSession (GarlicDestination * owner):
        GarlicRoutingSession (owner, true)
    {
    	ResetKeys ();
    }

    ECIESX25519AEADRatchetSession::~ECIESX25519AEADRatchetSession ()
    {
    }

	void ECIESX25519AEADRatchetSession::ResetKeys ()
	{
		// TODO : use precalculated hashes
		static const char protocolName[41] = "Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"; // 40 bytes
		SHA256 ((const uint8_t *)protocolName, 40, m_H);
		memcpy (m_CK, m_H, 32);
		SHA256 (m_H, 32, m_H);
	}	
		
    void ECIESX25519AEADRatchetSession::MixHash (const uint8_t * buf, size_t len)
    {
        SHA256_CTX ctx;
		SHA256_Init (&ctx);
		SHA256_Update (&ctx, m_H, 32);
		SHA256_Update (&ctx, buf, len);
		SHA256_Final (m_H, &ctx);
    }
	
    bool ECIESX25519AEADRatchetSession::GenerateEphemeralKeysAndEncode (uint8_t * buf)
    {
        for (int i = 0; i < 10; i++)
        {
            m_EphemeralKeys.GenerateKeys ();    
            if (i2p::crypto::GetElligator ()->Encode (m_EphemeralKeys.GetPublicKey (), buf))
		        return true; // success
        }         
        return false;
    }

    uint64_t ECIESX25519AEADRatchetSession::CreateNewSessionTag () const
    {
        uint8_t tagsetKey[32];    
        i2p::crypto::HKDF (m_CK, nullptr, 0, "SessionReplyTags", tagsetKey, 32); // tagsetKey = HKDF(chainKey, ZEROLEN, "SessionReplyTags", 32)
         // Session Tag Ratchet
        RatchetTagSet tagsetNsr;
        tagsetNsr.DHInitialize (m_CK, tagsetKey); // tagset_nsr = DH_INITIALIZE(chainKey, tagsetKey)
        tagsetNsr.NextSessionTagRatchet ();
        return tagsetNsr.GetNextSessionTag ();   
    }

    bool ECIESX25519AEADRatchetSession::HandleNewIncomingSession (const uint8_t * buf, size_t len,  CloveHandler handleClove)
    {
        if (!GetOwner ()) return false;
        // we are Bob
        // KDF1
        MixHash (GetOwner ()->GetEncryptionPublicKey (), 32); // h = SHA256(h || bpk)    
		
		if (!i2p::crypto::GetElligator ()->Decode (buf, m_Aepk))
		{ 
			LogPrint (eLogError, "Garlic: Can't decode elligator");
			return false;	
		}
        buf += 32; len -= 32;
        MixHash (m_Aepk, 32); // h = SHA256(h || aepk)  
    
        uint8_t sharedSecret[32];
		GetOwner ()->Decrypt (m_Aepk, sharedSecret, nullptr); // x25519(bsk, aepk)
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
		GetOwner ()->AddECIESx25519Session (m_RemoteStaticKey, shared_from_this ());

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
		ResetKeys ();
        // we are Alice, bpk is m_RemoteStaticKey
        size_t offset = 0;
        if (!GenerateEphemeralKeysAndEncode (out + offset))
		{ 
			LogPrint (eLogError, "Garlic: Can't encode elligator");
			return false;	
		} 
        offset += 32;   

        // KDF1
        MixHash (m_RemoteStaticKey, 32); // h = SHA256(h || bpk) 
        MixHash (m_EphemeralKeys.GetPublicKey (), 32); // h = SHA256(h || aepk)          
        uint8_t sharedSecret[32];
		m_EphemeralKeys.Agree (m_RemoteStaticKey, sharedSecret); // x25519(aesk, bpk)
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

		m_State = eSessionStateNewSessionSent;
        if (GetOwner ())
            GetOwner ()->AddECIESx25519SessionTag (CreateNewSessionTag (), shared_from_this ());   		

        return true;
    }

    bool ECIESX25519AEADRatchetSession::NewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen)
    {
        // we are Bob
        uint64_t tag = CreateNewSessionTag ();   
    
        size_t offset = 0;
        memcpy (out + offset, &tag, 8);
        offset += 8;
        if (!GenerateEphemeralKeysAndEncode (out + offset)) // bepk
		{ 
			LogPrint (eLogError, "Garlic: Can't encode elligator");
			return false;	
		}
        offset += 32;      
        // KDF for  Reply Key Section
        MixHash ((const uint8_t *)&tag, 8); // h = SHA256(h || tag)
        MixHash (m_EphemeralKeys.GetPublicKey (), 32); // h = SHA256(h || bepk)
        uint8_t sharedSecret[32];      
        m_EphemeralKeys.Agree (m_Aepk, sharedSecret); // sharedSecret = x25519(besk, aepk) 
        i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK, 32); // chainKey = HKDF(chainKey, sharedSecret, "", 32)       
		m_EphemeralKeys.Agree (m_RemoteStaticKey, sharedSecret); // sharedSecret = x25519(besk, apk) 
        i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)       
		uint8_t nonce[12];
		memset (nonce, 0, 12); // n = 0
        // calulate hash for zero length
		if (!i2p::crypto::AEADChaCha20Poly1305 (sharedSecret /* can be anything */, 0, m_H, 32, m_CK + 32, nonce, out + offset, 16, true)) // encrypt, ciphertext = ENCRYPT(k, n, ZEROLEN, ad)
		{
			LogPrint (eLogWarning, "Garlic: Reply key section AEAD encryption failed");
			return false;
		}
        MixHash (out + offset, 16); // h = SHA256(h || ciphertext)    
        out += 16;
        // KDF for payload
        uint8_t keydata[64];
        i2p::crypto::HKDF (m_CK, nullptr, 0, "", keydata); // keydata = HKDF(chainKey, ZEROLEN, "", 64)
        // k_ab = keydata[0:31], k_ba = keydata[32:63]
        m_TagsetAB.DHInitialize (m_CK, keydata); // tagset_ab = DH_INITIALIZE(chainKey, k_ab)
        m_TagsetBA.DHInitialize (m_CK, keydata + 32); // tagset_ba = DH_INITIALIZE(chainKey, k_ba)
        i2p::crypto::HKDF (keydata + 32, nullptr, 0, "AttachPayloadKDF", keydata, 32); // k = HKDF(k_ba, ZEROLEN, "AttachPayloadKDF", 32)
        // encrypt payload
        if (!i2p::crypto::AEADChaCha20Poly1305 (payload, len, m_H, 32, keydata, nonce, out + offset, len + 16, true)) // encrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD encryption failed");
			return false;
		}

        return true;
    }

    bool ECIESX25519AEADRatchetSession::HandleNewOutgoingSessionReply (const uint8_t * buf, size_t len, CloveHandler handleClove)
    {
		// we are Alice
		LogPrint (eLogDebug, "Garlic: reply received");
		const uint8_t * tag = buf;
		buf += 8; len -= 8; // tag
        uint8_t bepk[32]; // Bob's ephemeral key
		if (!i2p::crypto::GetElligator ()->Decode (buf, bepk))
		{ 
			LogPrint (eLogError, "Garlic: Can't decode elligator");
			return false;	
		} 
		buf += 32; len -= 32;
		// KDF for  Reply Key Section
        MixHash (tag, 8); // h = SHA256(h || tag)
        MixHash (bepk, 32); // h = SHA256(h || bepk)		
		uint8_t sharedSecret[32];      
        m_EphemeralKeys.Agree (bepk, sharedSecret); // sharedSecret = x25519(aesk, bepk)  
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK, 32); // chainKey = HKDF(chainKey, sharedSecret, "", 32) 
		GetOwner ()->Decrypt (bepk, sharedSecret, nullptr); // x25519 (ask, bepk)
		i2p::crypto::HKDF (m_CK, sharedSecret, 32, "", m_CK); // [chainKey, key] = HKDF(chainKey, sharedSecret, "", 64)
		uint8_t nonce[12];
		memset (nonce, 0, 12); // n = 0
        // calulate hash for zero length
		if (!i2p::crypto::AEADChaCha20Poly1305 (buf, 0, m_H, 32, m_CK + 32, nonce, sharedSecret/* can be anyting */, 0, false)) // decrypt, DECRYPT(k, n, ZEROLEN, ad) verification only
		{
			LogPrint (eLogWarning, "Garlic: Reply key section AEAD decryption failed");
			return false;
		}
		MixHash (buf, 16); // h = SHA256(h || ciphertext)  
		buf += 16; len -= 16;
		// KDF for payload
        uint8_t keydata[64];
        i2p::crypto::HKDF (m_CK, nullptr, 0, "", keydata); // keydata = HKDF(chainKey, ZEROLEN, "", 64)
        // k_ab = keydata[0:31], k_ba = keydata[32:63]
        m_TagsetAB.DHInitialize (m_CK, keydata); // tagset_ab = DH_INITIALIZE(chainKey, k_ab)
        m_TagsetBA.DHInitialize (m_CK, keydata + 32); // tagset_ba = DH_INITIALIZE(chainKey, k_ba)
        i2p::crypto::HKDF (keydata + 32, nullptr, 0, "AttachPayloadKDF", keydata, 32); // k = HKDF(k_ba, ZEROLEN, "AttachPayloadKDF", 32)		
		// decrypt payload
		std::vector<uint8_t> payload (len - 16);
        if (!i2p::crypto::AEADChaCha20Poly1305 (buf, len - 16, m_H, 32, keydata, nonce, payload.data (), len - 16, false)) // decrypt
		{
			LogPrint (eLogWarning, "Garlic: Payload section AEAD decryption failed");
			return false;
		}
	
		// TODO: change state
		GetOwner ()->AddECIESx25519Session (m_RemoteStaticKey, shared_from_this ());
		HandlePayload (payload.data (), len - 16, handleClove); 

        return true;
    }

	bool ECIESX25519AEADRatchetSession::HandleNextMessage (const uint8_t * buf, size_t len, CloveHandler handleClove)
	{
		switch (m_State)
		{
			case eSessionStateNew:
				return HandleNewIncomingSession (buf, len, handleClove);
			case eSessionStateNewSessionSent:
				return HandleNewOutgoingSessionReply (buf, len, handleClove);
			default:
				return false;
		}
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
            case eSessionStateNewSessionReceived:
                 if (!NewSessionReplyMessage (payload.data (), payload.size (), buf, m->maxLen))
                    return nullptr;
                 len += 72;   
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
        size_t payloadLen = 7; // datatime 
        if (msg && m_Destination) 
            payloadLen += msg->GetPayloadLength () + 13 + 32;
        auto leaseSet = CreateDatabaseStoreMsg (GetOwner ()->GetLeaseSet ());
        if (leaseSet)
            payloadLen += leaseSet->GetPayloadLength () + 13;   
        uint8_t paddingSize;
        RAND_bytes (&paddingSize, 1);
        paddingSize &= 0x0F; paddingSize++; // 1 - 16
        payloadLen += paddingSize + 3;                 
        std::vector<uint8_t> v(payloadLen);
        size_t offset = 0;
        // DateTime
        v[offset] = eECIESx25519BlkDateTime; offset++;
        htobe16buf (v.data () + offset, 4); offset += 2; 
        htobe32buf (v.data () + offset, i2p::util::GetSecondsSinceEpoch ()); offset += 4;
        // LeaseSet
        if (leaseSet)
            offset += CreateGarlicClove (leaseSet, v.data () + offset, payloadLen - offset);
        // msg    
        if (msg && m_Destination)    
            offset += CreateGarlicClove (msg, v.data () + offset, payloadLen - offset, true);
        // padding
        v[offset] = eECIESx25519BlkPadding; offset++; 
        htobe16buf (v.data () + offset, paddingSize); offset += 2;
        memset (v.data () + offset, 0, paddingSize); offset += paddingSize; 
        return v;
    }   

    size_t ECIESX25519AEADRatchetSession::CreateGarlicClove (std::shared_ptr<const I2NPMessage> msg, uint8_t * buf, size_t len, bool isDestination)
    {
        if (!msg) return 0;
        uint16_t cloveSize = msg->GetPayloadLength () + 9 + 1;
		if (isDestination) cloveSize += 32;
        if ((int)len < cloveSize + 3) return 0;
        buf[0] = eECIESx25519BlkGalicClove; // clove type
        htobe16buf (buf + 1, cloveSize); // size   
		buf += 3;
		if (isDestination)
		{
			*buf = (eGarlicDeliveryTypeDestination << 5);
			memcpy (buf + 1, *m_Destination, 32); buf += 32;
		}
		else
			*buf = 0; 
		buf++;	// flag and delivery instructions
        *buf = msg->GetTypeID (); // I2NP msg type
        htobe32buf (buf + 1, msg->GetMsgID ()); // msgID     
        htobe32buf (buf + 5, msg->GetExpiration ()/1000); // expiration in seconds     
        memcpy (buf + 9, msg->GetPayload (), msg->GetPayloadLength ());
        return cloveSize + 3;
    }
 
}
}


