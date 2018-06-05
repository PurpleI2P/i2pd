#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "Crypto.h"
#include "Ed25519.h"
#include "ChaCha20.h"
#include "Poly1305.h"
#include "NTCP2.h"

namespace i2p
{
namespace transport
{
	NTCP2Session::NTCP2Session (std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter):
		TransportSession (in_RemoteRouter, 30)
	{
	}

	NTCP2Session::~NTCP2Session ()
	{
	}

	bool NTCP2Session::KeyDerivationFunction (const uint8_t * rs, const uint8_t * pub, uint8_t * derived)
	{
		static const char protocolName[] = "Noise_XK_25519_ChaChaPoly_SHA256"; // 32 bytes
		uint8_t h[64], ck[33];
		memcpy (ck, protocolName, 32);
		SHA256 ((const uint8_t *)protocolName, 32, h);	
		// h = SHA256(h || rs)
		memcpy (h + 32, rs, 32); 
		SHA256 (h, 64, h); 
		// h = SHA256(h || pub)
		memcpy (h + 32, pub, 32); 
		SHA256 (h, 64, h); 
		// x25519 between rs and priv
		uint8_t inputKeyMaterial[32];
		BN_CTX * ctx = BN_CTX_new ();
		i2p::crypto::GetEd25519 ()->Mul (rs, m_ExpandedPrivateKey, inputKeyMaterial, ctx); // rs*priv
		BN_CTX_free (ctx);
		// temp_key = HMAC-SHA256(ck, input_key_material)
		uint8_t tempKey[32]; unsigned int len;
		HMAC(EVP_sha256(), ck, 32, inputKeyMaterial, 32, tempKey, &len); 	
		// ck = HMAC-SHA256(temp_key, byte(0x01))
		inputKeyMaterial[0] = 1;
		HMAC(EVP_sha256(), tempKey, 32, inputKeyMaterial, 1, ck, &len); 	
		// derived = HMAC-SHA256(temp_key, ck || byte(0x02))
		ck[32] = 2;
		HMAC(EVP_sha256(), tempKey, 32, ck, 33, derived, &len); 		
		return true;
	}

	void NTCP2Session::CreateEphemeralKey (uint8_t * pub)
	{
		uint8_t key[32];
		RAND_bytes (key, 32);
		i2p::crypto::Ed25519::ExpandPrivateKey (key, m_ExpandedPrivateKey);
		BN_CTX * ctx = BN_CTX_new ();
		auto publicKey = i2p::crypto::GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
		i2p::crypto::GetEd25519 ()->EncodePublicKey (publicKey, pub, ctx);
		BN_CTX_free (ctx);
	}

	void NTCP2Session::SendSessionRequest (const uint8_t * iv, const uint8_t * rs)
	{
		i2p::crypto::AESAlignedBuffer<32> x;
		CreateEphemeralKey (x);
		// encrypt X
		i2p::crypto::CBCEncryption encryption;
		encryption.SetKey (GetRemoteIdentity ()->GetIdentHash ());
		encryption.SetIV (iv);
		encryption.Encrypt (2, x.GetChipherBlock (), x.GetChipherBlock ());
		// encryption key for next block
		uint8_t key[32];
		KeyDerivationFunction (rs, x, key);
		// options
		uint8_t options[32];
		// TODO: fill 16 bytes options		
		i2p::crypto::Poly1305HMAC (((uint32_t *)options) + 4, (uint32_t *)key, options, 16); // calculate MAC first
		i2p::crypto::chacha20 (options, 16, 0, key); // then encrypt
	}	
}
}

