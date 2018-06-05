#include <memory>
#include "Log.h"
#include "Signature.h"

namespace i2p
{
namespace crypto
{
	EDDSA25519Verifier::EDDSA25519Verifier (const uint8_t * signingKey)
	{
		memcpy (m_PublicKeyEncoded, signingKey, EDDSA25519_PUBLIC_KEY_LENGTH);
		BN_CTX * ctx = BN_CTX_new ();
		m_PublicKey = GetEd25519 ()->DecodePublicKey (m_PublicKeyEncoded, ctx);
		BN_CTX_free (ctx);
	}

	bool EDDSA25519Verifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		uint8_t digest[64];
		SHA512_CTX ctx;
		SHA512_Init (&ctx);
		SHA512_Update (&ctx, signature, EDDSA25519_SIGNATURE_LENGTH/2); // R
		SHA512_Update (&ctx, m_PublicKeyEncoded, EDDSA25519_PUBLIC_KEY_LENGTH); // public key
		SHA512_Update (&ctx, buf, len); // data
		SHA512_Final (digest, &ctx);

		return GetEd25519 ()->Verify (m_PublicKey, digest, signature);
	}

	EDDSA25519Signer::EDDSA25519Signer (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
	{
		// expand key
		Ed25519::ExpandPrivateKey (signingPrivateKey, m_ExpandedPrivateKey);
		// generate and encode public key
		BN_CTX * ctx = BN_CTX_new ();
		auto publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
		GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);

		if (signingPublicKey && memcmp (m_PublicKeyEncoded, signingPublicKey, EDDSA25519_PUBLIC_KEY_LENGTH))
		{
			// keys don't match, it means older key with 0x1F
			LogPrint (eLogWarning, "Older EdDSA key detected");
			m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] &= 0xDF; // drop third bit
			publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
			GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);
		}
		BN_CTX_free (ctx);
	}

	void EDDSA25519Signer::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		GetEd25519 ()->Sign (m_ExpandedPrivateKey, m_PublicKeyEncoded, buf, len, signature);
	}
}
}


