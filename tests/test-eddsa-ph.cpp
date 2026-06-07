#include <cassert>
#include <cstring>

#include "Signature.h"

int main ()
{
#if (OPENSSL_VERSION_NUMBER >= 0x030000000) || defined(USE_LIBSODIUM_ED25519PH)
	uint8_t priv[i2p::crypto::EDDSA25519_PRIVATE_KEY_LENGTH];
	uint8_t pub[i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH];
	uint8_t sig[i2p::crypto::EDDSA25519_SIGNATURE_LENGTH];
	const uint8_t msg[] = "i2pd libressl ed25519ph compatibility test";

	i2p::crypto::CreateEDDSA25519phRandomKeys (priv, pub);

	i2p::crypto::EDDSA25519phSigner signer (priv);
	signer.Sign (msg, sizeof(msg) - 1, sig);

	i2p::crypto::EDDSA25519phVerifier verifier;
	verifier.SetPublicKey (pub);
	assert (verifier.Verify (msg, sizeof(msg) - 1, sig));

	uint8_t tampered[i2p::crypto::EDDSA25519_SIGNATURE_LENGTH];
	memcpy (tampered, sig, sizeof(tampered));
	tampered[0] ^= 0x01;
	assert (!verifier.Verify (msg, sizeof(msg) - 1, tampered));
#endif
}
