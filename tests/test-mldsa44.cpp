#include <cassert>
#include <cstring>

#include "Signature.h"

int main ()
{
#if OPENSSL_MLDSA
	uint8_t priv[i2p::crypto::MLDSA44_PRIVATE_KEY_LENGTH];
	uint8_t pub[i2p::crypto::MLDSA44_PUBLIC_KEY_LENGTH];
	uint8_t sig[i2p::crypto::MLDSA44_SIGNATURE_LENGTH];
	const uint8_t msg[] = "i2pd libressl mldsa44 compatibility test";

	i2p::crypto::CreateMLDSA44RandomKeys (priv, pub);

	i2p::crypto::MLDSA44Signer signer (priv);
	signer.Sign (msg, sizeof(msg) - 1, sig);

	i2p::crypto::MLDSA44Verifier verifier;
	verifier.SetPublicKey (pub);
	assert (verifier.Verify (msg, sizeof(msg) - 1, sig));

	uint8_t tampered[i2p::crypto::MLDSA44_SIGNATURE_LENGTH];
	memcpy (tampered, sig, sizeof(tampered));
	tampered[0] ^= 0x01;
	assert (!verifier.Verify (msg, sizeof(msg) - 1, tampered));
#endif
}
