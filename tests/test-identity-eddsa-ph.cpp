#include <cassert>
#include <vector>

#include "Identity.h"

int main ()
{
#if (OPENSSL_VERSION_NUMBER >= 0x030000000) || defined(USE_LIBSODIUM_ED25519PH)
	auto keys = i2p::data::PrivateKeys::CreateRandomKeys (
		i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph,
		i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD,
		true);

	const uint8_t msg[] = "identity-level ed25519ph signing check";
	std::vector<uint8_t> sig (keys.GetSignatureLen ());
	keys.Sign (msg, sizeof(msg) - 1, sig.data ());

	assert (keys.GetPublic ()->Verify (msg, sizeof(msg) - 1, sig.data ()));
	sig[0] ^= 0x01;
	assert (!keys.GetPublic ()->Verify (msg, sizeof(msg) - 1, sig.data ()));
#endif
}
