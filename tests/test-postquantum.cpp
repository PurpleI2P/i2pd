#include <array>
#include <cassert>
#include <cstring>

#include "PostQuantum.h"

namespace
{
#if OPENSSL_MLKEM
	void CheckRoundTrip (i2p::data::CryptoKeyType type)
	{
		auto alice = i2p::crypto::CreateMLKEMKeys (type);
		auto bob = i2p::crypto::CreateMLKEMKeys (type);
		assert (alice && bob);
		alice->GenerateKeys ();
		std::array<uint8_t, i2p::crypto::MLKEM1024_KEY_LENGTH> pub{};
		alice->GetPublicKey (pub.data ());
		bob->SetPublicKey (pub.data ());
		std::array<uint8_t, i2p::crypto::MLKEM1024_CIPHER_TEXT_LENGTH> ciphertext{};
		std::array<uint8_t, i2p::crypto::MLKEM_SHARED_SECRET_LENGTH> sharedBob{};
		std::array<uint8_t, i2p::crypto::MLKEM_SHARED_SECRET_LENGTH> sharedAlice{};
		bob->Encaps (ciphertext.data (), sharedBob.data ());
		alice->Decaps (ciphertext.data (), sharedAlice.data ());
		assert (memcmp (sharedAlice.data (), sharedBob.data (), sharedAlice.size ()) == 0);
	}
#endif
}

int main ()
{
#if OPENSSL_MLKEM
#if defined(LIBRESSL_VERSION_NUMBER)
	CheckRoundTrip (i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD);
#else
	CheckRoundTrip (i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM512_X25519_AEAD);
	CheckRoundTrip (i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD);
#endif
#endif
	return 0;
}

