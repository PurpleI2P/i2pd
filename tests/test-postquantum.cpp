#include <cassert>
#include <cstring>
#include <vector>

#include "PostQuantum.h"

int main ()
{
#if OPENSSL_MLKEM
	std::vector<i2p::data::CryptoKeyType> keyTypes
	{
#if !defined(LIBRESSL_VERSION_NUMBER)
		i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM512_X25519_AEAD,
#endif
		i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD,
		i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM1024_X25519_AEAD
	};

	for (auto type : keyTypes)
	{
		auto decapsKey = i2p::crypto::CreateMLKEMKeys (type);
		auto encapsKey = i2p::crypto::CreateMLKEMKeys (type);
		assert (decapsKey && encapsKey);

		decapsKey->GenerateKeys ();
		std::vector<uint8_t> pub (decapsKey->GetKeyLen ());
		decapsKey->GetPublicKey (pub.data ());
		encapsKey->SetPublicKey (pub.data ());

		std::vector<uint8_t> ciphertext (decapsKey->GetCTLen ());
		uint8_t sharedEncaps[i2p::crypto::MLKEM_SHARED_SECRET_LENGTH] = {};
		uint8_t sharedDecaps[i2p::crypto::MLKEM_SHARED_SECRET_LENGTH] = {};

		encapsKey->Encaps (ciphertext.data (), sharedEncaps);
		decapsKey->Decaps (ciphertext.data (), sharedDecaps);
		assert (!std::memcmp (sharedEncaps, sharedDecaps, i2p::crypto::MLKEM_SHARED_SECRET_LENGTH));

		ciphertext[0] ^= 0x01;
		std::memset (sharedDecaps, 0, sizeof(sharedDecaps));
		decapsKey->Decaps (ciphertext.data (), sharedDecaps);
		assert (std::memcmp (sharedEncaps, sharedDecaps, i2p::crypto::MLKEM_SHARED_SECRET_LENGTH));
	}
#endif
}
