/*
* Copyright (c) 2025-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef POST_QUANTUM_H__
#define POST_QUANTUM_H__

#include <memory>
#include <string_view>
#include <array>
#include <tuple>
#include "Crypto.h"
#include "Identity.h"
#ifdef LIBRESSL_VERSION_NUMBER
#	include <openssl/mlkem.h>
#endif

#if OPENSSL_PQ

namespace i2p
{
namespace crypto
{
	enum MLKEMTypes
	{
		eMLKEM512 = 0,
		eMLKEM768,
		eMLKEM1024
	};

	constexpr size_t MLKEM512_KEY_LENGTH = 800;
	constexpr size_t MLKEM512_CIPHER_TEXT_LENGTH = 768;
	constexpr size_t MLKEM768_KEY_LENGTH = 1184;
	constexpr size_t MLKEM768_CIPHER_TEXT_LENGTH = 1088;
	constexpr size_t MLKEM1024_KEY_LENGTH = 1568;
	constexpr size_t MLKEM1024_CIPHER_TEXT_LENGTH = 1568;

	constexpr std::array MLKEMS =
	{
		std::make_tuple ("ML-KEM-512", MLKEM512_KEY_LENGTH, MLKEM512_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-768", MLKEM768_KEY_LENGTH, MLKEM768_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-1024", MLKEM1024_KEY_LENGTH, MLKEM1024_CIPHER_TEXT_LENGTH)
	};

	constexpr size_t GetMLKEMPublicKeyLen (i2p::data::CryptoKeyType type)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)MLKEMS.size ()) return 0;
		return std::get<1>(MLKEMS[type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1]);
	}

	constexpr size_t GetMLKEMCipherTextLen (i2p::data::CryptoKeyType type)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)MLKEMS.size ()) return 0;
		return std::get<2>(MLKEMS[type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1]);
	}

	class MLKEMKeys
	{
		public:

			MLKEMKeys (MLKEMTypes type);
			~MLKEMKeys ();

			void GenerateKeys ();
			void GetPublicKey (uint8_t * pub) const;
			void SetPublicKey (const uint8_t * pub);
			size_t GetKeyLen () const { return m_KeyLen; }
			size_t GetCTLen () const { return m_CTLen; }
			void Encaps (uint8_t * ciphertext, uint8_t * shared);
			void Decaps (const uint8_t * ciphertext, uint8_t * shared);


		private:

			void FreeKeys();

		private:

			const std::string m_Name;
			const size_t m_KeyLen, m_CTLen;
#ifndef LIBRESSL_VERSION_NUMBER
			EVP_PKEY * m_Pkey;
#else
			MLKEM_private_key * m_Pkey;
			uint8_t m_CachedPub[MLKEM768_KEY_LENGTH];
			bool m_IsPubCached = false;
#endif
	};

	std::unique_ptr<MLKEMKeys> CreateMLKEMKeys (i2p::data::CryptoKeyType type);

	void InitNoiseIKStateMLKEM (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub); // Noise_IK (ratchets) PQ ML-KEM
	void InitNoiseXKStateMLKEM (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub); // Noise_XK (NTCP2) PQ ML-KEM
	void InitNoiseXKStateMLKEM1 (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub); // Noise_XK1 (SSU2) PQ ML-KEM
}
}

#endif

#endif
