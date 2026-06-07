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

#if OPENSSL_MLKEM

#if defined(LIBRESSL_VERSION_NUMBER)
typedef struct MLKEM_private_key_st MLKEM_private_key;
typedef struct MLKEM_public_key_st MLKEM_public_key;
#endif

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
	constexpr size_t MLKEM_SHARED_SECRET_LENGTH = 32;

#if defined(LIBRESSL_VERSION_NUMBER)
	constexpr std::array MLKEMS =
	{
		std::make_tuple ("ML-KEM-768", MLKEM768_KEY_LENGTH, MLKEM768_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-1024", MLKEM1024_KEY_LENGTH, MLKEM1024_CIPHER_TEXT_LENGTH)
	};
#else
	constexpr std::array MLKEMS =
	{
		std::make_tuple ("ML-KEM-512", MLKEM512_KEY_LENGTH, MLKEM512_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-768", MLKEM768_KEY_LENGTH, MLKEM768_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-1024", MLKEM1024_KEY_LENGTH, MLKEM1024_CIPHER_TEXT_LENGTH)
	};
#endif

	constexpr int GetMLKEMIndex (i2p::data::CryptoKeyType type)
	{
#if defined(LIBRESSL_VERSION_NUMBER)
		switch (type)
		{
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD: return 0;
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM1024_X25519_AEAD: return 1;
			default: return -1;
		}
#else
		switch (type)
		{
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM512_X25519_AEAD: return 0;
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM768_X25519_AEAD: return 1;
			case i2p::data::CRYPTO_KEY_TYPE_ECIES_MLKEM1024_X25519_AEAD: return 2;
			default: return -1;
		}
#endif
	}

	constexpr size_t GetMLKEMPublicKeyLen (i2p::data::CryptoKeyType type)
	{
		auto ind = GetMLKEMIndex (type);
		return ind >= 0 ? std::get<1>(MLKEMS[ind]) : 0;
	}

	constexpr size_t GetMLKEMCipherTextLen (i2p::data::CryptoKeyType type)
	{
		auto ind = GetMLKEMIndex (type);
		return ind >= 0 ? std::get<2>(MLKEMS[ind]) : 0;
	}

	class MLKEMKeys
	{
		public:

			MLKEMKeys (MLKEMTypes type);
			~MLKEMKeys ();

			void GenerateKeys ();
			void GetPublicKey (uint8_t * pub) const;
			void SetPublicKey (const uint8_t * pub);
			size_t GetKeyLen () const { return m_KeyLen; };
			size_t GetCTLen () const { return m_CTLen; };
			void Encaps (uint8_t * ciphertext, uint8_t * shared);
			void Decaps (const uint8_t * ciphertext, uint8_t * shared);

		private:

			const std::string m_Name;
#if defined(LIBRESSL_VERSION_NUMBER)
			const int m_Rank;
#endif
			const size_t m_KeyLen, m_CTLen;
			std::array<uint8_t, MLKEM1024_KEY_LENGTH> m_PublicKeyEncoded;
#if defined(LIBRESSL_VERSION_NUMBER)
			MLKEM_private_key * m_PrivateKey;
			MLKEM_public_key * m_PublicKey;
#else
			EVP_PKEY * m_Pkey;
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
