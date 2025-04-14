/*
* Copyright (c) 2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef POST_QUANTUM_H__
#define POST_QUANTUM_H__

#include <string_view>
#include <array>
#include <tuple>
#include "Crypto.h"
#include "Identity.h"

#if OPENSSL_PQ

namespace i2p
{
namespace crypto
{
	class MLKEMKeys
	{
		public:

			MLKEMKeys (std::string_view name, size_t keyLen, size_t ctLen);
			~MLKEMKeys ();

			void GenerateKeys ();
			void GetPublicKey (uint8_t * pub) const;
			void SetPublicKey (const uint8_t * pub);
			void Encaps (uint8_t * ciphertext, uint8_t * shared);
			void Decaps (const uint8_t * ciphertext, uint8_t * shared);
			
		private:

			const std::string m_Name;
			const size_t m_KeyLen, m_CTLen;
			EVP_PKEY * m_Pkey;		
	};

	constexpr size_t MLKEM512_KEY_LENGTH = 800;
	constexpr size_t MLKEM512_CIPHER_TEXT_LENGTH = 768;
	constexpr size_t MLKEM768_KEY_LENGTH = 1184;
	constexpr size_t MLKEM768_CIPHER_TEXT_LENGTH = 1088;
	constexpr size_t MLKEM1024_KEY_LENGTH = 1568;
	constexpr size_t MLKEM1024_CIPHER_TEXT_LENGTH = 1568;
	
	constexpr std::array<std::tuple<std::string_view, size_t, size_t>, 3> MLKEMS =
	{
		std::make_tuple ("ML-KEM-512", MLKEM512_KEY_LENGTH, MLKEM512_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-768", MLKEM768_KEY_LENGTH, MLKEM768_CIPHER_TEXT_LENGTH),
		std::make_tuple ("ML-KEM-1024", MLKEM1024_KEY_LENGTH, MLKEM1024_CIPHER_TEXT_LENGTH)
	};	
	
	class MLKEM512Keys: public MLKEMKeys
	{
		public:

			MLKEM512Keys (): MLKEMKeys (std::get<0>(MLKEMS[0]), std::get<1>(MLKEMS[0]), std::get<2>(MLKEMS[0])) {}
	};

	class MLKEM768Keys: public MLKEMKeys
	{
		public:

			MLKEM768Keys (): MLKEMKeys (std::get<0>(MLKEMS[1]), std::get<1>(MLKEMS[1]), std::get<2>(MLKEMS[1])) {}
	};

	class MLKEM1024Keys: public MLKEMKeys
	{
		public:

			MLKEM1024Keys (): MLKEMKeys (std::get<0>(MLKEMS[2]), std::get<1>(MLKEMS[2]), std::get<2>(MLKEMS[2])) {}
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
}	
}	

#endif

#endif
