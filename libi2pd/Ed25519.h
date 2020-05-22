/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef ED25519_H__
#define ED25519_H__

#include <memory>
#include <openssl/bn.h>
#include "Crypto.h"

namespace i2p
{
namespace crypto
{
	struct EDDSAPoint
	{
		BIGNUM * x {nullptr};
		BIGNUM * y {nullptr};
		BIGNUM * z {nullptr};
		BIGNUM * t {nullptr}; // projective coordinates

		EDDSAPoint () {}
		EDDSAPoint (const EDDSAPoint& other)   { *this = other; }
		EDDSAPoint (EDDSAPoint&& other)        { *this = std::move (other); }
		EDDSAPoint (BIGNUM * x1, BIGNUM * y1, BIGNUM * z1 = nullptr, BIGNUM * t1 = nullptr)
			: x(x1)
			, y(y1)
			, z(z1)
			, t(t1)
		{}
		~EDDSAPoint () { BN_free (x); BN_free (y); BN_free(z); BN_free(t); }

		EDDSAPoint& operator=(EDDSAPoint&& other)
		{
			if (this != &other)
			{
				BN_free (x); x = other.x; other.x = nullptr;
				BN_free (y); y = other.y; other.y = nullptr;
				BN_free (z); z = other.z; other.z = nullptr;
				BN_free (t); t = other.t; other.t = nullptr;
			}
			return *this;
		}

		EDDSAPoint& operator=(const EDDSAPoint& other)
		{
			if (this != &other)
			{
				BN_free (x); x = other.x ? BN_dup (other.x) : nullptr;
				BN_free (y); y = other.y ? BN_dup (other.y) : nullptr;
				BN_free (z); z = other.z ? BN_dup (other.z) : nullptr;
				BN_free (t); t = other.t ? BN_dup (other.t) : nullptr;
			}
			return *this;
		}

		EDDSAPoint operator-() const
		{
			BIGNUM * x1 = NULL, * y1 = NULL, * z1 = NULL, * t1 = NULL;
			if (x) { x1 = BN_dup (x); BN_set_negative (x1, !BN_is_negative (x)); };
			if (y) y1 = BN_dup (y);
			if (z) z1 = BN_dup (z);
			if (t) { t1 = BN_dup (t); BN_set_negative (t1, !BN_is_negative (t)); };
			return EDDSAPoint {x1, y1, z1, t1};
		}
	};

	const size_t EDDSA25519_PUBLIC_KEY_LENGTH = 32;
	const size_t EDDSA25519_SIGNATURE_LENGTH = 64;
	const size_t EDDSA25519_PRIVATE_KEY_LENGTH = 32;
	class Ed25519
	{
		public:

			Ed25519 ();
			Ed25519 (const Ed25519& other);
			~Ed25519 ();

			EDDSAPoint GeneratePublicKey (const uint8_t * expandedPrivateKey, BN_CTX * ctx) const;
			EDDSAPoint DecodePublicKey (const uint8_t * buf, BN_CTX * ctx) const;
			void EncodePublicKey (const EDDSAPoint& publicKey, uint8_t * buf, BN_CTX * ctx) const;
#if !OPENSSL_X25519
			void ScalarMul (const uint8_t * p, const  uint8_t * e, uint8_t * buf, BN_CTX * ctx) const; // p is point, e is number for x25519
			void ScalarMulB (const  uint8_t * e, uint8_t * buf, BN_CTX * ctx) const;
#endif
			void BlindPublicKey (const uint8_t * pub, const uint8_t * seed, uint8_t * blinded); // for encrypted LeaseSet2, pub - 32, seed - 64, blinded - 32
			void BlindPrivateKey (const uint8_t * priv, const uint8_t * seed, uint8_t * blindedPriv, uint8_t * blindedPub); // for encrypted LeaseSet2, pub - 32, seed - 64, blinded - 32

			bool Verify (const EDDSAPoint& publicKey, const uint8_t * digest, const uint8_t * signature) const;
			void Sign (const uint8_t * expandedPrivateKey, const uint8_t * publicKeyEncoded, const uint8_t * buf, size_t len, uint8_t * signature) const;
			void SignRedDSA (const uint8_t * privateKey, const uint8_t * publicKeyEncoded, const uint8_t * buf, size_t len, uint8_t * signature) const;

			static void ExpandPrivateKey (const uint8_t * key, uint8_t * expandedKey); // key - 32 bytes, expandedKey - 64 bytes
			void CreateRedDSAPrivateKey (uint8_t * priv); // priv is 32 bytes

		private:

			EDDSAPoint Sum (const EDDSAPoint& p1, const EDDSAPoint& p2, BN_CTX * ctx) const;
			void Double (EDDSAPoint& p, BN_CTX * ctx) const;
			EDDSAPoint Mul (const EDDSAPoint& p, const BIGNUM * e, BN_CTX * ctx) const;
			EDDSAPoint MulB (const uint8_t * e, BN_CTX * ctx) const; // B*e, e is 32 bytes Little Endian
			EDDSAPoint Normalize (const EDDSAPoint& p, BN_CTX * ctx) const;

			bool IsOnCurve (const EDDSAPoint& p, BN_CTX * ctx) const;
			BIGNUM * RecoverX (const BIGNUM * y, BN_CTX * ctx) const;
			EDDSAPoint DecodePoint (const uint8_t * buf, BN_CTX * ctx) const;
			void EncodePoint (const EDDSAPoint& p, uint8_t * buf) const;

			template<int len>
			BIGNUM * DecodeBN (const uint8_t * buf) const;
			void EncodeBN (const BIGNUM * bn, uint8_t * buf, size_t len) const;

#if !OPENSSL_X25519
			// for x25519
			BIGNUM * ScalarMul (const BIGNUM * p, const BIGNUM * e, BN_CTX * ctx) const;
#endif

		private:

			BIGNUM * q, * l, * d, * I;
			// transient values
			BIGNUM * two_252_2; // 2^252-2
			EDDSAPoint Bi256[32][128]; // per byte, Bi256[i][j] = (256+j+1)^i*B, we don't store zeroes
			// if j > 128 we use 256 - j and carry 1 to next byte
			// Bi256[0][0] = B, base point
			EDDSAPoint Bi256Carry; // Bi256[32][0]
	};

	std::unique_ptr<Ed25519>& GetEd25519 ();

}
}

#endif
