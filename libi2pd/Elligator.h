/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef ELLIGATOR_H__
#define ELLIGATOR_H__

#include <inttypes.h>
#include <memory>
#include <openssl/bn.h>

namespace i2p
{
namespace crypto
{

	class Elligator2
	{
		public:

			Elligator2 ();
			~Elligator2 ();

			bool Encode (const uint8_t * key, uint8_t * encoded, bool highY = false, bool random = true) const;
			bool Decode (const uint8_t * encoded, uint8_t * key) const;

		private:

			void SquareRoot (const BIGNUM * x, BIGNUM * r, BN_CTX * ctx) const;
			int Legendre (const BIGNUM * a, BN_CTX * ctx) const; // a/p

		private:

			BIGNUM * p, * p38, * p12, * p14, * sqrtn1, * A, * nA, * u, * iu;
	};

	std::unique_ptr<Elligator2>& GetElligator ();
}
}

#endif
