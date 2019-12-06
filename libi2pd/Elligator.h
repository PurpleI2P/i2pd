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

			void Encode (const uint8_t * key, uint8_t * encoded) const;

		private:

			BIGNUM * p, * n1, * n2, * p38, * p12, * sqrtn1, * A, * nA, * u, * iu, * d;
	};

	std::unique_ptr<Elligator2>& GetElligator ();
}
}

#endif


