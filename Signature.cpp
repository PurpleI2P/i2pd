#include <cryptopp/integer.h>
#include <cryptopp/eccrypto.h>
#include "Signature.h"

namespace i2p
{
namespace crypto
{
	class Ed25519
	{
		public:

			Ed25519 (): b(256)
			{
				q = CryptoPP::Integer::Power2 (255) - CryptoPP::Integer (19); // 2^255-19
				l = CryptoPP::Integer::Power2 (252) + CryptoPP::Integer ("27742317777372353535851937790883648493");
				// 2^252 + 27742317777372353535851937790883648493
				d = CryptoPP::Integer (-121665) * CryptoPP::Integer (121666).InverseMod (q); // -121665/121666
			}

		private:

			CryptoPP::ECP::Point Sum (CryptoPP::ECP::Point p1, CryptoPP::ECP::Point p2)
			{
				CryptoPP::Integer m = d*p1.x*p2.x*p1.y*p2.y,
				x = a_times_b_mod_c (p1.x*p2.y + p2.x*p1.y, (CryptoPP::Integer::One() + m).InverseMod (q), q),
				y = a_times_b_mod_c (p1.y*p2.y + p1.x*p2.x, (CryptoPP::Integer::One() - m).InverseMod (q), q);
				return CryptoPP::ECP::Point {x, y};
			}

			CryptoPP::ECP::Point Mul (CryptoPP::ECP::Point p, CryptoPP::Integer e)
			{
				if (e.IsZero ()) return CryptoPP::ECP::Point {0, 1};
				return p; // TODO
			} 

		private:

			CryptoPP::Integer b, q, l, d; 
	};	
}
}


