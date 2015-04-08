#include <cryptopp/integer.h>
#include <cryptopp/eccrypto.h>
#include "Log.h"
#include "Signature.h"

namespace i2p
{
namespace crypto
{
	class Ed25519
	{
		public:

			Ed25519 ()
			{
				q = CryptoPP::Integer::Power2 (255) - CryptoPP::Integer (19); // 2^255-19
				l = CryptoPP::Integer::Power2 (252) + CryptoPP::Integer ("27742317777372353535851937790883648493");
				// 2^252 + 27742317777372353535851937790883648493
				d = CryptoPP::Integer (-121665) * CryptoPP::Integer (121666).InverseMod (q); // -121665/121666
				I = a_exp_b_mod_c (CryptoPP::Integer::Two (), (q - CryptoPP::Integer::One ()).DividedBy (4), q);
			}

		private:

			CryptoPP::ECP::Point Sum (const CryptoPP::ECP::Point& p1, const CryptoPP::ECP::Point& p2)
			{
				CryptoPP::Integer m = d*p1.x*p2.x*p1.y*p2.y,
				x = a_times_b_mod_c (p1.x*p2.y + p2.x*p1.y, (CryptoPP::Integer::One() + m).InverseMod (q), q),
				y = a_times_b_mod_c (p1.y*p2.y + p1.x*p2.x, (CryptoPP::Integer::One() - m).InverseMod (q), q);
				return CryptoPP::ECP::Point {x, y};
			}

			CryptoPP::ECP::Point Mul (const CryptoPP::ECP::Point& p, const CryptoPP::Integer& e)
			{
				CryptoPP::ECP::Point res {0, 1};
				if (!e.IsZero ())
				{
					auto bitCount = e.BitCount ();
					for (int i = bitCount - 1; i >= 0; i--)
					{
						res = Sum (res, res);
						if (e.GetBit (i)) res = Sum (res, p);
					}
				}	
				return res;
			} 

			bool IsOnCurve (const CryptoPP::ECP::Point& p)
			{
				auto x2 = p.x.Squared(), y2 = p.y.Squared ();
				return  (y2 - x2 - CryptoPP::Integer::One() - d*x2*y2).Modulo (q).IsZero ();
			}	

			CryptoPP::Integer RecoverX (const CryptoPP::Integer& y)
			{
				auto y2 = y.Squared ();
				auto xx = (y2 - CryptoPP::Integer::One())*(d*y2 + CryptoPP::Integer::One()).InverseMod (q); 
				auto x = a_exp_b_mod_c (xx, (q + CryptoPP::Integer (3)).DividedBy (8), q);
				if (!(x.Squared () - xx).Modulo (q).IsZero ())
					x = a_times_b_mod_c (x, I, q);
				if (x.IsOdd ()) x = q - x;
				return x;
			}

			CryptoPP::ECP::Point DecodePoint (const CryptoPP::Integer& y)
			{
				auto x = RecoverX (y);
				CryptoPP::ECP::Point p {x, y};
				if (!IsOnCurve (p)) 
				{
					LogPrint (eLogError, "Decoded point is not on 25519");
					return CryptoPP::ECP::Point {0, 1};
				}
				return p;
			}

		private:

			CryptoPP::Integer q, l, d, I; 
	};

	bool EDDSAVerifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		return true; // TODO:	
	}	
}
}


