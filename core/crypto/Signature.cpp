#include <memory>
#include <cryptopp/integer.h>
#include <cryptopp/eccrypto.h>
#include "util/Log.h"
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
                B = DecodePoint (CryptoPP::Integer (4)*CryptoPP::Integer (5).InverseMod (q));
            }

            CryptoPP::ECP::Point DecodePublicKey (const uint8_t * key) const
            {
                return DecodePoint (CryptoPP::Integer (key, 32));
            }

            CryptoPP::ECP::Point GeneratePublicKey (const uint8_t * privateKey) const
            {
                return Mul (B, CryptoPP::Integer (privateKey, 32));
            }

        private:

            CryptoPP::ECP::Point Sum (const CryptoPP::ECP::Point& p1, const CryptoPP::ECP::Point& p2) const
            {
                CryptoPP::Integer m = d*p1.x*p2.x*p1.y*p2.y,
                x = a_times_b_mod_c (p1.x*p2.y + p2.x*p1.y, (CryptoPP::Integer::One() + m).InverseMod (q), q),
                y = a_times_b_mod_c (p1.y*p2.y + p1.x*p2.x, (CryptoPP::Integer::One() - m).InverseMod (q), q);
                return CryptoPP::ECP::Point {x, y};
            }

            CryptoPP::ECP::Point Mul (const CryptoPP::ECP::Point& p, const CryptoPP::Integer& e) const
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

            bool IsOnCurve (const CryptoPP::ECP::Point& p) const
            {
                auto x2 = p.x.Squared(), y2 = p.y.Squared ();
                return  (y2 - x2 - CryptoPP::Integer::One() - d*x2*y2).Modulo (q).IsZero ();
            }   

            CryptoPP::Integer RecoverX (const CryptoPP::Integer& y) const
            {
                auto y2 = y.Squared ();
                auto xx = (y2 - CryptoPP::Integer::One())*(d*y2 + CryptoPP::Integer::One()).InverseMod (q); 
                auto x = a_exp_b_mod_c (xx, (q + CryptoPP::Integer (3)).DividedBy (8), q);
                if (!(x.Squared () - xx).Modulo (q).IsZero ())
                    x = a_times_b_mod_c (x, I, q);
                if (x.IsOdd ()) x = q - x;
                return x;
            }

            CryptoPP::ECP::Point DecodePoint (const CryptoPP::Integer& y) const
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
            CryptoPP::ECP::Point B; // base point
    };

    static std::unique_ptr<Ed25519> g_Ed25519;
    std::unique_ptr<Ed25519>& GetEd25519 ()
    {
        if (!g_Ed25519)
            g_Ed25519.reset (new Ed25519 ());
        return g_Ed25519; 
    }       
    

    EDDSA25519Verifier::EDDSA25519Verifier (const uint8_t * signingKey):    
        m_PublicKey (GetEd25519 ()->DecodePublicKey (signingKey))
    {
    }

    bool EDDSA25519Verifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
    {
        return true; // TODO:   
    }

    void EDDSA25519Signer::Sign (CryptoPP::RandomNumberGenerator& rnd, const uint8_t * buf, int len, uint8_t * signature) const
    {
        // TODO
    }   
}
}


