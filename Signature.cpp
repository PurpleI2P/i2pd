#include <memory>
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
				BN_CTX * ctx = BN_CTX_new ();
				BIGNUM * two = BN_new (), * tmp = BN_new ();
				BN_set_word (two, 2);

				q = BN_new ();
				// 2^255-19				
				BN_set_word (tmp, 255);
				BN_exp (q, two, tmp, ctx);
				BN_sub_word (q, 19);
				// q_2 = q-2
				q_2 = BN_dup (q);
				BN_sub_word (q_2, 2);
				
				l = BN_new ();
				// 2^252 + 27742317777372353535851937790883648493
				BN_set_word (tmp, 252);
				BN_exp (l, two, tmp, ctx);
				two_252_2 = BN_dup (l);
				BN_dec2bn (&tmp, "27742317777372353535851937790883648493");
				BN_add (l, l, tmp);		
				BN_sub_word (two_252_2, 2); // 2^252 - 2		

				 // -121665*inv(121666)
				d = BN_new ();
				BN_set_word (tmp, 121666);
				Inv (tmp, ctx);	
				BN_set_word (d, 121665);
				BN_set_negative (d, 1);							
				BN_mul (d, d, tmp, ctx);

				// 2^((q-1)/4)
				I = BN_new ();
				BN_free (tmp);
				tmp = BN_dup (q);
				BN_sub_word (tmp, 1);
				BN_div_word (tmp, 4);	
				BN_mod_exp (I, two, tmp, q, ctx);

				// 4*inv(5)	
				BIGNUM * By = BN_new ();		
				BN_set_word (By, 5);
				Inv (By, ctx);	
				BN_mul_word (By, 4);
				BIGNUM * Bx = RecoverX (By, ctx);	
				BN_mod (Bx, Bx, q, ctx); // % q
				BN_mod (By, By, q, ctx); // % q								
				B = {Bx, By};

				BN_free (two);
				BN_free (tmp);
			
				// precalculate Bi16 table
				Bi16[0][0] = { BN_dup (Bx), BN_dup (By) }; 
				for (int i = 0; i < 64; i++)
				{
					if (i) Bi16[i][0] = Sum (Bi16[i-1][14], Bi16[i-1][0], ctx); 
					for (int j = 1; j < 15; j++)
						Bi16[i][j] = Sum (Bi16[i][j-1], Bi16[i][0], ctx); // (16+j+1)^i*B
				}

				BN_CTX_free (ctx);
			}

			~Ed25519 ()
			{
				BN_free (q);
				BN_free (l);
				BN_free (d);
				BN_free (I);
				BN_free (q_2);
				BN_free (two_252_2);
			}


			EDDSAPoint GeneratePublicKey (const uint8_t * expandedPrivateKey, BN_CTX * ctx) const
			{
				return MulB (expandedPrivateKey, ctx); // left half of expanded key, considered as Little Endian
			}

			EDDSAPoint DecodePublicKey (const uint8_t * buf, BN_CTX * ctx) const
			{
				return DecodePoint (buf, ctx);
			}

			void EncodePublicKey (const EDDSAPoint& publicKey, uint8_t * buf) const
			{
				EncodePoint (publicKey, buf);
			}

			bool Verify (const EDDSAPoint& publicKey, const uint8_t * digest, const uint8_t * signature, BN_CTX * ctx) const
			{
				BIGNUM * h = DecodeBN (digest, 64);
				// signature 0..31 - R, 32..63 - S 
				// B*S = R + PK*h => R = B*S - PK*h
				// we don't decode R, but encode (B*S - PK*h)
				auto Bs = MulB (signature + EDDSA25519_SIGNATURE_LENGTH/2, ctx); // B*S;
				auto PKh = Mul (publicKey, h, ctx); // PK*h
				uint8_t diff[32];
				EncodePoint (Sum (Bs, -PKh, ctx), diff); // Bs - PKh encoded
				bool passed = !memcmp (signature, diff, 32); // R
				BN_free (h); 
				if (!passed)
					LogPrint (eLogError, "25519 signature verification failed");
				return passed; 
			}

			void Sign (const uint8_t * expandedPrivateKey, const uint8_t * publicKeyEncoded, const uint8_t * buf, size_t len, 
				uint8_t * signature, BN_CTX * bnCtx) const
			{
				// calculate r
				SHA512_CTX ctx;
				SHA512_Init (&ctx);
				SHA512_Update (&ctx, expandedPrivateKey + EDDSA25519_PRIVATE_KEY_LENGTH, EDDSA25519_PRIVATE_KEY_LENGTH); // right half of expanded key
				SHA512_Update (&ctx, buf, len); // data
				uint8_t digest[64];
				SHA512_Final (digest, &ctx);
				BIGNUM * r = DecodeBN (digest, 32); // DecodeBN (digest, 64); // for test vectors
				// calculate R
				uint8_t R[EDDSA25519_SIGNATURE_LENGTH/2]; // we must use separate buffer because signature might be inside buf
				EncodePoint (MulB (digest, bnCtx), R); // EncodePoint (Mul (B, r, bnCtx), R); // for test vectors 
				// calculate S
				SHA512_Init (&ctx);
				SHA512_Update (&ctx, R, EDDSA25519_SIGNATURE_LENGTH/2); // R
				SHA512_Update (&ctx, publicKeyEncoded, EDDSA25519_PUBLIC_KEY_LENGTH); // public key
				SHA512_Update (&ctx, buf, len); // data
				SHA512_Final (digest, &ctx);
				BIGNUM * s = DecodeBN (digest, 64);			
				// S = (r + s*a) % l
				BIGNUM * a = DecodeBN (expandedPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH); // left half of expanded key
				BN_mul (s, s, a, bnCtx);
				BN_add (s, s, r);
				BN_mod (s, s, l, bnCtx); // % l
				memcpy (signature, R, EDDSA25519_SIGNATURE_LENGTH/2);
				EncodeBN (s, signature + EDDSA25519_SIGNATURE_LENGTH/2, EDDSA25519_SIGNATURE_LENGTH/2); // S
				BN_free (r); BN_free (s); BN_free (a);
			}

		private:		

			EDDSAPoint Sum (const EDDSAPoint& p1, const EDDSAPoint& p2, BN_CTX * ctx) const
			{
				BIGNUM * xx = BN_new (), * yy = BN_new ();
				// m = d*p1.x*p2.x*p1.y*p2.y
				BN_mul (xx, p1.x, p2.x, ctx);
				BN_mul (yy, p1.y, p2.y, ctx);
				BIGNUM * m = BN_dup (d);
				BN_mul (m, m, xx, ctx);
				BN_mul (m, m, yy, ctx);
				// x = (p1.x*p2.y + p2.x*p1.y)*inv(1 + m)
				// y = (p1.y*p2.y + p1.x*p2.x)*inv(1 - m)
				
				// use one inversion instead two
				// m1 = 1-m
				BIGNUM * m1 = BN_new ();		
				BN_one (m1);
				BN_sub (m1, m1, m);
				// m = m+1
				BN_add_word (m, 1);		
				// y = (p1.y*p2.y + p1.x*p2.x)*m
				BIGNUM * y = BN_new ();		
				BN_add (y, xx, yy);
				BN_mod_mul (y, y, m, q, ctx);		
				// x = (p1.x*p2.y + p2.x*p1.y)*m1
				BIGNUM * x = BN_new ();	
				BN_mul (yy, p1.x, p2.y, ctx);
				BN_mul (xx, p2.x, p1.y, ctx);
				BN_add (x, xx, yy);
				BN_mod_mul (x, x, m1, q, ctx);	
				// denominator m = m*m1	
				BN_mod_mul (m, m, m1, q, ctx);
				Inv (m, ctx); 	
				BN_mod_mul (x, x, m, q, ctx); // x = x/m
				BN_mod_mul (y, y, m, q, ctx); // y = y/m

				BN_free (xx);BN_free (yy); BN_free (m); BN_free (m1);
				return EDDSAPoint {x, y};
			}

			EDDSAPoint Double (const EDDSAPoint& p, BN_CTX * ctx) const
			{
				BIGNUM * pxy = BN_new ();
				BN_mul (pxy, p.x, p.y, ctx);
				// m = d*(p.x*p.y)^2
				BIGNUM * m = BN_new ();
				BN_sqr (m, pxy, ctx);
				BN_mul (m, m, d, ctx);
				// x = (2*p.x*p.y)*inv(1 + m)
				// y = (p.x^2 + p.y^2)*inv(1 - m)
				
				// use one inversion instead two
				// m1 = 1-m
				BIGNUM * m1 = BN_new ();		
				BN_one (m1);
				BN_sub (m1, m1, m);
				// m = m+1
				BN_add_word (m, 1);								
				// x = 2*p.x*p.y*m1
				BN_mul_word (pxy, 2);
				BIGNUM * x = BN_new ();
				BN_mod_mul (x, pxy, m1, q, ctx);
				// y = (p.x^2 + p.y^2)*m
				BIGNUM * y = BN_new ();
				BN_sqr (pxy, p.x, ctx);
				BN_sqr (y, p.y, ctx);
				BN_add (pxy, pxy, y);
				BN_mod_mul (y, pxy, m, q, ctx);
				// denominator m = m*m1	
				BN_mod_mul (m, m, m1, q, ctx);
				Inv (m, ctx); 	
				BN_mod_mul (x, x, m, q, ctx); // x = x/m
				BN_mod_mul (y, y, m, q, ctx); // y = y/m

				BN_free (pxy); BN_free (m); BN_free (m1);
				return EDDSAPoint {x, y};
			}
			
			EDDSAPoint Mul (const EDDSAPoint& p, const BIGNUM * e, BN_CTX * ctx) const
			{
				BIGNUM * zero = BN_new (), * one = BN_new ();
				BN_zero (zero); BN_one (one);
				EDDSAPoint res {zero, one};
				if (!BN_is_zero (e))
				{
					int bitCount = BN_num_bits (e);
					for (int i = bitCount - 1; i >= 0; i--)
					{
						res = Double (res, ctx);
						if (BN_is_bit_set (e, i)) res = Sum (res, p, ctx);
					}
				}	
				return res;
			} 
			
			EDDSAPoint MulB (const uint8_t * e, BN_CTX * ctx) const // B*e. e is 32 bytes Little Endian
			{
				BIGNUM * zero = BN_new (), * one = BN_new ();
				BN_zero (zero); BN_one (one);
				EDDSAPoint res {zero, one};
				for (int i = 0; i < 32; i++)
				{
					uint8_t x = e[i] & 0x0F; // 4 low bits
					if (x > 0)
						res = Sum (res, Bi16[i*2][x-1], ctx);
					x = e[i] >> 4; // 4 high bits
					if (x > 0)
						res = Sum (res, Bi16[i*2+1][x-1], ctx);
				}
				return res;
			}

			void Inv (BIGNUM * x, BN_CTX * ctx) const
			{
				BN_mod_exp (x, x, q_2, q, ctx);
			}

			bool IsOnCurve (const EDDSAPoint& p, BN_CTX * ctx) const
			{
				BIGNUM * x2 = BN_new ();
				BN_sqr (x2, p.x, ctx); // x^2
				BIGNUM * y2 = BN_new ();
				BN_sqr (y2, p.y, ctx); // y^2
				// y^2 - x^2 - 1 - d*x^2*y^2 
				BIGNUM * tmp = BN_new ();				
				BN_mul (tmp, d, x2, ctx);
				BN_mul (tmp, tmp, y2, ctx);	
				BN_sub (tmp, y2, tmp);
				BN_sub (tmp, tmp, x2);
				BN_sub_word (tmp, 1);
				BN_mod (tmp, tmp, q, ctx); // % q
				bool ret = BN_is_zero (tmp);
				BN_free (x2);
				BN_free (y2);
				BN_free (tmp);
				return ret;
			}	

			BIGNUM * RecoverX (const BIGNUM * y, BN_CTX * ctx) const
			{
				BIGNUM * y2 = BN_new ();
				BN_sqr (y2, y, ctx); // y^2
				// xx = (y^2 -1)*inv(d*y^2 +1) 
				BIGNUM * xx = BN_new ();
				BN_mul (xx, d, y2, ctx);
				BN_add_word (xx, 1);
				Inv (xx, ctx);
				BN_sub_word (y2, 1);
				BN_mul (xx, y2, xx, ctx);
				// x = srqt(xx) = xx^(2^252-2)		
				BIGNUM * x = BN_new ();
				BN_mod_exp (x, xx, two_252_2, q, ctx);
				// check (x^2 -xx) % q	
				BN_sqr (y2, x, ctx);
				BN_mod_sub (y2, y2, xx, q, ctx); 
				if (!BN_is_zero (y2))
					BN_mod_mul (x, x, I, q, ctx);
				if (BN_is_odd (x))
					BN_sub (x, q, x);
				BN_free (y2);
				BN_free (xx);
				return x;
			}

			EDDSAPoint DecodePoint (const uint8_t * buf, BN_CTX * ctx) const
			{
				// buf is 32 bytes Little Endian, convert it to Big Endian
				uint8_t buf1[EDDSA25519_PUBLIC_KEY_LENGTH];
				for (size_t i = 0; i < EDDSA25519_PUBLIC_KEY_LENGTH/2; i++) // invert bytes
				{
					buf1[i] = buf[EDDSA25519_PUBLIC_KEY_LENGTH -1 - i];
					buf1[EDDSA25519_PUBLIC_KEY_LENGTH -1 - i] = buf[i];
				}
				bool isHighestBitSet = buf1[0] & 0x80;
				if (isHighestBitSet)
					buf1[0] &= 0x7f; // clear highest bit
				BIGNUM * y = BN_new ();
				BN_bin2bn (buf1, EDDSA25519_PUBLIC_KEY_LENGTH, y);
				auto x = RecoverX (y, ctx);
				if (BN_is_bit_set (x, 0) != isHighestBitSet)
					BN_sub (x, q, x); // x = q - x 
				EDDSAPoint p {x, y};
				if (!IsOnCurve (p, ctx)) 
					LogPrint (eLogError, "Decoded point is not on 25519");
				return p;
			}
			
			void EncodePoint (const EDDSAPoint& p, uint8_t * buf) const
			{
				EncodeBN (p.y, buf,EDDSA25519_PUBLIC_KEY_LENGTH); 
				if (BN_is_bit_set (p.x, 0)) // highest bit
					buf[EDDSA25519_PUBLIC_KEY_LENGTH - 1] |= 0x80; // set highest bit
			}

			BIGNUM * DecodeBN (const uint8_t * buf, size_t len) const
			{
				// buf is Little Endian convert it to Big Endian
				uint8_t buf1[len];
				for (size_t i = 0; i < len/2; i++) // invert bytes
				{
					buf1[i] = buf[len -1 - i];
					buf1[len -1 - i] = buf[i];
				}
				BIGNUM * res = BN_new ();
				BN_bin2bn (buf1, len, res);
				return res;
			}

			void EncodeBN (const BIGNUM * bn, uint8_t * buf, size_t len) const
			{
				bn2buf (bn, buf, len);
				// To Little Endian
				for (size_t i = 0; i < len/2; i++) // invert bytes
				{
					uint8_t tmp = buf[i];
					buf[i] = buf[len -1 - i];
					buf[len -1 - i] = tmp;
				}	
			}

		private:
			
			BIGNUM * q, * l, * d, * I; 
			EDDSAPoint B; // base point
			// transient values
			BIGNUM * q_2; // q-2
			BIGNUM * two_252_2; // 2^252-2
			EDDSAPoint Bi16[64][15]; // per 4-bits, Bi16[i][j] = (16+j+1)^i*B, we don't store zeroes
	};

	static std::unique_ptr<Ed25519> g_Ed25519;
	std::unique_ptr<Ed25519>& GetEd25519 ()
	{
		if (!g_Ed25519)
			g_Ed25519.reset (new Ed25519 ());
		return g_Ed25519; 
	}	
	

	EDDSA25519Verifier::EDDSA25519Verifier (const uint8_t * signingKey):
		m_Ctx (BN_CTX_new ()),
		m_PublicKey (GetEd25519 ()->DecodePublicKey (signingKey, m_Ctx))
	{
		memcpy (m_PublicKeyEncoded, signingKey, EDDSA25519_PUBLIC_KEY_LENGTH); 
	}

	bool EDDSA25519Verifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		SHA512_CTX ctx;
		SHA512_Init (&ctx);
		SHA512_Update (&ctx, signature, EDDSA25519_SIGNATURE_LENGTH/2); // R
		SHA512_Update (&ctx, m_PublicKeyEncoded, EDDSA25519_PUBLIC_KEY_LENGTH); // public key
		SHA512_Update (&ctx, buf, len); // data
		uint8_t digest[64];
		SHA512_Final (digest, &ctx);
		return GetEd25519 ()->Verify (m_PublicKey, digest, signature, m_Ctx);
	}

	EDDSA25519Signer::EDDSA25519Signer (const uint8_t * signingPrivateKey):
		m_Ctx (BN_CTX_new ())
	{ 
		// expand key
		SHA512 (signingPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH, m_ExpandedPrivateKey);
		m_ExpandedPrivateKey[0] &= 0xF8; // drop last 3 bits 
		m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] &= 0x1F; // drop first 3 bits
		m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] |= 0x40; // set second bit
		// generate and encode public key
		auto publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, m_Ctx);
		GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded);	
	} 
		
	void EDDSA25519Signer::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		GetEd25519 ()->Sign (m_ExpandedPrivateKey, m_PublicKeyEncoded, buf, len, signature, m_Ctx);
	}	
}
}


