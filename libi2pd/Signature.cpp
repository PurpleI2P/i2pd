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
				BIGNUM * tmp = BN_new ();

				q = BN_new ();
				// 2^255-19				
				BN_set_bit (q, 255); // 2^255 
				BN_sub_word (q, 19);
				
				l = BN_new ();
				// 2^252 + 27742317777372353535851937790883648493
				BN_set_bit (l, 252);
				two_252_2 = BN_dup (l);
				BN_dec2bn (&tmp, "27742317777372353535851937790883648493");
				BN_add (l, l, tmp);		
				BN_sub_word (two_252_2, 2); // 2^252 - 2		

				 // -121665*inv(121666)
				d = BN_new ();
				BN_set_word (tmp, 121666);
				BN_mod_inverse (tmp, tmp, q, ctx);	
				BN_set_word (d, 121665);
				BN_set_negative (d, 1);							
				BN_mul (d, d, tmp, ctx);

				// 2^((q-1)/4)
				I = BN_new ();
				BN_free (tmp);
				tmp = BN_dup (q);
				BN_sub_word (tmp, 1);
				BN_div_word (tmp, 4);	
				BN_set_word (I, 2);
				BN_mod_exp (I, I, tmp, q, ctx);
				BN_free (tmp);	
				
				// 4*inv(5)	
				BIGNUM * By = BN_new ();		
				BN_set_word (By, 5);
				BN_mod_inverse (By, By, q, ctx);	
				BN_mul_word (By, 4);
				BIGNUM * Bx = RecoverX (By, ctx);	
				BN_mod (Bx, Bx, q, ctx); // % q
				BN_mod (By, By, q, ctx); // % q										
			
				// precalculate Bi256 table
				Bi256Carry = { Bx, By };  // B
				for (int i = 0; i < 32; i++)
				{
					Bi256[i][0] = Bi256Carry; // first point
					for (int j = 1; j < 128; j++)
						Bi256[i][j] = Sum (Bi256[i][j-1], Bi256[i][0], ctx); // (256+j+1)^i*B
					Bi256Carry = Bi256[i][127];
					for (int j = 0; j < 128; j++) // add first point 128 more times
						Bi256Carry = Sum (Bi256Carry, Bi256[i][0], ctx);
				}

				BN_CTX_free (ctx);
			}

			Ed25519 (const Ed25519& other): q (BN_dup (other.q)), l (BN_dup (other.l)), 
				d (BN_dup (other.d)), I (BN_dup (other.I)), two_252_2 (BN_dup (other.two_252_2)),
				Bi256Carry (other.Bi256Carry)
			{
				for (int i = 0; i < 32; i++)
					for (int j = 0; j < 128; j++)
						Bi256[i][j] = other.Bi256[i][j];
			}

			~Ed25519 ()
			{
				BN_free (q);
				BN_free (l);
				BN_free (d);
				BN_free (I);
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

			void EncodePublicKey (const EDDSAPoint& publicKey, uint8_t * buf, BN_CTX * ctx) const
			{
				EncodePoint (Normalize (publicKey, ctx), buf);
			}

			bool Verify (const EDDSAPoint& publicKey, const uint8_t * digest, const uint8_t * signature) const
			{
				BN_CTX * ctx = BN_CTX_new ();	
				BIGNUM * h = DecodeBN<64> (digest);
				// signature 0..31 - R, 32..63 - S 
				// B*S = R + PK*h => R = B*S - PK*h
				// we don't decode R, but encode (B*S - PK*h)
				auto Bs = MulB (signature + EDDSA25519_SIGNATURE_LENGTH/2, ctx); // B*S;
				BN_mod (h, h, l, ctx); // public key is multiple of B, but B%l = 0
				auto PKh = Mul (publicKey, h, ctx); // PK*h
				uint8_t diff[32];
				EncodePoint (Normalize (Sum (Bs, -PKh, ctx), ctx), diff); // Bs - PKh encoded
				bool passed = !memcmp (signature, diff, 32); // R
				BN_free (h); 
				BN_CTX_free (ctx);
				if (!passed)
					LogPrint (eLogError, "25519 signature verification failed");
				return passed; 
			}

			void Sign (const uint8_t * expandedPrivateKey, const uint8_t * publicKeyEncoded, const uint8_t * buf, size_t len, 
				uint8_t * signature) const
			{
				BN_CTX * bnCtx = BN_CTX_new ();
				// calculate r
				SHA512_CTX ctx;
				SHA512_Init (&ctx);
				SHA512_Update (&ctx, expandedPrivateKey + EDDSA25519_PRIVATE_KEY_LENGTH, EDDSA25519_PRIVATE_KEY_LENGTH); // right half of expanded key
				SHA512_Update (&ctx, buf, len); // data
				uint8_t digest[64];
				SHA512_Final (digest, &ctx);
				BIGNUM * r = DecodeBN<32> (digest); // DecodeBN<64> (digest); // for test vectors
				// calculate R
				uint8_t R[EDDSA25519_SIGNATURE_LENGTH/2]; // we must use separate buffer because signature might be inside buf
				EncodePoint (Normalize (MulB (digest, bnCtx), bnCtx), R); // EncodePoint (Mul (B, r, bnCtx), R); // for test vectors 
				// calculate S
				SHA512_Init (&ctx);
				SHA512_Update (&ctx, R, EDDSA25519_SIGNATURE_LENGTH/2); // R
				SHA512_Update (&ctx, publicKeyEncoded, EDDSA25519_PUBLIC_KEY_LENGTH); // public key
				SHA512_Update (&ctx, buf, len); // data
				SHA512_Final (digest, &ctx);
				BIGNUM * h = DecodeBN<64> (digest);			
				// S = (r + h*a) % l
				BIGNUM * a = DecodeBN<EDDSA25519_PRIVATE_KEY_LENGTH> (expandedPrivateKey); // left half of expanded key
				BN_mod_mul (h, h, a, l, bnCtx); // %l
				BN_mod_add (h, h, r, l, bnCtx); // %l
				memcpy (signature, R, EDDSA25519_SIGNATURE_LENGTH/2);
				EncodeBN (h, signature + EDDSA25519_SIGNATURE_LENGTH/2, EDDSA25519_SIGNATURE_LENGTH/2); // S
				BN_free (r); BN_free (h); BN_free (a);
				BN_CTX_free (bnCtx);
			}

		private:		

			EDDSAPoint Sum (const EDDSAPoint& p1, const EDDSAPoint& p2, BN_CTX * ctx) const
			{
				// x3 = (x1*y2+y1*x2)*(z1*z2-d*t1*t2)
				// y3 = (y1*y2+x1*x2)*(z1*z2+d*t1*t2)
				// z3 = (z1*z2-d*t1*t2)*(z1*z2+d*t1*t2)
				// t3 = (y1*y2+x1*x2)*(x1*y2+y1*x2)
				BIGNUM * x3 = BN_new (), * y3 = BN_new (), * z3 = BN_new (), * t3 = BN_new ();
				
				BN_mul (x3, p1.x, p2.x, ctx); // A = x1*x2		
				BN_mul (y3, p1.y, p2.y, ctx); // B = y1*y2	

				BN_CTX_start (ctx);
				BIGNUM * t1 = p1.t, * t2 = p2.t;
				if (!t1) { t1 = BN_CTX_get (ctx); BN_mul (t1, p1.x, p1.y, ctx); }
				if (!t2) { t2 = BN_CTX_get (ctx); BN_mul (t2, p2.x, p2.y, ctx); }
				BN_mul (t3, t1, t2, ctx);
				BN_mul (t3, t3, d, ctx);  // C = d*t1*t2

				if (p1.z)
				{
					if (p2.z)
						BN_mul (z3, p1.z, p2.z, ctx); // D = z1*z2
					else
						BN_copy (z3, p1.z); // D = z1
				}
				else
				{
					if (p2.z)
						BN_copy (z3, p2.z); // D = z2
					else
						BN_one (z3); // D = 1
				}	

				BIGNUM * E = BN_CTX_get (ctx), * F = BN_CTX_get (ctx), * G = BN_CTX_get (ctx), * H = BN_CTX_get (ctx);
				BN_add (E, p1.x, p1.y);				
				BN_add (F, p2.x, p2.y);
				BN_mul (E, E, F, ctx); // (x1 + y1)*(x2 + y2)
				BN_sub (E, E, x3);
				BN_sub (E, E, y3); // E = (x1 + y1)*(x2 + y2) - A - B
				BN_sub (F, z3, t3); // F = D - C
				BN_add (G, z3, t3); // G = D + C
				BN_add (H, y3, x3); // H = B + A

				BN_mod_mul (x3, E, F, q, ctx); // x3 = E*F
				BN_mod_mul (y3, G, H, q, ctx); // y3 = G*H	
				BN_mod_mul (z3, F, G, q, ctx); // z3 = F*G	
				BN_mod_mul (t3, E, H, q, ctx); // t3 = E*H	

				BN_CTX_end (ctx);

				return EDDSAPoint {x3, y3, z3, t3};
			}

			void Double (EDDSAPoint& p, BN_CTX * ctx) const
			{
				BN_CTX_start (ctx);
				BIGNUM * x2 = BN_CTX_get (ctx), * y2 = BN_CTX_get (ctx), * z2 = BN_CTX_get (ctx), * t2 = BN_CTX_get (ctx);
				
				BN_sqr (x2, p.x, ctx); // x2 = A = x^2		
				BN_sqr (y2, p.y, ctx); // y2 = B = y^2	
				if (p.t)
					BN_sqr (t2, p.t, ctx); // t2 = t^2
				else
				{
					BN_mul (t2, p.x, p.y, ctx); // t = x*y
					BN_sqr (t2, t2, ctx);  // t2 = t^2
				}	
				BN_mul (t2, t2, d, ctx);  // t2 = C = d*t^2 	
				if (p.z)
					BN_sqr (z2, p.z, ctx); // z2 = D = z^2 		
				else
					BN_one (z2); // z2 = 1

				BIGNUM * E = BN_CTX_get (ctx), * F = BN_CTX_get (ctx), * G = BN_CTX_get (ctx), * H = BN_CTX_get (ctx);
				// E = (x+y)*(x+y)-A-B = x^2+y^2+2xy-A-B = 2xy
				BN_mul (E, p.x, p.y, ctx);
				BN_lshift1 (E, E);	// E =2*x*y							
				BN_sub (F, z2, t2); // F = D - C
				BN_add (G, z2, t2); // G = D + C 
				BN_add (H, y2, x2); // H = B + A

				BN_mod_mul (p.x, E, F, q, ctx); // x2 = E*F
				BN_mod_mul (p.y, G, H, q, ctx); // y2 = G*H	
				if (!p.z) p.z = BN_new ();
				BN_mod_mul (p.z, F, G, q, ctx); // z2 = F*G	
				if (!p.t) p.t = BN_new ();
				BN_mod_mul (p.t, E, H, q, ctx); // t2 = E*H	

				BN_CTX_end (ctx);
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
						Double (res, ctx);
						if (BN_is_bit_set (e, i)) res = Sum (res, p, ctx);
					}
				}	
				return res;
			} 
			
			EDDSAPoint MulB (const uint8_t * e, BN_CTX * ctx) const // B*e, e is 32 bytes Little Endian
			{
				BIGNUM * zero = BN_new (), * one = BN_new ();
				BN_zero (zero); BN_one (one);
				EDDSAPoint res {zero, one};
				bool carry = false;
				for (int i = 0; i < 32; i++)
				{
					uint8_t x = e[i];
					if (carry) 
					{ 
						if (x < 255) 
						{ 
							x++; 
							carry = false;
						} 
						else 
							x = 0; 
					}
					if (x > 0)
					{
						if (x <= 128)
							res = Sum (res, Bi256[i][x-1], ctx);
						else
						{
							res = Sum (res, -Bi256[i][255-x], ctx); // -Bi[256-x]
							carry = true;
						}		
					}
				}
				if (carry) res = Sum (res, Bi256Carry, ctx);
				return res;
			}

			EDDSAPoint Normalize (const EDDSAPoint& p, BN_CTX * ctx) const
			{
				if (p.z)
				{
					BIGNUM * x = BN_new (), * y = BN_new ();
					BN_mod_inverse (y, p.z, q, ctx);
					BN_mod_mul (x, p.x, y, q, ctx); // x = x/z
					BN_mod_mul (y, p.y, y, q, ctx); // y = y/z
					return  EDDSAPoint{x, y};
				}
				else
					return EDDSAPoint{BN_dup (p.x), BN_dup (p.y)};
			}

			bool IsOnCurve (const EDDSAPoint& p, BN_CTX * ctx) const
			{
				BN_CTX_start (ctx);
				BIGNUM * x2 = BN_CTX_get (ctx), * y2 = BN_CTX_get (ctx), * tmp = BN_CTX_get (ctx);
				BN_sqr (x2, p.x, ctx); // x^2
				BN_sqr (y2, p.y, ctx); // y^2
				// y^2 - x^2 - 1 - d*x^2*y^2 			
				BN_mul (tmp, d, x2, ctx);
				BN_mul (tmp, tmp, y2, ctx);	
				BN_sub (tmp, y2, tmp);
				BN_sub (tmp, tmp, x2);
				BN_sub_word (tmp, 1);
				BN_mod (tmp, tmp, q, ctx); // % q
				bool ret = BN_is_zero (tmp);
				BN_CTX_end (ctx);
				return ret;
			}	

			BIGNUM * RecoverX (const BIGNUM * y, BN_CTX * ctx) const
			{
				BN_CTX_start (ctx);
				BIGNUM * y2 = BN_CTX_get (ctx), * xx = BN_CTX_get (ctx);
				BN_sqr (y2, y, ctx); // y^2
				// xx = (y^2 -1)*inv(d*y^2 +1) 
				BN_mul (xx, d, y2, ctx);
				BN_add_word (xx, 1);
				BN_mod_inverse (xx, xx, q, ctx);
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
				BN_CTX_end (ctx);
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
				BIGNUM * x = RecoverX (y, ctx);
				if (BN_is_bit_set (x, 0) != isHighestBitSet)
					BN_sub (x, q, x); // x = q - x 
				BIGNUM * z = BN_new (), * t = BN_new (); 
				BN_one (z); BN_mod_mul (t, x, y, q, ctx); // pre-calculate t
				EDDSAPoint p {x, y, z, t};
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

			template<int len>
			BIGNUM * DecodeBN (const uint8_t * buf) const
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
			// transient values
			BIGNUM * two_252_2; // 2^252-2
			EDDSAPoint Bi256[32][128]; // per byte, Bi256[i][j] = (256+j+1)^i*B, we don't store zeroes
			// if j > 128 we use 256 - j and carry 1 to next byte
			// Bi256[0][0] = B, base point
			EDDSAPoint Bi256Carry; // Bi256[32][0]
	};

	static std::unique_ptr<Ed25519> g_Ed25519;
	std::unique_ptr<Ed25519>& GetEd25519 ()
	{
		if (!g_Ed25519)
		{
			auto c = new Ed25519();
			if (!g_Ed25519) // make sure it was not created already
				g_Ed25519.reset (c);
			else
				delete c;
		}	
		return g_Ed25519; 
	}	
	

	EDDSA25519Verifier::EDDSA25519Verifier (const uint8_t * signingKey)
	{
		memcpy (m_PublicKeyEncoded, signingKey, EDDSA25519_PUBLIC_KEY_LENGTH); 
		BN_CTX * ctx = BN_CTX_new ();
		m_PublicKey = GetEd25519 ()->DecodePublicKey (m_PublicKeyEncoded, ctx);
		BN_CTX_free (ctx);
	}

	bool EDDSA25519Verifier::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
	{
		uint8_t digest[64];
		SHA512_CTX ctx;
		SHA512_Init (&ctx);
		SHA512_Update (&ctx, signature, EDDSA25519_SIGNATURE_LENGTH/2); // R
		SHA512_Update (&ctx, m_PublicKeyEncoded, EDDSA25519_PUBLIC_KEY_LENGTH); // public key
		SHA512_Update (&ctx, buf, len); // data	
		SHA512_Final (digest, &ctx);
		
		return GetEd25519 ()->Verify (m_PublicKey, digest, signature);
	}

	EDDSA25519Signer::EDDSA25519Signer (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
	{ 
		// expand key
		SHA512 (signingPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH, m_ExpandedPrivateKey);
		m_ExpandedPrivateKey[0] &= 0xF8; // drop last 3 bits 
		m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] &= 0x3F; // drop first 2 bits
		m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] |= 0x40; // set second bit
		
		// generate and encode public key
		BN_CTX * ctx = BN_CTX_new ();	
		auto publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
		GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);	
		
		if (signingPublicKey && memcmp (m_PublicKeyEncoded, signingPublicKey, EDDSA25519_PUBLIC_KEY_LENGTH))
		{
			// keys don't match, it means older key with 0x1F
			LogPrint (eLogWarning, "Older EdDSA key detected");
			m_ExpandedPrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH - 1] &= 0xDF; // drop third bit 
			publicKey = GetEd25519 ()->GeneratePublicKey (m_ExpandedPrivateKey, ctx);
			GetEd25519 ()->EncodePublicKey (publicKey, m_PublicKeyEncoded, ctx);	
		}
		BN_CTX_free (ctx);
	} 
		
	void EDDSA25519Signer::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		GetEd25519 ()->Sign (m_ExpandedPrivateKey, m_PublicKeyEncoded, buf, len, signature);
	}	
}
}


