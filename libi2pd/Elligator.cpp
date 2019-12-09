#include "Crypto.h"
#include "Elligator.h"

namespace i2p
{
namespace crypto
{
	
	Elligator2::Elligator2 ()
	{
		// TODO: share with Ed22519
		p = BN_new ();
		// 2^255-19
		BN_set_bit (p, 255); // 2^255
		BN_sub_word (p, 19);
		p38 = BN_dup (p); BN_add_word (p38, 3); BN_div_word (p38, 8); // (p+3)/8
		p12 = BN_dup (p); BN_sub_word (p12, 1); BN_div_word (p12, 2); // (p-1)/2
		p14 = BN_dup (p); BN_sub_word (p14, 1); BN_div_word (p14, 4); // (p-1)/4

		auto A = BN_new (); BN_set_word (A, 486662);
		nA = BN_new (); BN_sub  (nA, p, A);

		BN_CTX * ctx = BN_CTX_new ();	
		// calculate sqrt(-1)		
		sqrtn1 = BN_new ();
		BN_set_word (sqrtn1, 2);	
		BN_mod_exp (sqrtn1, sqrtn1, p14, p, ctx); // 2^((p-1)/4
		
		u = BN_new (); BN_set_word (u, 2);
		iu = BN_new (); BN_mod_inverse (iu, u, p, ctx);	
		//printf ("%s\n", BN_bn2hex (iu));

		BN_CTX_free (ctx);
	}

	Elligator2::~Elligator2 ()
	{
		BN_free (p); BN_free (p38); BN_free (p12); BN_free (p14);
		BN_free (sqrtn1); BN_free (A); BN_free (nA); 
		BN_free (u); BN_free (iu); 
	}

	void Elligator2::Encode (const uint8_t * key, uint8_t * encoded) const
	{
		BN_CTX * ctx = BN_CTX_new ();
		BN_CTX_start (ctx);

		uint8_t key1[32];	
		for (size_t i = 0; i < 16; i++) // from Little Endian
		{
			key1[i] = key[15 - i];
			key1[15 - i] = key[i];
		}

		BIGNUM * x = BN_CTX_get (ctx); BN_bin2bn (key1, 32, x);
		BIGNUM * xA = BN_CTX_get (ctx); BN_add (xA, x, A); // x + A
		BN_sub (xA, p, xA); // p - (x + A)

		BIGNUM * r = BN_CTX_get (ctx);
		BN_mod_inverse (r, xA, p, ctx);	
		BN_mod_mul (r, r, x, p, ctx);	
		BN_mod_mul (r, r, iu, p, ctx);	
		
		SquareRoot (r, r, ctx);
		bn2buf (r, encoded, 32);
		
		for (size_t i = 0; i < 16; i++) // To Little Endian
		{
			uint8_t tmp = encoded[i];
			encoded[i] = encoded[15 - i];
			encoded[15 - i] = tmp;
		}

		BN_CTX_end (ctx);	
		BN_CTX_free (ctx);
	}

	void Elligator2::Decode (const uint8_t * encoded, uint8_t * key) const
	{
		BN_CTX * ctx = BN_CTX_new ();
		BN_CTX_start (ctx);

		uint8_t encoded1[32];	
		for (size_t i = 0; i < 16; i++) // from Little Endian
		{
			encoded1[i] = encoded[15 - i];
			encoded1[15 - i] = encoded[i];
		}

		BIGNUM * r = BN_CTX_get (ctx); BN_bin2bn (encoded1, 32, r);

		// v=-A/(1+u*r^2)
		BIGNUM * v = BN_CTX_get (ctx); BN_mod_sqr (v, r, p, ctx); 
		BN_mod_mul (v, v, u, p, ctx);
		BN_add_word (v, 1);
		BN_mod_inverse (v, v, p, ctx);	
		BN_mod_mul (v, v, nA, p, ctx);

		BIGNUM * vpA = BN_CTX_get (ctx);
		BN_add (vpA, v, A); // v + A
		// t = v^3+A*v^2+v = v^2*(v+A)+v
		BIGNUM * t = BN_CTX_get (ctx); BN_mod_sqr (t, v, p, ctx); 
		BN_mod_mul (t, t, vpA, p, ctx);		
		BN_mod_add (t, t, v, p, ctx);		

		int legendre = 0; // TODO:
		BIGNUM * x = BN_CTX_get (ctx);
		if (legendre == 1)
			BN_copy (x, v);
		else
		{
			BN_sub (x, p, v);
			BN_mod_sub (x, x, A, p, ctx);
		}	
		
		bn2buf (x, key, 32);	
		for (size_t i = 0; i < 16; i++) // To Little Endian
		{
			uint8_t tmp = key[i];
			key[i] = key[15 - i];
			key[15 - i] = tmp;
		}


		BN_CTX_end (ctx);	
		BN_CTX_free (ctx);
	}

	void Elligator2::SquareRoot (const BIGNUM * x, BIGNUM * r, BN_CTX * ctx) const
	{
		BIGNUM * t = BN_CTX_get (ctx);
		BN_mod_exp (t, x, p14, p, ctx); // t = x^((p-1)/4)
		BN_mod_exp (r, x, p38, p, ctx); // r = x^((p+3)/8)
		BN_add_word (t, 1);

		if (!BN_cmp (t, p))
			BN_mod_mul (r, r, sqrtn1, p, ctx);	

		if (BN_cmp (r, p12) > 0) // r > (p-1)/2
			BN_sub (r, p, r);
	}	
	
	static std::unique_ptr<Elligator2> g_Elligator;
	std::unique_ptr<Elligator2>& GetElligator ()
	{
		if (!g_Elligator)
		{
			auto el = new Elligator2();
			if (!g_Elligator) // make sure it was not created already
				g_Elligator.reset (el);
			else
				delete el;
		}
		return g_Elligator;
	}
}
}

