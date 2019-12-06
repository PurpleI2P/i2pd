#include "Crypto.h"
#include "Elligator.h"

namespace i2p
{
namespace crypto
{
	static const uint8_t u_[32] = 
	{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	
	Elligator2::Elligator2 ()
	{
		// TODO: share with Ed22519
		p = BN_new ();
		// 2^255-19
		BN_set_bit (p, 255); // 2^255
		BN_sub_word (p, 19);
		p38 = BN_dup (p); BN_add_word (p38, 3); BN_div_word (p38, 8); // (p+3)/8
		p12 = BN_dup (p); BN_sub_word (p12, 1); BN_div_word (p12, 2); // (p-1)/2
		n1 = BN_dup (p); BN_sub_word (n1, 1); // p-1
		n2 = BN_dup (p); BN_sub_word (n2, 2); // p-2

		A = BN_new (); BN_set_word (A, 486662);
		nA = BN_new (); BN_sub  (nA, p, A);

		BN_CTX * ctx = BN_CTX_new ();	
		// calculate sqrt(-1)		
		sqrtn1 = BN_new ();
		BN_mod_exp (sqrtn1, n1, p38, p, ctx); // (-1)^((p+3)/8)		
		auto p14 = BN_dup (p); BN_sub_word (p14, 1); BN_div_word (p14, 4); // (p-1)/4
		auto tmp = BN_new (); BN_set_word (tmp, 2);	
		BN_mod_exp (tmp, tmp, p14, p, ctx); // 2^((p-1)/4
		BN_mod_mul (sqrtn1, tmp, sqrtn1, p, ctx); // 2^((p-1)/4 * (-1)^((p+3)/8)
		BN_free (p14); 
		
		u = BN_new (); BN_bin2bn (u_, 32, u); // TODO: endianess
		iu = BN_new (); BN_mod_inverse (iu, u, p, ctx);	

		// calculate d = -121665*inv(121666)
		d = BN_new ();
		BN_set_word (tmp, 121666);
		BN_mod_inverse (tmp, tmp, p, ctx);
		BN_set_word (d, 121665);
		BN_set_negative (d, 1);
		BN_mod_mul (d, d, tmp, p, ctx);
		BN_free (tmp);
		//printf ("%s\n", BN_bn2hex (d));

		BN_CTX_free (ctx);
	}

	Elligator2::~Elligator2 ()
	{
		BN_free (p); BN_free (p38); BN_free (p12);
		BN_free (n1);BN_free (n2); BN_free (sqrtn1);
		BN_free (A); BN_free (nA);
		BN_free (u); BN_free (iu); BN_free (d);
	}

	void Elligator2::Encode (const uint8_t * key, uint8_t * encoded) const
	{
		BN_CTX * ctx = BN_CTX_new ();
		BN_CTX_start (ctx);

		BIGNUM * a = BN_CTX_get (ctx); BN_bin2bn (key, 32, a);
		BIGNUM * b = BN_CTX_get (ctx);
		BN_add (a, A, b);
		BIGNUM * c = BN_CTX_get (ctx);
		BN_mod_exp (c, b, n2, p, ctx);		
		BN_mod_mul (b, c, a, p, ctx);
		BN_sub (b, p, b);

		//BN_mod_exp (c, b, n2, p, ctx);	
		
		BN_mod_mul (c, b, iu, p, ctx);
		// TODO:
		bn2buf (b, encoded, 32);

		BN_CTX_end (ctx);	
		BN_CTX_free (ctx);
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

