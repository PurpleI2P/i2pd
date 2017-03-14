#include <array>
#include <openssl/evp.h>
#include "Gost.h"

namespace i2p
{
namespace crypto
{
	GOSTR3410Curve::GOSTR3410Curve (BIGNUM * a, BIGNUM * b, BIGNUM * p, BIGNUM * q, BIGNUM * x, BIGNUM * y)
	{
		BN_CTX * ctx = BN_CTX_new ();
		m_Group = EC_GROUP_new_curve_GFp (p, a, b, ctx);
		EC_POINT * P = EC_POINT_new (m_Group);
		EC_POINT_set_affine_coordinates_GFp (m_Group, P, x, y, ctx);
		EC_GROUP_set_generator (m_Group, P, q, nullptr);
		EC_GROUP_set_curve_name (m_Group, NID_id_GostR3410_2001);
		EC_POINT_free(P);
		BN_CTX_free (ctx);
	}

	GOSTR3410Curve::~GOSTR3410Curve ()
	{
		EC_GROUP_free (m_Group);
	}				

	EC_POINT * GOSTR3410Curve::MulP (const BIGNUM * n) const
	{
		BN_CTX * ctx = BN_CTX_new ();
		auto p = EC_POINT_new (m_Group);
		EC_POINT_mul (m_Group, p, n, nullptr, nullptr, ctx);
		BN_CTX_free (ctx);
		return p;
	}

	bool GOSTR3410Curve::GetXY (const EC_POINT * p, BIGNUM * x, BIGNUM * y) const
	{
		return EC_POINT_get_affine_coordinates_GFp (m_Group, p, x, y, nullptr);
	}

	EC_POINT * GOSTR3410Curve::CreatePoint (const BIGNUM * x, const BIGNUM * y) const
	{
		EC_POINT * p = EC_POINT_new (m_Group);
		EC_POINT_set_affine_coordinates_GFp (m_Group, p, x, y, nullptr);
		return p;
	}

	void GOSTR3410Curve::Sign (const BIGNUM * priv, const BIGNUM * digest, BIGNUM * r, BIGNUM * s)
	{
		BN_CTX * ctx = BN_CTX_new ();
		BN_CTX_start (ctx);
		BIGNUM * q = BN_CTX_get (ctx);
		EC_GROUP_get_order(m_Group, q, ctx);
		BIGNUM * k = BN_CTX_get (ctx);
		BN_rand_range (k, q); // 0 < k < q
		EC_POINT * C = MulP (k); // C = k*P
		GetXY (C, r, nullptr); // r = Cx
		EC_POINT_free (C);
		BN_mod_mul (s, r, priv, q, ctx); // (r*priv)%q
		BIGNUM * tmp = BN_CTX_get (ctx);
		BN_mod_mul (tmp, k, digest, q, ctx); // (k*digest)%q
		BN_mod_add (s, s, tmp, q, ctx); // (r*priv+k*digest)%q
		BN_CTX_end (ctx);
		BN_CTX_free (ctx);
	}

	bool GOSTR3410Curve::Verify (const EC_POINT * pub, const BIGNUM * digest, const BIGNUM * r, const BIGNUM * s)
	{
		BN_CTX * ctx = BN_CTX_new ();
		BN_CTX_start (ctx);
		BIGNUM * q = BN_CTX_get (ctx);
		EC_GROUP_get_order(m_Group, q, ctx);
		BIGNUM * h = BN_CTX_get (ctx);
		BN_mod (h, digest, q, ctx); // h = digest % q
		BN_mod_inverse (h, h, q, ctx); // 1/h mod q
		BIGNUM * z1 = BN_CTX_get (ctx);
		BN_mod_mul (z1, s, h, q, ctx); // z1 = s/h
		BIGNUM * z2 = BN_CTX_get (ctx);				
		BN_sub (z2, q, r); // z2 = -r
		BN_mod_mul (z2, z2, h, q, ctx); // z2 = -r/h
		EC_POINT * C = EC_POINT_new (m_Group);
		EC_POINT_mul (m_Group, C, z1, pub, z2, ctx); // z1*P + z2*pub
		BIGNUM * x = BN_CTX_get (ctx);	
		GetXY  (C, x, nullptr); // Cx
		BN_mod (x, x, q, ctx); // Cx % q
		bool ret = !BN_cmp (x, r); // Cx = r ?
		EC_POINT_free (C);
		BN_CTX_end (ctx);
		BN_CTX_free (ctx);
		return ret;
	}	

	static GOSTR3410Curve * CreateGOSTR3410Curve (GOSTR3410ParamSet paramSet)
	{
		// a, b, p, q, x, y	
		static const char * params[eGOSTR3410NumParamSets][6] = 
		{
			{ 
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
				"A6",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
				"1",
				"8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"
			}, // A
			{
				"8000000000000000000000000000000000000000000000000000000000000C96",
 				"3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
 				"8000000000000000000000000000000000000000000000000000000000000C99",
 				"800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
				"1",
				"3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"
			}, // B	
			{
				"9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
 				"805A",
 				"9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
 				"9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
 				"0",
				"41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"
			} // C
		};	
		
		BIGNUM * a = nullptr, * b = nullptr, * p = nullptr, * q =nullptr, * x = nullptr, * y = nullptr;
		BN_hex2bn(&a, params[paramSet][0]);
		BN_hex2bn(&b, params[paramSet][1]);
		BN_hex2bn(&p, params[paramSet][2]);
		BN_hex2bn(&q, params[paramSet][3]);
		BN_hex2bn(&x, params[paramSet][4]);
		BN_hex2bn(&y, params[paramSet][5]);
		auto curve = new GOSTR3410Curve (a, b, p, q, x, y);
		BN_free (a); BN_free (b); BN_free (p); BN_free (q); BN_free (x); BN_free (y);
		return curve;
	}	

	static std::array<std::unique_ptr<GOSTR3410Curve>, eGOSTR3410NumParamSets> g_GOSTR3410Curves;
	std::unique_ptr<GOSTR3410Curve>& GetGOSTR3410Curve (GOSTR3410ParamSet paramSet)
	{
		if (!g_GOSTR3410Curves[paramSet])
		{
			auto c = CreateGOSTR3410Curve (paramSet);	
			if (!g_GOSTR3410Curves[paramSet]) // make sure it was not created already
				g_GOSTR3410Curves[paramSet].reset (c);
			else
				delete c;
		}	
		return g_GOSTR3410Curves[paramSet]; 
	}	
	
}
}
