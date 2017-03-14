#include <array>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "Gost.h"

namespace i2p
{
namespace crypto
{

// GOST R 34.10

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
			}, // C
			{
				"C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
				"295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
				"400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
				"91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
				"32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"		
			}, // tc26-2012-paramSetA-256
			{
				"DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
				"B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",	
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
				"3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
				"E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
				"F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED27EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"	
			} // tc26-2012-paramSetC-256
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
