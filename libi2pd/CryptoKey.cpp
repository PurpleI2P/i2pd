#include "CryptoKey.h"

namespace i2p
{
namespace crypto
{
	void CreateECIESP256RandomKeys (uint8_t * priv, uint8_t * pub)
	{
		EC_GROUP * curve = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
		EC_POINT * p = nullptr; 
		BIGNUM * key = nullptr;
		GenerateECIESKeyPair (curve, key, p);
		bn2buf (key, priv, 32);
		RAND_bytes (priv + 32, 224);
		BN_free (key);
		BIGNUM * x = BN_new (), * y = BN_new ();
		EC_POINT_get_affine_coordinates_GFp (curve, p, x, y, NULL);
		bn2buf (x, pub, 32);
		bn2buf (y, pub + 32, 32);				
		RAND_bytes (priv + 64, 192);
		EC_POINT_free (p); 
		BN_free (x); BN_free (y);
		EC_GROUP_free (curve);	
	}
}
}

