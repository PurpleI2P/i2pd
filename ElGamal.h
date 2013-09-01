#ifndef EL_GAMAL_H__
#define EL_GAMAL_H__

#include <inttypes.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include "CryptoConst.h"
#include "Log.h"

namespace i2p
{
namespace crypto
{
	inline void ElGamalEncrypt (const uint8_t * key, const uint8_t * data, int len, uint8_t * encrypted)
	{
		CryptoPP::AutoSeededRandomPool rnd;		
		CryptoPP::Integer y(key, 256), k(rnd, CryptoPP::Integer::One(), elgp-1);

		a_exp_b_mod_c (elgg, k, elgp).Encode (encrypted, 256);
		uint8_t m[255];
		m[0] = 0xFF;
		memcpy (m+33, data, len);
		CryptoPP::SHA256().CalculateDigest(m+1, m+33, 222);
		a_times_b_mod_c (a_exp_b_mod_c (y, k, elgp), 
			CryptoPP::Integer (m, 255), elgp).Encode (encrypted + 256, 256);
	}	

	inline bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted, uint8_t * data)
	{
		CryptoPP::Integer x(key, 256), a(encrypted, 256), b(encrypted + 256, 256);
		uint8_t m[255], hash[32];
		a_times_b_mod_c (b, a_exp_b_mod_c (a, elgp - x - 1, elgp), elgp).Encode (m, 255);
		CryptoPP::SHA256().CalculateDigest(hash, m+33, 222);
		for (int i = 0; i < 32; i++)
			if (hash[i] != m[i+1])
			{
				LogPrint ("ElGamal decrypt hash doesn't match");
				return false;
			}
		memcpy (data, m + 33, 222);
		return true;
	}	
}
}	

#endif
