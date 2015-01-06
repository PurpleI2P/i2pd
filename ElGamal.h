#ifndef EL_GAMAL_H__
#define EL_GAMAL_H__

#include <inttypes.h>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>
#include <cryptopp/sha.h>
#include "CryptoConst.h"
#include "Log.h"

namespace i2p
{
namespace crypto
{

	class ElGamalEncryption
	{
		public:

			ElGamalEncryption (const uint8_t * key):
				y (key, 256), k (rnd, CryptoPP::Integer::One(), elgp-1),
				a (a_exp_b_mod_c (elgg, k, elgp)), b1 (a_exp_b_mod_c (y, k, elgp))
			{
			}

			void Encrypt (const uint8_t * data, int len, uint8_t * encrypted, bool zeroPadding = false)
			{
				// calculate b = b1*m mod p
				uint8_t m[255];
				m[0] = 0xFF;
				memcpy (m+33, data, len);
				CryptoPP::SHA256().CalculateDigest(m+1, m+33, 222);
				CryptoPP::Integer b (a_times_b_mod_c (b1, CryptoPP::Integer (m, 255), elgp));

				// copy a and b
				if (zeroPadding)
				{
					encrypted[0] = 0;
					a.Encode (encrypted + 1, 256);
					encrypted[257] = 0;
					b.Encode (encrypted + 258, 256);
				}	
				else
				{
					a.Encode (encrypted, 256);	
					b.Encode (encrypted + 256, 256);
				}	
			}

		private:

			CryptoPP::AutoSeededRandomPool rnd;	
			CryptoPP::Integer y, k, a, b1;	
	};

	inline bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted, 
		uint8_t * data, bool zeroPadding = false)
	{
		CryptoPP::Integer x(key, 256), a(zeroPadding? encrypted +1 : encrypted, 256), 
			b(zeroPadding? encrypted + 258 :encrypted + 256, 256);
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

	inline void GenerateElGamalKeyPair (CryptoPP::RandomNumberGenerator& rnd, uint8_t * priv, uint8_t * pub)
	{
#if defined(__x86_64__) || defined(__i386__) || defined(_MSC_VER)	
		rnd.GenerateBlock (priv, 256);
		a_exp_b_mod_c (elgg, CryptoPP::Integer (priv, 256), elgp).Encode (pub, 256);
#else
		CryptoPP::DH dh (elgp, elgg);
		dh.GenerateKeyPair(rnd, priv, pub);	
#endif		
	}	
}
}	

#endif
