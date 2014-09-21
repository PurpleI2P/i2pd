#ifndef CRYPTO_CONST_H__
#define CRYPTO_CONST_H__

#include <cryptopp/integer.h>

namespace i2p
{
namespace crypto
{
	struct CryptoConstants
	{
		// DH/ElGamal
		const CryptoPP::Integer elgp;
		const CryptoPP::Integer elgg; 

		// DSA
		const CryptoPP::Integer dsap;		
		const CryptoPP::Integer dsaq;
		const CryptoPP::Integer dsag;			
	};	
	
	const CryptoConstants& GetCryptoConstants ();
	
	// DH/ElGamal	
	#define elgp GetCryptoConstants ().elgp
	#define elgg GetCryptoConstants ().elgg

	// DSA
	#define dsap GetCryptoConstants ().dsap	
	#define dsaq GetCryptoConstants ().dsaq
	#define dsag GetCryptoConstants ().dsag		
}		
}	

#endif
