#ifndef CRYPTO_CONST_H__
#define CRYPTO_CONST_H__

#include <cryptopp/integer.h>

namespace i2p
{
namespace crypto
{
	// DH	
	extern const CryptoPP::Integer elgp;
	extern const CryptoPP::Integer elgg; 


	// DSA
	extern const CryptoPP::Integer dsap;		
	extern const CryptoPP::Integer dsaq;
	extern const CryptoPP::Integer dsag;	
}		
}	

#endif
