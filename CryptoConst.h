#ifndef CRYPTO_CONST_H__
#define CRYPTO_CONST_H__

#include <cryptopp/integer.h>

namespace i2p
{
namespace crypto
{
	// DH	
	const CryptoPP::Integer& elgp();
	const CryptoPP::Integer& elgg();

	// DSA
	const CryptoPP::Integer& dsap();
	const CryptoPP::Integer& dsaq();
	const CryptoPP::Integer& dsag();
}		
}	

#endif
