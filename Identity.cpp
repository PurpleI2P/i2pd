#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "Identity.h"

namespace i2p
{
namespace data
{
	Identity& Identity::operator=(const Keys& keys)
	{
		// copy public and signing keys together
		memcpy (publicKey, keys.publicKey, sizeof (publicKey) + sizeof (signingKey));
		memset (certificate, 0, sizeof (certificate));		
		return *this;
	}	
	
	IdentHash CalculateIdentHash (const Identity& identity)
	{
		IdentHash hash;
		CryptoPP::SHA256().CalculateDigest((uint8_t *)hash, (uint8_t *)&identity, sizeof (Identity));
		return hash;
	}

	Keys CreateRandomKeys ()
	{
		Keys keys;		
		CryptoPP::AutoSeededRandomPool rnd;

		// encryption
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(rnd, keys.privateKey, keys.publicKey);

		// signing
		CryptoPP::DSA::PrivateKey privateKey;
		CryptoPP::DSA::PublicKey publicKey;
		privateKey.Initialize (rnd, i2p::crypto::dsap, i2p::crypto::dsaq, i2p::crypto::dsag);
		privateKey.MakePublicKey (publicKey);
		privateKey.GetPrivateExponent ().Encode (keys.signingPrivateKey, 20);	
		publicKey.GetPublicElement ().Encode (keys.signingKey, 128);
		
		return keys;
	}	
}
}
