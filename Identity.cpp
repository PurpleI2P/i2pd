#include <time.h>
#include <stdio.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>
#include <cryptopp/dsa.h>
#include "CryptoConst.h"
#include "Identity.h"
#include "base64.h"

namespace i2p
{
namespace data
{
	Identity& Identity::operator=(const Keys& keys)
	{
		// copy public and signing keys together
		memcpy (publicKey, keys.publicKey, sizeof (publicKey) + sizeof (signingKey));
		memset (&certificate, 0, sizeof (certificate));		
		return *this;
	}

	bool Identity::FromBase64 (const std::string& s)
	{
		size_t count = Base64ToByteStream (s.c_str(), s.length(), publicKey, DEFAULT_IDENTITY_SIZE);
		return count == DEFAULT_IDENTITY_SIZE;
	}

	size_t Identity::FromBuffer (const uint8_t * buf, size_t len)
	{
		memcpy (publicKey, buf, DEFAULT_IDENTITY_SIZE);
		// TODO: process certificate
		return DEFAULT_IDENTITY_SIZE;
	}

	IdentHash Identity::Hash() const 
	{
		IdentHash hash;
		CryptoPP::SHA256().CalculateDigest(hash, publicKey, DEFAULT_IDENTITY_SIZE);
		return hash;
	}	
	
	PrivateKeys& PrivateKeys::operator=(const Keys& keys)
	{
		pub = keys;
		memcpy (privateKey, keys.privateKey, 276); // 256 + 20
		return *this;
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

	void CreateRandomDHKeysPair (DHKeysPair * keys)
	{
		if (!keys) return;
		CryptoPP::AutoSeededRandomPool rnd;
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(rnd, keys->privateKey, keys->publicKey);
	}

	RoutingKey CreateRoutingKey (const IdentHash& ident)
	{
		uint8_t buf[41]; // ident + yyyymmdd
		memcpy (buf, (const uint8_t *)ident, 32);
		time_t t = time (nullptr);
		struct tm tm;
		// WARNING!!! check if it is correct
#ifdef _WIN32
		gmtime_s(&tm, &t);
		// тут возвращается какое-то значение sprintf'ом. может стоит его проверять?
		// http://msdn.microsoft.com/en-us/library/ce3zzk1k.aspx
		sprintf_s((char *)(buf + 32), 9, "%4i%2i%2i", tm.tm_year, tm.tm_mon, tm.tm_mday);
#else
		gmtime_r(&t, &tm);
		// тут возвращается какое-то значение sprintf'ом. может стоит его проверять?
		sprintf((char *)(buf + 32), "%4i%2i%2i", tm.tm_year, tm.tm_mon, tm.tm_mday);
#endif		
		RoutingKey key;
		CryptoPP::SHA256().CalculateDigest(key.hash, buf, 40);
		return key;
	}	
	
	XORMetric operator^(const RoutingKey& key1, const RoutingKey& key2)
	{
		XORMetric m;
		m.metric_ll[0] = key1.hash_ll[0] ^ key2.hash_ll[0];
		m.metric_ll[1] = key1.hash_ll[1] ^ key2.hash_ll[1];
		m.metric_ll[2] = key1.hash_ll[2] ^ key2.hash_ll[2];
		m.metric_ll[3] = key1.hash_ll[3] ^ key2.hash_ll[3];
		return m;
	}	
}
}
