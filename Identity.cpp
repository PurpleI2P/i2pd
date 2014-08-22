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

	IdentityEx::IdentityEx ():
		m_Verifier (nullptr), m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
	}
	
	IdentityEx::IdentityEx (const uint8_t * buf, size_t len):
		m_Verifier (nullptr), m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
		FromBuffer (buf, len);
	}

	IdentityEx::IdentityEx (const IdentityEx& other):
		m_Verifier (nullptr), m_ExtendedBuffer (nullptr)
	{
		*this = other;
	}	
		
	IdentityEx::~IdentityEx ()
	{
		delete m_Verifier;
		delete[] m_ExtendedBuffer;
	}	

	IdentityEx& IdentityEx::operator=(const IdentityEx& other)
	{
		memcpy (&m_StandardIdentity, &other.m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
		m_IdentHash = other.m_IdentHash;
		
		delete m_Verifier;
		m_Verifier = nullptr;
		
		delete[] m_ExtendedBuffer;
		m_ExtendedLen = other.m_ExtendedLen;
		if (m_ExtendedLen > 0)
		{	
			m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
			memcpy (m_ExtendedBuffer, other.m_ExtendedBuffer, m_ExtendedLen);
		}	        
		else
			m_ExtendedBuffer = nullptr;

		return *this;
	}	

	size_t IdentityEx::FromBuffer (const uint8_t * buf, size_t len)
	{
		delete m_Verifier;
		m_Verifier = nullptr;
		delete[] m_ExtendedBuffer;
		
		memcpy (&m_StandardIdentity, buf, DEFAULT_IDENTITY_SIZE);
		if (m_StandardIdentity.certificate.length)
		{
			m_ExtendedLen = be16toh (m_StandardIdentity.certificate.length);
			m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
			memcpy (m_ExtendedBuffer, buf + DEFAULT_IDENTITY_SIZE, m_ExtendedLen);
		}		
		else
		{
			m_ExtendedLen = 0;
			m_ExtendedBuffer = nullptr;
		}	
		CryptoPP::SHA256().CalculateDigest(m_IdentHash, buf, GetFullLen ());
		return GetFullLen ();
	}	

	size_t IdentityEx::GetSigningPublicKeyLen () 
	{
		if (!m_Verifier) 
			CreateVerifier ();
		if (m_Verifier)
			return m_Verifier->GetPublicKeyLen ();
		return 128;
	}	
		
	bool IdentityEx::Verify (const uint8_t * buf, size_t len, const uint8_t * signature)
	{
		if (!m_Verifier) 
			CreateVerifier ();
		if (m_Verifier)
			return m_Verifier->Verify (buf, len, signature);
		return false;
	}	
		
	void IdentityEx::CreateVerifier ()
	{
		switch (m_StandardIdentity.certificate.type)
		{	
			case CERTIFICATE_TYPE_NULL:
				m_Verifier = new i2p::crypto::DSAVerifier (m_StandardIdentity.signingKey);
			break;
			case CERTIFICATE_TYPE_KEY:
			{	
				if (m_ExtendedBuffer)
				{
					uint16_t keyType = be16toh (*(uint16_t *)m_ExtendedBuffer); // sigining key
					switch (keyType)
					{
						case PUBLIC_KEY_TYPE_DSA_SHA1:
							m_Verifier = new i2p::crypto::DSAVerifier (m_StandardIdentity.signingKey);
						break;
						case PUBLIC_KEY_TYPE_ECDSA_SHA256_P256:
							m_Verifier = new i2p::crypto::ECDSAP256Verifier (m_StandardIdentity.signingKey + 64);
						break;	
						default:
							LogPrint ("Signing key type ", keyType, " is not supported");
					}	
				}
				else
					LogPrint ("Missing certificate payload");
				break;
			}	
			default:
				LogPrint ("Certificate type ", m_StandardIdentity.certificate.type, " is not supported");
		}	
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
