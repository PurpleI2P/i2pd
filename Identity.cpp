#include <time.h>
#include <stdio.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dsa.h>
#include "base64.h"
#include "CryptoConst.h"
#include "RouterContext.h"
#include "Identity.h"
#include "I2PEndian.h"

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

	size_t Identity::FromBuffer (const uint8_t * buf, size_t len)
	{
		memcpy (publicKey, buf, DEFAULT_IDENTITY_SIZE);
		return DEFAULT_IDENTITY_SIZE;
	}

	IdentHash Identity::Hash () const
	{
		IdentHash hash;
		CryptoPP::SHA256().CalculateDigest(hash, publicKey, DEFAULT_IDENTITY_SIZE);
		return hash;
	}	
	
	IdentityEx::IdentityEx ():
		m_Verifier (nullptr), m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
	}

	IdentityEx::IdentityEx(const uint8_t * publicKey, const uint8_t * signingKey, SigningKeyType type)
	{	
		memcpy (m_StandardIdentity.publicKey, publicKey, sizeof (m_StandardIdentity.publicKey));
		if (type == SIGNING_KEY_TYPE_ECDSA_SHA256_P256)
		{
			memcpy (m_StandardIdentity.signingKey + 64, signingKey, 64);
			m_StandardIdentity.certificate.type = CERTIFICATE_TYPE_KEY;
			m_ExtendedLen = 4; // 4 bytes extra
			m_StandardIdentity.certificate.length = htobe16 (4); 
			m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
			*(uint16_t *)m_ExtendedBuffer = htobe16 (SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
			*(uint16_t *)(m_ExtendedBuffer + 2) = htobe16 (CRYPTO_KEY_TYPE_ELGAMAL);
			uint8_t buf[DEFAULT_IDENTITY_SIZE + 4];
			ToBuffer (buf, DEFAULT_IDENTITY_SIZE + 4);
			CryptoPP::SHA256().CalculateDigest(m_IdentHash, buf, GetFullLen ());
		}
		else // DSA-SHA1
		{
			memcpy (m_StandardIdentity.signingKey, signingKey, sizeof (m_StandardIdentity.signingKey));
			memset (&m_StandardIdentity.certificate, 0, sizeof (m_StandardIdentity.certificate));
			m_IdentHash = m_StandardIdentity.Hash ();
			m_ExtendedLen = 0;
			m_ExtendedBuffer = nullptr;
		}	
		CreateVerifier ();
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
		
		delete[] m_ExtendedBuffer;
		m_ExtendedLen = other.m_ExtendedLen;
		if (m_ExtendedLen > 0)
		{	
			m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
			memcpy (m_ExtendedBuffer, other.m_ExtendedBuffer, m_ExtendedLen);
		}	        
		else
			m_ExtendedBuffer = nullptr;
		
		delete m_Verifier;
		m_Verifier = nullptr;
		
		return *this;
	}	

	IdentityEx& IdentityEx::operator=(const Identity& standard)
	{
		m_StandardIdentity = standard;
		m_IdentHash = m_StandardIdentity.Hash ();
		
		delete[] m_ExtendedBuffer;
		m_ExtendedBuffer = nullptr;
		m_ExtendedLen = 0;

		delete m_Verifier;
		m_Verifier = nullptr;
		
		return *this;
	}	
		
	size_t IdentityEx::FromBuffer (const uint8_t * buf, size_t len)
	{
		memcpy (&m_StandardIdentity, buf, DEFAULT_IDENTITY_SIZE);

		delete[] m_ExtendedBuffer;
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
		
		delete m_Verifier;
		m_Verifier = nullptr;
		
		return GetFullLen ();
	}	

	size_t IdentityEx::ToBuffer (uint8_t * buf, size_t len) const
	{		
		memcpy (buf, &m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
		if (m_ExtendedLen > 0 && m_ExtendedBuffer)
			memcpy (buf + DEFAULT_IDENTITY_SIZE, m_ExtendedBuffer, m_ExtendedLen);
		return GetFullLen ();
	}

	size_t IdentityEx::FromBase64(const std::string& s)
	{
		uint8_t buf[512];
		auto len = Base64ToByteStream (s.c_str(), s.length(), buf, 512);
		return FromBuffer (buf, len);
	}	
		
	size_t IdentityEx::GetSigningPublicKeyLen () const
	{
		if (!m_Verifier) CreateVerifier ();
		if (m_Verifier)	
			return m_Verifier->GetPublicKeyLen ();
		return 128;
	}	

	size_t IdentityEx::GetSignatureLen () const
	{	
		if (!m_Verifier) CreateVerifier ();	
		if (m_Verifier)
			return m_Verifier->GetSignatureLen ();
		return 40;
	}	
	bool IdentityEx::Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const 
	{
		if (!m_Verifier) CreateVerifier ();
		if (m_Verifier)
			return m_Verifier->Verify (buf, len, signature);
		return false;
	}	

	SigningKeyType IdentityEx::GetSigningKeyType () const
	{
		if (m_StandardIdentity.certificate.type == CERTIFICATE_TYPE_KEY && m_ExtendedBuffer)				
			return be16toh (*(const uint16_t *)m_ExtendedBuffer); // signing key
		return SIGNING_KEY_TYPE_DSA_SHA1;
	}	
		
	void IdentityEx::CreateVerifier () const 
	{
		auto keyType = GetSigningKeyType ();
		switch (keyType)
		{
			case SIGNING_KEY_TYPE_DSA_SHA1:
				m_Verifier = new i2p::crypto::DSAVerifier (m_StandardIdentity.signingKey);
			break;
			case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				m_Verifier = new i2p::crypto::ECDSAP256Verifier (m_StandardIdentity.signingKey + 64);
			break;	
			default:
				LogPrint ("Signing key type ", (int)keyType, " is not supported");
		}			
	}	
	
	PrivateKeys& PrivateKeys::operator=(const Keys& keys)
	{
		m_Public = Identity (keys);
		memcpy (m_PrivateKey, keys.privateKey, 256); // 256 
		memcpy (m_SigningPrivateKey, keys.signingPrivateKey, 20); // 20 - DSA
		delete m_Signer;
		CreateSigner ();
		return *this;
	}

	PrivateKeys& PrivateKeys::operator=(const PrivateKeys& other)
	{		
		m_Public = other.m_Public;
		memcpy (m_PrivateKey, other.m_PrivateKey, 256); // 256 
		memcpy (m_SigningPrivateKey, other.m_SigningPrivateKey, 128); // 128
		delete m_Signer;
		CreateSigner ();
		return *this;
	}	
		
	size_t PrivateKeys::FromBuffer (const uint8_t * buf, size_t len)
	{
		size_t ret = m_Public.FromBuffer (buf, len);
		memcpy (m_PrivateKey, buf + ret, 256); // private key always 256
		ret += 256;
		size_t signingPrivateKeySize = m_Public.GetSignatureLen ()/2; // 20 for DSA
		memcpy (m_SigningPrivateKey, buf + ret, signingPrivateKeySize); 
		ret += signingPrivateKeySize;
		delete m_Signer;
		CreateSigner ();
		return ret;
	}
		
	size_t PrivateKeys::ToBuffer (uint8_t * buf, size_t len) const
	{
		size_t ret = m_Public.ToBuffer (buf, len);
		memcpy (buf + ret, m_PrivateKey, 256); // private key always 256
		ret += 256;
		size_t signingPrivateKeySize = m_Public.GetSignatureLen ()/2; // 20 for DSA
		memcpy (buf + ret, m_SigningPrivateKey, signingPrivateKeySize); 
		ret += signingPrivateKeySize;
		return ret;
	}	

	void PrivateKeys::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		if (m_Signer)
			m_Signer->Sign (i2p::context.GetRandomNumberGenerator (), buf, len, signature);
	}			

	void PrivateKeys::CreateSigner ()
	{
		if (m_Public.GetSigningKeyType () == SIGNING_KEY_TYPE_ECDSA_SHA256_P256)
			m_Signer = new i2p::crypto::ECDSAP256Signer (m_SigningPrivateKey);
		else
			m_Signer = new i2p::crypto::DSASigner (m_SigningPrivateKey);
	}	
		
	PrivateKeys PrivateKeys::CreateRandomKeys (SigningKeyType type)
	{
		if (type == SIGNING_KEY_TYPE_ECDSA_SHA256_P256)
		{
			PrivateKeys keys;
			auto& rnd = i2p::context.GetRandomNumberGenerator ();
			// encryption
			uint8_t publicKey[256];
			CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
			dh.GenerateKeyPair(rnd, keys.m_PrivateKey, publicKey);
			// signature
			uint8_t signingPublicKey[64];
			i2p::crypto::CreateECDSAP256RandomKeys (rnd, keys.m_SigningPrivateKey, signingPublicKey);
			keys.m_Public = IdentityEx (publicKey, signingPublicKey, SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
			keys.CreateSigner ();
			return keys;
		}	
		return PrivateKeys (i2p::data::CreateRandomKeys ()); // DSA-SHA1
	}	
		
	Keys CreateRandomKeys ()
	{
		Keys keys;		
		auto& rnd = i2p::context.GetRandomNumberGenerator ();
		// encryption
		CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
		dh.GenerateKeyPair(rnd, keys.privateKey, keys.publicKey);
		// signing
		i2p::crypto::CreateDSARandomKeys (rnd, keys.signingPrivateKey, keys.signingKey);	
		return keys;
	}	

	IdentHash CreateRoutingKey (const IdentHash& ident)
	{
		uint8_t buf[41]; // ident + yyyymmdd
		memcpy (buf, (const uint8_t *)ident, 32);
		time_t t = time (nullptr);
		struct tm tm;
#ifdef _WIN32
		gmtime_s(&tm, &t);
		sprintf_s((char *)(buf + 32), 9, "%04i%02i%02i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
#else
		gmtime_r(&t, &tm);
		sprintf((char *)(buf + 32), "%04i%02i%02i", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
#endif		
		IdentHash key;
		CryptoPP::SHA256().CalculateDigest((uint8_t *)key, buf, 40);
		return key;
	}	
	
	XORMetric operator^(const IdentHash& key1, const IdentHash& key2)
	{
		XORMetric m;
		const uint64_t * hash1 = key1.GetLL (), * hash2 = key2.GetLL ();
		m.metric_ll[0] = hash1[0] ^ hash2[0];
		m.metric_ll[1] = hash1[1] ^ hash2[1];
		m.metric_ll[2] = hash1[2] ^ hash2[2];
		m.metric_ll[3] = hash1[3] ^ hash2[3];
		return m;
	}	
}
}
