#include <time.h>
#include <stdio.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dsa.h>
#include "base64.h"
#include "CryptoConst.h"
#include "ElGamal.h"
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
		if (type != SIGNING_KEY_TYPE_DSA_SHA1)
		{
			size_t excessLen = 0;
			uint8_t * excessBuf = nullptr;
			switch (type)
			{
				case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				{	
					size_t padding =  128 - i2p::crypto::ECDSAP256_KEY_LENGTH; // 64 = 128 - 64
					i2p::context.GetRandomNumberGenerator ().GenerateBlock (m_StandardIdentity.signingKey, padding);
					memcpy (m_StandardIdentity.signingKey + padding, signingKey, i2p::crypto::ECDSAP256_KEY_LENGTH);
					break;
				}
				case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
				{	
					size_t padding = 128 - i2p::crypto::ECDSAP384_KEY_LENGTH; // 32 = 128 - 96
					i2p::context.GetRandomNumberGenerator ().GenerateBlock (m_StandardIdentity.signingKey, padding);
					memcpy (m_StandardIdentity.signingKey + padding, signingKey, i2p::crypto::ECDSAP384_KEY_LENGTH);
					break;
				}	
				case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
				{
					memcpy (m_StandardIdentity.signingKey, signingKey, 128);
					excessLen = i2p::crypto::ECDSAP521_KEY_LENGTH - 128; // 4 = 132 - 128
					excessBuf = new uint8_t[excessLen];
					memcpy (excessBuf, signingKey + 128, excessLen);
					break;
				}	
				case SIGNING_KEY_TYPE_RSA_SHA256_2048:
				{
					memcpy (m_StandardIdentity.signingKey, signingKey, 128);
					excessLen = i2p::crypto::RSASHA2562048_KEY_LENGTH - 128; // 128 = 256 - 128
					excessBuf = new uint8_t[excessLen];
					memcpy (excessBuf, signingKey + 128, excessLen);
					break;
				}	
				case SIGNING_KEY_TYPE_RSA_SHA384_3072:
				{
					memcpy (m_StandardIdentity.signingKey, signingKey, 128);
					excessLen = i2p::crypto::RSASHA3843072_KEY_LENGTH - 128; // 256 = 384 - 128
					excessBuf = new uint8_t[excessLen];
					memcpy (excessBuf, signingKey + 128, excessLen);
					break;
				}	
				case SIGNING_KEY_TYPE_RSA_SHA512_4096:
				{
					memcpy (m_StandardIdentity.signingKey, signingKey, 128);
					excessLen = i2p::crypto::RSASHA5124096_KEY_LENGTH - 128; // 384 = 512 - 128
					excessBuf = new uint8_t[excessLen];
					memcpy (excessBuf, signingKey + 128, excessLen);
					break;
				}		
				default:
					LogPrint ("Signing key type ", (int)type, " is not supported");
			}	
			m_ExtendedLen = 4 + excessLen; // 4 bytes extra + excess length
			// fill certificate
			m_StandardIdentity.certificate.type = CERTIFICATE_TYPE_KEY;
			m_StandardIdentity.certificate.length = htobe16 (m_ExtendedLen); 
			// fill extended buffer
			m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
			htobe16buf (m_ExtendedBuffer, type);
			htobe16buf (m_ExtendedBuffer + 2, CRYPTO_KEY_TYPE_ELGAMAL);
			if (excessLen && excessBuf)
			{
				memcpy (m_ExtendedBuffer + 4, excessBuf, excessLen);
				delete[] excessBuf;
			}	
			// calculate ident hash
			uint8_t * buf = new uint8_t[GetFullLen ()];
			ToBuffer (buf, GetFullLen ());
			CryptoPP::SHA256().CalculateDigest(m_IdentHash, buf, GetFullLen ());
			delete[] buf;
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
		if (len < DEFAULT_IDENTITY_SIZE)
		{
			LogPrint (eLogError, "Identity buffer length ", len, " is too small");
			return 0;
		}	
		memcpy (&m_StandardIdentity, buf, DEFAULT_IDENTITY_SIZE);

		delete[] m_ExtendedBuffer;
		if (m_StandardIdentity.certificate.length)
		{
			m_ExtendedLen = be16toh (m_StandardIdentity.certificate.length);
			if (m_ExtendedLen + DEFAULT_IDENTITY_SIZE <= len)
			{	
				m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
				memcpy (m_ExtendedBuffer, buf + DEFAULT_IDENTITY_SIZE, m_ExtendedLen);
			}	
			else
			{
				LogPrint (eLogError, "Certificate length ", m_ExtendedLen, " exceeds buffer length ", len - DEFAULT_IDENTITY_SIZE);
				return 0;
			}	
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
		uint8_t buf[1024];
		auto len = Base64ToByteStream (s.c_str(), s.length(), buf, 1024);
		return FromBuffer (buf, len);
	}	
	
	std::string IdentityEx::ToBase64 () const
	{
		uint8_t buf[1024];
		char str[1536];
		size_t l = ToBuffer (buf, 1024);
		size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, str, 1536);
		str[l1] = 0;
		return std::string (str);
	}
	
	size_t IdentityEx::GetSigningPublicKeyLen () const
	{
		if (!m_Verifier) CreateVerifier ();
		if (m_Verifier)	
			return m_Verifier->GetPublicKeyLen ();
		return 128;
	}	

	size_t IdentityEx::GetSigningPrivateKeyLen () const
	{
		if (!m_Verifier) CreateVerifier ();
		if (m_Verifier)	
			return m_Verifier->GetPrivateKeyLen ();
		return GetSignatureLen ()/2;
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
			return bufbe16toh (m_ExtendedBuffer); // signing key
		return SIGNING_KEY_TYPE_DSA_SHA1;
	}	

	CryptoKeyType IdentityEx::GetCryptoKeyType () const
	{
		if (m_StandardIdentity.certificate.type == CERTIFICATE_TYPE_KEY && m_ExtendedBuffer)				
			return bufbe16toh (m_ExtendedBuffer + 2); // crypto key
		return CRYPTO_KEY_TYPE_ELGAMAL;
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
			{	
				size_t padding =  128 - i2p::crypto::ECDSAP256_KEY_LENGTH; // 64 = 128 - 64
				m_Verifier = new i2p::crypto::ECDSAP256Verifier (m_StandardIdentity.signingKey + padding);
				break;
			}	
			case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
			{	
				size_t padding = 128 - i2p::crypto::ECDSAP384_KEY_LENGTH; // 32 = 128 - 96
				m_Verifier = new i2p::crypto::ECDSAP384Verifier (m_StandardIdentity.signingKey + padding);
				break;
			}	
			case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
			{	
				uint8_t signingKey[i2p::crypto::ECDSAP521_KEY_LENGTH];
				memcpy (signingKey, m_StandardIdentity.signingKey, 128);
				size_t excessLen = i2p::crypto::ECDSAP521_KEY_LENGTH - 128; // 4 = 132- 128
				memcpy (signingKey + 128, m_ExtendedBuffer + 4, excessLen); // right after signing and crypto key types
				m_Verifier = new i2p::crypto::ECDSAP521Verifier (signingKey);
				break;
			}		
			case SIGNING_KEY_TYPE_RSA_SHA256_2048:
			{	
				uint8_t signingKey[i2p::crypto::RSASHA2562048_KEY_LENGTH];
				memcpy (signingKey, m_StandardIdentity.signingKey, 128);
				size_t excessLen = i2p::crypto::RSASHA2562048_KEY_LENGTH - 128; // 128 = 256- 128
				memcpy (signingKey + 128, m_ExtendedBuffer + 4, excessLen); // right after signing and crypto key types
				m_Verifier = new i2p::crypto:: RSASHA2562048Verifier (signingKey);
				break;
			}	
			case SIGNING_KEY_TYPE_RSA_SHA384_3072:
			{	
				uint8_t signingKey[i2p::crypto::RSASHA3843072_KEY_LENGTH];
				memcpy (signingKey, m_StandardIdentity.signingKey, 128);
				size_t excessLen = i2p::crypto::RSASHA3843072_KEY_LENGTH - 128; // 256 = 384- 128
				memcpy (signingKey + 128, m_ExtendedBuffer + 4, excessLen); // right after signing and crypto key types
				m_Verifier = new i2p::crypto:: RSASHA3843072Verifier (signingKey);
				break;
			}	
			case SIGNING_KEY_TYPE_RSA_SHA512_4096:
			{	
				uint8_t signingKey[i2p::crypto::RSASHA5124096_KEY_LENGTH];
				memcpy (signingKey, m_StandardIdentity.signingKey, 128);
				size_t excessLen = i2p::crypto::RSASHA5124096_KEY_LENGTH - 128; // 384 = 512- 128
				memcpy (signingKey + 128, m_ExtendedBuffer + 4, excessLen); // right after signing and crypto key types
				m_Verifier = new i2p::crypto:: RSASHA5124096Verifier (signingKey);
				break;
			}		
			default:
				LogPrint ("Signing key type ", (int)keyType, " is not supported");
		}			
	}	
	
	void IdentityEx::DropVerifier ()
	{
		auto verifier = m_Verifier;
		m_Verifier = nullptr; // TODO: make this atomic
		delete verifier;
	}

	PrivateKeys& PrivateKeys::operator=(const Keys& keys)
	{
		m_Public = Identity (keys);
		memcpy (m_PrivateKey, keys.privateKey, 256); // 256 
		memcpy (m_SigningPrivateKey, keys.signingPrivateKey, m_Public.GetSigningPrivateKeyLen ());
		delete m_Signer;
		m_Signer = nullptr;
		CreateSigner ();
		return *this;
	}

	PrivateKeys& PrivateKeys::operator=(const PrivateKeys& other)
	{		
		m_Public = other.m_Public;
		memcpy (m_PrivateKey, other.m_PrivateKey, 256); // 256 
		memcpy (m_SigningPrivateKey, other.m_SigningPrivateKey, m_Public.GetSigningPrivateKeyLen ()); 
		delete m_Signer;
		m_Signer = nullptr;
		CreateSigner ();
		return *this;
	}	
		
	size_t PrivateKeys::FromBuffer (const uint8_t * buf, size_t len)
	{
		size_t ret = m_Public.FromBuffer (buf, len);
		memcpy (m_PrivateKey, buf + ret, 256); // private key always 256
		ret += 256;
		size_t signingPrivateKeySize = m_Public.GetSigningPrivateKeyLen ();
		memcpy (m_SigningPrivateKey, buf + ret, signingPrivateKeySize); 
		ret += signingPrivateKeySize;
		delete m_Signer;
		m_Signer = nullptr;
		CreateSigner ();
		return ret;
	}
		
	size_t PrivateKeys::ToBuffer (uint8_t * buf, size_t len) const
	{
		size_t ret = m_Public.ToBuffer (buf, len);
		memcpy (buf + ret, m_PrivateKey, 256); // private key always 256
		ret += 256;
		size_t signingPrivateKeySize = m_Public.GetSigningPrivateKeyLen (); 
		memcpy (buf + ret, m_SigningPrivateKey, signingPrivateKeySize); 
		ret += signingPrivateKeySize;
		return ret;
	}	

	size_t PrivateKeys::FromBase64(const std::string& s)
	{
		uint8_t * buf = new uint8_t[s.length ()];
		size_t l = i2p::data::Base64ToByteStream (s.c_str (), s.length (), buf, s.length ());
		size_t ret = FromBuffer (buf, l);
		delete[] buf;
		return ret;
	}	
	
	std::string PrivateKeys::ToBase64 () const
	{
		uint8_t * buf = new uint8_t[GetFullLen ()];
		char * str = new char[GetFullLen ()*2];
		size_t l = ToBuffer (buf, GetFullLen ());
		size_t l1 = i2p::data::ByteStreamToBase64 (buf, l, str, GetFullLen ()*2);
		str[l1] = 0;
		delete[] buf;
		std::string ret(str);
		delete[] str;
		return ret;
	}

	void PrivateKeys::Sign (const uint8_t * buf, int len, uint8_t * signature) const
	{
		if (m_Signer)
			m_Signer->Sign (i2p::context.GetRandomNumberGenerator (), buf, len, signature);
	}			

	void PrivateKeys::CreateSigner ()
	{
		switch (m_Public.GetSigningKeyType ())
		{	
			case SIGNING_KEY_TYPE_DSA_SHA1:
				m_Signer = new i2p::crypto::DSASigner (m_SigningPrivateKey);
			break;	
			case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				m_Signer = new i2p::crypto::ECDSAP256Signer (m_SigningPrivateKey);
			break;
			case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
				m_Signer = new i2p::crypto::ECDSAP384Signer (m_SigningPrivateKey);
			break;	
			case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
				m_Signer = new i2p::crypto::ECDSAP521Signer (m_SigningPrivateKey);
			break;	
			case SIGNING_KEY_TYPE_RSA_SHA256_2048:
				m_Signer = new i2p::crypto::RSASHA2562048Signer (m_SigningPrivateKey);
			break;
			case SIGNING_KEY_TYPE_RSA_SHA384_3072:
				m_Signer = new i2p::crypto::RSASHA3843072Signer (m_SigningPrivateKey);
			break;
			case SIGNING_KEY_TYPE_RSA_SHA512_4096:
				m_Signer = new i2p::crypto::RSASHA5124096Signer (m_SigningPrivateKey);
			break;	
			default:
				LogPrint ("Signing key type ", (int)m_Public.GetSigningKeyType (), " is not supported");
		}
	}	
		
	PrivateKeys PrivateKeys::CreateRandomKeys (SigningKeyType type)
	{
		if (type != SIGNING_KEY_TYPE_DSA_SHA1)
		{
			PrivateKeys keys;
			auto& rnd = i2p::context.GetRandomNumberGenerator ();
			// signature
			uint8_t signingPublicKey[512]; // signing public key is 512 bytes max 
			switch (type)
			{	
				case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
					i2p::crypto::CreateECDSAP256RandomKeys (rnd, keys.m_SigningPrivateKey, signingPublicKey);
				break;	
				case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
					i2p::crypto::CreateECDSAP384RandomKeys (rnd, keys.m_SigningPrivateKey, signingPublicKey);	
				break;
				case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
					i2p::crypto::CreateECDSAP521RandomKeys (rnd, keys.m_SigningPrivateKey, signingPublicKey);	
				break;	
				case SIGNING_KEY_TYPE_RSA_SHA256_2048:
					i2p::crypto::CreateRSARandomKeys (rnd, i2p::crypto::RSASHA2562048_KEY_LENGTH, keys.m_SigningPrivateKey, signingPublicKey);	
				break;
				case SIGNING_KEY_TYPE_RSA_SHA384_3072:
					i2p::crypto::CreateRSARandomKeys (rnd, i2p::crypto::RSASHA3843072_KEY_LENGTH, keys.m_SigningPrivateKey, signingPublicKey);	
				break;
				case SIGNING_KEY_TYPE_RSA_SHA512_4096:
					i2p::crypto::CreateRSARandomKeys (rnd, i2p::crypto::RSASHA5124096_KEY_LENGTH, keys.m_SigningPrivateKey, signingPublicKey);	
				break;	
				default:
					LogPrint ("Signing key type ", (int)type, " is not supported. Create DSA-SHA1");
					return PrivateKeys (i2p::data::CreateRandomKeys ()); // DSA-SHA1
			}	
			// encryption
			uint8_t publicKey[256];
			CryptoPP::DH dh (i2p::crypto::elgp, i2p::crypto::elgg);
			dh.GenerateKeyPair(rnd, keys.m_PrivateKey, publicKey);
			// identity
			keys.m_Public = IdentityEx (publicKey, signingPublicKey, type);

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
		i2p::crypto::GenerateElGamalKeyPair(rnd, keys.privateKey, keys.publicKey);
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
