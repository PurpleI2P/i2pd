/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Crypto.h"
#include "I2PEndian.h"
#include "Log.h"
#include "Timestamp.h"
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

	size_t Identity::FromBuffer (const uint8_t * buf, size_t len)
	{
		if ( len < DEFAULT_IDENTITY_SIZE ) {
			// buffer too small, don't overflow
			return 0;
		}
		memcpy (publicKey, buf, DEFAULT_IDENTITY_SIZE);
		return DEFAULT_IDENTITY_SIZE;
	}

	IdentHash Identity::Hash () const
	{
		IdentHash hash;
		SHA256(publicKey, DEFAULT_IDENTITY_SIZE, hash);
		return hash;
	}

	IdentityEx::IdentityEx ():
		m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
	}

	IdentityEx::IdentityEx(const uint8_t * publicKey, const uint8_t * signingKey, SigningKeyType type, CryptoKeyType cryptoType)
	{
		memcpy (m_StandardIdentity.publicKey, publicKey, 256); // publicKey in awlays assumed 256 regardless actual size, padding must be taken care of
		if (type != SIGNING_KEY_TYPE_DSA_SHA1)
		{
			size_t excessLen = 0;
			uint8_t * excessBuf = nullptr;
			switch (type)
			{
				case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				{
					size_t padding =  128 - i2p::crypto::ECDSAP256_KEY_LENGTH; // 64 = 128 - 64
					RAND_bytes (m_StandardIdentity.signingKey, padding);
					memcpy (m_StandardIdentity.signingKey + padding, signingKey, i2p::crypto::ECDSAP256_KEY_LENGTH);
					break;
				}
				case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
				{
					size_t padding = 128 - i2p::crypto::ECDSAP384_KEY_LENGTH; // 32 = 128 - 96
					RAND_bytes (m_StandardIdentity.signingKey, padding);
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
				case SIGNING_KEY_TYPE_RSA_SHA384_3072:
				case SIGNING_KEY_TYPE_RSA_SHA512_4096:
					LogPrint (eLogError, "Identity: RSA signing key type ", (int)type, " is not supported");
				break;
				case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
				case SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
				{
					size_t padding = 128 - i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH; // 96 = 128 - 32
					RAND_bytes (m_StandardIdentity.signingKey, padding);
					memcpy (m_StandardIdentity.signingKey + padding, signingKey, i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH);
					break;
				}
				case SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256:
				{
					// 256
					size_t padding = 128 - i2p::crypto::GOSTR3410_256_PUBLIC_KEY_LENGTH; // 64 = 128 - 64
					RAND_bytes (m_StandardIdentity.signingKey, padding);
					memcpy (m_StandardIdentity.signingKey + padding, signingKey, i2p::crypto::GOSTR3410_256_PUBLIC_KEY_LENGTH);
					break;
				}
				case SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512:
				{
					// 512
					// no padding, key length is 128
					memcpy (m_StandardIdentity.signingKey, signingKey, i2p::crypto::GOSTR3410_512_PUBLIC_KEY_LENGTH);
					break;
				}
				default:
					LogPrint (eLogError, "Identity: Signing key type ", (int)type, " is not supported");
			}
			m_ExtendedLen = 4 + excessLen; // 4 bytes extra + excess length
			// fill certificate
			m_StandardIdentity.certificate[0] = CERTIFICATE_TYPE_KEY;
			htobe16buf (m_StandardIdentity.certificate + 1, m_ExtendedLen);
			// fill extended buffer
			m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
			htobe16buf (m_ExtendedBuffer, type);
			htobe16buf (m_ExtendedBuffer + 2, cryptoType);
			if (excessLen && excessBuf)
			{
				memcpy (m_ExtendedBuffer + 4, excessBuf, excessLen);
				delete[] excessBuf;
			}
			// calculate ident hash
			RecalculateIdentHash();
		}
		else // DSA-SHA1
		{
			memcpy (m_StandardIdentity.signingKey, signingKey, sizeof (m_StandardIdentity.signingKey));
			memset (m_StandardIdentity.certificate, 0, sizeof (m_StandardIdentity.certificate));
			m_IdentHash = m_StandardIdentity.Hash ();
			m_ExtendedLen = 0;
			m_ExtendedBuffer = nullptr;
		}
		CreateVerifier ();
	}

	void IdentityEx::RecalculateIdentHash(uint8_t * buf)
	{
		bool dofree = buf == nullptr;
		size_t sz = GetFullLen();
		if(!buf)
			buf = new uint8_t[sz];
		ToBuffer (buf, sz);
		SHA256(buf, sz, m_IdentHash);
		if(dofree)
			delete[] buf;
	}

	IdentityEx::IdentityEx (const uint8_t * buf, size_t len):
		m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
		FromBuffer (buf, len);
	}

	IdentityEx::IdentityEx (const IdentityEx& other):
		m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
		*this = other;
	}

	IdentityEx::IdentityEx (const Identity& standard):
		m_ExtendedLen (0), m_ExtendedBuffer (nullptr)
	{
		*this = standard;
	}

	IdentityEx::~IdentityEx ()
	{
		delete[] m_ExtendedBuffer;
		delete m_Verifier;
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
			LogPrint (eLogError, "Identity: buffer length ", len, " is too small");
			return 0;
		}
		memcpy (&m_StandardIdentity, buf, DEFAULT_IDENTITY_SIZE);

		if(m_ExtendedBuffer) delete[] m_ExtendedBuffer;
		m_ExtendedBuffer = nullptr;

		m_ExtendedLen = bufbe16toh (m_StandardIdentity.certificate + 1);
		if (m_ExtendedLen)
		{
			if (m_ExtendedLen + DEFAULT_IDENTITY_SIZE <= len)
			{
				m_ExtendedBuffer = new uint8_t[m_ExtendedLen];
				memcpy (m_ExtendedBuffer, buf + DEFAULT_IDENTITY_SIZE, m_ExtendedLen);
			}
			else
			{
				LogPrint (eLogError, "Identity: Certificate length ", m_ExtendedLen, " exceeds buffer length ", len - DEFAULT_IDENTITY_SIZE);
				m_ExtendedLen = 0;
				return 0;
			}
		}
		else
		{
			m_ExtendedLen = 0;
			m_ExtendedBuffer = nullptr;
		}
		SHA256(buf, GetFullLen (), m_IdentHash);

		delete m_Verifier;
		m_Verifier = nullptr;

		return GetFullLen ();
	}

	size_t IdentityEx::ToBuffer (uint8_t * buf, size_t len) const
	{
		const size_t fullLen = GetFullLen();
		if (fullLen > len) return 0; // buffer is too small and may overflow somewhere else
		memcpy (buf, &m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
		if (m_ExtendedLen > 0 && m_ExtendedBuffer)
			memcpy (buf + DEFAULT_IDENTITY_SIZE, m_ExtendedBuffer, m_ExtendedLen);
		return fullLen;
	}

	size_t IdentityEx::FromBase64(const std::string& s)
	{
		const size_t slen = s.length();
		std::vector<uint8_t> buf(slen); // binary data can't exceed base64
		const size_t len = Base64ToByteStream (s.c_str(), slen, buf.data(), slen);
		return FromBuffer (buf.data(), len);
	}

	std::string IdentityEx::ToBase64 () const
	{
		const size_t bufLen = GetFullLen();
		const size_t strLen = Base64EncodingBufferSize(bufLen);
		std::vector<uint8_t> buf(bufLen);
		std::vector<char> str(strLen);
		size_t l = ToBuffer (buf.data(), bufLen);
		size_t l1 = i2p::data::ByteStreamToBase64 (buf.data(), l, str.data(), strLen);
		return std::string (str.data(), l1);
	}

	size_t IdentityEx::GetSigningPublicKeyLen () const
	{
		if (!m_Verifier) CreateVerifier ();
		if (m_Verifier)
			return m_Verifier->GetPublicKeyLen ();
		return 128;
	}

	const uint8_t * IdentityEx::GetSigningPublicKeyBuffer () const
	{
		auto keyLen = GetSigningPublicKeyLen ();
		if (keyLen > 128) return nullptr; // P521
		return m_StandardIdentity.signingKey + 128 - keyLen;
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
		return i2p::crypto::DSA_SIGNATURE_LENGTH;
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
		if (m_StandardIdentity.certificate[0] == CERTIFICATE_TYPE_KEY && m_ExtendedLen >= 2)
			return bufbe16toh (m_ExtendedBuffer); // signing key
		return SIGNING_KEY_TYPE_DSA_SHA1;
	}

	bool IdentityEx::IsRSA () const
	{
		auto sigType = GetSigningKeyType ();
		return sigType <= SIGNING_KEY_TYPE_RSA_SHA512_4096 && sigType >= SIGNING_KEY_TYPE_RSA_SHA256_2048;
	}

	CryptoKeyType IdentityEx::GetCryptoKeyType () const
	{
		if (m_StandardIdentity.certificate[0] == CERTIFICATE_TYPE_KEY && m_ExtendedLen >= 4)
			return bufbe16toh (m_ExtendedBuffer + 2); // crypto key
		return CRYPTO_KEY_TYPE_ELGAMAL;
	}

	i2p::crypto::Verifier * IdentityEx::CreateVerifier (SigningKeyType keyType)
	{
		switch (keyType)
		{
			case SIGNING_KEY_TYPE_DSA_SHA1:
				return new i2p::crypto::DSAVerifier ();
			case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				return new i2p::crypto::ECDSAP256Verifier ();
			case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
				return new i2p::crypto::ECDSAP384Verifier ();
			case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
				return new i2p::crypto::ECDSAP521Verifier ();
			case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
				return new i2p::crypto::EDDSA25519Verifier ();
			case SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256:
				return new i2p::crypto::GOSTR3410_256_Verifier (i2p::crypto::eGOSTR3410CryptoProA);
			case SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512:
				return new i2p::crypto::GOSTR3410_512_Verifier (i2p::crypto::eGOSTR3410TC26A512);
			case SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
				return new i2p::crypto::RedDSA25519Verifier ();
			case SIGNING_KEY_TYPE_RSA_SHA256_2048:
			case SIGNING_KEY_TYPE_RSA_SHA384_3072:
			case SIGNING_KEY_TYPE_RSA_SHA512_4096:
				LogPrint (eLogError, "Identity: RSA signing key type ", (int)keyType, " is not supported");
			break;
			default:
				LogPrint (eLogError, "Identity: Signing key type ", (int)keyType, " is not supported");
		}
		return nullptr;
	}

	void IdentityEx::CreateVerifier () const
	{
		if (m_Verifier) return; // don't create again
		auto verifier = CreateVerifier (GetSigningKeyType ());
		if (verifier)
		{
			auto keyLen = verifier->GetPublicKeyLen ();
			if (keyLen <= 128)
				verifier->SetPublicKey (m_StandardIdentity.signingKey + 128 - keyLen);
			else
			{
				// for P521
				uint8_t * signingKey = new uint8_t[keyLen];
				memcpy (signingKey, m_StandardIdentity.signingKey, 128);
				size_t excessLen = keyLen - 128;
				memcpy (signingKey + 128, m_ExtendedBuffer + 4, excessLen); // right after signing and crypto key types
				verifier->SetPublicKey (signingKey);
				delete[] signingKey;
			}
		}
		UpdateVerifier (verifier);
	}

	void IdentityEx::UpdateVerifier (i2p::crypto::Verifier * verifier) const
	{
		bool del = false;
		{
			std::lock_guard<std::mutex> l(m_VerifierMutex);
			if (!m_Verifier)
				m_Verifier = verifier;
			else
				del = true;
		}
		if (del)
			delete verifier;
	}

	void IdentityEx::DropVerifier () const
	{
		i2p::crypto::Verifier * verifier;
		{
			std::lock_guard<std::mutex> l(m_VerifierMutex);
			verifier = m_Verifier;
			m_Verifier = nullptr;
		}
		delete verifier;
	}

	std::shared_ptr<i2p::crypto::CryptoKeyEncryptor> IdentityEx::CreateEncryptor (CryptoKeyType keyType, const uint8_t * key)
	{
		switch (keyType)
		{
			case CRYPTO_KEY_TYPE_ELGAMAL:
				return std::make_shared<i2p::crypto::ElGamalEncryptor>(key);
			break;
			case CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET:
				return std::make_shared<i2p::crypto::ECIESX25519AEADRatchetEncryptor>(key);
			break;
			case CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC:
			case CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC_TEST:
				return std::make_shared<i2p::crypto::ECIESP256Encryptor>(key);
			break;
			case CRYPTO_KEY_TYPE_ECIES_GOSTR3410_CRYPTO_PRO_A_SHA256_AES256CBC:
				return std::make_shared<i2p::crypto::ECIESGOSTR3410Encryptor>(key);
			break;
			default:
				LogPrint (eLogError, "Identity: Unknown crypto key type ", (int)keyType);
		};
		return nullptr;
	}

	std::shared_ptr<i2p::crypto::CryptoKeyEncryptor> IdentityEx::CreateEncryptor (const uint8_t * key) const
	{
		if (!key) key = GetEncryptionPublicKey (); // use publicKey
		return CreateEncryptor (GetCryptoKeyType (), key);
	}

	PrivateKeys& PrivateKeys::operator=(const Keys& keys)
	{
		m_Public = std::make_shared<IdentityEx>(Identity (keys));
		memcpy (m_PrivateKey, keys.privateKey, 256); // 256
		memcpy (m_SigningPrivateKey, keys.signingPrivateKey, m_Public->GetSigningPrivateKeyLen ());
		m_OfflineSignature.resize (0);
		m_TransientSignatureLen = 0;
		m_TransientSigningPrivateKeyLen = 0;
		m_Signer = nullptr;
		CreateSigner ();
		return *this;
	}

	PrivateKeys& PrivateKeys::operator=(const PrivateKeys& other)
	{
		m_Public = std::make_shared<IdentityEx>(*other.m_Public);
		memcpy (m_PrivateKey, other.m_PrivateKey, 256); // 256
		m_OfflineSignature = other.m_OfflineSignature;
		m_TransientSignatureLen = other.m_TransientSignatureLen;
		m_TransientSigningPrivateKeyLen = other.m_TransientSigningPrivateKeyLen;
		memcpy (m_SigningPrivateKey, other.m_SigningPrivateKey, m_TransientSigningPrivateKeyLen > 0 ? m_TransientSigningPrivateKeyLen : m_Public->GetSigningPrivateKeyLen ());
		m_Signer = nullptr;
		CreateSigner ();
		return *this;
	}

	size_t PrivateKeys::GetFullLen () const
	{
		size_t ret = m_Public->GetFullLen () + 256 + m_Public->GetSigningPrivateKeyLen ();
		if (IsOfflineSignature ())
			ret += m_OfflineSignature.size () + m_TransientSigningPrivateKeyLen;
		return ret;
	}

	size_t PrivateKeys::FromBuffer (const uint8_t * buf, size_t len)
	{
		m_Public = std::make_shared<IdentityEx>();
		size_t ret = m_Public->FromBuffer (buf, len);
		if (!ret || ret + 256 > len) return 0; // overflow
		memcpy (m_PrivateKey, buf + ret, 256); // private key always 256
		ret += 256;
		size_t signingPrivateKeySize = m_Public->GetSigningPrivateKeyLen ();
		if(signingPrivateKeySize + ret > len || signingPrivateKeySize > 128) return 0; // overflow
		memcpy (m_SigningPrivateKey, buf + ret, signingPrivateKeySize);
		ret += signingPrivateKeySize;
		m_Signer = nullptr;
		// check if signing private key is all zeros
		bool allzeros = true;
		for (size_t i = 0; i < signingPrivateKeySize; i++)
			if (m_SigningPrivateKey[i])
			{
				allzeros = false;
				break;
			}
		if (allzeros)
		{
			// offline information
			const uint8_t * offlineInfo = buf + ret;
			ret += 4; // expires timestamp
			SigningKeyType keyType = bufbe16toh (buf + ret); ret += 2; // key type
			std::unique_ptr<i2p::crypto::Verifier> transientVerifier (IdentityEx::CreateVerifier (keyType));
			if (!transientVerifier) return 0;
			auto keyLen = transientVerifier->GetPublicKeyLen ();
			if (keyLen + ret > len) return 0;
			transientVerifier->SetPublicKey (buf + ret); ret += keyLen;
			if (m_Public->GetSignatureLen () + ret > len) return 0;
			if (!m_Public->Verify (offlineInfo, keyLen + 6, buf + ret))
			{
				LogPrint (eLogError, "Identity: offline signature verification failed");
				return 0;
			}
			ret += m_Public->GetSignatureLen ();
			m_TransientSignatureLen = transientVerifier->GetSignatureLen ();
			// copy offline signature
			size_t offlineInfoLen = buf + ret - offlineInfo;
			m_OfflineSignature.resize (offlineInfoLen);
			memcpy (m_OfflineSignature.data (), offlineInfo, offlineInfoLen);
			// override signing private key
			m_TransientSigningPrivateKeyLen = transientVerifier->GetPrivateKeyLen ();
			if (m_TransientSigningPrivateKeyLen + ret > len || m_TransientSigningPrivateKeyLen > 128) return 0;
			memcpy (m_SigningPrivateKey, buf + ret, m_TransientSigningPrivateKeyLen);
			ret += m_TransientSigningPrivateKeyLen;
			CreateSigner (keyType);
		}
		else
			CreateSigner (m_Public->GetSigningKeyType ());
		return ret;
	}

	size_t PrivateKeys::ToBuffer (uint8_t * buf, size_t len) const
	{
		size_t ret = m_Public->ToBuffer (buf, len);
		memcpy (buf + ret, m_PrivateKey, 256); // private key always 256
		ret += 256;
		size_t signingPrivateKeySize = m_Public->GetSigningPrivateKeyLen ();
		if(ret + signingPrivateKeySize > len) return 0; // overflow
		if (IsOfflineSignature ())
			memset (buf + ret, 0, signingPrivateKeySize);
		else
			memcpy (buf + ret, m_SigningPrivateKey, signingPrivateKeySize);
		ret += signingPrivateKeySize;
		if (IsOfflineSignature ())
		{
			// offline signature
			auto offlineSignatureLen = m_OfflineSignature.size ();
			if (ret + offlineSignatureLen > len) return 0;
			memcpy (buf + ret, m_OfflineSignature.data (), offlineSignatureLen);
			ret += offlineSignatureLen;
			// transient private key
			if (ret + m_TransientSigningPrivateKeyLen > len) return 0;
			memcpy (buf + ret, m_SigningPrivateKey, m_TransientSigningPrivateKeyLen);
			ret += m_TransientSigningPrivateKeyLen;
		}
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
		if (!m_Signer)
			CreateSigner();
		m_Signer->Sign (buf, len, signature);
	}

	void PrivateKeys::CreateSigner () const
	{
		if (IsOfflineSignature ())
			CreateSigner (bufbe16toh (m_OfflineSignature.data () + 4)); // key type
		else
			CreateSigner (m_Public->GetSigningKeyType ());
	}

	void PrivateKeys::CreateSigner (SigningKeyType keyType) const
	{
		if (m_Signer) return;
		if (keyType == SIGNING_KEY_TYPE_DSA_SHA1)
			m_Signer.reset (new i2p::crypto::DSASigner (m_SigningPrivateKey, m_Public->GetStandardIdentity ().signingKey));
		else if (keyType == SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 && !IsOfflineSignature ())
			m_Signer.reset (new i2p::crypto::EDDSA25519Signer (m_SigningPrivateKey, m_Public->GetStandardIdentity ().certificate - i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH)); // TODO: remove public key check
		else
		{
			// public key is not required
			auto signer = CreateSigner (keyType, m_SigningPrivateKey);
			if (signer) m_Signer.reset (signer);
		}
	}

	i2p::crypto::Signer * PrivateKeys::CreateSigner (SigningKeyType keyType, const uint8_t * priv)
	{
		switch (keyType)
		{
			case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				return new i2p::crypto::ECDSAP256Signer (priv);
			break;
			case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
				return new i2p::crypto::ECDSAP384Signer (priv);
			break;
			case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
				return new i2p::crypto::ECDSAP521Signer (priv);
			break;
			case SIGNING_KEY_TYPE_RSA_SHA256_2048:
			case SIGNING_KEY_TYPE_RSA_SHA384_3072:
			case SIGNING_KEY_TYPE_RSA_SHA512_4096:
				LogPrint (eLogError, "Identity: RSA signing key type ", (int)keyType, " is not supported");
			break;
			case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
				return new i2p::crypto::EDDSA25519Signer (priv, nullptr);
			break;
			case SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256:
				return new i2p::crypto::GOSTR3410_256_Signer (i2p::crypto::eGOSTR3410CryptoProA, priv);
			break;
			case SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512:
				return new i2p::crypto::GOSTR3410_512_Signer (i2p::crypto::eGOSTR3410TC26A512, priv);
			break;
			case SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
				return new i2p::crypto::RedDSA25519Signer (priv);
			break;
			default:
				LogPrint (eLogError, "Identity: Signing key type ", (int)keyType, " is not supported");
		}
		return nullptr;
	}

	size_t PrivateKeys::GetSignatureLen () const
	{
		return IsOfflineSignature () ? m_TransientSignatureLen : m_Public->GetSignatureLen ();
	}

	uint8_t * PrivateKeys::GetPadding()
	{
		if(m_Public->GetSigningKeyType () == SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519)
			return m_Public->GetEncryptionPublicKeyBuffer() + 256;
		else
			return nullptr; // TODO: implement me
	}

	std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> PrivateKeys::CreateDecryptor (const uint8_t * key) const
	{
		if (!key) key = m_PrivateKey; // use privateKey
		return CreateDecryptor (m_Public->GetCryptoKeyType (), key);
	}

	std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> PrivateKeys::CreateDecryptor (CryptoKeyType cryptoType, const uint8_t * key)
	{
		if (!key) return nullptr;
		switch (cryptoType)
		{
			case CRYPTO_KEY_TYPE_ELGAMAL:
				return std::make_shared<i2p::crypto::ElGamalDecryptor>(key);
			break;
			case CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC:
			case CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC_TEST:
				return std::make_shared<i2p::crypto::ECIESP256Decryptor>(key);
			break;
			case CRYPTO_KEY_TYPE_ECIES_GOSTR3410_CRYPTO_PRO_A_SHA256_AES256CBC:
				return std::make_shared<i2p::crypto::ECIESGOSTR3410Decryptor>(key);
			break;
			case CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET:
				return std::make_shared<i2p::crypto::ECIESX25519AEADRatchetDecryptor>(key);
			break;
			default:
				LogPrint (eLogError, "Identity: Unknown crypto key type ", (int)cryptoType);
		};
		return nullptr;
	}

	PrivateKeys PrivateKeys::CreateRandomKeys (SigningKeyType type, CryptoKeyType cryptoType)
	{
		if (type != SIGNING_KEY_TYPE_DSA_SHA1)
		{
			PrivateKeys keys;
			// signature
			uint8_t signingPublicKey[512]; // signing public key is 512 bytes max
			GenerateSigningKeyPair (type, keys.m_SigningPrivateKey, signingPublicKey);
			// encryption
			uint8_t publicKey[256];
			GenerateCryptoKeyPair (cryptoType, keys.m_PrivateKey, publicKey);
			// identity
			keys.m_Public = std::make_shared<IdentityEx> (publicKey, signingPublicKey, type, cryptoType);

			keys.CreateSigner ();
			return keys;
		}
		return PrivateKeys (i2p::data::CreateRandomKeys ()); // DSA-SHA1
	}

	void PrivateKeys::GenerateSigningKeyPair (SigningKeyType type, uint8_t * priv, uint8_t * pub)
	{
		switch (type)
		{
			case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
				i2p::crypto::CreateECDSAP256RandomKeys (priv, pub);
			break;
			case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
				i2p::crypto::CreateECDSAP384RandomKeys (priv, pub);
			break;
			case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
				i2p::crypto::CreateECDSAP521RandomKeys (priv, pub);
			break;
			case SIGNING_KEY_TYPE_RSA_SHA256_2048:
			case SIGNING_KEY_TYPE_RSA_SHA384_3072:
			case SIGNING_KEY_TYPE_RSA_SHA512_4096:
				LogPrint (eLogWarning, "Identity: RSA signature type is not supported. Creating EdDSA");
#if (__cplusplus >= 201703L) // C++ 17 or higher
				[[fallthrough]];
#endif
				// no break here
			case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
				i2p::crypto::CreateEDDSA25519RandomKeys (priv, pub);
			break;
			case SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256:
				i2p::crypto::CreateGOSTR3410RandomKeys (i2p::crypto::eGOSTR3410CryptoProA, priv, pub);
			break;
			case SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512:
				i2p::crypto::CreateGOSTR3410RandomKeys (i2p::crypto::eGOSTR3410TC26A512, priv, pub);
			break;
			case SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:
				i2p::crypto::CreateRedDSA25519RandomKeys (priv, pub);
			break;
			default:
				LogPrint (eLogWarning, "Identity: Signing key type ", (int)type, " is not supported. Create DSA-SHA1");
				i2p::crypto::CreateDSARandomKeys (priv, pub); // DSA-SHA1
		}
	}

	void PrivateKeys::GenerateCryptoKeyPair (CryptoKeyType type, uint8_t * priv, uint8_t * pub)
	{
		switch (type)
		{
			case CRYPTO_KEY_TYPE_ELGAMAL:
				i2p::crypto::GenerateElGamalKeyPair(priv, pub);
			break;
			case CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC:
			case CRYPTO_KEY_TYPE_ECIES_P256_SHA256_AES256CBC_TEST:
				i2p::crypto::CreateECIESP256RandomKeys (priv, pub);
			break;
			case CRYPTO_KEY_TYPE_ECIES_GOSTR3410_CRYPTO_PRO_A_SHA256_AES256CBC:
				i2p::crypto::CreateECIESGOSTR3410RandomKeys (priv, pub);
			break;
			case CRYPTO_KEY_TYPE_ECIES_X25519_AEAD_RATCHET:
				i2p::crypto::CreateECIESX25519AEADRatchetRandomKeys (priv, pub);
			break;
			default:
				LogPrint (eLogError, "Identity: Crypto key type ", (int)type, " is not supported");
		}
	}

	PrivateKeys PrivateKeys::CreateOfflineKeys (SigningKeyType type, uint32_t expires) const
	{
		PrivateKeys keys (*this);
		std::unique_ptr<i2p::crypto::Verifier> verifier (IdentityEx::CreateVerifier (type));
		if (verifier)
		{
			size_t pubKeyLen = verifier->GetPublicKeyLen ();
			keys.m_TransientSigningPrivateKeyLen = verifier->GetPrivateKeyLen ();
			keys.m_TransientSignatureLen = verifier->GetSignatureLen ();
			keys.m_OfflineSignature.resize (pubKeyLen + m_Public->GetSignatureLen () + 6);
			htobe32buf (keys.m_OfflineSignature.data (), expires); // expires
			htobe16buf (keys.m_OfflineSignature.data () + 4, type); // type
			GenerateSigningKeyPair (type, keys.m_SigningPrivateKey, keys.m_OfflineSignature.data () + 6); // public  key
			Sign (keys.m_OfflineSignature.data (), pubKeyLen + 6, keys.m_OfflineSignature.data () + 6 + pubKeyLen); // signature
			// recreate signer
			keys.m_Signer = nullptr;
			keys.CreateSigner (type);
		}
		return keys;
	}

	Keys CreateRandomKeys ()
	{
		Keys keys;
		// encryption
		i2p::crypto::GenerateElGamalKeyPair(keys.privateKey, keys.publicKey);
		// signing
		i2p::crypto::CreateDSARandomKeys (keys.signingPrivateKey, keys.signingKey);
		return keys;
	}

	IdentHash CreateRoutingKey (const IdentHash& ident)
	{
		uint8_t buf[41]; // ident + yyyymmdd
		memcpy (buf, (const uint8_t *)ident, 32);
		i2p::util::GetCurrentDate ((char *)(buf + 32));
		IdentHash key;
		SHA256(buf, 40, key);
		return key;
	}

	XORMetric operator^(const IdentHash& key1, const IdentHash& key2)
	{
		XORMetric m;
#ifdef __AVX__
		if(i2p::cpu::avx)
		{
			__asm__
			(
				"vmovups %1, %%ymm0 \n"
				"vmovups %2, %%ymm1 \n"
				"vxorps %%ymm0, %%ymm1, %%ymm1 \n"
				"vmovups %%ymm1, %0 \n"
				: "=m"(*m.metric)
				: "m"(*key1), "m"(*key2)
				: "memory", "%xmm0", "%xmm1" // should be replaced by %ymm0/1 once supported by compiler
			);
		}
		else
#endif
		{
			const uint64_t * hash1 = key1.GetLL (), * hash2 = key2.GetLL ();
			m.metric_ll[0] = hash1[0] ^ hash2[0];
			m.metric_ll[1] = hash1[1] ^ hash2[1];
			m.metric_ll[2] = hash1[2] ^ hash2[2];
			m.metric_ll[3] = hash1[3] ^ hash2[3];
		}

		return m;
	}
}
}
