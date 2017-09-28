#ifndef SIGNATURE_H__
#define SIGNATURE_H__

#include <inttypes.h>
#include <string.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "Crypto.h"
#include "Gost.h"

namespace i2p
{
namespace crypto
{
	class Verifier
	{
		public:
			
			virtual ~Verifier () {};
			virtual bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const = 0;
			virtual size_t GetPublicKeyLen () const = 0;
			virtual size_t GetSignatureLen () const = 0;
			virtual size_t GetPrivateKeyLen () const { return GetSignatureLen ()/2; };
	};

	class Signer
	{
		public:

			virtual ~Signer () {};		
			virtual void Sign (const uint8_t * buf, int len, uint8_t * signature) const = 0; 
	};

	const size_t DSA_PUBLIC_KEY_LENGTH = 128;
	const size_t DSA_SIGNATURE_LENGTH = 40;	
	const size_t DSA_PRIVATE_KEY_LENGTH = DSA_SIGNATURE_LENGTH/2;
	class DSAVerifier: public Verifier
	{
		public:

			DSAVerifier (const uint8_t * signingKey)
			{
				m_PublicKey = CreateDSA ();
				DSA_set0_key (m_PublicKey, BN_bin2bn (signingKey, DSA_PUBLIC_KEY_LENGTH, NULL), NULL);
			}

			~DSAVerifier ()
			{
				DSA_free (m_PublicKey);
			}
			
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				// calculate SHA1 digest
				uint8_t digest[20];
				SHA1 (buf, len, digest);
				// signature
				DSA_SIG * sig = DSA_SIG_new();
				DSA_SIG_set0 (sig, BN_bin2bn (signature, DSA_SIGNATURE_LENGTH/2, NULL), BN_bin2bn (signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2, NULL));
				// DSA verification
				int ret = DSA_do_verify (digest, 20, sig, m_PublicKey);
				DSA_SIG_free(sig);
				return ret;
			}	

			size_t GetPublicKeyLen () const { return DSA_PUBLIC_KEY_LENGTH; };
			size_t GetSignatureLen () const { return DSA_SIGNATURE_LENGTH; };
			
		private:

			DSA * m_PublicKey;
	};

	class DSASigner: public Signer
	{
		public:

			DSASigner (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey)
			// openssl 1.1 always requires DSA public key even for signing
			{
				m_PrivateKey = CreateDSA ();
				DSA_set0_key (m_PrivateKey, BN_bin2bn (signingPublicKey, DSA_PUBLIC_KEY_LENGTH, NULL), BN_bin2bn (signingPrivateKey, DSA_PRIVATE_KEY_LENGTH, NULL));
			}

			~DSASigner ()
			{
				DSA_free (m_PrivateKey);
			}
			
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[20];
				SHA1 (buf, len, digest);
				DSA_SIG * sig = DSA_do_sign (digest, 20, m_PrivateKey);
				const BIGNUM * r, * s;
				DSA_SIG_get0 (sig, &r, &s);
				bn2buf (r, signature, DSA_SIGNATURE_LENGTH/2);
				bn2buf (s, signature + DSA_SIGNATURE_LENGTH/2, DSA_SIGNATURE_LENGTH/2);
				DSA_SIG_free(sig);
			}

		private:

			DSA * m_PrivateKey;
	};

	inline void CreateDSARandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		DSA * dsa = CreateDSA ();
		DSA_generate_key (dsa);
		const BIGNUM * pub_key, * priv_key;
		DSA_get0_key(dsa, &pub_key, &priv_key);
		bn2buf (priv_key, signingPrivateKey, DSA_PRIVATE_KEY_LENGTH);
		bn2buf (pub_key, signingPublicKey, DSA_PUBLIC_KEY_LENGTH);
		DSA_free (dsa);	
	}	

	struct SHA256Hash
	{	
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			SHA256 (buf, len, digest);
		}

		enum { hashLen = 32 };
	};	

	struct SHA384Hash
	{	
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			SHA384 (buf, len, digest);
		}

		enum { hashLen = 48 };
	};

	struct SHA512Hash
	{	
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			SHA512 (buf, len, digest);
		}

		enum { hashLen = 64 };
	};
	
	template<typename Hash, int curve, size_t keyLen>
	class ECDSAVerifier: public Verifier
	{		
		public:

			ECDSAVerifier (const uint8_t * signingKey)
			{
				m_PublicKey = EC_KEY_new_by_curve_name (curve);
				BIGNUM * x = BN_bin2bn (signingKey, keyLen/2, NULL);
				BIGNUM * y = BN_bin2bn (signingKey + keyLen/2, keyLen/2, NULL);
				EC_KEY_set_public_key_affine_coordinates (m_PublicKey, x, y);
				BN_free (x); BN_free (y);
			}

			~ECDSAVerifier ()
			{
				EC_KEY_free (m_PublicKey);
			}
			
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				ECDSA_SIG * sig = ECDSA_SIG_new();
				auto r = BN_bin2bn (signature, GetSignatureLen ()/2, NULL);
				auto s = BN_bin2bn (signature + GetSignatureLen ()/2, GetSignatureLen ()/2, NULL);
				ECDSA_SIG_set0(sig, r, s);
				// ECDSA verification
				int ret = ECDSA_do_verify (digest, Hash::hashLen, sig, m_PublicKey);
				ECDSA_SIG_free(sig);
				return ret;
			}	
			
			size_t GetPublicKeyLen () const { return keyLen; };
			size_t GetSignatureLen () const { return keyLen; }; // signature length = key length

			
		private:

			EC_KEY * m_PublicKey;
	};

	template<typename Hash, int curve, size_t keyLen>
	class ECDSASigner: public Signer
	{
		public:

			ECDSASigner (const uint8_t * signingPrivateKey)
			{
				m_PrivateKey = EC_KEY_new_by_curve_name (curve);
				EC_KEY_set_private_key (m_PrivateKey, BN_bin2bn (signingPrivateKey, keyLen/2, NULL));			
			}

			~ECDSASigner ()
			{
				EC_KEY_free (m_PrivateKey);
			}
			
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				ECDSA_SIG * sig = ECDSA_do_sign (digest, Hash::hashLen, m_PrivateKey);
				const BIGNUM * r, * s;
				ECDSA_SIG_get0 (sig, &r, &s);
				// signatureLen = keyLen
				bn2buf (r, signature, keyLen/2);
				bn2buf (s, signature + keyLen/2, keyLen/2);
				ECDSA_SIG_free(sig);
			}

		private:

			EC_KEY * m_PrivateKey;
	};

	inline void CreateECDSARandomKeys (int curve, size_t keyLen, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		EC_KEY * signingKey = EC_KEY_new_by_curve_name (curve);
		EC_KEY_generate_key (signingKey);
		bn2buf (EC_KEY_get0_private_key (signingKey), signingPrivateKey, keyLen/2);
		BIGNUM * x = BN_new(), * y = BN_new();
		EC_POINT_get_affine_coordinates_GFp (EC_KEY_get0_group(signingKey),
			EC_KEY_get0_public_key (signingKey), x, y, NULL);
		bn2buf (x, signingPublicKey, keyLen/2);
		bn2buf (y, signingPublicKey + keyLen/2, keyLen/2);
		BN_free (x); BN_free (y);
		EC_KEY_free (signingKey);		
	}

// ECDSA_SHA256_P256
	const size_t ECDSAP256_KEY_LENGTH = 64;	
	typedef ECDSAVerifier<SHA256Hash, NID_X9_62_prime256v1, ECDSAP256_KEY_LENGTH> ECDSAP256Verifier;
	typedef ECDSASigner<SHA256Hash, NID_X9_62_prime256v1, ECDSAP256_KEY_LENGTH> ECDSAP256Signer;

	inline void CreateECDSAP256RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		CreateECDSARandomKeys (NID_X9_62_prime256v1, ECDSAP256_KEY_LENGTH, signingPrivateKey, signingPublicKey);
	}	

// ECDSA_SHA384_P384
	const size_t ECDSAP384_KEY_LENGTH = 96;
	typedef ECDSAVerifier<SHA384Hash, NID_secp384r1, ECDSAP384_KEY_LENGTH> ECDSAP384Verifier;
	typedef ECDSASigner<SHA384Hash, NID_secp384r1, ECDSAP384_KEY_LENGTH> ECDSAP384Signer;

	inline void CreateECDSAP384RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		CreateECDSARandomKeys (NID_secp384r1, ECDSAP384_KEY_LENGTH, signingPrivateKey, signingPublicKey);
	}	

// ECDSA_SHA512_P521
	const size_t ECDSAP521_KEY_LENGTH = 132;
	typedef ECDSAVerifier<SHA512Hash, NID_secp521r1, ECDSAP521_KEY_LENGTH> ECDSAP521Verifier;
	typedef ECDSASigner<SHA512Hash, NID_secp521r1, ECDSAP521_KEY_LENGTH> ECDSAP521Signer;

	inline void CreateECDSAP521RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		CreateECDSARandomKeys (NID_secp521r1, ECDSAP521_KEY_LENGTH, signingPrivateKey, signingPublicKey);
	}

// RSA
	template<typename Hash, int type, size_t keyLen>	
	class RSAVerifier: public Verifier
	{
		public:

			RSAVerifier (const uint8_t * signingKey)
			{
				m_PublicKey = RSA_new ();
				RSA_set0_key (m_PublicKey, BN_bin2bn (signingKey, keyLen, NULL) /* n */ , BN_dup (GetRSAE ()) /* d */, NULL);
			}

			~RSAVerifier ()
			{
				RSA_free (m_PublicKey);
			}
			
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const 
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				return RSA_verify (type, digest, Hash::hashLen, signature, GetSignatureLen (), m_PublicKey);
			}
			size_t GetPublicKeyLen () const { return keyLen; }
			size_t GetSignatureLen () const { return keyLen; }	
			size_t GetPrivateKeyLen () const { return GetSignatureLen ()*2; };

		private:
			
			RSA * m_PublicKey;			
	};	

	
	template<typename Hash, int type, size_t keyLen>
	class RSASigner: public Signer
	{
		public:

			RSASigner (const uint8_t * signingPrivateKey)
			{
				m_PrivateKey = RSA_new ();
				RSA_set0_key (m_PrivateKey, BN_bin2bn (signingPrivateKey, keyLen, NULL), /* n */
					BN_dup (GetRSAE ()) /* e */, BN_bin2bn (signingPrivateKey + keyLen, keyLen, NULL) /* d */);
			}

			~RSASigner ()
			{
				RSA_free (m_PrivateKey);
			}
			
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				unsigned int signatureLen = keyLen;
				RSA_sign (type, digest, Hash::hashLen, signature, &signatureLen, m_PrivateKey);
			}
			
		private:

			RSA * m_PrivateKey;
	};		

	inline void CreateRSARandomKeys (size_t publicKeyLen, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		RSA * rsa = RSA_new ();
		BIGNUM * e = BN_dup (GetRSAE ()); // make it non-const
		RSA_generate_key_ex (rsa, publicKeyLen*8, e, NULL);
		const BIGNUM * n, * d, * e1;
		RSA_get0_key (rsa, &n, &e1, &d);	
		bn2buf (n, signingPrivateKey, publicKeyLen);
		bn2buf (d, signingPrivateKey + publicKeyLen, publicKeyLen);
		bn2buf (n, signingPublicKey, publicKeyLen);
		BN_free (e); // this e is not assigned to rsa->e
		RSA_free (rsa);
	}	
	
//  RSA_SHA256_2048
	const size_t RSASHA2562048_KEY_LENGTH = 256;
	typedef RSAVerifier<SHA256Hash, NID_sha256, RSASHA2562048_KEY_LENGTH> RSASHA2562048Verifier;
	typedef RSASigner<SHA256Hash, NID_sha256, RSASHA2562048_KEY_LENGTH> RSASHA2562048Signer;

//  RSA_SHA384_3072
	const size_t RSASHA3843072_KEY_LENGTH = 384;
	typedef RSAVerifier<SHA384Hash, NID_sha384, RSASHA3843072_KEY_LENGTH> RSASHA3843072Verifier;
	typedef RSASigner<SHA384Hash, NID_sha384, RSASHA3843072_KEY_LENGTH> RSASHA3843072Signer;	

//  RSA_SHA512_4096
	const size_t RSASHA5124096_KEY_LENGTH = 512;
	typedef RSAVerifier<SHA512Hash, NID_sha512, RSASHA5124096_KEY_LENGTH> RSASHA5124096Verifier;
	typedef RSASigner<SHA512Hash, NID_sha512, RSASHA5124096_KEY_LENGTH> RSASHA5124096Signer;

	// EdDSA
	struct EDDSAPoint
	{
		BIGNUM * x {nullptr};
		BIGNUM * y {nullptr};
		BIGNUM * z {nullptr};
		BIGNUM * t {nullptr}; // projective coordinates

		EDDSAPoint () {}
		EDDSAPoint (const EDDSAPoint& other)   { *this = other; }
		EDDSAPoint (EDDSAPoint&& other)        { *this = std::move (other); }
		EDDSAPoint (BIGNUM * x1, BIGNUM * y1, BIGNUM * z1 = nullptr, BIGNUM * t1 = nullptr)
			: x(x1)
			, y(y1)
			, z(z1)
			, t(t1)
		{}
		~EDDSAPoint () { BN_free (x); BN_free (y); BN_free(z); BN_free(t); }

		EDDSAPoint& operator=(EDDSAPoint&& other) 
		{
			if (this != &other)
			{
				BN_free (x); x = other.x; other.x = nullptr;
				BN_free (y); y = other.y; other.y = nullptr;
				BN_free (z); z = other.z; other.z = nullptr;
				BN_free (t); t = other.t; other.t = nullptr;
			}
			return *this;
		} 	

		EDDSAPoint& operator=(const EDDSAPoint& other) 
		{
			if (this != &other)
			{
				BN_free (x); x = other.x ? BN_dup (other.x) : nullptr;
				BN_free (y); y = other.y ? BN_dup (other.y) : nullptr;
				BN_free (z); z = other.z ? BN_dup (other.z) : nullptr;
				BN_free (t); t = other.t ? BN_dup (other.t) : nullptr;
			}
			return *this;
		}

		EDDSAPoint operator-() const
		{
			BIGNUM * x1 = NULL, * y1 = NULL, * z1 = NULL, * t1 = NULL;
			if (x) { x1 = BN_dup (x); BN_set_negative (x1, !BN_is_negative (x)); };
			if (y) y1 = BN_dup (y);
			if (z) z1 = BN_dup (z);
			if (t) { t1 = BN_dup (t); BN_set_negative (t1, !BN_is_negative (t)); };
			return EDDSAPoint {x1, y1, z1, t1};
		}
	};	

	const size_t EDDSA25519_PUBLIC_KEY_LENGTH = 32;
	const size_t EDDSA25519_SIGNATURE_LENGTH = 64;
	const size_t EDDSA25519_PRIVATE_KEY_LENGTH = 32;		
	class EDDSA25519Verifier: public Verifier
	{
		public:

			EDDSA25519Verifier (const uint8_t * signingKey);
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const;

			size_t GetPublicKeyLen () const { return EDDSA25519_PUBLIC_KEY_LENGTH; };
			size_t GetSignatureLen () const { return EDDSA25519_SIGNATURE_LENGTH; };

		private:

			EDDSAPoint m_PublicKey;	
			uint8_t m_PublicKeyEncoded[EDDSA25519_PUBLIC_KEY_LENGTH];
	};

	class EDDSA25519Signer: public Signer
	{
		public:

			EDDSA25519Signer (const uint8_t * signingPrivateKey, const uint8_t * signingPublicKey = nullptr); 
			// we pass signingPublicKey to check if it matches private key 
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const; 
			const uint8_t * GetPublicKey () const { return m_PublicKeyEncoded; };
			
		private:

			uint8_t m_ExpandedPrivateKey[64]; 
			uint8_t m_PublicKeyEncoded[EDDSA25519_PUBLIC_KEY_LENGTH];
	};

	inline void CreateEDDSA25519RandomKeys (uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		RAND_bytes (signingPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH);
		EDDSA25519Signer signer (signingPrivateKey);
		memcpy (signingPublicKey, signer.GetPublicKey (), EDDSA25519_PUBLIC_KEY_LENGTH);
	}


	// ГОСТ Р 34.11		
	struct GOSTR3411_256_Hash
	{	
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			GOSTR3411_2012_256 (buf, len, digest); 
		}

		enum { hashLen = 32 };
	};

	struct GOSTR3411_512_Hash
	{	
		static void CalculateHash (const uint8_t * buf, size_t len, uint8_t * digest)
		{
			GOSTR3411_2012_512 (buf, len, digest); 
		}

		enum { hashLen = 64 };
	};

	// ГОСТ Р 34.10
	const size_t GOSTR3410_256_PUBLIC_KEY_LENGTH = 64;
	const size_t GOSTR3410_512_PUBLIC_KEY_LENGTH = 128;

	template<typename Hash>
	class GOSTR3410Verifier: public Verifier
	{
		public:

			enum { keyLen = Hash::hashLen };
			
			GOSTR3410Verifier (GOSTR3410ParamSet paramSet, const uint8_t * signingKey):
				m_ParamSet (paramSet)
			{
				BIGNUM * x = BN_bin2bn (signingKey, GetPublicKeyLen ()/2, NULL);
				BIGNUM * y = BN_bin2bn (signingKey + GetPublicKeyLen ()/2, GetPublicKeyLen ()/2, NULL);
				m_PublicKey = GetGOSTR3410Curve (m_ParamSet)->CreatePoint (x, y);
				BN_free (x); BN_free (y);
			}
			~GOSTR3410Verifier () { EC_POINT_free (m_PublicKey); }
			
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				BIGNUM * d = BN_bin2bn (digest, Hash::hashLen, nullptr);
				BIGNUM * r = BN_bin2bn (signature, GetSignatureLen ()/2, NULL);
				BIGNUM * s = BN_bin2bn (signature + GetSignatureLen ()/2, GetSignatureLen ()/2, NULL);
				bool ret = GetGOSTR3410Curve (m_ParamSet)->Verify (m_PublicKey, d, r, s);
				BN_free (d); BN_free (r); BN_free (s);	
				return ret;
			}

			size_t GetPublicKeyLen () const { return keyLen*2; }
			size_t GetSignatureLen () const { return keyLen*2; }

		private:

			GOSTR3410ParamSet m_ParamSet;
			EC_POINT * m_PublicKey;
	};	

	template<typename Hash>
	class GOSTR3410Signer: public Signer
	{
		public:

			enum { keyLen = Hash::hashLen };
			
			GOSTR3410Signer (GOSTR3410ParamSet paramSet, const uint8_t * signingPrivateKey):
				m_ParamSet (paramSet)
			{ 
				m_PrivateKey = BN_bin2bn (signingPrivateKey, keyLen, nullptr); 
			}
			~GOSTR3410Signer () { BN_free (m_PrivateKey); }

			void Sign (const uint8_t * buf, int len, uint8_t * signature) const
			{
				uint8_t digest[Hash::hashLen];
				Hash::CalculateHash (buf, len, digest);
				BIGNUM * d = BN_bin2bn (digest, Hash::hashLen, nullptr); 
				BIGNUM * r = BN_new (), * s = BN_new ();
				GetGOSTR3410Curve (m_ParamSet)->Sign (m_PrivateKey, d, r, s);
				bn2buf (r, signature, keyLen);
				bn2buf (s, signature + keyLen, keyLen);
				BN_free (d); BN_free (r); BN_free (s);
			}
			
		private:

			GOSTR3410ParamSet m_ParamSet;
			BIGNUM * m_PrivateKey;
	};	

	inline void CreateGOSTR3410RandomKeys (GOSTR3410ParamSet paramSet, uint8_t * signingPrivateKey, uint8_t * signingPublicKey)
	{
		const auto& curve = GetGOSTR3410Curve (paramSet);
		auto keyLen = curve->GetKeyLen ();
		RAND_bytes (signingPrivateKey, keyLen);
		BIGNUM * priv = BN_bin2bn (signingPrivateKey, keyLen, nullptr);
		
		auto pub = curve->MulP (priv);
		BN_free (priv);
		BIGNUM * x = BN_new (), * y = BN_new ();
		curve->GetXY (pub, x, y);
		EC_POINT_free (pub);
		bn2buf (x, signingPublicKey, keyLen);
		bn2buf (y, signingPublicKey + keyLen, keyLen);
		BN_free (x); BN_free (y); 
	}

	typedef GOSTR3410Verifier<GOSTR3411_256_Hash> GOSTR3410_256_Verifier;
	typedef GOSTR3410Signer<GOSTR3411_256_Hash> GOSTR3410_256_Signer;
	typedef GOSTR3410Verifier<GOSTR3411_512_Hash> GOSTR3410_512_Verifier;
	typedef GOSTR3410Signer<GOSTR3411_512_Hash> GOSTR3410_512_Signer;
}
}

#endif

