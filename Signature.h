#ifndef SIGNATURE_H__
#define SIGNATURE_H__

#include <inttypes.h>
#include <cryptopp/dsa.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include "CryptoConst.h"

namespace i2p
{
namespace crypto
{
	class Verifier
	{
		public:
			
			virtual ~Verifier () {};
			virtual bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature) = 0;
			virtual size_t GetPublicKeyLen () const = 0;
			virtual size_t GetSignatureLen () const = 0;
	};

	class Singer
	{
		public:

			virtual ~Singer () {};		
			virtual void Sign (CryptoPP::RandomNumberGenerator& rnd, const uint8_t * buf, int len, uint8_t * signature) = 0; 
	};

	class DSAVerifier: public Verifier
	{
		public:

			DSAVerifier (const uint8_t * signingKey)
			{
				m_PublicKey.Initialize (dsap, dsaq, dsag, CryptoPP::Integer (signingKey, 128));
			}
	
			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature)
			{
				CryptoPP::DSA::Verifier verifier (m_PublicKey);
				return verifier.VerifyMessage (buf, len, signature, 40);
			}	

			size_t GetPublicKeyLen () const { return 128; };
			size_t GetSignatureLen () const { return 40; };
			
		private:

			CryptoPP::DSA::PublicKey m_PublicKey;
	};

	class DSASinger: public Singer
	{
		public:

			DSASinger (const uint8_t * signingPrivateKey)
			{
				m_PrivateKey.Initialize (dsap, dsaq, dsag, CryptoPP::Integer (signingPrivateKey, 20));
			}

			void Sign (CryptoPP::RandomNumberGenerator& rnd, const uint8_t * buf, int len, uint8_t * signature)
			{
				CryptoPP::DSA::Signer signer (m_PrivateKey);
				signer.SignMessage (rnd, buf, len, signature);
			}

		private:

			CryptoPP::DSA::PrivateKey m_PrivateKey;
	};

	class ECDSAP256Verifier: public Verifier
	{
		public:

			ECDSAP256Verifier (const uint8_t * signingKey)
			{
				m_PublicKey.Initialize (CryptoPP::ASN1::secp256r1(), 
					CryptoPP::ECP::Point (CryptoPP::Integer (signingKey, 32), 
					CryptoPP::Integer (signingKey + 32, 32)));
			}			

			bool Verify (const uint8_t * buf, size_t len, const uint8_t * signature)
			{
				CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier (m_PublicKey);
				return verifier.VerifyMessage (buf, len, signature, 64);
			}	

			size_t GetPublicKeyLen () const { return 64; };
			size_t GetSignatureLen () const { return 64; };
			
		private:

			CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey m_PublicKey;
	};	

	class ECDSAP256Singer: public Singer
	{
		public:

			ECDSAP256Singer (const uint8_t * signingPrivateKey)
			{
				m_PrivateKey.Initialize (CryptoPP::ASN1::secp256r1(), CryptoPP::Integer (signingPrivateKey, 32));
			}

			void Sign (CryptoPP::RandomNumberGenerator& rnd, const uint8_t * buf, int len, uint8_t * signature)
			{
				CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer (m_PrivateKey);
				signer.SignMessage (rnd, buf, len, signature);
			}

		private:

			CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey m_PrivateKey;
	};
}
}

#endif

