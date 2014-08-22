#ifndef SIGNATURE_H__
#define SIGNATURE_H__

#include <inttypes.h>
#include <cryptopp/dsa.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
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
}
}

#endif

