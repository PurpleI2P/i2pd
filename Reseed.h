#ifndef RESEED_H
#define RESEED_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <boost/asio.hpp>
#include "Identity.h"
#include "aes.h"

namespace i2p
{
namespace data
{

	class Reseeder
	{
		typedef Tag<512> PublicKey;	
		
		public:
		
			Reseeder();
			~Reseeder();
			bool reseedNow(); // depreacted
			int ReseedNowSU3 ();

			void LoadCertificates ();
			
		private:

			void LoadCertificate (const std::string& filename);
			std::string LoadCertificate (CryptoPP::ByteQueue& queue); // returns issuer's name
			
			int ReseedFromSU3 (const std::string& host, bool https = false);
			int ProcessSU3File (const char * filename);	
			int ProcessSU3Stream (std::istream& s);	

			bool FindZipDataDescriptor (std::istream& s);
			
			std::string HttpsRequest (const std::string& address);

		private:	

			std::map<std::string, PublicKey> m_SigningKeys;
	};


	class TlsCipher
	{
		public:

			virtual ~TlsCipher () {};

			virtual void CalculateMAC (uint8_t type, const uint8_t * buf, size_t len, uint8_t * mac) = 0;
			virtual size_t Encrypt (const uint8_t * in, size_t len, const uint8_t * mac, uint8_t * out) = 0;
			virtual size_t Decrypt (uint8_t * buf, size_t len) = 0;
	};


	class TlsSession
	{
		public:

			TlsSession (const std::string& host, int port);
			~TlsSession ();
			void Send (const uint8_t * buf, size_t len);
			bool Receive (std::ostream& rs);

			static void PRF (const uint8_t * secret, const char * label, const uint8_t * random, size_t randomLen,
				size_t len, uint8_t * buf);

		private:

			void Handshake ();
			void SendHandshakeMsg (uint8_t handshakeType, uint8_t * data, size_t len);
			void SendFinishedMsg ();
			CryptoPP::RSA::PublicKey ExtractPublicKey (const uint8_t * certificate, size_t len);

		private:

			boost::asio::ip::tcp::iostream m_Site;
			CryptoPP::SHA256 m_FinishedHash;
			uint8_t m_MasterSecret[64]; // actual size is 48, but must be multiple of 32
			TlsCipher * m_Cipher;
	};
}
}

#endif
