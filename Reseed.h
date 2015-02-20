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

	class TlsSession
	{
		public:

			TlsSession (const std::string& host, int port);
			void Send (const uint8_t * buf, size_t len);
			bool Receive (std::ostream& rs);

		private:

			void Handshake ();
			void SendHandshakeMsg (uint8_t handshakeType, uint8_t * data, size_t len);
			CryptoPP::RSA::PublicKey ExtractPublicKey (const uint8_t * certificate, size_t len);
			void PRF (const uint8_t * secret, const char * label, const uint8_t * random, size_t randomLen,
				size_t len, uint8_t * buf);
			void CalculateMAC (uint8_t type, const uint8_t * buf, size_t len, uint8_t * mac);
			size_t Encrypt (const uint8_t * in, size_t len, const uint8_t * mac, uint8_t * out);
			size_t Decrypt (uint8_t * buf, size_t len); // pyaload is buf + 16		

		private:

			uint64_t m_Seqn;
			boost::asio::ip::tcp::iostream m_Site;
			CryptoPP::SHA256 m_FinishedHash;
			CryptoPP::AutoSeededRandomPool m_Rnd;
			i2p::crypto::CBCEncryption m_Encryption;
			i2p::crypto::CBCDecryption m_Decryption; 
			uint8_t m_MacKey[32]; // client	
	};
}
}

#endif
