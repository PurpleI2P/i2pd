#ifndef RESEED_H
#define RESEED_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include "Identity.h"

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

			std::string HttpsRequest (const std::string& address); // TODO: move to private section
			
		private:

			void LoadCertificate (const std::string& filename);
			std::string LoadCertificate (CryptoPP::ByteQueue& queue); // returns issuer's name
			
			int ReseedFromSU3 (const std::string& host);
			int ProcessSU3File (const char * filename);	
			int ProcessSU3Stream (std::istream& s);	

			bool FindZipDataDescriptor (std::istream& s);
			
			// for HTTPS
			void PRF (const uint8_t * secret, const char * label, const uint8_t * random, size_t len, uint8_t * buf);

		private:	

			std::map<std::string, PublicKey> m_SigningKeys;
	};
}
}

#endif
