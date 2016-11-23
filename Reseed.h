#ifndef RESEED_H
#define RESEED_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include "Identity.h"
#include "Crypto.h"

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
			int ReseedNowSU3 ();

			void LoadCertificates ();
			
		private:

			void LoadCertificate (const std::string& filename);
						
			int ReseedFromSU3 (const std::string& url);
			int ProcessSU3File (const char * filename);	
			int ProcessSU3Stream (std::istream& s);	

			bool FindZipDataDescriptor (std::istream& s);
			
			std::string HttpsRequest (const std::string& address);

		private:	

			std::map<std::string, PublicKey> m_SigningKeys;
	};
}
}

#endif
