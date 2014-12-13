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
		
		private:

			void LoadCertificate (const std::string& filename);
			
			int ReseedFromSU3 (const std::string& host);
			int ProcessSU3File (const char * filename);	
			int ProcessSU3Stream (std::istream& s);	

			bool FindZipDataDescriptor (std::istream& s);

		private:	

			std::map<std::string, PublicKey> m_SigningKeys;
	};
}
}

#endif
