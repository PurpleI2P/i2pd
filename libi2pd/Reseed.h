/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

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
			void Bootstrap ();
			int ReseedFromServers ();
			int ProcessSU3File (const char * filename);
			int ProcessZIPFile (const char * filename);

			void LoadCertificates ();

		private:

			int ReseedFromSU3Url (const std::string& url, bool isHttps = true);
			void LoadCertificate (const std::string& filename);

			int ProcessSU3Stream (std::istream& s);
			int ProcessZIPStream (std::istream& s, uint64_t contentLength);

			bool FindZipDataDescriptor (std::istream& s);

			std::string HttpsRequest (const std::string& address);
			std::string YggdrasilRequest (const std::string& address);
			template<typename Stream>
			std::string ReseedRequest (Stream& s, const std::string& uri);		
		
		private:

			std::map<std::string, PublicKey> m_SigningKeys;
	};
}
}

#endif
