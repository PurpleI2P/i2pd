/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef FAMILY_H__
#define FAMILY_H__

#include <map>
#include <string>
#include <memory>
#include "Signature.h"
#include "Identity.h"

namespace i2p
{
namespace data
{
	typedef int FamilyID;
	class Families
	{
		public:

			Families ();
			~Families ();
			void LoadCertificates ();
			bool VerifyFamily (const std::string& family, const IdentHash& ident,
				const char * signature, const char * key = nullptr) const;
			FamilyID GetFamilyID (const std::string& family) const;

		private:

			void LoadCertificate (const std::string& filename);

		private:

			std::map<std::string, std::pair<std::shared_ptr<i2p::crypto::Verifier>, FamilyID> > m_SigningKeys; // family -> (verifier, id)
	};

	std::string CreateFamilySignature (const std::string& family, const IdentHash& ident);
	// return base64 signature of empty string in case of failure
}
}

#endif
