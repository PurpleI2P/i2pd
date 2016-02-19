#ifndef FAMILY_H__
#define FAMILY_H_

#include <map>
#include <string>
#include <memory>
#include "Signature.h"

namespace i2p
{
namespace data
{
	class Families
	{
		public:

			Families ();
			~Families ();
			void LoadCertificates ();

		private:

			void LoadCertificate (const std::string& filename);

		private:

			std::map<std::string, std::shared_ptr<i2p::crypto::Verifier> > m_SigningKeys;
	};		
}
}

#endif
