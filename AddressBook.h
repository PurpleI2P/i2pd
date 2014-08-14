#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string.h>
#include <string>
#include <map>
#include "base64.h"
#include "util.h"
#include "Identity.h"
#include "Log.h"

namespace i2p
{
namespace data
{
	class AddressBook
	{
		public:

			AddressBook ();
			const IdentHash * FindAddress (const std::string& address);
		
		private:
	
			void LoadHosts ();
			void LoadHostsFromI2P ();

			std::map<std::string, IdentHash>  m_Addresses;
			bool m_IsLoaded, m_IsDowloading;
	};
}
}

#endif


