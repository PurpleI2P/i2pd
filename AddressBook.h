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
namespace client
{
	class AddressBookStorage // interface for storage
	{
		public:

			virtual ~AddressBookStorage () {};
			virtual bool GetAddress (const i2p::data::IdentHash& ident, i2p::data::IdentityEx& address) const = 0;
			virtual const i2p::data::IdentHash * FindAddress (const std::string& name) const = 0;	
			virtual void AddAddress (std::string& name, const i2p::data::IdentHash& ident) = 0;		
			virtual void AddAddress (const i2p::data::IdentityEx& address) = 0;
			virtual void RemoveAddress (const i2p::data::IdentHash& ident) = 0;
		
			virtual int Load () = 0;
			virtual int Save () = 0;
	};			

	class AddressBook
	{
		public:

			AddressBook ();
			~AddressBook ();
			bool GetIdentHash (const std::string& address, i2p::data::IdentHash& ident);
			bool GetAddress (const std::string& address, i2p::data::IdentityEx& identity);
			const i2p::data::IdentHash * FindAddress (const std::string& address);
			void InsertAddress (const std::string& address, const std::string& base64); // for jump service
			void InsertAddress (const i2p::data::IdentityEx& address);
		
		private:

			AddressBookStorage * CreateStorage ();	

		private:	

			void LoadHosts ();
			void LoadHostsFromI2P ();

			std::map<std::string, i2p::data::IdentHash>  m_Addresses;
			AddressBookStorage * m_Storage;
			bool m_IsLoaded, m_IsDowloading;
	};
}
}

#endif


