#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string.h>
#include <string>
#include <map>
#include <iostream>
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
			virtual void AddAddress (const i2p::data::IdentityEx& address) = 0;
			virtual void RemoveAddress (const i2p::data::IdentHash& ident) = 0;
		
			virtual int Load (std::map<std::string, i2p::data::IdentHash>& addresses) = 0;
			virtual int Save (const std::map<std::string, i2p::data::IdentHash>& addresses) = 0;
	};			

	class AddressBookSubscription;
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

			void LoadHostsFromStream (std::istream& f);
			
		private:

			AddressBookStorage * CreateStorage ();	

			void LoadHosts ();
			void LoadHostsFromI2P ();

		private:	
			
			std::map<std::string, i2p::data::IdentHash>  m_Addresses;
			AddressBookStorage * m_Storage;
			bool m_IsLoaded, m_IsDowloading;
	};

	class AddressBookSubscription
	{
		public:

			AddressBookSubscription (AddressBook& book, const std::string& link);
			void CheckSubscription ();

		private:

			void Request ();
		
		private:

			AddressBook& m_Book;
			std::string m_Link;
	};
}
}

#endif


