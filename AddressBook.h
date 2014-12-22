#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string.h>
#include <string>
#include <map>
#include <list>
#include <iostream>
#include <mutex>
#include "base64.h"
#include "util.h"
#include "Identity.h"
#include "Log.h"

namespace i2p
{
namespace client
{
	const char DEFAULT_SUBSCRIPTION_ADDRESS[] = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt";
	// TODO: move http fields to common http code	
	const char HTTP_FIELD_ETAG[] = "ETag";
	const char HTTP_FIELD_IF_MODIFIED_SINCE[] = "If-Modified-Since";
	const char HTTP_FIELD_LAST_MODIFIED[] = "Last-Modified";
		
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
			void SetIsDownloading (bool isDownloading) {  m_IsDownloading = isDownloading; };
			
		private:

			AddressBookStorage * CreateStorage ();	
			void LoadHosts ();
			void LoadSubscriptions ();

		private:	

			std::mutex m_AddressBookMutex;
			std::map<std::string, i2p::data::IdentHash>  m_Addresses;
			AddressBookStorage * m_Storage;
			volatile bool m_IsLoaded, m_IsDownloading;
			std::list<AddressBookSubscription *> m_Subscriptions;
			AddressBookSubscription * m_DefaultSubscription; // in case if we don't know any addresses yet
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
			std::string m_Link, m_Etag, m_LastModified;
	};
}
}

#endif


