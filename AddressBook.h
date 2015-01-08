#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <mutex>
#include <boost/asio.hpp>
#include "base64.h"
#include "util.h"
#include "Identity.h"
#include "Log.h"

namespace i2p
{
namespace client
{
	const char DEFAULT_SUBSCRIPTION_ADDRESS[] = "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt";
	const int INITIAL_SUBSCRIPTION_UPDATE_TIMEOUT = 3; // in minutes	
	const int INITIAL_SUBSCRIPTION_RETRY_TIMEOUT = 1; // in minutes			
	const int CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT = 720; // in minutes (12 hours)			
	const int CONTINIOUS_SUBSCRIPTION_RETRY_TIMEOUT = 5; // in minutes	
	const int SUBSCRIPTION_REQUEST_TIMEOUT = 60; //in second
	
	inline std::string GetB32Address(const i2p::data::IdentHash& ident) { return ident.ToBase32().append(".b32.i2p"); }

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

			void StartSubscriptions ();
			void StopSubscriptions ();
			void LoadHostsFromStream (std::istream& f);
			void DownloadComplete (bool success);
			//This method returns the ".b32.i2p" address
			std::string ToAddress(const i2p::data::IdentHash& ident) { return GetB32Address(ident); }
			std::string ToAddress(const i2p::data::IdentityEx& ident) { return ToAddress(ident.GetIdentHash ()); }
		private:

			AddressBookStorage * CreateStorage ();	
			void LoadHosts ();
			void LoadSubscriptions ();

			void HandleSubscriptionsUpdateTimer (const boost::system::error_code& ecode);

		private:	

			std::mutex m_AddressBookMutex;
			std::map<std::string, i2p::data::IdentHash>  m_Addresses;
			AddressBookStorage * m_Storage;
			volatile bool m_IsLoaded, m_IsDownloading;
			std::vector<AddressBookSubscription *> m_Subscriptions;
			AddressBookSubscription * m_DefaultSubscription; // in case if we don't know any addresses yet
			boost::asio::deadline_timer * m_SubscriptionsUpdateTimer;
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


