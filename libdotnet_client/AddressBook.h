#ifndef ADDRESS_BOOK_H__
#define ADDRESS_BOOK_H__

#include <string.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>
#include "Base.h"
#include "Identity.h"
#include "Log.h"
#include "Destination.h"
#include "LeaseSet.h"

namespace dotnet
{
namespace client
{
	const int INITIAL_SUBSCRIPTION_UPDATE_TIMEOUT = 3; // in minutes
	const int INITIAL_SUBSCRIPTION_RETRY_TIMEOUT = 1; // in minutes
	const int CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT = 720; // in minutes (12 hours)
	const int CONTINIOUS_SUBSCRIPTION_RETRY_TIMEOUT = 5; // in minutes
	const int CONTINIOUS_SUBSCRIPTION_MAX_NUM_RETRIES = 10; // then update timeout
	const int SUBSCRIPTION_REQUEST_TIMEOUT = 120; //in second

	const uint16_t ADDRESS_RESOLVER_DATAGRAM_PORT = 53;
	const uint16_t ADDRESS_RESPONSE_DATAGRAM_PORT = 54;

	const size_t B33_ADDRESS_THRESHOLD = 52; // characters

	struct Address
	{
		enum { eAddressIndentHash, eAddressBlindedPublicKey } addressType;
		dotnet::data::IdentHash identHash;
		std::shared_ptr<dotnet::data::BlindedPublicKey> blindedPublicKey;

		Address (const std::string& b32);	
		Address (const dotnet::data::IdentHash& hash);	
		bool IsIdentHash () const { return addressType == eAddressIndentHash; };
	};

	inline std::string GetB32Address(const dotnet::data::IdentHash& ident) { return ident.ToBase32().append(".dot.net"); }

	class AddressBookStorage // interface for storage
	{
		public:

			virtual ~AddressBookStorage () {};
			virtual std::shared_ptr<const dotnet::data::IdentityEx> GetAddress (const dotnet::data::IdentHash& ident) const = 0;
			virtual void AddAddress (std::shared_ptr<const dotnet::data::IdentityEx> address) = 0;
			virtual void RemoveAddress (const dotnet::data::IdentHash& ident) = 0;

			virtual bool Init () = 0;
			virtual int Load (std::map<std::string, std::shared_ptr<Address> >& addresses) = 0;
			virtual int LoadLocal (std::map<std::string, std::shared_ptr<Address> >& addresses) = 0;
			virtual int Save (const std::map<std::string, std::shared_ptr<Address> >& addresses) = 0;

			virtual void SaveEtag (const dotnet::data::IdentHash& subscription, const std::string& etag, const std::string& lastModified) = 0;
			virtual bool GetEtag (const dotnet::data::IdentHash& subscription, std::string& etag, std::string& lastModified) = 0;
			virtual void ResetEtags () = 0;
	};

	class AddressBookSubscription;
	class AddressResolver;
	class AddressBook
	{
		public:

			AddressBook ();
			~AddressBook ();
			void Start ();
			void StartResolvers ();
			void Stop ();
			std::shared_ptr<const Address> GetAddress (const std::string& address);
			std::shared_ptr<const dotnet::data::IdentityEx> GetFullAddress (const std::string& address);
			std::shared_ptr<const Address> FindAddress (const std::string& address);
			void LookupAddress (const std::string& address);
			void InsertAddress (const std::string& address, const std::string& jump); // for jump links
			void InsertFullAddress (std::shared_ptr<const dotnet::data::IdentityEx> address);

			bool LoadHostsFromStream (std::istream& f, bool is_update);
			void DownloadComplete (bool success, const dotnet::data::IdentHash& subscription, const std::string& etag, const std::string& lastModified);
			//This method returns the ".dot.net" address
			std::string ToAddress(const dotnet::data::IdentHash& ident) { return GetB32Address(ident); }
			std::string ToAddress(std::shared_ptr<const dotnet::data::IdentityEx> ident) { return ToAddress(ident->GetIdentHash ()); }

			bool GetEtag (const dotnet::data::IdentHash& subscription, std::string& etag, std::string& lastModified);

		private:

			void StartSubscriptions ();
			void StopSubscriptions ();

			void LoadHosts ();
			void LoadSubscriptions ();
			void LoadLocal ();

			void HandleSubscriptionsUpdateTimer (const boost::system::error_code& ecode);

			void StartLookups ();
			void StopLookups ();
			void HandleLookupResponse (const dotnet::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

		private:

			std::mutex m_AddressBookMutex;
			std::map<std::string, std::shared_ptr<Address> >  m_Addresses;
			std::map<dotnet::data::IdentHash, std::shared_ptr<AddressResolver> > m_Resolvers; // local destination->resolver
			std::mutex m_LookupsMutex;
			std::map<uint32_t, std::string> m_Lookups; // nonce -> address
			AddressBookStorage * m_Storage;
			volatile bool m_IsLoaded, m_IsDownloading;
			int m_NumRetries;
			std::vector<std::shared_ptr<AddressBookSubscription> > m_Subscriptions;
			std::shared_ptr<AddressBookSubscription> m_DefaultSubscription; // in case if we don't know any addresses yet
			boost::asio::deadline_timer * m_SubscriptionsUpdateTimer;
	};

	class AddressBookSubscription
	{
		public:

			AddressBookSubscription (AddressBook& book, const std::string& link);
			void CheckUpdates ();

		private:

			bool MakeRequest ();

		private:

			AddressBook& m_Book;
			std::string m_Link, m_Etag, m_LastModified;
			dotnet::data::IdentHash m_Ident;
			// m_Etag must be surrounded by ""
	};

	class AddressResolver
	{
		public:

			AddressResolver (std::shared_ptr<ClientDestination> destination);
			~AddressResolver ();
			void AddAddress (const std::string& name, const dotnet::data::IdentHash& ident);

		private:

			void HandleRequest (const dotnet::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

		private:

			std::shared_ptr<ClientDestination> m_LocalDestination;
			std::map<std::string, dotnet::data::IdentHash>  m_LocalAddresses;
	};
}
}

#endif


