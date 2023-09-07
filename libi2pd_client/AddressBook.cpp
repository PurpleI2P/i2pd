/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <inttypes.h>
#include <string>
#include <map>
#include <fstream>
#include <chrono>
#include <condition_variable>
#include <openssl/rand.h>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include "Base.h"
#include "util.h"
#include "Identity.h"
#include "FS.h"
#include "Log.h"
#include "HTTP.h"
#include "NetDb.hpp"
#include "ClientContext.h"
#include "AddressBook.h"
#include "Config.h"

namespace i2p
{
namespace client
{
	// TODO: this is actually proxy class
	class AddressBookFilesystemStorage: public AddressBookStorage
	{
		public:

			AddressBookFilesystemStorage (): storage("addressbook", "b", "", "b32")
			{
				i2p::config::GetOption("persist.addressbook", m_IsPersist);
				if (m_IsPersist)
					i2p::config::GetOption("addressbook.hostsfile", m_HostsFile);
			}
			std::shared_ptr<const i2p::data::IdentityEx> GetAddress (const i2p::data::IdentHash& ident) const;
			void AddAddress (std::shared_ptr<const i2p::data::IdentityEx> address);
			void RemoveAddress (const i2p::data::IdentHash& ident);

			bool Init ();
			int Load (std::map<std::string, std::shared_ptr<Address> > & addresses);
			int LoadLocal (std::map<std::string, std::shared_ptr<Address> >& addresses);
			int Save (const std::map<std::string, std::shared_ptr<Address> >& addresses);

			void SaveEtag (const i2p::data::IdentHash& subsciption, const std::string& etag, const std::string& lastModified);
			bool GetEtag (const i2p::data::IdentHash& subscription, std::string& etag, std::string& lastModified);
			void ResetEtags ();

		private:

			int LoadFromFile (const std::string& filename, std::map<std::string, std::shared_ptr<Address> >& addresses); // returns -1 if can't open file, otherwise number of records

		private:

			i2p::fs::HashedStorage storage;
			std::string etagsPath, indexPath, localPath;
			bool m_IsPersist;
			std::string m_HostsFile; // file to dump hosts.txt, empty if not used
	};

	bool AddressBookFilesystemStorage::Init()
	{
		storage.SetPlace(i2p::fs::GetDataDir());
		// init storage
		if (storage.Init(i2p::data::GetBase32SubstitutionTable(), 32))
		{
			// init ETags
			etagsPath = i2p::fs::StorageRootPath (storage, "etags");
			if (!i2p::fs::Exists (etagsPath))
				i2p::fs::CreateDirectory (etagsPath);
			// init address files
			indexPath = i2p::fs::StorageRootPath (storage, "addresses.csv");
			localPath = i2p::fs::StorageRootPath (storage, "local.csv");
			return true;
		}
		return false;
	}

	std::shared_ptr<const i2p::data::IdentityEx> AddressBookFilesystemStorage::GetAddress (const i2p::data::IdentHash& ident) const
	{
		if (!m_IsPersist)
		{
			LogPrint(eLogDebug, "Addressbook: Persistence is disabled");
			return nullptr;
		}
		std::string filename = storage.Path(ident.ToBase32());
		std::ifstream f(filename, std::ifstream::binary);
		if (!f.is_open ()) {
			LogPrint(eLogDebug, "Addressbook: Requested, but not found: ", filename);
			return nullptr;
		}

		f.seekg (0,std::ios::end);
		size_t len = f.tellg ();
		if (len < i2p::data::DEFAULT_IDENTITY_SIZE) {
			LogPrint (eLogError, "Addressbook: File ", filename, " is too short: ", len);
			return nullptr;
		}
		f.seekg(0, std::ios::beg);
		uint8_t * buf = new uint8_t[len];
		f.read((char *)buf, len);
		auto address = std::make_shared<i2p::data::IdentityEx>(buf, len);
		delete[] buf;
		return address;
	}

	void AddressBookFilesystemStorage::AddAddress (std::shared_ptr<const i2p::data::IdentityEx> address)
	{
		if (!m_IsPersist) return;
		std::string path = storage.Path( address->GetIdentHash().ToBase32() );
		std::ofstream f (path, std::ofstream::binary | std::ofstream::out);
		if (!f.is_open ())	{
			LogPrint (eLogError, "Addressbook: Can't open file ", path);
			return;
		}
		size_t len = address->GetFullLen ();
		uint8_t * buf = new uint8_t[len];
		address->ToBuffer (buf, len);
		f.write ((char *)buf, len);
		delete[] buf;
	}

	void AddressBookFilesystemStorage::RemoveAddress (const i2p::data::IdentHash& ident)
	{
		if (!m_IsPersist) return;
		storage.Remove( ident.ToBase32() );
	}

	int AddressBookFilesystemStorage::LoadFromFile (const std::string& filename, std::map<std::string, std::shared_ptr<Address> >& addresses)
	{
		int num = 0;
		std::ifstream f (filename, std::ifstream::in); // in text mode
		if (!f) return -1;

		addresses.clear ();
		while (!f.eof ())
		{
			std::string s;
			getline(f, s);
			if (!s.length()) continue; // skip empty line

			std::size_t pos = s.find(',');
			if (pos != std::string::npos)
			{
				std::string name = s.substr(0, pos++);
				std::string addr = s.substr(pos);

				addresses[name] = std::make_shared<Address>(addr);
				num++;
			}
		}
		return num;
	}

	int AddressBookFilesystemStorage::Load (std::map<std::string, std::shared_ptr<Address> >& addresses)
	{
		int num = LoadFromFile (indexPath, addresses);
		if (num < 0)
		{
			LogPrint(eLogWarning, "Addressbook: Can't open ", indexPath);
			return 0;
		}
		LogPrint(eLogInfo, "Addressbook: Using index file ", indexPath);
		LogPrint (eLogInfo, "Addressbook: ", num, " addresses loaded from storage");

		return num;
	}

	int AddressBookFilesystemStorage::LoadLocal (std::map<std::string, std::shared_ptr<Address> >& addresses)
	{
		int num = LoadFromFile (localPath, addresses);
		if (num < 0) return 0;
		LogPrint (eLogInfo, "Addressbook: ", num, " local addresses loaded");
		return num;
	}

	int AddressBookFilesystemStorage::Save (const std::map<std::string, std::shared_ptr<Address> >& addresses)
	{
		if (addresses.empty())
		{
			LogPrint(eLogWarning, "Addressbook: Not saving empty addressbook");
			return 0;
		}

		int num = 0;
		{
			// save index file
			std::ofstream f (indexPath, std::ofstream::out); // in text mode
			if (f.is_open ())
			{
				for (const auto& it: addresses)
				{
					if (it.second->IsValid ())
					{
						f << it.first << ",";
						if (it.second->IsIdentHash ())
							f << it.second->identHash.ToBase32 ();
						else
							f << it.second->blindedPublicKey->ToB33 ();
						f << std::endl;
						num++;
					}
					else
						LogPrint (eLogWarning, "Addressbook: Invalid address ", it.first);
				}
				LogPrint (eLogInfo, "Addressbook: ", num, " addresses saved");
			}
			else
				LogPrint (eLogWarning, "Addressbook: Can't open ", indexPath);
		}
		if (!m_HostsFile.empty ())
		{
			// dump full hosts.txt
			std::ofstream f (m_HostsFile, std::ofstream::out); // in text mode
			if (f.is_open ())
			{
				for (const auto& it: addresses)
				{
					std::shared_ptr<const i2p::data::IdentityEx> addr;
					if (it.second->IsIdentHash ())
					{
						addr = GetAddress (it.second->identHash);
						if (addr)
							f << it.first << "=" << addr->ToBase64 () << std::endl;
					}
				}
			}
			else
				LogPrint (eLogWarning, "Addressbook: Can't open ", m_HostsFile);
		}

		return num;
	}

	void AddressBookFilesystemStorage::SaveEtag (const i2p::data::IdentHash& subscription, const std::string& etag, const std::string& lastModified)
	{
		std::string fname = etagsPath + i2p::fs::dirSep + subscription.ToBase32 () + ".txt";
		std::ofstream f (fname, std::ofstream::out | std::ofstream::trunc);
		if (f)
		{
			f << etag << std::endl;
			f<< lastModified << std::endl;
		}
	}

	bool AddressBookFilesystemStorage::GetEtag (const i2p::data::IdentHash& subscription, std::string& etag, std::string& lastModified)
	{
		std::string fname = etagsPath + i2p::fs::dirSep + subscription.ToBase32 () + ".txt";
		std::ifstream f (fname, std::ofstream::in);
		if (!f || f.eof ()) return false;
		std::getline (f, etag);
		if (f.eof ()) return false;
		std::getline (f, lastModified);
		return true;
	}

	void AddressBookFilesystemStorage::ResetEtags ()
	{
		LogPrint (eLogError, "Addressbook: Resetting eTags");
		for (boost::filesystem::directory_iterator it (etagsPath); it != boost::filesystem::directory_iterator (); ++it)
		{
			if (!boost::filesystem::is_regular_file (it->status ()))
				continue;
			boost::filesystem::remove (it->path ());
		}
	}

//---------------------------------------------------------------------

	Address::Address (const std::string& b32):
		addressType (eAddressInvalid)
	{
		if (b32.length () <= B33_ADDRESS_THRESHOLD)
		{
			if (identHash.FromBase32 (b32) > 0)
				addressType = eAddressIndentHash;
		}
		else
		{
			blindedPublicKey = std::make_shared<i2p::data::BlindedPublicKey>(b32);
			if (blindedPublicKey->IsValid ())
				addressType = eAddressBlindedPublicKey;
		}
	}

	Address::Address (const i2p::data::IdentHash& hash)
	{
		addressType = eAddressIndentHash;
		identHash = hash;
	}

	AddressBook::AddressBook (): m_Storage(nullptr), m_IsLoaded (false), m_IsDownloading (false),
		m_NumRetries (0), m_DefaultSubscription (nullptr), m_SubscriptionsUpdateTimer (nullptr),
		m_IsEnabled (true)
	{
	}

	AddressBook::~AddressBook ()
	{
		Stop ();
	}

	void AddressBook::Start ()
	{
		i2p::config::GetOption("addressbook.enabled", m_IsEnabled);
		if (m_IsEnabled)
		{
			if (!m_Storage)
				m_Storage = new AddressBookFilesystemStorage;
			m_Storage->Init();
			LoadHosts (); /* try storage, then hosts.txt, then download */
			StartSubscriptions ();
			StartLookups ();
		}
	}

	void AddressBook::StartResolvers ()
	{
		LoadLocal ();
	}

	void AddressBook::Stop ()
	{
		StopLookups ();
		StopSubscriptions ();
		if (m_SubscriptionsUpdateTimer)
		{
			delete m_SubscriptionsUpdateTimer;
			m_SubscriptionsUpdateTimer = nullptr;
		}
		if (m_IsDownloading)
		{
			LogPrint (eLogInfo, "Addressbook: Subscriptions are downloading, abort");
			for (int i = 0; i < 30; i++)
			{
				if (!m_IsDownloading)
				{
					LogPrint (eLogInfo, "Addressbook: Subscriptions download complete");
					break;
				}
				std::this_thread::sleep_for (std::chrono::seconds (1)); // wait for 1 seconds
			}
			LogPrint (eLogError, "Addressbook: Subscription download timeout");
			m_IsDownloading = false;
		}
		if (m_Storage)
		{
			m_Storage->Save (m_Addresses);
			delete m_Storage;
			m_Storage = nullptr;
		}
		m_DefaultSubscription = nullptr;
		m_Subscriptions.clear ();
	}

	std::shared_ptr<const Address> AddressBook::GetAddress (const std::string& address)
	{
		auto pos = address.find(".b32.i2p");
		if (pos != std::string::npos)
		{
			auto addr = std::make_shared<const Address>(address.substr (0, pos));
			return addr->IsValid () ? addr : nullptr;
		}
		else
		{
			pos = address.find (".i2p");
			if (pos != std::string::npos)
			{
				if (!m_IsEnabled) return nullptr;
				auto addr = FindAddress (address);
				if (!addr)
					LookupAddress (address); // TODO:
				return addr;
			}
		}
		// if not .b32 we assume full base64 address
		i2p::data::IdentityEx dest;
		if (!dest.FromBase64 (address))
			return nullptr;
		return std::make_shared<const Address>(dest.GetIdentHash ());
	}

	std::shared_ptr<const Address> AddressBook::FindAddress (const std::string& address)
	{
		auto it = m_Addresses.find (address);
		if (it != m_Addresses.end ())
			return it->second;
		return nullptr;
	}

	bool AddressBook::RecordExists (const std::string& address, const std::string& jump)
	{
		auto addr = FindAddress(address);
		if (!addr)
			return false;

		i2p::data::IdentityEx ident;
		if (ident.FromBase64 (jump) && ident.GetIdentHash () == addr->identHash)
			return true;

		return false;
	}

	void AddressBook::InsertAddress (const std::string& address, const std::string& jump)
	{
		auto pos = jump.find(".b32.i2p");
		if (pos != std::string::npos)
		{
			m_Addresses[address] = std::make_shared<Address>(jump.substr (0, pos));
			LogPrint (eLogInfo, "Addressbook: Added ", address," -> ", jump);
		}
		else
		{
			// assume base64
			auto ident = std::make_shared<i2p::data::IdentityEx>();
			if (ident->FromBase64 (jump))
			{
				m_Storage->AddAddress (ident);
				m_Addresses[address] = std::make_shared<Address>(ident->GetIdentHash ());
				LogPrint (eLogInfo, "Addressbook: Added ", address," -> ", ToAddress(ident->GetIdentHash ()));
			}
			else
				LogPrint (eLogError, "Addressbook: Malformed address ", jump);
		}
	}

	void AddressBook::InsertFullAddress (std::shared_ptr<const i2p::data::IdentityEx> address)
	{
		m_Storage->AddAddress (address);
	}

	std::shared_ptr<const i2p::data::IdentityEx> AddressBook::GetFullAddress (const std::string& address)
	{
		auto addr = GetAddress (address);
		if (!addr || !addr->IsIdentHash ()) return nullptr;
		return m_Storage->GetAddress (addr->identHash);
	}

	void AddressBook::LoadHosts ()
	{
		if (m_Storage->Load (m_Addresses) > 0)
		{
			m_IsLoaded = true;
			return;
		}

		// then try hosts.txt
		std::ifstream f (i2p::fs::DataDirPath("hosts.txt"), std::ifstream::in); // in text mode
		if (f.is_open ())
		{
			LoadHostsFromStream (f, false);
			m_IsLoaded = true;
		}

		// reset eTags, because we don’t know how old hosts.txt is or can't load addressbook
		m_Storage->ResetEtags ();
	}

	bool AddressBook::LoadHostsFromStream (std::istream& f, bool is_update)
	{
		std::unique_lock<std::mutex> l(m_AddressBookMutex);
		int numAddresses = 0;
		bool incomplete = false;
		std::string s;
		while (!f.eof ())
		{
			getline(f, s);

			if (!s.length() || s[0] == '#')
				continue; // skip empty or comment line

			size_t pos = s.find('=');

			if (pos != std::string::npos)
			{
				std::string name = s.substr(0, pos++);
				std::string addr = s.substr(pos);

				size_t pos = addr.find('#');
				if (pos != std::string::npos)
					addr = addr.substr(0, pos); // remove comments

				pos = name.find(".b32.i2p");
				if (pos != std::string::npos)
				{
					LogPrint (eLogError, "Addressbook: Skipped adding of b32 address: ", name);
					continue;
				}

				pos = name.find(".i2p");
				if (pos == std::string::npos)
				{
					LogPrint (eLogError, "Addressbook: Malformed domain: ", name);
					continue;
				}

				auto ident = std::make_shared<i2p::data::IdentityEx> ();
				if (!ident->FromBase64(addr)) {
					LogPrint (eLogError, "Addressbook: Malformed address ", addr, " for ", name);
					incomplete = f.eof ();
					continue;
				}
				numAddresses++;
				auto it = m_Addresses.find (name);
				if (it != m_Addresses.end ()) // already exists ?
				{
					if (it->second->IsIdentHash () && it->second->identHash != ident->GetIdentHash () && // address changed?
						ident->GetSigningKeyType () != i2p::data::SIGNING_KEY_TYPE_DSA_SHA1) // don't replace by DSA
					{
						it->second->identHash = ident->GetIdentHash ();
						m_Storage->AddAddress (ident);
						m_Storage->RemoveAddress (it->second->identHash);
						LogPrint (eLogInfo, "Addressbook: Updated host: ", name);
					}
				}
				else
				{
					m_Addresses.emplace (name, std::make_shared<Address>(ident->GetIdentHash ()));
					m_Storage->AddAddress (ident);
					if (is_update)
						LogPrint (eLogInfo, "Addressbook: Added new host: ", name);
				}
			}
			else
				incomplete = f.eof ();
		}
		LogPrint (eLogInfo, "Addressbook: ", numAddresses, " addresses processed");
		if (numAddresses > 0)
		{
			if (!incomplete) m_IsLoaded = true;
			m_Storage->Save (m_Addresses);
		}
		return !incomplete;
	}

	void AddressBook::LoadSubscriptions ()
	{
		if (!m_Subscriptions.size ())
		{
			std::ifstream f (i2p::fs::DataDirPath ("subscriptions.txt"), std::ifstream::in); // in text mode
			if (f.is_open ())
			{
				std::string s;
				while (!f.eof ())
				{
					getline(f, s);
					if (s.empty () || s[0] == '#') continue; // skip empty line or comment
					m_Subscriptions.push_back (std::make_shared<AddressBookSubscription> (*this, s));
				}
				LogPrint (eLogInfo, "Addressbook: ", m_Subscriptions.size (), " subscriptions urls loaded");
				LogPrint (eLogWarning, "Addressbook: subscriptions.txt usage is deprecated, use config file instead");
			}
			else
			{
				LogPrint (eLogInfo, "Addressbook: Loading subscriptions from config file");
				// using config file items
				std::string subscriptionURLs; i2p::config::GetOption("addressbook.subscriptions", subscriptionURLs);
				std::vector<std::string> subsList;
				boost::split(subsList, subscriptionURLs, boost::is_any_of(","), boost::token_compress_on);

				for (const auto& s: subsList)
				{
					m_Subscriptions.push_back (std::make_shared<AddressBookSubscription> (*this, s));
				}
				LogPrint (eLogInfo, "Addressbook: ", m_Subscriptions.size (), " subscriptions urls loaded");
			}
		}
		else
			LogPrint (eLogError, "Addressbook: Subscriptions already loaded");
	}

	void AddressBook::LoadLocal ()
	{
		if (!m_Storage) return;
		std::map<std::string, std::shared_ptr<Address>> localAddresses;
		m_Storage->LoadLocal (localAddresses);
		for (const auto& it: localAddresses)
		{
			if (!it.second->IsIdentHash ()) continue; // skip blinded for now
			auto dot = it.first.find ('.');
			if (dot != std::string::npos)
			{
				auto domain = it.first.substr (dot + 1);
				auto it1 = m_Addresses.find (domain); // find domain in our addressbook
				if (it1 != m_Addresses.end () && it1->second->IsIdentHash ())
				{
					auto dest = context.FindLocalDestination (it1->second->identHash);
					if (dest)
					{
						// address is ours
						std::shared_ptr<AddressResolver> resolver;
						auto it2 = m_Resolvers.find (it1->second->identHash);
						if (it2 != m_Resolvers.end ())
							resolver = it2->second; // resolver exists
						else
						{
							// create new resolver
							resolver = std::make_shared<AddressResolver>(dest);
							m_Resolvers.insert (std::make_pair(it1->second->identHash, resolver));
						}
						resolver->AddAddress (it.first, it.second->identHash);
					}
				}
			}
		}
	}

	bool AddressBook::GetEtag (const i2p::data::IdentHash& subscription, std::string& etag, std::string& lastModified)
	{
		if (m_Storage)
			return m_Storage->GetEtag (subscription, etag, lastModified);
		else
			return false;
	}

	void AddressBook::DownloadComplete (bool success, const i2p::data::IdentHash& subscription, const std::string& etag, const std::string& lastModified)
	{
		m_IsDownloading = false;
		m_NumRetries++;
		int nextUpdateTimeout = m_NumRetries*CONTINIOUS_SUBSCRIPTION_RETRY_TIMEOUT;
		if (m_NumRetries > CONTINIOUS_SUBSCRIPTION_MAX_NUM_RETRIES || nextUpdateTimeout > CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT)
			nextUpdateTimeout = CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT;
		if (success)
		{
			m_NumRetries = 0;
			if (m_DefaultSubscription) m_DefaultSubscription = nullptr;
			if (m_IsLoaded)
				nextUpdateTimeout = CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT;
			else
				m_IsLoaded = true;
			if (m_Storage) m_Storage->SaveEtag (subscription, etag, lastModified);
		}
		if (m_SubscriptionsUpdateTimer)
		{
			m_SubscriptionsUpdateTimer->expires_from_now (boost::posix_time::minutes(nextUpdateTimeout));
			m_SubscriptionsUpdateTimer->async_wait (std::bind (&AddressBook::HandleSubscriptionsUpdateTimer,
				this, std::placeholders::_1));
		}
	}

	void AddressBook::StartSubscriptions ()
	{
		LoadSubscriptions ();
		if (m_IsLoaded && m_Subscriptions.empty ()) return;

		auto dest = i2p::client::context.GetSharedLocalDestination ();
		if (dest)
		{
			m_SubscriptionsUpdateTimer = new boost::asio::deadline_timer (dest->GetService ());
			m_SubscriptionsUpdateTimer->expires_from_now (boost::posix_time::minutes(INITIAL_SUBSCRIPTION_UPDATE_TIMEOUT));
			m_SubscriptionsUpdateTimer->async_wait (std::bind (&AddressBook::HandleSubscriptionsUpdateTimer,
				this, std::placeholders::_1));
		}
		else
			LogPrint (eLogCritical, "Addressbook: Can't start subscriptions: missing shared local destination");
	}

	void AddressBook::StopSubscriptions ()
	{
		if (m_SubscriptionsUpdateTimer)
			m_SubscriptionsUpdateTimer->cancel ();
	}

	void AddressBook::HandleSubscriptionsUpdateTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			auto dest = i2p::client::context.GetSharedLocalDestination ();
			if (!dest) {
				LogPrint(eLogWarning, "Addressbook: Missing local destination, skip subscription update");
				return;
			}
			if (!m_IsDownloading && dest->IsReady ())
			{
				if (!m_IsLoaded)
				{
					// download it from default subscription
					LogPrint (eLogInfo, "Addressbook: Trying to download it from default subscription.");
					std::string defaultSubURL; i2p::config::GetOption("addressbook.defaulturl", defaultSubURL);
					if (!m_DefaultSubscription)
						m_DefaultSubscription = std::make_shared<AddressBookSubscription>(*this, defaultSubURL);
					m_IsDownloading = true;
					std::thread load_hosts(std::bind (&AddressBookSubscription::CheckUpdates, m_DefaultSubscription));
					load_hosts.detach(); // TODO: use join
				}
				else if (!m_Subscriptions.empty ())
				{
					// pick random subscription
					auto ind = rand () % m_Subscriptions.size();
					m_IsDownloading = true;
					std::thread load_hosts(std::bind (&AddressBookSubscription::CheckUpdates, m_Subscriptions[ind]));
					load_hosts.detach(); // TODO: use join
				}
			}
			else
			{
				// try it again later
				m_SubscriptionsUpdateTimer->expires_from_now (boost::posix_time::minutes(INITIAL_SUBSCRIPTION_RETRY_TIMEOUT));
				m_SubscriptionsUpdateTimer->async_wait (std::bind (&AddressBook::HandleSubscriptionsUpdateTimer,
					this, std::placeholders::_1));
			}
		}
	}

	void AddressBook::StartLookups ()
	{
		auto dest = i2p::client::context.GetSharedLocalDestination ();
		if (dest)
		{
			auto datagram = dest->GetDatagramDestination ();
			if (!datagram)
				datagram = dest->CreateDatagramDestination ();
			datagram->SetReceiver (std::bind (&AddressBook::HandleLookupResponse, this,
				std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5),
				ADDRESS_RESPONSE_DATAGRAM_PORT);
		}
	}

	void AddressBook::StopLookups ()
	{
		auto dest = i2p::client::context.GetSharedLocalDestination ();
		if (dest)
		{
			auto datagram = dest->GetDatagramDestination ();
			if (datagram) datagram->ResetReceiver (ADDRESS_RESPONSE_DATAGRAM_PORT);
		}
	}

	void AddressBook::LookupAddress (const std::string& address)
	{
		std::shared_ptr<const Address> addr;
		auto dot = address.find ('.');
		if (dot != std::string::npos)
			addr = FindAddress (address.substr (dot + 1));
		if (!addr || !addr->IsIdentHash ()) // TODO:
		{
			LogPrint (eLogError, "Addressbook: Can't find domain for ", address);
			return;
		}

		auto dest = i2p::client::context.GetSharedLocalDestination ();
		if (dest)
		{
			auto datagram = dest->GetDatagramDestination ();
			if (datagram)
			{
				uint32_t nonce;
				RAND_bytes ((uint8_t *)&nonce, 4);
				{
					std::unique_lock<std::mutex> l(m_LookupsMutex);
					m_Lookups[nonce] = address;
				}
				LogPrint (eLogDebug, "Addressbook: Lookup of ", address, " to ", addr->identHash.ToBase32 (), " nonce=", nonce);
				size_t len = address.length () + 9;
				uint8_t * buf = new uint8_t[len];
				memset (buf, 0, 4);
				htobe32buf (buf + 4, nonce);
				buf[8] = address.length ();
				memcpy (buf + 9, address.c_str (), address.length ());
				datagram->SendDatagramTo (buf, len, addr->identHash, ADDRESS_RESPONSE_DATAGRAM_PORT, ADDRESS_RESOLVER_DATAGRAM_PORT);
				delete[] buf;
			}
		}
	}

	void AddressBook::HandleLookupResponse (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (len < 44)
		{
			LogPrint (eLogError, "Addressbook: Lookup response is too short ", len);
			return;
		}
		uint32_t nonce = bufbe32toh (buf + 4);
		LogPrint (eLogDebug, "Addressbook: Lookup response received from ", from.GetIdentHash ().ToBase32 (), " nonce=", nonce);
		std::string address;
		{
			std::unique_lock<std::mutex> l(m_LookupsMutex);
			auto it = m_Lookups.find (nonce);
			if (it != m_Lookups.end ())
			{
				address = it->second;
				m_Lookups.erase (it);
			}
		}
		if (address.length () > 0)
		{
			// TODO: verify from
			i2p::data::IdentHash hash(buf + 8);
			if (!hash.IsZero ())
				m_Addresses[address] = std::make_shared<Address>(hash);
			else
				LogPrint (eLogInfo, "AddressBook: Lookup response: ", address, " not found");
		}
	}

	AddressBookSubscription::AddressBookSubscription (AddressBook& book, const std::string& link):
		m_Book (book), m_Link (link)
	{
	}

	void AddressBookSubscription::CheckUpdates ()
	{
		i2p::util::SetThreadName("Addressbook");

		bool result = MakeRequest ();
		m_Book.DownloadComplete (result, m_Ident, m_Etag, m_LastModified);
	}

	bool AddressBookSubscription::MakeRequest ()
	{
		i2p::http::URL url;
		// must be run in separate thread
		LogPrint (eLogInfo, "Addressbook: Downloading hosts database from ", m_Link);
		if (!url.parse(m_Link))
		{
			LogPrint(eLogError, "Addressbook: Failed to parse url: ", m_Link);
			return false;
		}
		auto addr = m_Book.GetAddress (url.host);
		if (!addr || !addr->IsIdentHash ())
		{
			LogPrint (eLogError, "Addressbook: Can't resolve ", url.host);
			return false;
		}
		else
			m_Ident = addr->identHash;
		// save url parts for later use
		std::string dest_host = url.host;
		int         dest_port = url.port ? url.port : 80;
		// try to create stream to addressbook site
		auto stream = i2p::client::context.GetSharedLocalDestination ()->CreateStream (m_Ident, dest_port);
		if (!stream)
		{
			LogPrint (eLogError, "Addressbook: LeaseSet for address ", url.host, " not found");
			return false;
		}
		if (m_Etag.empty() && m_LastModified.empty())
		{
			m_Book.GetEtag (m_Ident, m_Etag, m_LastModified);
			LogPrint (eLogDebug, "Addressbook: Loaded for ", url.host, ": ETag: ", m_Etag, ", Last-Modified: ", m_LastModified);
		}
		// create http request & send it
		i2p::http::HTTPReq req;
		req.AddHeader("Host", dest_host);
		req.AddHeader("User-Agent", "Wget/1.11.4");
		req.AddHeader("Accept-Encoding", "gzip");
		req.AddHeader("X-Accept-Encoding", "x-i2p-gzip;q=1.0, identity;q=0.5, deflate;q=0, gzip;q=0, *;q=0");
		req.AddHeader("Connection", "close");
		if (!m_Etag.empty())
			req.AddHeader("If-None-Match", m_Etag);
		if (!m_LastModified.empty())
			req.AddHeader("If-Modified-Since", m_LastModified);
		// convert url to relative
		url.schema  = "";
		url.host    = "";
		req.uri     = url.to_string();
		req.version = "HTTP/1.1";
		std::string request = req.to_string();
		stream->Send ((const uint8_t *) request.data(), request.length());
		// read response
		std::string response;
		uint8_t recv_buf[4096];
		bool end = false;
		int numAttempts = 0;
		while (!end)
		{
			size_t received = stream->Receive (recv_buf, 4096, SUBSCRIPTION_REQUEST_TIMEOUT);
			if (received)
			{
				response.append ((char *)recv_buf, received);
				if (!stream->IsOpen ()) end = true;
			}
			else if (!stream->IsOpen ())
				end = true;
			else
			{
				LogPrint (eLogError, "Addressbook: Subscriptions request timeout expired");
				numAttempts++;
				if (numAttempts > 5) end = true;
			}
		}
		// process remaining buffer
		while (size_t len = stream->ReadSome (recv_buf, sizeof(recv_buf)))
			response.append ((char *)recv_buf, len);
		// parse response
		i2p::http::HTTPRes res;
		int res_head_len = res.parse(response);
		if (res_head_len < 0)
		{
			LogPrint(eLogError, "Addressbook: Can't parse http response from ", dest_host);
			return false;
		}
		if (res_head_len == 0)
		{
			LogPrint(eLogError, "Addressbook: Incomplete http response from ", dest_host, ", interrupted by timeout");
			return false;
		}
		// assert: res_head_len > 0
		response.erase(0, res_head_len);
		if (res.code == 304)
		{
			LogPrint (eLogInfo, "Addressbook: No updates from ", dest_host, ", code 304");
			return false;
		}
		if (res.code != 200)
		{
			LogPrint (eLogWarning, "Adressbook: Can't get updates from ", dest_host, ", response code ", res.code);
			return false;
		}
		int len = res.content_length();
		if (response.empty())
		{
			LogPrint(eLogError, "Addressbook: Empty response from ", dest_host, ", expected ", len, " bytes");
			return false;
		}
		if (!res.is_gzipped () && len > 0 && len != (int) response.length())
		{
			LogPrint(eLogError, "Addressbook: Response size mismatch, expected: ", len, ", got: ", response.length(), "bytes");
			return false;
		}
		// assert: res.code == 200
		auto it = res.headers.find("ETag");
		if (it != res.headers.end()) m_Etag = it->second;
		it = res.headers.find("Last-Modified");
		if (it != res.headers.end()) m_LastModified = it->second;
		if (res.is_chunked())
		{
			std::stringstream in(response), out;
			i2p::http::MergeChunkedResponse (in, out);
			response = out.str();
		}
		if (res.is_gzipped())
		{
			std::stringstream out;
			i2p::data::GzipInflator inflator;
			inflator.Inflate ((const uint8_t *) response.data(), response.length(), out);
			if (out.fail())
			{
				LogPrint(eLogError, "Addressbook: Can't gunzip http response");
				return false;
			}
			response = out.str();
		}
		std::stringstream ss(response);
		LogPrint (eLogInfo, "Addressbook: Got update from ", dest_host);
		m_Book.LoadHostsFromStream (ss, true);
		return true;
	}

	AddressResolver::AddressResolver (std::shared_ptr<ClientDestination> destination):
		m_LocalDestination (destination)
	{
		if (m_LocalDestination)
		{
			auto datagram = m_LocalDestination->GetDatagramDestination ();
			if (!datagram)
				datagram = m_LocalDestination->CreateDatagramDestination ();
			datagram->SetReceiver (std::bind (&AddressResolver::HandleRequest, this,
				std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5),
				ADDRESS_RESOLVER_DATAGRAM_PORT);
		}
	}

	AddressResolver::~AddressResolver ()
	{
		if (m_LocalDestination)
		{
			auto datagram = m_LocalDestination->GetDatagramDestination ();
			if (datagram)
				datagram->ResetReceiver (ADDRESS_RESOLVER_DATAGRAM_PORT);
		}
	}

	void AddressResolver::HandleRequest (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (len < 9 || len < buf[8] + 9U)
		{
			LogPrint (eLogError, "Addressbook: Address request is too short ", len);
			return;
		}
		// read requested address
		uint8_t l = buf[8];
		char address[255];
		memcpy (address, buf + 9, l);
		address[l] = 0;
		LogPrint (eLogDebug, "Addressbook: Address request ", address);
		// send response
		uint8_t response[44];
		memset (response, 0, 4); // reserved
		memcpy (response + 4, buf + 4, 4); // nonce
		auto it = m_LocalAddresses.find (address); // address lookup
		if (it != m_LocalAddresses.end ())
			memcpy (response + 8, it->second, 32); // ident
		else
			memset (response + 8, 0, 32); // not found
		memset (response + 40, 0, 4); // set expiration time to zero
		m_LocalDestination->GetDatagramDestination ()->SendDatagramTo (response, 44, from.GetIdentHash(), toPort, fromPort);
	}

	void AddressResolver::AddAddress (const std::string& name, const i2p::data::IdentHash& ident)
	{
		m_LocalAddresses[name] = ident;
	}

}
}
