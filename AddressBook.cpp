#include <string.h>
#include <inttypes.h>
#include <string>
#include <map>
#include <fstream>
#include <chrono>
#include <condition_variable>
#include <boost/lexical_cast.hpp>
#include "Base.h"
#include "util.h"
#include "Identity.h"
#include "FS.h"
#include "Log.h"
#include "NetDb.h"
#include "ClientContext.h"
#include "AddressBook.h"

namespace i2p
{
namespace client
{
	// TODO: this is actually proxy class
	class AddressBookFilesystemStorage: public AddressBookStorage
	{
		private:
			i2p::fs::HashedStorage storage;
			std::string indexPath;

		public:
			AddressBookFilesystemStorage (): storage("addressbook", "b", "", "b32") {};
			std::shared_ptr<const i2p::data::IdentityEx> GetAddress (const i2p::data::IdentHash& ident) const;
			void AddAddress (std::shared_ptr<const i2p::data::IdentityEx> address);
			void RemoveAddress (const i2p::data::IdentHash& ident);

			bool Init ();
			int Load (std::map<std::string, i2p::data::IdentHash>& addresses);
			int Save (const std::map<std::string, i2p::data::IdentHash>& addresses);
	};

	bool AddressBookFilesystemStorage::Init()
	{
		storage.SetPlace(i2p::fs::GetDataDir());
		indexPath = storage.GetRoot() + i2p::fs::dirSep + "addresses.csv";
		return storage.Init(i2p::data::GetBase32SubstitutionTable(), 32);
	}

	std::shared_ptr<const i2p::data::IdentityEx> AddressBookFilesystemStorage::GetAddress (const i2p::data::IdentHash& ident) const
	{
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
		std::string path = storage.Path( address->GetIdentHash().ToBase32() );
		std::ofstream f (path, std::ofstream::binary | std::ofstream::out);
		if (!f.is_open ())	{
			LogPrint (eLogError, "Addressbook: can't open file ", path);
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
		storage.Remove( ident.ToBase32() );
	}

	int AddressBookFilesystemStorage::Load (std::map<std::string, i2p::data::IdentHash>& addresses)
	{
		int num = 0;	
		std::string s;
		std::ifstream f (indexPath, std::ifstream::in); // in text mode

		if (f.is_open ()) {
			LogPrint(eLogInfo, "Addressbook: using index file ", indexPath);
		} else {
			LogPrint(eLogWarning, "Addressbook: Can't open ", indexPath);
			return 0;
		}

		addresses.clear ();
		while (!f.eof ()) {
			getline(f, s);
			if (!s.length())
				continue; // skip empty line

			std::size_t pos = s.find(',');
			if (pos != std::string::npos)
			{
				std::string name = s.substr(0, pos++);
				std::string addr = s.substr(pos);

				i2p::data::IdentHash ident;
				ident.FromBase32 (addr);
				addresses[name] = ident;
				num++;
			}		
		}

		LogPrint (eLogInfo, "Addressbook: ", num, " addresses loaded from storage");
		return num;
	}

	int AddressBookFilesystemStorage::Save (const std::map<std::string, i2p::data::IdentHash>& addresses)
	{
		if (addresses.size() == 0) {
			LogPrint(eLogWarning, "Addressbook: not saving empty addressbook");
			return 0;
		}

		int num = 0;
		std::ofstream f (indexPath, std::ofstream::out); // in text mode

		if (!f.is_open ()) {
			LogPrint (eLogWarning, "Addressbook: Can't open ", indexPath);
			return 0;
		}

		for (auto it: addresses) {
			f << it.first << "," << it.second.ToBase32 () << std::endl;
			num++;
		}
		LogPrint (eLogInfo, "Addressbook: ", num, " addresses saved");
		return num;	
	}	

//---------------------------------------------------------------------
	AddressBook::AddressBook (): m_Storage(new AddressBookFilesystemStorage), m_IsLoaded (false), m_IsDownloading (false), 
		m_DefaultSubscription (nullptr), m_SubscriptionsUpdateTimer (nullptr)
	{
	}

	AddressBook::~AddressBook ()
	{	
		Stop ();
	}

	void AddressBook::Start ()
	{
		m_Storage->Init();
		LoadHosts (); /* try storage, then hosts.txt, then download */
		StartSubscriptions ();
	}
	
	void AddressBook::Stop ()
	{
		StopSubscriptions ();
		if (m_SubscriptionsUpdateTimer)
		{	
			delete m_SubscriptionsUpdateTimer;	
			m_SubscriptionsUpdateTimer = nullptr;
		}	
		if (m_IsDownloading)
		{
			LogPrint (eLogInfo, "Addressbook: subscriptions is downloading, abort");
			for (int i = 0; i < 30; i++)
			{
				if (!m_IsDownloading)
				{
					LogPrint (eLogInfo, "Addressbook: subscriptions download complete");
					break;
				}	
				std::this_thread::sleep_for (std::chrono::seconds (1)); // wait for 1 seconds
			}	
			LogPrint (eLogError, "Addressbook: subscription download timeout");
			m_IsDownloading = false;
		}	
		if (m_Storage)
		{
			m_Storage->Save (m_Addresses);
			delete m_Storage;
			m_Storage = nullptr;
		}
		m_DefaultSubscription = nullptr;	
		for (auto it: m_Subscriptions)
			delete it;
		m_Subscriptions.clear ();	
	}	
	
	bool AddressBook::GetIdentHash (const std::string& address, i2p::data::IdentHash& ident)
	{
		auto pos = address.find(".b32.i2p");
		if (pos != std::string::npos)
		{
			Base32ToByteStream (address.c_str(), pos, ident, 32);
			return true;
		}
		else
		{	
			pos = address.find (".i2p");
			if (pos != std::string::npos)
			{
				auto identHash = FindAddress (address);	
				if (identHash)
				{
					ident = *identHash;
					return true;
				}
				else
					return false;
			}
		}	
		// if not .b32 we assume full base64 address
		i2p::data::IdentityEx dest;
		if (!dest.FromBase64 (address))
			return false;
		ident = dest.GetIdentHash ();
		return true;
	}
	
	const i2p::data::IdentHash * AddressBook::FindAddress (const std::string& address)
	{
		auto it = m_Addresses.find (address);
		if (it != m_Addresses.end ())
			return &it->second;
		return nullptr;	
	}

	void AddressBook::InsertAddress (const std::string& address, const std::string& base64)
	{
		auto ident = std::make_shared<i2p::data::IdentityEx>();
		ident->FromBase64 (base64);
		m_Storage->AddAddress (ident);
		m_Addresses[address] = ident->GetIdentHash ();
		LogPrint (eLogInfo, "Addressbook: added ", address," -> ", ToAddress(ident->GetIdentHash ()));
	}

	void AddressBook::InsertAddress (std::shared_ptr<const i2p::data::IdentityEx> address)
	{
		m_Storage->AddAddress (address);
	}

	std::shared_ptr<const i2p::data::IdentityEx> AddressBook::GetAddress (const std::string& address)
	{
		i2p::data::IdentHash ident;
		if (!GetIdentHash (address, ident)) return nullptr;
		return m_Storage->GetAddress (ident);
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
			LoadHostsFromStream (f);
			m_IsLoaded = true;
		}
	}

	void AddressBook::LoadHostsFromStream (std::istream& f)
	{
		std::unique_lock<std::mutex> l(m_AddressBookMutex);
		int numAddresses = 0;
		std::string s;
		while (!f.eof ())
		{
			getline(f, s);

			if (!s.length())
				continue; // skip empty line

			size_t pos = s.find('=');

			if (pos != std::string::npos)
			{
				std::string name = s.substr(0, pos++);
				std::string addr = s.substr(pos);

				auto ident = std::make_shared<i2p::data::IdentityEx> ();
				if (ident->FromBase64(addr))
				{	
					m_Addresses[name] = ident->GetIdentHash ();
					m_Storage->AddAddress (ident);
					numAddresses++;
				}	
				else
					LogPrint (eLogError, "Addressbook: malformed address ", addr, " for ", name);
			}		
		}
		LogPrint (eLogInfo, "Addressbook: ", numAddresses, " addresses processed");
		if (numAddresses > 0)
		{	
			m_IsLoaded = true;
			m_Storage->Save (m_Addresses);
		}	
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
					if (!s.length()) continue; // skip empty line
					m_Subscriptions.push_back (new AddressBookSubscription (*this, s));
				}
				LogPrint (eLogInfo, "Addressbook: ", m_Subscriptions.size (), " subscriptions urls loaded");
			}
			else
				LogPrint (eLogWarning, "Addressbook: subscriptions.txt not found in datadir");
		}
		else
			LogPrint (eLogError, "Addressbook: subscriptions already loaded");
	}

	void AddressBook::DownloadComplete (bool success)
	{
		m_IsDownloading = false;
		if (success && m_DefaultSubscription)
		{	
			m_DefaultSubscription.reset (nullptr);
			m_IsLoaded = true;
		}	
		if (m_SubscriptionsUpdateTimer)
		{
			m_SubscriptionsUpdateTimer->expires_from_now (boost::posix_time::minutes(
				success ? CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT : CONTINIOUS_SUBSCRIPTION_RETRY_TIMEOUT));
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
			LogPrint (eLogError, "Addressbook: can't start subscriptions: missing shared local destination");
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
				LogPrint(eLogWarning, "Addressbook: missing local destination, skip subscription update");
				return;
			}
			if (!m_IsDownloading && dest->IsReady ())
			{
				if (!m_IsLoaded)
				{
					// download it from http://i2p-projekt.i2p/hosts.txt 
					LogPrint (eLogInfo, "Addressbook: trying to download it from default subscription.");
					if (!m_DefaultSubscription)
						m_DefaultSubscription.reset (new AddressBookSubscription (*this, DEFAULT_SUBSCRIPTION_ADDRESS));
					m_IsDownloading = true;	
					m_DefaultSubscription->CheckSubscription ();
				}	
				else if (!m_Subscriptions.empty ())
				{	
					// pick random subscription
					auto ind = rand () % m_Subscriptions.size();	
					m_IsDownloading = true;	
					m_Subscriptions[ind]->CheckSubscription ();
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

	AddressBookSubscription::AddressBookSubscription (AddressBook& book, const std::string& link):
		m_Book (book), m_Link (link)
	{
	}

	void AddressBookSubscription::CheckSubscription ()
	{
		std::thread load_hosts(&AddressBookSubscription::Request, this);
		load_hosts.detach(); // TODO: use join
	}

	void AddressBookSubscription::Request ()
	{
		// must be run in separate thread	
		LogPrint (eLogInfo, "Addressbook: Downloading hosts database from ", m_Link, " ETag: ", m_Etag, " Last-Modified: ", m_LastModified);
		bool success = false;	
		i2p::util::http::url u (m_Link);
		i2p::data::IdentHash ident;
		if (m_Book.GetIdentHash (u.host_, ident))
		{
			std::condition_variable newDataReceived;
			std::mutex newDataReceivedMutex;
			auto leaseSet = i2p::client::context.GetSharedLocalDestination ()->FindLeaseSet (ident);
			if (!leaseSet)
			{
				std::unique_lock<std::mutex> l(newDataReceivedMutex);
				i2p::client::context.GetSharedLocalDestination ()->RequestDestination (ident,
					[&newDataReceived, &leaseSet](std::shared_ptr<i2p::data::LeaseSet> ls)
				    {
						leaseSet = ls;
						newDataReceived.notify_all ();
					});
				if (newDataReceived.wait_for (l, std::chrono::seconds (SUBSCRIPTION_REQUEST_TIMEOUT)) == std::cv_status::timeout)
				{	
					LogPrint (eLogError, "Addressbook: Subscription LeaseSet request timeout expired");
					i2p::client::context.GetSharedLocalDestination ()->CancelDestinationRequest (ident);
				}	
			}
			if (leaseSet)
			{
				std::stringstream request, response;
				// standard header
				request << "GET "   << u.path_ << " HTTP/1.1\r\n"
				        << "Host: " << u.host_ << "\r\n"
				        << "Accept: */*\r\n"
				        << "User-Agent: Wget/1.11.4\r\n"
						//<< "Accept-Encoding: gzip\r\n"
						<< "X-Accept-Encoding: x-i2p-gzip;q=1.0, identity;q=0.5, deflate;q=0, gzip;q=0, *;q=0\r\n"
				        << "Connection: close\r\n";
				if (m_Etag.length () > 0) // etag
					request << i2p::util::http::IF_NONE_MATCH << ": \"" << m_Etag << "\"\r\n";
				if (m_LastModified.length () > 0) // if-modfief-since
					request << i2p::util::http::IF_MODIFIED_SINCE << ": " << m_LastModified << "\r\n";
				request << "\r\n"; // end of header
				auto stream = i2p::client::context.GetSharedLocalDestination ()->CreateStream (leaseSet, u.port_);
				stream->Send ((uint8_t *)request.str ().c_str (), request.str ().length ());
				
				uint8_t buf[4096];
				bool end = false;
				while (!end)
				{
					stream->AsyncReceive (boost::asio::buffer (buf, 4096), 
						[&](const boost::system::error_code& ecode, std::size_t bytes_transferred)
						{
							if (bytes_transferred)
								response.write ((char *)buf, bytes_transferred);
							if (ecode == boost::asio::error::timed_out || !stream->IsOpen ())
								end = true;	
							newDataReceived.notify_all ();
						},
						30); // wait for 30 seconds
					std::unique_lock<std::mutex> l(newDataReceivedMutex);
					if (newDataReceived.wait_for (l, std::chrono::seconds (SUBSCRIPTION_REQUEST_TIMEOUT)) == std::cv_status::timeout)
						LogPrint (eLogError, "Addressbook: subscriptions request timeout expired");
				}
				// process remaining buffer
				while (size_t len = stream->ReadSome (buf, 4096))
					response.write ((char *)buf, len);
				
				// parse response
				std::string version;
				response >> version; // HTTP version
				int status = 0;
				response >> status; // status
				if (status == 200) // OK
				{
					bool isChunked = false, isGzip = false;
					std::string header, statusMessage;
					std::getline (response, statusMessage);
					// read until new line meaning end of header
					while (!response.eof () && header != "\r")
					{
						std::getline (response, header);
						auto colon = header.find (':');
						if (colon != std::string::npos)
						{
							std::string field = header.substr (0, colon);
							boost::to_lower (field); // field are not case-sensitive
							colon++;
							header.resize (header.length () - 1); // delete \r	
							if (field == i2p::util::http::ETAG)
								m_Etag = header.substr (colon + 1);
							else if (field == i2p::util::http::LAST_MODIFIED)
								m_LastModified = header.substr (colon + 1);
							else if (field == i2p::util::http::TRANSFER_ENCODING)
								isChunked = !header.compare (colon + 1, std::string::npos, "chunked");
							else if (field == i2p::util::http::CONTENT_ENCODING)
								isGzip = !header.compare (colon + 1, std::string::npos, "gzip") ||
									!header.compare (colon + 1, std::string::npos, "x-i2p-gzip");
						}	
					}
					LogPrint (eLogInfo, "Addressbook: ", m_Link, " ETag: ", m_Etag, " Last-Modified: ", m_LastModified);
					if (!response.eof ())	
					{
						success = true;
						if (!isChunked)
							success = ProcessResponse (response, isGzip);
						else
						{
							// merge chunks
							std::stringstream merged;
							i2p::util::http::MergeChunkedResponse (response, merged);
							success = ProcessResponse (merged, isGzip);
						}	
					}	
				}
				else if (status == 304)
				{	
					success = true;
					LogPrint (eLogInfo, "Addressbook: no updates from ", m_Link);
				}	
				else
					LogPrint (eLogWarning, "Adressbook: HTTP response ", status);
			}
			else
				LogPrint (eLogError, "Addressbook: address ", u.host_, " not found");
		}
		else
			LogPrint (eLogError, "Addressbook: Can't resolve ", u.host_);

		if (!success)
			LogPrint (eLogError, "Addressbook: download hosts.txt from ", m_Link, " failed");

		m_Book.DownloadComplete (success);
	}

	bool AddressBookSubscription::ProcessResponse (std::stringstream& s, bool isGzip)
	{
		if (isGzip)
		{
			std::stringstream uncompressed;
			i2p::data::GzipInflator inflator;
			inflator.Inflate (s, uncompressed);
			if (!uncompressed.fail ())
				m_Book.LoadHostsFromStream (uncompressed);
			else
				return false;
		}	
		else
			m_Book.LoadHostsFromStream (s);
		return true;	
	}
}
}

