#include <string.h>
#include <inttypes.h>
#include <string>
#include <map>
#include <fstream>
#include <chrono>
#include <condition_variable>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <cryptopp/osrng.h>
#include "base64.h"
#include "util.h"
#include "Identity.h"
#include "Log.h"
#include "NetDb.h"
#include "ClientContext.h"
#include "AddressBook.h"

namespace i2p
{
namespace client
{

	class AddressBookFilesystemStorage: public AddressBookStorage
	{
		public:

			AddressBookFilesystemStorage ();
			bool GetAddress (const i2p::data::IdentHash& ident, i2p::data::IdentityEx& address) const;
			void AddAddress (const i2p::data::IdentityEx& address);
			void RemoveAddress (const i2p::data::IdentHash& ident);

			int Load (std::map<std::string, i2p::data::IdentHash>& addresses);
			int Save (const std::map<std::string, i2p::data::IdentHash>& addresses);

		private:	
			
			boost::filesystem::path GetPath () const { return i2p::util::filesystem::GetDefaultDataDir() / "addressbook"; };

	};

	AddressBookFilesystemStorage::AddressBookFilesystemStorage ()
	{
		auto path = GetPath ();
		if (!boost::filesystem::exists (path))
		{
			// Create directory is necessary
			if (!boost::filesystem::create_directory (path))
				LogPrint (eLogError, "Failed to create addressbook directory");
		}
	}

	bool AddressBookFilesystemStorage::GetAddress (const i2p::data::IdentHash& ident, i2p::data::IdentityEx& address) const
	{
		auto filename = GetPath () / (ident.ToBase32() + ".b32");
		std::ifstream f(filename.c_str (), std::ifstream::binary);
		if (f.is_open ())	
		{
			f.seekg (0,std::ios::end);
			size_t len = f.tellg ();
			if (len < i2p::data::DEFAULT_IDENTITY_SIZE)
			{
				LogPrint (eLogError, "File ", filename, " is too short. ", len);
				return false;
			}
			f.seekg(0, std::ios::beg);
			uint8_t * buf = new uint8_t[len];
			f.read((char *)buf, len);
			address.FromBuffer (buf, len);
			delete[] buf;
			return true;
		}
		else
			return false;
	}

	void AddressBookFilesystemStorage::AddAddress (const i2p::data::IdentityEx& address)
	{
		auto filename = GetPath () / (address.GetIdentHash ().ToBase32() + ".b32");
		std::ofstream f (filename.c_str (), std::ofstream::binary | std::ofstream::out);
		if (f.is_open ())	
		{
			size_t len = address.GetFullLen ();
			uint8_t * buf = new uint8_t[len];
			address.ToBuffer (buf, len);
			f.write ((char *)buf, len);
			delete[] buf;
		}
		else
			LogPrint (eLogError, "Can't open file ", filename);	
	}	

	void AddressBookFilesystemStorage::RemoveAddress (const i2p::data::IdentHash& ident)
	{
		auto filename = GetPath () / (ident.ToBase32() + ".b32");
		if (boost::filesystem::exists (filename))  
			boost::filesystem::remove (filename);
	}

	int AddressBookFilesystemStorage::Load (std::map<std::string, i2p::data::IdentHash>& addresses)
	{
		int num = 0;	
		auto filename = GetPath () / "addresses.csv";
		std::ifstream f (filename.c_str (), std::ofstream::in); // in text mode
		if (f.is_open ())	
		{
			addresses.clear ();
			while (!f.eof ())
			{
				std::string s;
				getline(f, s);
				if (!s.length())
					continue; // skip empty line

				size_t pos = s.find(',');
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
			LogPrint (eLogInfo, num, " addresses loaded");
		}
		else
			LogPrint (eLogWarning, filename, " not found");
		return num;
	}

	int AddressBookFilesystemStorage::Save (const std::map<std::string, i2p::data::IdentHash>& addresses)
	{
		int num = 0;
		auto filename = GetPath () / "addresses.csv";
		std::ofstream f (filename.c_str (), std::ofstream::out); // in text mode
		if (f.is_open ())	
		{
			for (auto it: addresses)
			{
				f << it.first << "," << it.second.ToBase32 () << std::endl;
				num++;
			}
			LogPrint (eLogInfo, num, " addresses saved");
		}
		else	
			LogPrint (eLogError, "Can't open file ", filename);	
		return num;	
	}	

//---------------------------------------------------------------------
	AddressBook::AddressBook (): m_IsLoaded (false), m_IsDownloading (false), 
		m_DefaultSubscription (nullptr), m_SubscriptionsUpdateTimer (nullptr)
	{
	}

	AddressBook::~AddressBook ()
	{	
		if (m_IsDownloading)
		{
			LogPrint (eLogInfo, "Subscription is downloading. Waiting for temination...");
			for (int i = 0; i < 30; i++)
			{
				if (!m_IsDownloading)
				{
					LogPrint (eLogInfo, "Subscription download complete");
					break;
				}	
				std::this_thread::sleep_for (std::chrono::seconds (1)); // wait for 1 seconds
			}	
			LogPrint (eLogError, "Subscription download hangs");
		}	
		if (m_Storage)
		{
			m_Storage->Save (m_Addresses);
			delete m_Storage;
		}
		delete m_DefaultSubscription;
		for (auto it: m_Subscriptions)
			delete it;
		delete m_SubscriptionsUpdateTimer;		
	}

	AddressBookStorage * AddressBook::CreateStorage ()
	{
		return new AddressBookFilesystemStorage ();
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
		if (!m_IsLoaded)
			LoadHosts ();
		if (m_IsLoaded)
		{
			auto it = m_Addresses.find (address);
			if (it != m_Addresses.end ())
				return &it->second;
		}
		return nullptr;	
	}

	void AddressBook::InsertAddress (const std::string& address, const std::string& base64)
	{
		i2p::data::IdentityEx ident;
		ident.FromBase64 (base64);
		if (!m_Storage)
			 m_Storage = CreateStorage ();
		m_Storage->AddAddress (ident);
		m_Addresses[address] = ident.GetIdentHash ();
		LogPrint (address,"->", ToAddress(ident.GetIdentHash ()), " added");
	}

	void AddressBook::InsertAddress (const i2p::data::IdentityEx& address)
	{
		if (!m_Storage) 
			m_Storage = CreateStorage ();
		m_Storage->AddAddress (address);
	}

	bool AddressBook::GetAddress (const std::string& address, i2p::data::IdentityEx& identity)
	{
		if (!m_Storage) 
			m_Storage = CreateStorage ();
		i2p::data::IdentHash ident;
		if (!GetIdentHash (address, ident)) return false;
		return m_Storage->GetAddress (ident, identity);
	}	

	void AddressBook::LoadHosts ()
	{
		if (!m_Storage)
			 m_Storage = CreateStorage ();
		if (m_Storage->Load (m_Addresses) > 0)
		{
			m_IsLoaded = true;
			return;
		}
	
		// try hosts.txt first
		std::ifstream f (i2p::util::filesystem::GetFullPath ("hosts.txt").c_str (), std::ofstream::in); // in text mode
		if (f.is_open ())	
		{
			LoadHostsFromStream (f);
			m_IsLoaded = true;
		}
		else
		{
			// if not found download it from http://i2p-projekt.i2p/hosts.txt 
			LogPrint (eLogInfo, "hosts.txt not found. Try to download it from default subscription...");
			if (!m_IsDownloading)
			{
				m_IsDownloading = true;
				if (!m_DefaultSubscription)
					m_DefaultSubscription = new AddressBookSubscription (*this, DEFAULT_SUBSCRIPTION_ADDRESS);
				m_DefaultSubscription->CheckSubscription ();
			}
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

				i2p::data::IdentityEx ident;
				if (ident.FromBase64(addr))
				{	
					m_Addresses[name] = ident.GetIdentHash ();
					m_Storage->AddAddress (ident);
					numAddresses++;
				}	
				else
					LogPrint (eLogError, "Malformed address ", addr, " for ", name);
			}		
		}
		LogPrint (eLogInfo, numAddresses, " addresses processed");
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
			std::ifstream f (i2p::util::filesystem::GetFullPath ("subscriptions.txt").c_str (), std::ofstream::in); // in text mode
			if (f.is_open ())
			{
				std::string s;
				while (!f.eof ())
				{
					getline(f, s);
					if (!s.length()) continue; // skip empty line
					m_Subscriptions.push_back (new AddressBookSubscription (*this, s));
				}
				LogPrint (eLogInfo, m_Subscriptions.size (), " subscriptions loaded");
			}
			else
				LogPrint (eLogWarning, "subscriptions.txt not found");
		}
		else
			LogPrint (eLogError, "Subscriptions already loaded");
	}

	void AddressBook::DownloadComplete (bool success)
	{
		m_IsDownloading = false;
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
		if (!m_Subscriptions.size ()) return;	

		auto dest = i2p::client::context.GetSharedLocalDestination ();
		if (dest)
		{
			m_SubscriptionsUpdateTimer = new boost::asio::deadline_timer (dest->GetService ());
			m_SubscriptionsUpdateTimer->expires_from_now (boost::posix_time::minutes(INITIAL_SUBSCRIPTION_UPDATE_TIMEOUT));
			m_SubscriptionsUpdateTimer->async_wait (std::bind (&AddressBook::HandleSubscriptionsUpdateTimer,
				this, std::placeholders::_1));
		}
		else
			LogPrint (eLogError, "Can't start subscriptions: missing shared local destination");
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
			if (!dest) return;
			if (m_IsLoaded && !m_IsDownloading && dest->IsReady ())
			{
				// pick random subscription
				CryptoPP::AutoSeededRandomPool rnd;
				auto ind = rnd.GenerateWord32 (0, m_Subscriptions.size() - 1);	
				m_IsDownloading = true;	
				m_Subscriptions[ind]->CheckSubscription ();		
			}
			else
			{
				if (!m_IsLoaded)
					LoadHosts ();
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
		LogPrint (eLogInfo, "Downloading hosts from ", m_Link, " ETag: ", m_Etag, " Last-Modified: ", m_LastModified);
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
				bool found = false;
				std::unique_lock<std::mutex> l(newDataReceivedMutex);
				i2p::client::context.GetSharedLocalDestination ()->RequestDestination (ident,
					[&newDataReceived, &found](bool success)
				    {
						found = success;
						newDataReceived.notify_all ();
					});
				if (newDataReceived.wait_for (l, std::chrono::seconds (SUBSCRIPTION_REQUEST_TIMEOUT)) == std::cv_status::timeout)
					LogPrint (eLogError, "Subscription LeseseSet request timeout expired");
				if (found)
					leaseSet = i2p::client::context.GetSharedLocalDestination ()->FindLeaseSet (ident);	
			}
			if (leaseSet)
			{
				std::stringstream request, response;
				// standard header
				request << "GET " << u.path_ << " HTTP/1.1\r\nHost: " << u.host_
				<< "\r\nAccept: */*\r\n" << "User-Agent: Wget/1.11.4\r\n" << "Connection: close\r\n";
				if (m_Etag.length () > 0) // etag
					request << i2p::util::http::IF_NONE_MATCH << ": \"" << m_Etag << "\"\r\n";
				if (m_LastModified.length () > 0) // if-modfief-since
					request << i2p::util::http::IF_MODIFIED_SINCE << ": " << m_LastModified << "\r\n";
				request << "\r\n"; // end of header
				auto stream = i2p::client::context.GetSharedLocalDestination ()->CreateStream (leaseSet, u.port_);
				stream->Send ((uint8_t *)request.str ().c_str (), request.str ().length ());
				
				uint8_t buf[4095];
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
						LogPrint (eLogError, "Subscription timeout expired");
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
					bool isChunked = false;
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
							header.resize (header.length () - 1); // delete \r	
							if (field == i2p::util::http::ETAG)
								m_Etag = header.substr (colon + 1);
							else if (field == i2p::util::http::LAST_MODIFIED)
								m_LastModified = header.substr (colon + 1);
							else if (field == i2p::util::http::TRANSFER_ENCODING)
								isChunked = !header.compare (colon + 1, std::string::npos, "chunked");
						}	
					}
					LogPrint (eLogInfo, m_Link, " ETag: ", m_Etag, " Last-Modified: ", m_LastModified);
					if (!response.eof ())	
					{
						success = true;
						if (!isChunked)
							m_Book.LoadHostsFromStream (response);
						else
						{
							// merge chunks
							std::stringstream merged;
							i2p::util::http::MergeChunkedResponse (response, merged);
							m_Book.LoadHostsFromStream (merged);
						}	
					}	
				}
				else if (status == 304)
				{	
					success = true;
					LogPrint (eLogInfo, "No updates from ", m_Link);
				}	
				else
					LogPrint (eLogWarning, "Adressbook HTTP response ", status);
			}
			else
				LogPrint (eLogError, "Address ", u.host_, " not found");
		}
		else
			LogPrint (eLogError, "Can't resolve ", u.host_);
		LogPrint (eLogInfo, "Download complete ", success ? "Success" : "Failed");
		m_Book.DownloadComplete (success);
	}
}
}

