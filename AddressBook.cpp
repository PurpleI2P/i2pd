#include <string.h>
#include <inttypes.h>
#include <string>
#include <map>
#include <fstream>
#include <chrono>
#include <condition_variable>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
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
			LogPrint (eLogInfo, num, " addresses save");
		}
		else	
			LogPrint (eLogError, "Can't open file ", filename);	
		return num;	
	}	

//---------------------------------------------------------------------
	AddressBook::AddressBook (): m_IsLoaded (false), m_IsDowloading (false)
	{
	}

	AddressBook::~AddressBook ()
	{
		if (m_Storage)
		{
			m_Storage->Save (m_Addresses);
			delete m_Storage;
		}
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
		LogPrint (address,"->",ident.GetIdentHash ().ToBase32 (), ".b32.i2p added");
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

	void AddressBook::LoadHostsFromI2P ()
	{
		std::string content;
		int http_code = i2p::util::http::httpRequestViaI2pProxy("http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt", content);
		if (http_code == 200)
		{
			std::ofstream f_save(i2p::util::filesystem::GetFullPath("hosts.txt").c_str(), std::ofstream::out);
			if (f_save.is_open())
			{
				f_save << content;
				f_save.close();
			}
			else
				LogPrint("Can't write hosts.txt");
			m_IsLoaded = false;
		}	
		else
			LogPrint ("Failed to download hosts.txt");
		m_IsDowloading = false;	
	
		return;
	}

	void AddressBook::LoadHosts ()
	{
		if (!m_Storage)
			 m_Storage = CreateStorage ();
		int numAddresses = m_Storage->Load (m_Addresses);
		if (numAddresses > 0)
		{
			m_IsLoaded = true;
			return;
		}
	
		// otherwise try hosts.txt
		std::ifstream f (i2p::util::filesystem::GetFullPath ("hosts.txt").c_str (), std::ofstream::in); // in text mode
		if (!f.is_open ())	
		{
			LogPrint ("hosts.txt not found. Try to load...");
			if (!m_IsDowloading)
			{
				m_IsDowloading = true;
				std::thread load_hosts(&AddressBook::LoadHostsFromI2P, this);
				load_hosts.detach();
			}
			return;
		}

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
				ident.FromBase64(addr);
				m_Addresses[name] = ident.GetIdentHash ();
				m_Storage->AddAddress (ident);
				numAddresses++;
			}		
		}
		LogPrint (numAddresses, " addresses loaded");
		m_Storage->Save (m_Addresses);
		m_IsLoaded = true;
	}

	AddressBookSubscription::AddressBookSubscription (AddressBook& book, const std::string& link):
		m_Book (book), m_Link (link)
	{
	}

	void AddressBookSubscription::CheckSubscription ()
	{
		std::thread load_hosts(&AddressBookSubscription::Request, this);
		load_hosts.detach();
	}

	void AddressBookSubscription::Request ()
	{
		// must be run in separate thread	
		i2p::util::http::url u (m_Link);
		i2p::data::IdentHash ident;
		if (m_Book.GetIdentHash (u.host_, ident))
		{
			auto leaseSet = i2p::data::netdb.FindLeaseSet (ident);
			if (!leaseSet)
			{
				i2p::data::netdb.RequestDestination (ident, true, i2p::client::context.GetSharedLocalDestination ()->GetTunnelPool ());
				std::this_thread::sleep_for (std::chrono::seconds (5)); // wait for 5 seconds
				leaseSet = i2p::data::netdb.FindLeaseSet (ident);
			}
			if (leaseSet)
			{
				std::stringstream request, response;
				request << "GET " << u.path_ << " HTTP/1.0\r\nHost: " << u.host_
				<< "\r\nAccept: */*\r\n" << "User-Agent: Wget/1.11.4\r\n" << "Connection: close\r\n\r\n";

				auto stream = i2p::client::context.GetSharedLocalDestination ()->CreateStream (*leaseSet, u.port_);
				stream->Send ((uint8_t *)request.str ().c_str (), request.str ().length ());
				
				uint8_t buf[4095];
				bool end = false;
				while (!end)
				{
					std::condition_variable newDataReceived;
					std::mutex newDataReceivedMutex;
					stream->AsyncReceive (boost::asio::buffer (buf, 4096), 
						[&](const boost::system::error_code& ecode, std::size_t bytes_transferred)
						{
							if (!ecode)
								response.write ((char *)buf, bytes_transferred);
							else
								end = true;	
							newDataReceived.notify_one ();
						},
						30); // wait for 30 seconds
					std::unique_lock<std::mutex> l(newDataReceivedMutex);
					newDataReceived.wait (l);
					if (!end)
						end = !stream->IsOpen ();
				}
			}
			else
				LogPrint (eLogError, "Address ", u.host_, " not found");
		}
		else
			LogPrint (eLogError, "Can't resolve ", u.host_);
	}
}
}

