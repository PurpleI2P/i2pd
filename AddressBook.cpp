#include <string.h>
#include <inttypes.h>
#include <string>
#include <map>
#include <fstream>
#include <boost/filesystem.hpp>
#include "base64.h"
#include "util.h"
#include "Identity.h"
#include "Log.h"
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
			}
		}	
		return false;
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

}
}

