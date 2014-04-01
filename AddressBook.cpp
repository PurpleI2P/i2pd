#include <string.h>
#include <string>
#include <map>
#include "base64.h"
#include "util.h"
#include "Identity.h"
#include "Log.h"
#include "AddressBook.h"

namespace i2p
{
namespace data
{

AddressBook::AddressBook (): m_IsLoaded (false)
{
}

	
const IdentHash * AddressBook::FindAddress (const std::string& address)
{
	if (!m_IsLoaded)
		LoadHosts ();
	auto it = m_Addresses.find (address);
	if (it != m_Addresses.end ())
		return &it->second;
	else
		return nullptr;	
}
		

void AddressBook::LoadHosts ()
{
	m_IsLoaded = true;
	std::ifstream f (i2p::util::filesystem::GetFullPath ("hosts.txt").c_str (), std::ofstream::in); // in text mode
	if (!f.is_open ())	
	{
		LogPrint ("hosts.txt not found");
		return;
	}
	int numAddresses = 0;

	std::string s;

	while (!f.eof ())
	{
		getline(f, s);

		if (!s.length())
			break;

		size_t pos = s.find('=');

		if (pos != std::string::npos)
		{
			std::string name = s.substr(0, pos++);
			std::string addr = s.substr(pos);

			Identity ident;
			Base64ToByteStream (addr.c_str(), addr.length(), (uint8_t *)&ident, sizeof (ident));
			m_Addresses[name] = CalculateIdentHash (ident);	
			numAddresses++;
		}		
	}
	LogPrint (numAddresses, " addresses loaded");
}

}
}

