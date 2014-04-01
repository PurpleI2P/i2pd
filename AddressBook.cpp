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
	char str[1024];
	while (!f.eof ())
	{
		f.getline (str, 1024);
		char * key = strchr (str, '=');
		if (key)
		{
			*key = 0;
			key++;
			Identity ident;
			Base64ToByteStream (key, strlen(key), (uint8_t *)&ident, sizeof (ident));
			m_Addresses[str] = CalculateIdentHash (ident);	
			numAddresses++;
		}		
	}
	LogPrint (numAddresses, " addresses loaded");
}

}
}

